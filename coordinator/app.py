import json
import jwt
import openai
import os
import MySQLdb
import requests
import secrets
import time
from apscheduler.schedulers.background import BackgroundScheduler
from base64 import b64encode, urlsafe_b64decode
from bs4 import BeautifulSoup
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from datetime import datetime
from dotenv import load_dotenv
from flask import Flask, g, jsonify, request
from flask_cors import CORS
from hdwallet import HDWallet
from hdwallet.cryptocurrencies import get_cryptocurrency
from hdwallet.symbols import DOGE, ETH, LTC
from uuid import uuid4


# Constants
class PaymentType:
    ECASH = "ecash"
    CRYPTO = "crypto"


class PaymentStatus:
    IN_PROGRESS = "in_progress"
    DONE = "done"


class ProxyType:
    BROWSER = "browser"
    SERVER = "server"


class ProxyStatus:
    REGISTERED = "registered"
    VERIFYING = "verifying"
    VERIFICATION_FAILED = "verification_failed"


class QueryType:
    NORMAL = "normal"
    VERIFICATION = "verification"


class QueryVerificationStatus:
    NOT_STARTED = "not_started"
    STARTED = "started"
    COMPLETED = "completed"
    FAILED = "failed"


class TokenType:
    AUTH = "auth"
    AUTH_OK = "auth_ok"
    REGISTER = "register"


ETHERSCAN_URL = "https://api-sepolia.etherscan.io/api"
TLSNOTARY_URL = "https://proxygpt.cs.umass.edu/notary"
TLSNOTARY_PUB_KEY = requests.get(f"{TLSNOTARY_URL}/info").json()["publicKey"]

REGISTER_TOKEN_DURATION = 600

# Retrieve secrets
load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")
DB_USERNAME = os.getenv("DB_USERNAME")
DB_PASSWORD = os.getenv("DB_PASSWORD")
MNEMONIC = os.getenv("WALLET_MNEMONIC")
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")
ECASH_PUB_KEY = os.getenv("ECASH_PUB_KEY")

ecash_private_key = serialization.load_der_private_key(
    urlsafe_b64decode(os.getenv("ECASH_PRIV_KEY")), password=None
).private_numbers()

auth_public_key = serialization.load_der_public_key(
    urlsafe_b64decode(os.getenv("AUTH_PUB_KEY"))
).public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

auth_private_key = serialization.load_der_private_key(
    urlsafe_b64decode(os.getenv("AUTH_PRIV_KEY")), password=None
).private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

# Route all requests through Tor
SOCKS_ADDR = "socks5h://127.0.0.1:9050"
os.environ["http_proxy"] = os.environ["https_proxy"] = SOCKS_ADDR
os.environ["no_proxy"] = "localhost"

# Load challenges
challenges = []
with open("./coordinator/jeopardy.txt", "r", encoding="utf-8") as file:
    for line in file:
        challenges.append(line.strip())


def gen_challenge():
    question = secrets.choice(challenges)
    nonce = str(uuid4())
    prompt = f"Answer succinctly in Jeopardy style: {question}\nUse ASCII letters and numbers only.\nMake sure to include this string {nonce} in the same line, do not add any extra character."
    return prompt


# Database config
db_config = {
    "user": DB_USERNAME,
    "password": DB_PASSWORD,
    "host": "localhost",
    "database": "mass_db",
}


def get_db_and_cursor():
    if "db" not in g:
        g.db = MySQLdb.connect(**db_config)
        g.db_cursor = g.db.cursor()
        create_tbl_query = """
        CREATE TABLE IF NOT EXISTS proxy_info (
            pseudonym VARCHAR(255) PRIMARY KEY,
            pid VARCHAR(36) NOT NULL,
            type ENUM(%s, %s) NOT NULL,
            status ENUM(%s, %s, %s) NOT NULL,
            encryption_key VARCHAR(255),
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_contact_ts TIMESTAMP,
            sla_1min_7d FLOAT,
            mean_ttr_7d FLOAT,
            avg_daily_load_7d FLOAT,
            load_1h INT,
            downvote_rate_7d FLOAT
        );
        """
        g.db_cursor.execute(
            create_tbl_query,
            (
                ProxyType.BROWSER,
                ProxyType.SERVER,
                ProxyStatus.REGISTERED,
                ProxyStatus.VERIFYING,
                ProxyStatus.VERIFICATION_FAILED,
            ),
        )
        g.db_cursor.nextset()

        create_tbl_query = """
        CREATE TABLE IF NOT EXISTS query_info (
            qid VARCHAR(36) PRIMARY KEY,
            type ENUM(%s, %s) NOT NULL,
            user_pseudonym VARCHAR(255),
            user_encryption_key VARCHAR(255),
            user_symmetric_encryption_key VARCHAR(255),
            user_iv VARCHAR(16),
            proxy_pseudonym VARCHAR(255) NOT NULL,
            proxy_iv VARCHAR(16),
            content TEXT NOT NULL,
            content_plaintext TEXT NULL,
            proxy_response TEXT,
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ts_response TIMESTAMP,
            verification_status ENUM(%s, %s, %s, %s) NOT NULL,
            downvote BOOL NOT NULL DEFAULT FALSE,
            FOREIGN KEY (proxy_pseudonym) REFERENCES proxy_info (pseudonym)
        );
        """
        g.db_cursor.execute(
            create_tbl_query,
            (
                QueryType.NORMAL,
                QueryType.VERIFICATION,
                QueryVerificationStatus.NOT_STARTED,
                QueryVerificationStatus.STARTED,
                QueryVerificationStatus.COMPLETED,
                QueryVerificationStatus.FAILED,
            ),
        )
        g.db_cursor.nextset()

        create_tbl_query = """
        CREATE TABLE IF NOT EXISTS payment_info (
            id VARCHAR(512) PRIMARY KEY,
            qid VARCHAR(36) NOT NULL,
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            type ENUM(%s, %s) NOT NULL,
            status ENUM(%s, %s) NOT NULL,
            currency VARCHAR(4),
            value DOUBLE,
            FOREIGN KEY (qid) REFERENCES query_info (qid)
        );
        """
        g.db_cursor.execute(
            create_tbl_query,
            (
                PaymentType.ECASH,
                PaymentType.CRYPTO,
                PaymentStatus.IN_PROGRESS,
                PaymentStatus.DONE,
            ),
        )
        g.db_cursor.nextset()

        g.db.commit()

    return g.db, g.db_cursor


def base64encode(arr):
    return b64encode(arr).decode("utf-8")


def b64ToInt(str):
    return int.from_bytes(urlsafe_b64decode(str), byteorder="big")


def intToB64(n):
    bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")
    return base64encode(bytes)


def sign_ecash(ecash):
    try:
        ecash = b64ToInt(ecash)
        signature = pow(ecash, ecash_private_key.d, ecash_private_key.public_numbers.n)
        return intToB64(signature)
    except:
        return None


def verify_ecash(ecash):
    payment_parts = ecash.split("||")
    if len(payment_parts) != 2:
        raise Exception("Invalid payment")
    digest = hashes.Hash(hashes.SHA256())
    digest.update(payment_parts[0].encode("utf-8"))
    msg = int(digest.finalize().hex(), 16)
    signature = b64ToInt(payment_parts[1])
    new_s = pow(
        signature,
        ecash_private_key.public_numbers.e,
        ecash_private_key.public_numbers.n,
    )
    if new_s != msg:
        raise Exception("Invalid payment")


def verify_ecash_usage(ecash):
    _, cursor = get_db_and_cursor()
    select_query = """
    SELECT id FROM payment_info
    WHERE id = %s;
    """
    cursor.execute(select_query, (ecash,))
    row = cursor.fetchone()
    if row is not None:
        raise Exception("Invalid payment")


def verify_nonce_signature(nonce, signature, public_key):
    nonce = urlsafe_b64decode(nonce)
    signature = urlsafe_b64decode(signature)
    l = len(signature) // 2
    r = int.from_bytes(signature[:l], byteorder="big")
    s = int.from_bytes(signature[l:], byteorder="big")
    signature = utils.encode_dss_signature(r, s)
    public_key = serialization.load_der_public_key(urlsafe_b64decode(public_key))
    public_key.verify(signature, nonce, ec.ECDSA(hashes.SHA256()))


# TODO: Check conversation structure
def verify_tlsn_proof(
    proof, query, responses, expiration_time=None, html_response=None
):
    if proof is None or responses is None or len(responses) == 0:
        return False
    try:
        res = requests.post(
            "http://localhost:7175",
            json={"proof": proof, "notaryPubKey": TLSNOTARY_PUB_KEY},
        )
        if res.status_code != 200:
            return False, res.status_code
        res = res.json()["result"]

        # Check server
        if res["serverName"] != "chatgpt.com" or not res["sent"].startswith(
            "GET https://chatgpt.com/backend-api/conversation/"
        ):
            return False

        # Check expiration time
        if expiration_time is not None:
            time = res["time"]
            if (
                time > expiration_time
                or time < expiration_time - REGISTER_TOKEN_DURATION
            ):
                return False

        # Check query
        recv = res["recv"]
        if json.dumps(query)[1:-1] not in recv:
            return False

        # Check proxy's responses
        if any([r not in recv for r in responses]):
            return False

        # Check html response.
        # TODO: This is rather strict, does not work well with markdown.
        # Only uses simple one-line challenges!
        if html_response is not None:
            soup = BeautifulSoup(html_response, features="html.parser")
            html_text = soup.get_text(strip=True)
            if html_text != "".join(responses):
                return False

        return True
    except Exception:
        return False


# App
app = Flask(__name__)
cors = CORS(app)


@app.teardown_appcontext
def close_db(error):
    if "db" in g:
        g.db_cursor.close()
        g.db.close()


@app.after_request
def add_cache_control(response):
    if response.mimetype == "application/javascript":
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


@app.route("/proxies", methods=["GET"])
def handle_proxies():
    _, cursor = get_db_and_cursor()
    select_query = """
    SELECT
        pseudonym, pid, type, encryption_key,
        sla_1min_7d, mean_ttr_7d, avg_daily_load_7d, load_1h, downvote_rate_7d
    FROM proxy_info
    WHERE
        status = %s
        AND last_contact_ts IS NOT NULL
        AND last_contact_ts > TIMESTAMPADD(MINUTE, -10, NOW())
    ORDER BY
        sla_1min_7d DESC,
        load_1h,
        last_contact_ts DESC
    LIMIT 10;
    """
    cursor.execute(select_query, (ProxyStatus.REGISTERED,))
    rows = cursor.fetchall()

    if rows is None or len(rows) == 0:
        return "No available proxy.", 503

    results = [
        {
            "pseudonym": row[0],
            "pid": row[1],
            "type": row[2],
            "encryption_key": row[3],
            "sla_1min_7d": row[4],
            "mean_ttr_7d": row[5],
            "avg_daily_load_7d": row[6],
            "load_1h": row[7],
            "downvote_rate_7d": row[8],
        }
        for row in rows
    ]
    return jsonify(results), 200


@app.route("/auth", methods=["POST"])
def handle_auth():
    invalid_request = "Invalid request.", 400
    if not request.is_json:
        return invalid_request
    data = request.get_json()
    pseudonym = data.get("pseudonym", "")
    _, cursor = get_db_and_cursor()
    select_query = """
    SELECT status, type FROM proxy_info
    WHERE pseudonym = %s AND type = %s AND status = %s;
    """
    cursor.execute(select_query, (pseudonym, ProxyType.BROWSER, ProxyStatus.REGISTERED))
    row = cursor.fetchone()
    if row is None:
        return "Forbidden.", 403

    token = data.get("token", None)
    signature = data.get("signature", None)
    if token is None:
        nonce = intToB64(secrets.randbits(256))
        payload = {
            "aud": pseudonym,
            "exp": int(time.time()) + 900,
            "type": TokenType.AUTH,
            "nonce": nonce,
        }
        token = jwt.encode(payload, auth_private_key, algorithm="EdDSA")
        return jsonify({"nonce": nonce, "token": token}), 200
    elif signature is not None:
        try:
            token = jwt.decode(
                token,
                auth_public_key,
                algorithms=["EdDSA"],
                options={
                    "require": ["aud", "exp", "type", "nonce"],
                    "verify_aud": True,
                    "verify_exp": True,
                },
                audience=pseudonym,
            )
            verify_nonce_signature(token["nonce"], signature, pseudonym)
            if token["type"] != TokenType.AUTH:
                raise Exception("Invalid token type!")

            payload = {
                "aud": pseudonym,
                "exp": int(time.time()) + 86400,
                "type": TokenType.AUTH_OK,
            }
            token = jwt.encode(payload, auth_private_key, algorithm="EdDSA")
            return jsonify({"token": token}), 200
        except:
            return "Authorization failed.", 401
    else:
        return invalid_request


@app.route("/register", methods=["POST"])
def handle_register():
    invalid_request = "Invalid request.", 400
    if not request.is_json:
        return invalid_request
    data = request.get_json()
    proxy_type = data.get("proxy_type", "")
    encryption_key = data.get("encryption_key", None)
    pseudonym = data.get("pseudonym", "")
    if proxy_type != ProxyType.BROWSER or pseudonym is None or encryption_key is None:
        return invalid_request

    db, cursor = get_db_and_cursor()
    select_query = """
    SELECT status, type FROM proxy_info
    WHERE pseudonym = %s;
    """
    cursor.execute(select_query, (pseudonym,))
    row = cursor.fetchone()

    # Issue challenge if new
    if row is None:
        pid = str(uuid4())
        insert_query = """
        INSERT INTO proxy_info (pseudonym, pid, type, status, encryption_key)
        VALUES (%s, %s, %s, %s, %s);
        """
        cursor.execute(
            insert_query,
            (pseudonym, pid, proxy_type, ProxyStatus.VERIFYING, encryption_key),
        )
        db.commit()
        qid = str(uuid4())
        query = gen_challenge()
        payload = {
            "aud": pseudonym,
            "exp": int(time.time()) + REGISTER_TOKEN_DURATION,
            "type": TokenType.REGISTER,
            "qid": qid,
            "query": query,
        }
        token = jwt.encode(payload, auth_private_key, algorithm="EdDSA")
        return jsonify({"pid": pid, "qid": qid, "query": query, "token": token}), 200

    # Check response
    status = row[0]
    type = row[1]
    if status != ProxyStatus.VERIFYING or type != proxy_type:
        return invalid_request

    qid = data.get("qid", "")
    token = data.get("token", "")
    try:
        token = jwt.decode(
            token,
            auth_public_key,
            algorithms=["EdDSA"],
            options={
                "require": ["aud", "exp", "type", "qid", "query"],
                "verify_aud": True,
                "verify_exp": True,
            },
            audience=pseudonym,
        )
        if token["type"] != TokenType.REGISTER or token["qid"] != qid:
            raise Exception("Invalid token!")
    except:
        return invalid_request

    challenge_query = token["query"]
    proxy_response = data.get("response", None)
    proof = data.get("proof", None)
    is_valid = verify_tlsn_proof(
        proof, challenge_query, proxy_response, expiration_time=token["exp"]
    )

    update_query = """
    UPDATE proxy_info
    SET
        status = %s
    WHERE pseudonym = %s;
    """
    new_status = ProxyStatus.REGISTERED if is_valid else ProxyStatus.VERIFICATION_FAILED
    cursor.execute(update_query, (new_status, pseudonym))
    cursor.nextset()
    db.commit()

    if not is_valid:
        return "Invalid request.", 401
    else:
        return jsonify({"ecash_key": ECASH_PUB_KEY}), 200


@app.route("/query", methods=["POST"])
def handle_query():
    if not request.is_json:
        return "Invalid JSON data received.", 400

    data = request.get_json()

    proxy_type = data["proxy_type"]
    if proxy_type == ProxyType.BROWSER:
        return handle_browser_proxy_query(data)
    elif proxy_type == ProxyType.SERVER:
        return handle_server_proxy_query(data)
    else:
        return "Invalid proxy type.", 400


def handle_browser_proxy_query(data):
    proxy_pseudonym = data["proxy_pseudonym"]
    db, cursor = get_db_and_cursor()
    select_query = """
    SELECT encryption_key FROM proxy_info
    WHERE pseudonym = %s AND status = %s AND type = %s;
    """
    cursor.execute(
        select_query, (proxy_pseudonym, ProxyStatus.REGISTERED, ProxyType.BROWSER)
    )
    row = cursor.fetchone()
    if row is None:
        return "Invalid proxy.", 400

    # Check payment information
    payment = data["payment"]
    if payment != "test":
        try:
            verify_ecash(payment)
            verify_ecash_usage(payment)
        except:
            return "Invalid payment.", 400

    qid = str(uuid4())
    user_pseudonym = data["pseudonym"]
    user_encryption_key = data["encryption_key"]
    user_iv = data["iv"]
    content = data["content"]

    insert_query = """
    INSERT INTO query_info (qid, type, user_pseudonym, proxy_pseudonym, user_encryption_key, user_iv, content, verification_status)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
    """
    cursor.execute(
        insert_query,
        (
            qid,
            QueryType.NORMAL,
            user_pseudonym,
            proxy_pseudonym,
            user_encryption_key,
            user_iv,
            content,
            QueryVerificationStatus.NOT_STARTED,
        ),
    )
    cursor.nextset()

    if secrets.randbits(3) == 1:
        insert_verification_query(proxy_pseudonym, row[0], cursor)

    if payment != "test":
        insert_query = """
        INSERT INTO payment_info (id, qid, type, status)
            VALUES (%s, %s, %s, %s);
        """
        cursor.execute(
            insert_query, (payment, qid, PaymentType.ECASH, PaymentStatus.IN_PROGRESS)
        )

    db.commit()
    return jsonify({"qid": qid}), 200


def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def insert_verification_query(proxy_pseudonym, proxy_encryption_key, cursor):
    insert_query = """
    INSERT INTO query_info (
        qid, type, user_pseudonym, proxy_pseudonym,
        user_encryption_key, user_symmetric_encryption_key, user_iv,
        content, content_plaintext, verification_status
    )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
    """
    prompt = gen_challenge()

    signature_key_pair = generate_key_pair()
    encryption_key_pair = generate_key_pair()
    iv = os.urandom(12)

    payload = json.dumps({"prompt_text": prompt, "prev_qid": None, "signature": None})

    proxy_encryption_pub_key = serialization.load_der_public_key(
        urlsafe_b64decode(proxy_encryption_key)
    )
    aes_key = encryption_key_pair[0].exchange(ec.ECDH(), proxy_encryption_pub_key)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    encrypted = (
        encryptor.update(payload.encode()) + encryptor.finalize() + encryptor.tag
    )

    signature_public_key_spki = signature_key_pair[1].public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    encryption_public_key_spki = encryption_key_pair[1].public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    cursor.execute(
        insert_query,
        (
            str(uuid4()),
            QueryType.VERIFICATION,
            base64encode(signature_public_key_spki),
            proxy_pseudonym,
            base64encode(encryption_public_key_spki),
            base64encode(aes_key),
            base64encode(iv),
            base64encode(encrypted),
            payload,
            QueryVerificationStatus.NOT_STARTED,
        ),
    )
    cursor.nextset()


def handle_server_proxy_query(data):
    # Validate payment
    currency = data["currency"]
    if currency not in ["ETH"]:
        return "Invalid currency. Only ETH is supported.", 400

    payment = data["payment"]
    url_params = {
        "module": "proxy",
        "action": "eth_getTransactionByHash",
        "txhash": payment,
        "apikey": ETHERSCAN_API_KEY,
    }
    r = requests.get(url=ETHERSCAN_URL, params=url_params)
    result = r.json().get("result")
    if result is None:
        return "Invalid transaction.", 400

    to_addr = result.get("to")
    actual_addr = (
        HDWallet(ETH)
        .from_mnemonic(MNEMONIC)
        .from_path("m/44'/60'/0'/0/0")
        .p2pkh_address()
    )
    if to_addr is None or to_addr.lower() != actual_addr.lower():
        return "Invalid transaction.", 400

    value = result.get("value")
    if value is None:
        return "Invalid transaction fund.", 400
    value = int(value, 0) / (10**18)  # Hex to decimal
    if value < 0.001:
        return "Insufficient transaction fund.", 400

    # Chat
    messages = data["messages"]
    completion = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=messages,
    )
    return jsonify({"response": str(completion.choices[0].message)}), 200


@app.route("/pay", methods=["GET"])
def handle_pay():
    currencies = [DOGE, ETH, LTC]
    addresses = {}
    for currency in currencies:
        path = get_cryptocurrency(currency).DEFAULT_PATH
        addresses[currency] = (
            HDWallet(currency).from_mnemonic(MNEMONIC).from_path(path).p2pkh_address()
        )
    return addresses, 200


@app.route("/request", methods=["GET", "POST"])
def handle_request():
    data = None
    invalid_request = "Invalid request.", 400
    if request.method == "GET":
        pseudonym = request.args.get("pseudonym")
    elif request.method == "POST" and request.is_json:
        data = request.get_json()
        pseudonym = data.get("pseudonym", None)
    else:
        return invalid_request

    if pseudonym is None:
        return invalid_request

    unauthorized_request = "Authorization failed.", 401
    authorization_header = request.headers.get("Authorization", None)
    if authorization_header is None or not authorization_header.startswith("Bearer "):
        return unauthorized_request
    token = authorization_header[len("Bearer ") :]
    try:
        token = jwt.decode(
            token,
            auth_public_key,
            algorithms=["EdDSA"],
            options={
                "require": ["aud", "exp", "type"],
                "verify_aud": True,
                "verify_exp": True,
            },
            audience=pseudonym,
        )
        if token["type"] != TokenType.AUTH_OK:
            raise Exception("Invalid token type!")
    except:
        return unauthorized_request

    db, cursor = get_db_and_cursor()
    select_query = """
    SELECT last_contact_ts FROM proxy_info
    WHERE pseudonym = %s AND status = %s;
    """
    cursor.execute(select_query, (pseudonym, ProxyStatus.REGISTERED))
    row = cursor.fetchone()
    if row is None:
        return "Forbidden.", 403

    # Update last contact time
    last_contact_ts = row[0]
    if last_contact_ts is None or last_contact_ts.timestamp() < time.time() - 300:
        update_query = """
        UPDATE proxy_info
            SET
                last_contact_ts = NOW()
            WHERE pseudonym = %s;
        """
        cursor.execute(update_query, (pseudonym,))
        cursor.nextset()
        db.commit()

    if request.method == "GET":
        return handle_proxy_get_request(pseudonym, cursor)
    else:
        return handle_proxy_post_request(data, pseudonym, cursor, db)


def handle_proxy_get_request(pseudonym, cursor):
    select_query = """
    SELECT qid FROM query_info WHERE proxy_pseudonym = %s AND verification_status = %s;
    """
    cursor.execute(select_query, (pseudonym, QueryVerificationStatus.FAILED))
    if cursor.fetchone() is not None:
        return "Verification challenge failed.", 403

    select_query = """
    SELECT qid FROM query_info
    WHERE
        proxy_pseudonym = %s
        AND proxy_response IS NOT NULL
        AND type = %s
        AND verification_status = %s;
    """
    cursor.execute(
        select_query,
        (pseudonym, QueryType.VERIFICATION, QueryVerificationStatus.STARTED),
    )
    rows = cursor.fetchall()
    if len(rows) > 0:
        rows = [{"qid": row[0], "proof_required": True} for row in rows]
        return jsonify({"requests": rows}), 200

    select_query = """
    SELECT qid, user_pseudonym, user_encryption_key, user_iv, content
    FROM query_info
    WHERE proxy_pseudonym = %s AND proxy_response IS NULL AND verification_status = %s
    ORDER BY ts;
    """
    cursor.execute(select_query, (pseudonym, QueryVerificationStatus.NOT_STARTED))
    rows = cursor.fetchall()
    rows = [
        {
            "qid": row[0],
            "user_pseudonym": row[1],
            "user_encryption_key": row[2],
            "user_iv": row[3],
            "content": row[4],
        }
        for row in rows
    ]
    return jsonify({"requests": rows}), 200


def handle_proxy_post_request(data, pseudonym, cursor, db):
    invalid_request = "Invalid request.", 400
    # NOTE: response is a string for normal query, an array for verification
    response = data.get("response", None)
    qid = data.get("qid", None)
    if qid is None or response is None:
        return invalid_request

    select_query = """
    SELECT
        type, proxy_response, proxy_iv, verification_status,
        content_plaintext, user_symmetric_encryption_key
    FROM query_info
    WHERE qid = %s AND proxy_pseudonym = %s;
    """
    cursor.execute(select_query, (qid, pseudonym))
    row = cursor.fetchone()
    if row is None:
        return invalid_request

    query_type = row[0]
    prev_response = row[1]  # Note: Contains HTML
    prev_iv = row[2]
    status = row[3]
    is_verification = query_type == QueryType.VERIFICATION
    if not is_verification or status == QueryVerificationStatus.NOT_STARTED:
        proxy_iv = data.get("iv", None)
        if (
            prev_response is not None
            or prev_iv is not None
            or proxy_iv is None
            or response is None
        ):
            return invalid_request
        update_query = """
        UPDATE query_info
            SET
                proxy_iv = %s,
                proxy_response = %s,
                verification_status = %s,
                ts_response = NOW()
            WHERE qid = %s;
        """
        status = (
            QueryVerificationStatus.STARTED
            if is_verification
            else QueryVerificationStatus.NOT_STARTED
        )
        cursor.execute(update_query, (proxy_iv, response, status, qid))
        db.commit()
        return jsonify({"ecash_signature": None}), 200
    elif status == QueryVerificationStatus.STARTED:
        proof = data.get("proof", None)
        payload = row[4]
        aes_key = row[5]
        if (
            prev_response is None
            or prev_iv is None
            or proof is None
            or payload is None
            or aes_key is None
        ):
            return invalid_request

        # Decrypt previous proxy's response
        prev_response = urlsafe_b64decode(prev_response)
        aes_key = urlsafe_b64decode(aes_key)
        prev_iv = urlsafe_b64decode(prev_iv)
        ciphertext = prev_response[:-16]
        tag = prev_response[-16:]
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(prev_iv, tag))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()

        query = json.loads(payload)["prompt_text"]
        is_valid = verify_tlsn_proof(proof, query, response, html_response=decrypted)
        update_query = """
        UPDATE query_info
            SET
                verification_status = %s,
                ts_response = NOW()
            WHERE qid = %s;
        """
        status = (
            QueryVerificationStatus.COMPLETED
            if is_valid
            else QueryVerificationStatus.FAILED
        )
        cursor.execute(update_query, (status, qid))
        cursor.nextset()
        if not is_valid:
            update_query = """
            UPDATE proxy_info SET status = %s WHERE pseudonym = %s;
            """
            cursor.execute(update_query, (ProxyStatus.VERIFICATION_FAILED, pseudonym))
        db.commit()

        if is_valid:
            signature = sign_ecash(data.get("ecash", None))
            return jsonify({"ecash_signature": signature}), 200

    return invalid_request


@app.route("/result", methods=["GET"])
def handle_result():
    pseudonym = request.args.get("pseudonym")
    _, cursor = get_db_and_cursor()
    select_query = """
    SELECT qid, proxy_pseudonym, proxy_iv, proxy_response FROM query_info
    WHERE user_pseudonym = %s AND proxy_response IS NOT NULL;
    """
    cursor.execute(select_query, (pseudonym,))
    rows = cursor.fetchall()
    if rows is None or len(rows) == 0:
        return jsonify({"results": []}), 200

    results = [
        {
            "qid": row[0],
            "proxy_pseudonym": row[1],
            "proxy_iv": row[2],
            "proxy_response": row[3],
        }
        for row in rows
    ]
    return jsonify({"results": results}), 200


@app.route("/feedback", methods=["POST"])
def handle_feedback():
    invalid_request = "Invalid request.", 400
    if not request.is_json:
        return invalid_request
    db, cursor = get_db_and_cursor()
    data = request.get_json()
    pseudonym = data.get("pseudonym", None)
    qid = data.get("qid", None)
    downvote = data.get("downvote", None)
    if pseudonym is None or qid is None or downvote is None:
        return invalid_request
    
    select_query = """
    SELECT downvote
    FROM query_info
    WHERE
        user_pseudonym = %s
        AND qid = %s
        AND type = %s
        AND ts_response IS NOT NULL;
    """
    cursor.execute(select_query, (pseudonym, qid, QueryType.NORMAL))
    row = cursor.fetchone()
    if row is None:
        return invalid_request
    if row[0] != downvote:
        update_query = """
        UPDATE query_info
        SET downvote = %s
        WHERE qid = %s;
        """
        cursor.execute(update_query, (downvote, qid))
        db.commit()
    return jsonify({"msg": "OK"}), 200


# Set up scheduler for recurring job
def update_proxy_stats():
    with app.app_context():
        db, cursor = get_db_and_cursor()
        update_query = """
        UPDATE proxy_info
        LEFT JOIN (
            SELECT
                proxy_pseudonym,
                (
                    1.0 * SUM(IF(ts_response IS NOT NULL AND ts_response < TIMESTAMPADD(MINUTE, 1, ts), 1, 0)) /
                    NULLIF(SUM(IF(NOW() < TIMESTAMPADD(MINUTE, 1, ts), 0, 1)), 0)
                ) AS sla_1min,
                (
                    1.0 * SUM(IF(ts_response IS NOT NULL, TIMESTAMPDIFF(SECOND, ts, ts_response), 0)) /
                    NULLIF(SUM(IF(ts_response IS NOT NULL, 1, 0)), 0)
                ) AS mean_ttr,
                (
                    1.0 * COUNT(*) / 7
                ) AS avg_daily_load,
                SUM(IF(ts > TIMESTAMPADD(HOUR, -1, NOW()), 1, 0)) AS load_1h,
                (
                    1.0 * SUM(IF(ts_response IS NOT NULL, downvote, 0)) /
                    NULLIF(SUM(IF(ts_response IS NOT NULL, 1, 0)), 0)
                ) AS downvote_rate
            FROM query_info
            WHERE
                type = %s
                AND ts > TIMESTAMPADD(DAY, -7, NOW())
            GROUP BY proxy_pseudonym
        ) stats_7d
        ON proxy_info.pseudonym = stats_7d.proxy_pseudonym
        SET
            proxy_info.sla_1min_7d = COALESCE(stats_7d.sla_1min, NULL),
            proxy_info.mean_ttr_7d = COALESCE(stats_7d.mean_ttr, NULL),
            proxy_info.avg_daily_load_7d = COALESCE(stats_7d.avg_daily_load, NULL),
            proxy_info.load_1h = COALESCE(stats_7d.load_1h, NULL),
            proxy_info.downvote_rate_7d = COALESCE(stats_7d.downvote_rate, NULL);
        """

        cursor.execute(update_query, (QueryType.NORMAL,))
        db.commit()


scheduler = BackgroundScheduler()
scheduler.add_job(
    update_proxy_stats,
    trigger="interval",
    minutes=5,
    id="update_proxy_stats",
    next_run_time=datetime.now(),
)
scheduler.start()

if __name__ == "__main__":
    app.run()
