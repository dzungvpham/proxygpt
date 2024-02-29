import jwt
import html
import openai
import os
import MySQLdb
import requests
import secrets
import time
from base64 import b64encode, urlsafe_b64decode
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from dotenv import load_dotenv
from flask import Flask, g, jsonify, request
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

# Init constants
ETHERSCAN_URL = f"https://api-sepolia.etherscan.io/api"

# Route all requests through Tor
SOCKS_ADDR = "socks5h://127.0.0.1:9050"
os.environ["http_proxy"] = os.environ["https_proxy"] = SOCKS_ADDR

# Load challenges
challenges = []
with open("./coordinator/challenges.txt", "r", encoding="utf-8") as file:
    for line in file:
        answer, question = line.strip().split("\t")
        challenges.append((answer, question))


def gen_challenge():
    answer, question = secrets.choice(challenges)
    answer_tag = secrets.choice(
        ["name", "target", "answer", "response", "reply", "solution"]
    )
    answer = f"<{answer_tag}>{answer}</{answer_tag}>"
    prompt = """You have seen the following passage in your training data. What is the proper name that fills in the [MASK] token in it?  This name is exactly one word long, and is a proper name (not a pronoun or any other word). You must make a guess, even if you are uncertain. Only include the output, not the input.

Example:

Input: "Stay gold, [MASK], stay gold."
Output: <%s>Ponyboy</%s>

Input: "The door opened, and [MASK], dressed and hatted, entered with a cup of tea."
Output: <%s>Gerty</%s>

Input: %s
Output: 

""" % (
        answer_tag,
        answer_tag,
        answer_tag,
        answer_tag,
        question,
    )
    return answer, prompt


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
            type ENUM(%s, %s) NOT NULL,
            status ENUM(%s, %s, %s) NOT NULL,
            encryption_key VARCHAR(255),
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ts_final TIMESTAMP
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
            user_iv VARCHAR(16),
            proxy_pseudonym VARCHAR(255) NOT NULL,
            proxy_iv VARCHAR(16),
            content TEXT NOT NULL,
            expected_response TEXT,
            proxy_response TEXT,
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ts_response TIMESTAMP,
            FOREIGN KEY (proxy_pseudonym) REFERENCES proxy_info (pseudonym)
        );
        """
        g.db_cursor.execute(
            create_tbl_query, (QueryType.NORMAL, QueryType.VERIFICATION)
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


def b64ToInt(str):
    return int.from_bytes(urlsafe_b64decode(str), byteorder="big")


def intToB64(n):
    bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")
    return b64encode(bytes).decode("utf-8")


def sign_ecash(ecash):
    ecash = b64ToInt(ecash)
    signature = pow(ecash, ecash_private_key.d, ecash_private_key.public_numbers.n)
    return intToB64(signature)


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


# App
app = Flask(__name__)


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
    SELECT pseudonym, type, encryption_key FROM proxy_info
    WHERE status = %s
    ORDER BY ts_final DESC
    LIMIT 5;
    """
    cursor.execute(select_query, (ProxyStatus.REGISTERED,))
    rows = cursor.fetchall()

    if rows is None or len(rows) == 0:
        return "No available proxy.", 503

    results = [
        {"pseudonym": row[0], "type": row[1], "encryption_key": row[2]} for row in rows
    ]
    return jsonify(results), 200


@app.route("/auth", methods=["POST"])
def handle_auth():
    invalid_request = jsonify({"ok": False, "msg": "Invalid request."}), 400
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
        return invalid_request

    token = data.get("token", None)
    signature = data.get("signature", None)
    if token is None:
        nonce = intToB64(secrets.randbits(256))
        payload = {
            "aud": pseudonym,
            "exp": int(time.time()) + 900,
            "nonce": nonce,
        }
        token = jwt.encode(payload, auth_private_key, algorithm="EdDSA")
        return jsonify({"ok": True, "nonce": nonce, "token": token}), 200
    elif signature is not None:
        try:
            token = jwt.decode(
                token,
                auth_public_key,
                algorithms=["EdDSA"],
                options={
                    "require": ["aud", "exp", "nonce"],
                    "verify_aud": True,
                    "verify_exp": True,
                },
                audience=pseudonym,
            )
            verify_nonce_signature(token["nonce"], signature, pseudonym)

            payload = {
                "aud": pseudonym,
                "exp": int(time.time()) + 86400,
            }
            token = jwt.encode(payload, auth_private_key, algorithm="EdDSA")
            return jsonify({"ok": True, "token": token}), 200
        except:
            return jsonify({"ok": False, "msg": "Authorization failed."}), 401
    else:
        return invalid_request


@app.route("/register", methods=["POST"])
def handle_register():
    if not request.is_json:
        return "Invalid request.", 400
    data = request.get_json()
    proxy_type = data.get("proxy_type", "")
    encryption_key = data.get("encryption_key", None)
    if proxy_type != ProxyType.BROWSER or encryption_key is None:
        return "Invalid request.", 400

    pseudonym = data.get("pseudonym", "")
    db, cursor = get_db_and_cursor()
    select_query = """
    SELECT status, type FROM proxy_info
    WHERE pseudonym = %s;
    """
    cursor.execute(select_query, (pseudonym,))
    row = cursor.fetchone()

    if row is None:
        answer, question = gen_challenge()

        insert_query = """
        INSERT INTO proxy_info (pseudonym, type, status, encryption_key)
        VALUES (%s, %s, %s, %s);
        """
        cursor.execute(
            insert_query, (pseudonym, proxy_type, ProxyStatus.VERIFYING, encryption_key)
        )
        cursor.nextset()

        qid = uuid4()
        insert_query = """
        INSERT INTO query_info (qid, type, proxy_pseudonym, content, expected_response)
        VALUES (%s, %s, %s, %s, %s);
        """
        cursor.execute(
            insert_query,
            (
                qid,
                QueryType.VERIFICATION,
                pseudonym,
                question,
                f"<p>{html.escape(answer)}</p>",
            ),
        )
        db.commit()

        return jsonify({"ok": True, "qid": qid, "query": question}), 200

    # Check response
    status = row[0]
    type = row[1]
    if status != ProxyStatus.VERIFYING or type != proxy_type:
        return "Invalid request.", 400

    qid = data.get("qid", "")
    select_query = """
    SELECT expected_response FROM query_info
    WHERE qid = %s AND type = %s AND proxy_pseudonym = %s AND proxy_response IS NULL;
    """
    cursor.execute(select_query, (qid, QueryType.VERIFICATION, pseudonym))
    query_row = cursor.fetchone()
    if query_row is None:
        return "Invalid request.", 400

    proxy_response = data.get("response", "")
    is_correct = proxy_response == query_row[0]
    update_query = """
    UPDATE proxy_info
    SET
        status = %s,
        ts_final = NOW()
    WHERE pseudonym = %s;
    """
    new_status = (
        ProxyStatus.REGISTERED if is_correct else ProxyStatus.VERIFICATION_FAILED
    )
    cursor.execute(update_query, (new_status, pseudonym))
    cursor.nextset()

    update_query = """
    UPDATE query_info
    SET
        proxy_response = %s,
        ts_response = NOW()
    WHERE qid = %s;
    """
    cursor.execute(
        update_query,
        (proxy_response, qid),
    )
    cursor.nextset()
    db.commit()

    if not is_correct:
        return jsonify({"ok": False, "msg": "Incorrect answer."}), 406
    else:
        return jsonify({"ok": True, "ecash_key": ECASH_PUB_KEY}), 200


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
    SELECT pseudonym FROM proxy_info
    WHERE pseudonym = %s AND status = %s AND type = %s;
    """
    cursor.execute(
        select_query, (proxy_pseudonym, ProxyStatus.REGISTERED, ProxyType.BROWSER)
    )
    row = cursor.fetchone()
    if row is None:
        return jsonify({"ok": False, "msg": "Invalid proxy."}), 400

    # Check payment information
    payment = data["payment"]
    if payment != "test":
        try:
            verify_ecash(payment)
            verify_ecash_usage(payment)
        except:
            return jsonify({"ok": False, "msg": "Invalid payment."}), 400

    qid = str(uuid4())
    user_pseudonym = data["pseudonym"]
    user_encryption_key = data["encryption_key"]
    user_iv = data["iv"]
    content = data["content"]

    insert_query = """
    INSERT INTO query_info (qid, type, user_pseudonym, proxy_pseudonym, user_encryption_key, user_iv, content)
        VALUES (%s, %s, %s, %s, %s, %s, %s);
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
        ),
    )
    cursor.nextset()

    if payment != "test":
        insert_query = """
        INSERT INTO payment_info (id, qid, type, status)
            VALUES (%s, %s, %s, %s);
        """
        cursor.execute(
            insert_query, (payment, qid, PaymentType.ECASH, PaymentStatus.IN_PROGRESS)
        )

    db.commit()
    return jsonify({"ok": True, "qid": qid}), 200


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
    return jsonify({"ok": True, "response": str(completion.choices[0].message)}), 200


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
    if request.method == "GET":
        pseudonym = request.args.get("pseudonym")
    elif request.method == "POST" and request.is_json:
        data = request.get_json()
        pseudonym = data["pseudonym"]
    else:
        return "Invalid request.", 400

    invalid_request = jsonify({"ok": False, "msg": "Invalid request."}), 400
    unauthorized_request = jsonify({"ok": False, "msg": "Authorization failed."}), 401
    if pseudonym is None:
        return invalid_request

    authorization_header = request.headers.get("Authorization", None)
    if authorization_header is None or not authorization_header.startswith("Bearer "):
        return unauthorized_request
    token = authorization_header[len("Bearer ") :]
    try:
        jwt.decode(
            token,
            auth_public_key,
            algorithms=["EdDSA"],
            options={
                "require": ["aud", "exp"],
                "verify_aud": True,
                "verify_exp": True,
            },
            audience=pseudonym,
        )
    except:
        return unauthorized_request

    db, cursor = get_db_and_cursor()
    select_query = """
    SELECT pseudonym FROM proxy_info
    WHERE pseudonym = %s AND status = %s;
    """
    cursor.execute(select_query, (pseudonym, ProxyStatus.REGISTERED))
    result = cursor.fetchone()
    if result is None:
        return invalid_request

    if request.method == "GET":
        select_query = """
        SELECT qid, user_pseudonym, user_encryption_key, user_iv, content FROM query_info
        WHERE proxy_pseudonym = %s AND proxy_response IS NULL;
        """
        cursor.execute(select_query, (pseudonym,))
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
        return jsonify({"ok": True, "requests": rows}), 200
    else:
        qid = data["qid"]
        select_query = """
        SELECT qid FROM query_info
        WHERE qid = %s AND proxy_pseudonym = %s AND proxy_response IS NULL;
        """
        cursor.execute(select_query, (qid, pseudonym))
        row = cursor.fetchone()
        if row is None:
            return invalid_request

        proxy_iv = data["iv"]
        response = data["response"]

        update_query = """
        UPDATE query_info
            SET
                proxy_iv = %s,
                proxy_response = %s,
                ts_response = NOW()
            WHERE qid = %s;
        """
        cursor.execute(update_query, (proxy_iv, response, qid))
        db.commit()

        try:
            signature = sign_ecash(data["ecash"])
        except:
            signature = None

        return jsonify({"ok": True, "ecash_signature": signature}), 200


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
        return jsonify({"ok": True, "results": []}), 200

    results = [
        {
            "qid": row[0],
            "proxy_pseudonym": row[1],
            "proxy_iv": row[2],
            "proxy_response": row[3],
        }
        for row in rows
    ]
    return jsonify({"ok": True, "results": results}), 200


if __name__ == "__main__":
    app.run()
