import {
    CHATBOT_CHATGPT,
    CHATBOT_CLAUDE,
    COORDINATOR_HOST,
    CONTENT_SCRIPT_PORT,
    DEFAULT_HOURLY_LIMIT,
    MSG_TYPE_REQUEST_CAPTURE,
    MSG_TYPE_REQUEST_CAPTURE_RESULT,
    MSG_TYPE_UPDATE_DB,
    MSG_TYPE_RESET,
    REQUEST_TYPE_PROOF,
    REQUEST_TYPE_REGISTRATION,
    REQUEST_TYPE_REGISTRATION_PROOF,
    REQUEST_TYPE_REGULAR,
} from "./constants";
import * as db from "./db";
import { prove } from "tlsn-js";
import browser from "webextension-polyfill";
const blindSig = __non_webpack_require__("blind-sig");

(async () => {
    console.log("Starting offscreen...");
    const BASE_ENDPOINT = `http://${COORDINATOR_HOST}`;
    const NOTARY_URL = "https://proxygpt.cs.umass.edu/notary";
    const WS_PROXY_URL = "wss://proxygpt.cs.umass.edu/wsproxy";

    const port_map = {}
    for (const chatbot of [CHATBOT_CHATGPT, CHATBOT_CLAUDE]) {
        port_map[chatbot] = new Map();
    }
    const request_interval = 5000;
    const request_queue = [];
    const textEncoder = new TextEncoder();
    const textDecoder = new TextDecoder();
    let request_timer = null;
    let send_to_cs_timer = null;
    let signature_public_key_str = null;
    let signature_private_key = null;
    let encryption_public_key_str = null;
    let encryption_private_key = null;
    let coordinator_ecash_key = null;
    let auth_token = null;

    function base64encode(arr) {
        return btoa(String.fromCharCode(...arr));
    }

    function base64decode(str) {
        return Uint8Array.from(atob(str), (s) => s.charCodeAt(0));
    }

    function isPortMapEmpty() {
        return Object.values(port_map).every(m => m.size == 0);
    }

    async function fetchPost(
        endpoint,
        body,
        headers = { mode: "cors", "Content-Type": "application/json" }
    ) {
        return await fetch(`${BASE_ENDPOINT}/${endpoint}`, {
            method: "POST",
            headers: headers,
            body: JSON.stringify(body),
        });
    }

    async function importEcashKey(str) {
        let key = await crypto.subtle.importKey(
            "spki",
            base64decode(str),
            {
                name: "RSASSA-PKCS1-v1_5",
                hash: "SHA-256",
            },
            true,
            ["verify"]
        );
        key = await crypto.subtle.exportKey("jwk", key);
        return {
            e: blindSig.base64ToBigInt(key.e),
            n: blindSig.base64ToBigInt(key.n),
        };
    }

    async function genKeyPair(sign = true) {
        return await crypto.subtle.generateKey(
            {
                name: sign ? "ECDSA" : "ECDH",
                namedCurve: "P-256",
            },
            false,
            sign ? ["sign", "verify"] : ["deriveKey"]
        );
    }

    const csConnectListener = async (port) => {
        if (!port.name.startsWith(CONTENT_SCRIPT_PORT)) {
            return;
        }        
        let chatbot = null;
        if (port.name.endsWith(CHATBOT_CHATGPT)) {
            chatbot = CHATBOT_CHATGPT;
        } else if (port.name.endsWith(CHATBOT_CLAUDE)) {
            chatbot = CHATBOT_CLAUDE;
        } else {
            return;
        }

        console.log(`Tab ${port.sender.tab.id} is connected.`);
        port_map[chatbot].set(port.sender.tab.id, port);
        port.onMessage.addListener(async (msg) => {
            const current_request = request_queue[0];
            if (current_request == null) {
                console.log("No current request.");
                return;
            }

            if (msg.error) {
                console.log(`Client responded with error: ${msg.error}`);
                current_request.retry = true;
                return;
            }

            console.log("Handling content script's response to request");
            try {
                switch (current_request.type) {
                    case REQUEST_TYPE_REGISTRATION:
                        await handleRegistrationResponse(current_request, msg);
                        break;
                    case REQUEST_TYPE_REGISTRATION_PROOF:
                    case REQUEST_TYPE_PROOF:
                        await handleProofResponse(current_request, msg);
                        break;
                    case REQUEST_TYPE_REGULAR:
                        const [query_timestamps] = await db.queryDB(["query_timestamps"], [[]]);
                        const cur_time = Date.now()
                        query_timestamps.push(cur_time);
                        if (query_timestamps.length >= 100) {
                            query_timestamps.shift();
                        }
                        await db.updateDB({ query_timestamps: query_timestamps });
                        await sendResponseToServer(current_request, msg);
                        break;
                    default:
                        throw new Error(
                            `Invalid request type: ${current_request.type}`
                        );
                }
                if (!current_request.blocked) {
                    console.log("Updating request queue.");
                    request_queue.shift();
                } else {
                    current_request.needs_manual_removal = true;
                }
            } catch (e) {
                console.log(
                    `Exception occurred when handling content script's response: ${e}`
                );
                current_request.retry = true;
            }
        });

        port.onDisconnect.addListener((p) => {
            console.log(`Tab ${p.sender.tab.id} is disconnected.`);
            port_map[chatbot].delete(p.sender.tab.id);
        });
    };

    async function handleRegistrationResponse(current_request, msg) {
        console.log("Initiating request for registration proof...");
        const thread_id = msg.thread_id ?? current_request.thread_id;
        if (!thread_id) {
            throw new Error("No thread id found!");
        }
        current_request.type = REQUEST_TYPE_REGISTRATION_PROOF;
        current_request.time = null;
        current_request.response = msg.response;
        current_request.thread_id = thread_id;
        current_request.blocked = true;

        chrome.runtime.sendMessage({
            type: MSG_TYPE_REQUEST_CAPTURE,
            data: { thread_id },
        });
    }

    async function handleProofResponse(current_request, msg) {
        if (current_request.request_capture == null) {
            console.log("Request not yet captured...");
            current_request.blocked = true;
            setTimeout(() => handleProofResponse(current_request, msg), 3000);
            return;
        }

        console.log("Preparing to generate proof");
        const { url, method, requestHeaders } = current_request.request_capture;
        const headers = requestHeaders.reduce((acc, h) => {
            acc[h.name] = h.value;
            return acc;
        }, {});

        const result = await fetch(url, { method, headers: headers });
        const response = await result.json();

        //TODO: for some reason, these needs to be overridden to work
        headers["Host"] = new URL(url).hostname;
        headers["Accept-Encoding"] = "identity";
        headers["Connection"] = "close";
        const secretHeaders = [
            current_request.thread_id,
            ...Object.entries(headers).map(
                ([k, v]) => `${k.toLowerCase()}: ${v || ""}`
            ),
        ];

        const publicResps = [];
        const proxyResponses = [];
        if ("mapping" in response) {
            publicResps.push(
                ...Object.values(response.mapping)
                    .map((v) => v?.message?.content?.parts ?? [])
                    .flat()
                    .filter((v) => !!v)
                    .map((v) => JSON.stringify(v).slice(1, -1))
            );
            proxyResponses.push(
                ...Object.values(response.mapping)
                    .filter((v) => v?.message?.author?.role === "assistant")
                    .map((v) => v?.message?.content?.parts ?? [])
                    .flat()
                    .filter((v) => !!v)
                    .map((v) => JSON.stringify(v).slice(1, -1))
            );
            publicResps.push(
                '"title":',
                '"create_time":',
                '"update_time":',
                '"mapping":',
                '"author":',
                '"role":"user"',
                '"role":"assistant"',
                '"role":"system"',
                '"message":',
                '"id":',
                '"parent":',
                '"children":',
                '"content":{"content_type":',
                '"parts":[',
                '"status":'
            );
        }

        let proof;
        try {
            console.log("Generating registration proof...");
            proof = await prove(url, {
                method,
                headers,
                maxSentData: 16384,
                maxRecvData: 16384,
                maxTranscriptSize: 2 * 16384,
                notaryUrl: NOTARY_URL,
                websocketProxyUrl: WS_PROXY_URL,
                secretHeaders,
                publicResps,
            });
            proof = JSON.stringify(proof);
        } catch (e) {
            console.log("Failed to generate proof: ", e);
            return;
        }

        if (current_request.type == REQUEST_TYPE_PROOF) {
            await sendProofResponseToServer(
                current_request,
                proof,
                proxyResponses
            );
        } else {
            await sendRegistrationProofResponseToServer(
                current_request,
                proof,
                proxyResponses
            );
        }

        if (current_request.blocked) {
            current_request.blocked = false;
            if (current_request.needs_manual_removal) {
                request_queue.shift();
            }
        }
    }

    function configContentScriptConnection(enable) {
        if (enable) {
            if (!browser.runtime.onConnect.hasListener(csConnectListener)) {
                browser.runtime.onConnect.addListener(csConnectListener);
                console.log("Started listening to content script side...");
            }
        } else {
            if (browser.runtime.onConnect.hasListener(csConnectListener)) {
                browser.runtime.onConnect.removeListener(csConnectListener);
                console.log("Stopped listening to content script side...");
            }
        }
    }

    async function configRegistration(enable) {
        if (!enable) {
            console.log(`Registration skipped since extension is disabled.`);
            return;
        }
        console.log("Configuring registration with coordinator...");
        const [keys, registered, ecash_key] = await db.queryDB([
            "keys",
            "registered",
            "ecash_key",
        ]);
        if (keys != null && registered && ecash_key != null) {
            signature_public_key_str = keys.signature_public;
            encryption_public_key_str = keys.encryption_public;
            signature_private_key = keys.signature_private;
            encryption_private_key = keys.encryption_private;
            coordinator_ecash_key = await importEcashKey(ecash_key);
            console.log(
                `Registration is already completed with public key: ${signature_public_key_str}`
            );
            const auth_result = await authenticate();
            if (auth_result.ok) {
                return;
            }
            console.log(
                `Authentication failed: ${auth_result.msg}. Continuing registration...`
            );
        }

        console.log("Generating new keys...");
        const signatureKeyPair = await genKeyPair(true);
        const encryptionKeyPair = await genKeyPair(false);
        const signaturePublicKeySpki = await crypto.subtle.exportKey(
            "spki",
            signatureKeyPair.publicKey
        );
        const encryptionPublicKeySpki = await crypto.subtle.exportKey(
            "spki",
            encryptionKeyPair.publicKey
        );
        signature_public_key_str = base64encode(
            new Uint8Array(signaturePublicKeySpki)
        );
        encryption_public_key_str = base64encode(
            new Uint8Array(encryptionPublicKeySpki)
        );
        signature_private_key = signatureKeyPair.privateKey;
        encryption_private_key = encryptionKeyPair.privateKey;

        await db.updateDB({
            keys: {
                signature_public: signature_public_key_str,
                encryption_public: encryption_public_key_str,
                signature_private: signature_private_key,
                encryption_private: encryption_private_key,
            },
            pid: null,
            registered: false,
        });

        console.log("Initiating registration with coordinator...");
        let res = await fetchPost("register", {
            proxy_type: "browser",
            pseudonym: signature_public_key_str,
            encryption_key: encryption_public_key_str,
        });
        if (res.ok) {
            res = await res.json();
            console.log("Registration started.");
            request_queue.push({
                type: REQUEST_TYPE_REGISTRATION,
                time: null,
                qid: res.qid,
                query: res.query,
                token: res.token,
            });
            await db.updateDB({ pid: res.pid });
        } else {
            res = await res.text();
            console.log(`Failed to start registration: ${res}`);
        }
    }

    async function authenticate() {
        console.log("Attempting to authenticate...");
        if (
            signature_public_key_str === null ||
            signature_private_key === null
        ) {
            return { ok: false, msg: "Invalid keys." };
        }
        let res = await fetchPost("auth", {
            pseudonym: signature_public_key_str,
        });
        if (!res.ok) {
            return {
                ok: false,
                msg: `Failed to authenticate: ${res.statusText}`,
            };
        }

        res = await res.json();
        const nonce = base64decode(res["nonce"]);
        const temp_token = res["token"];
        const signature = await crypto.subtle.sign(
            { name: "ECDSA", hash: "SHA-256" },
            signature_private_key,
            nonce
        );
        res = await fetchPost("auth", {
            pseudonym: signature_public_key_str,
            signature: base64encode(new Uint8Array(signature)),
            token: temp_token,
        });
        if (!res.ok) {
            return {
                ok: false,
                msg: `Authentication failed: ${res.statusText}`,
            };
        }
        res = await res.json();
        auth_token = res["token"];
        console.log("Authentication successful!");
        return { ok: true };
    }

    function configRequestFromServer(enable) {
        if (!enable) {
            if (request_timer !== null) {
                clearInterval(request_timer);
                request_timer = null;
            }
            console.log("Disabled requests to coordinator.");
            return;
        }
        if (request_timer !== null) {
            clearInterval(request_timer);
        }
        request_timer = setInterval(getQueriesFromServer, request_interval);
        console.log("Enabled requests to coordinator.");
    }

    async function getQueriesFromServer() {
        if (!auth_token || isPortMapEmpty() || request_queue.length > 0) {
            return;
        }
        let [registered] = await db.queryDB(["registered"], [false]);
        if (!registered) {
            return;
        }

        const pseudonymParam = `pseudonym=${encodeURIComponent(signature_public_key_str)}`;
        const availableChatbots = Object.entries(port_map).filter(([_, v]) => v.size > 0).map(([k, _]) => k);
        const chatbotParam = `chatbot=${availableChatbots.join(",")}`;
        const url = `${BASE_ENDPOINT}/request?${pseudonymParam}&${chatbotParam}`;
        let result;
        try {
            result = await fetch(url, {
                headers: { Authorization: `Bearer ${auth_token}` },
            });
        } catch (e) {
            printConnectionErr(e);
            return;
        }

        if (!result.ok) {
            console.log(`Requesting from server failed: ${result.statusText}`);
            if (result.status === 401 || result.status == 403) {
                auth_token = null;
                await configExtension();
            }
            return;
        }

        result = await result.json();
        let [requests] = await db.queryDB(["requests"], [{}]);
        const queries = result.requests.filter(
            (q) =>
                ((q.proof_required &&
                    requests.hasOwnProperty(q.qid) &&
                    !requests[q.qid].proof) ||
                    (!q.proof_required && !requests.hasOwnProperty(q.qid))) &&
                request_queue.every((r) => r.qid != q.qid)
        );
        if (queries.length === 0) {
            return;
        }
        console.log(
            `Got ${queries.length} new ${
                queries.length == 1 ? "query" : "queries"
            }.`
        );
        for (const q of queries) {
            if (q.proof_required) {
                const thread_id = requests[q.qid]?.thread_id;
                if (thread_id == null) {
                    console.log(
                        `Cannot find original thread for proof request ${q.qid}!`
                    );
                    continue;
                }
                const proof_request = {
                    type: REQUEST_TYPE_PROOF,
                    time: null,
                    qid: q.qid,
                    thread_id,
                };
                request_queue.push(proof_request);
                chrome.runtime.sendMessage({
                    type: MSG_TYPE_REQUEST_CAPTURE,
                    data: { thread_id },
                });
                continue;
            }
            const content = base64decode(q.content);
            const user_encryption_key = await crypto.subtle.importKey(
                "spki",
                base64decode(q.user_encryption_key),
                { name: "ECDH", namedCurve: "P-256" },
                false,
                []
            );
            const user_iv = base64decode(q.user_iv);
            const aes_key = await crypto.subtle.deriveKey(
                { name: "ECDH", public: user_encryption_key },
                encryption_private_key,
                { name: "AES-GCM", length: 256 },
                false,
                ["encrypt", "decrypt"]
            );
            const decrypted = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: user_iv },
                aes_key,
                content
            );
            const decryptedJson = JSON.parse(textDecoder.decode(decrypted));
            let thread_id = null;
            if (requests.hasOwnProperty(decryptedJson.prev_qid)) {
                const prevQueryObj = requests[decryptedJson.prev_qid];
                thread_id = prevQueryObj.thread_id;
                const prevQueryPublicSignKey = await crypto.subtle.importKey(
                    "spki",
                    base64decode(prevQueryObj.user_pseudonym),
                    { name: "ECDSA", namedCurve: "P-256" },
                    true,
                    ["verify"]
                );
                const valid = await crypto.subtle.verify(
                    { name: "ECDSA", hash: "SHA-256" },
                    prevQueryPublicSignKey,
                    base64decode(decryptedJson.signature),
                    textEncoder.encode(decryptedJson.prev_qid)
                );
                if (!valid) {
                    console.log("Follow-up query has invalid signature!");
                    continue;
                }
            }

            request_queue.push({
                type: REQUEST_TYPE_REGULAR,
                time: null,
                qid: q.qid,
                chatbot: decryptedJson.chatbot ?? CHATBOT_CHATGPT, // Default to ChatGPT
                query: decryptedJson.prompt_text,
                thread_id,
                user_pseudonym: q.user_pseudonym,
                aes_key,
            });
        }
    }

    async function sendResponseToServer(current_request, msg) {
        if (!auth_token) {
            throw new Error("Invalid authorization token!");
        }
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            current_request["aes_key"],
            textEncoder.encode(msg.response)
        );

        console.log("Sending response to server...");
        let res;
        try {
            res = await fetchPost(
                "request",
                {
                    qid: current_request.qid,
                    pseudonym: signature_public_key_str,
                    iv: base64encode(iv),
                    response: base64encode(new Uint8Array(encrypted)),
                },
                {
                    mode: "cors",
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${auth_token}`,
                }
            );
        } catch (e) {
            printConnectionErr(e);
            throw e;
        }

        if (!res.ok) {
            console.log(`Response submission failed: ${res.statusText}`);
            if (res.status === 401 || res.status === 403) {
                await configExtension();
            }
            return;
        }

        console.log("Response successfully delivered.");
        let [requests] = await db.queryDB(["requests"], [{}]);
        requests[current_request.qid] = {
            response: msg.response,
            thread_id: msg.thread_id,
            user_pseudonym: current_request.user_pseudonym,
        };
        await db.updateDB({ requests });
    }

    async function sendProofResponseToServer(
        current_request,
        proof,
        proxy_response
    ) {
        if (!auth_token) {
            throw new Error("Invalid authorization token!");
        }

        console.log("Creating e-cash...");
        const ecash_msg = base64encode(
            crypto.getRandomValues(new Uint8Array(32))
        );
        const { blinded, r } = blindSig.blind(
            ecash_msg,
            coordinator_ecash_key.e,
            coordinator_ecash_key.n
        );

        console.log("Sending proof response to server...");
        let res;
        try {
            res = await fetchPost(
                "request",
                {
                    qid: current_request.qid,
                    pseudonym: signature_public_key_str,
                    proof,
                    response: proxy_response,
                    ecash: blindSig.bigIntToBase64(blinded),
                },
                {
                    mode: "cors",
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${auth_token}`,
                }
            );
        } catch (e) {
            printConnectionErr(e);
            throw e;
        }

        if (!res.ok) {
            console.log(`Response submission failed: ${res.statusText}`);
            if (res.status === 401 || res.status === 403) {
                await configExtension();
            }
            return;
        }

        console.log("Response successfully delivered.");
        let [requests] = await db.queryDB(["requests"], [{}]);
        requests[current_request.qid].proof = proof;
        await db.updateDB({ requests });

        res = await res.json();
        let [ecash_wallet] = await db.queryDB(["ecash_wallet"], [[]]);
        const ecash_signature = res["ecash_signature"];
        if (ecash_signature !== null) {
            try {
                const unblinded = blindSig.unblindVerify(
                    ecash_msg,
                    blindSig.base64ToBigInt(ecash_signature),
                    r,
                    coordinator_ecash_key.e,
                    coordinator_ecash_key.n
                );
                ecash_wallet.push({
                    msg: ecash_msg,
                    signature: blindSig.bigIntToBase64(unblinded),
                });
                await db.updateDB({ ecash_wallet });
                console.log("Obtained e-cash!");
            } catch (e) {
                console.log(`Failed to obtain e-cash: ${e}`);
            }
        }
    }

    async function sendRegistrationProofResponseToServer(
        current_request,
        proof,
        proxyResponses
    ) {
        console.log("Sending registration response to coordinator...");
        try {
            let res = await fetchPost("register", {
                proxy_type: "browser",
                pseudonym: signature_public_key_str,
                encryption_key: encryption_public_key_str,
                qid: current_request.qid,
                token: current_request.token,
                response: proxyResponses,
                proof,
            });
            if (res.ok) {
                res = await res.json();
                const ecash_key = res["ecash_key"];
                coordinator_ecash_key = await importEcashKey(ecash_key);
                await db.updateDB({ registered: true, ecash_key });
                console.log("Registration successful!");
                const auth_result = await authenticate();
                if (!auth_result.ok) {
                    await configExtension();
                }
                return;
            } else {
                res = await res.text();
                console.log(`Registration failed: ${res}. Retrying...`);
                await configExtension();
            }
        } catch (e) {
            printConnectionErr(e);
            throw e;
        }
    }

    function configRequestToContentScript(enable) {
        if (enable) {
            if (send_to_cs_timer == null) {
                console.log("Enabled sending requests to content script");
                send_to_cs_timer = setInterval(
                    sendRequestToContentScript,
                    1000
                );
            }
        } else {
            if (send_to_cs_timer != null) {
                console.log("Disabled sending requests to content script");
                clearInterval(send_to_cs_timer);
                send_to_cs_timer = null;
            }
        }
    }

    async function sendRequestToContentScript() {
        if (request_queue.length === 0 || isPortMapEmpty()) {
            return;
        }
        
        let current_request = request_queue[0];
        const ports = port_map[current_request.chatbot ?? CHATBOT_CHATGPT];
        if (ports.size == 0) {
            request_queue.shift();
            request_queue.push(current_request);
            return;
        }
        let cur_time = Date.now();
        if (
            (!current_request.retry && current_request.time != null) ||
            cur_time - current_request.time < 60000
        ) {
            return;
        }

        if (current_request.type == REQUEST_TYPE_REGULAR) {
            const [hourly_limit, query_timestamps] = await db.queryDB(["hourly_limit", "query_timestamps"], [DEFAULT_HOURLY_LIMIT, []]);
            const last_hour_timestamps = query_timestamps.filter(ts => ts > cur_time - 3600000);
            if (last_hour_timestamps.length >= hourly_limit) {
                return;
            }            
        }

        console.log("Sending request to content script.");
        current_request.retry = false;
        current_request.time = cur_time;
        ports.values().next().value.postMessage({
            query: current_request.query,
            thread_id: current_request.thread_id,
            type: current_request.type,
        });
    }

    async function configExtension() {
        const [enable] = await db.queryDB(["enabled"], [true]);
        try {
            await configRegistration(enable);
        } catch (e) {
            printConnectionErr(e);
            console.log("Retrying extension config in a few minutes...");
            setTimeout(configExtension, 60000);
            return;
        }
        configContentScriptConnection(enable);
        configRequestFromServer(enable);
        configRequestToContentScript(enable);
    }

    function printConnectionErr(e) {
        console.log(e);
        console.log(
            "Make sure Tor is running and browser's proxy setting is correct!"
        );
    }

    browser.runtime.onMessage.addListener(async (msg) => {
        switch (msg.type) {
            case MSG_TYPE_UPDATE_DB:
                if (msg.data.keys.includes("enabled")) {
                    await configExtension();
                }
                break;
            case MSG_TYPE_RESET:
                await db.updateDB({
                    registered: false,
                    pid: null,
                    requests: {},
                    query_timestamps: [],
                });
                await configExtension();
                break;
            case MSG_TYPE_REQUEST_CAPTURE_RESULT:
                const current_request = request_queue[0];
                if (
                    current_request == null ||
                    (current_request.type != REQUEST_TYPE_PROOF &&
                        current_request.type !=
                            REQUEST_TYPE_REGISTRATION_PROOF) ||
                    current_request.thread_id != msg.data.thread_id
                ) {
                    return;
                }
                console.log("Got request capture!");
                current_request.request_capture = msg.data.details;
                break;
            default:
                break;
        }
    });

    await configExtension();
})();
