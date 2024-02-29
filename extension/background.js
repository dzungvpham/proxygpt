(async () => {
    const blindSig = require("blind-sig");

    const BASE_ENDPOINT =
        "http://v6tlhwumds2qp2pnmyto6w73frg3ofcy3tya2ozkjs2tg24vrpdnb5yd.onion";

    const ports = new Map();
    const request_interval = 5000;
    const client_interval = 5000;
    const request_to_client_timeout = 1 * 60 * 1000;
    const request_queue = [];
    const textEncoder = new TextEncoder();
    const textDecoder = new TextDecoder();
    let request_timer = null;
    let signature_public_key_str = null;
    let signature_private_key = null;
    let encryption_public_key_str = null;
    let encryption_private_key = null;
    let coordinator_ecash_key = null;
    let auth_token = null;

    const torProxyListener = (_) => ({
        type: "socks",
        host: "127.0.0.1",
        port: 9150,
        proxyDNS: true,
    });

    function base64encode(arr) {
        return btoa(String.fromCharCode(...arr));
    }

    function base64decode(str) {
        return Uint8Array.from(atob(str), (s) => s.charCodeAt(0));
    }

    async function fetchPost(
        endpoint,
        body,
        headers = { "Content-Type": "application/json" }
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

    function configProxy(enable) {
        console.log("Configuring proxy settings...");
        let event = browser.proxy.onRequest;
        let isTorProxyEnabled = event.hasListener(torProxyListener);
        if (enable) {
            // Proxy all requests to MassChat hidden server via Tor
            if (!isTorProxyEnabled) {
                event.addListener(torProxyListener, {
                    urls: [`${BASE_ENDPOINT}/*`],
                });
            }
            console.log("Proxy is enabled.");
        } else {
            if (isTorProxyEnabled) {
                event.removeListener(torProxyListener);
            }
            console.log("Proxy is disabled.");
        }
    }

    const csConnectListener = async (port) => {
        console.log(`Tab ${port.sender.tab.id} is connected.`);
        ports.set(port.sender.tab.id, port);
        port.onMessage.addListener(async (msg) => {
            if (msg.hasOwnProperty("error")) {
                console.log(`Client responded with error: ${msg.error}`);
                console.log(`Retrying...`);
                setTimeout(sendRequestToClient, request_to_client_timeout);
                return;
            }

            let current_request =
                request_queue.length === 0 ? null : request_queue[0];
            if (
                current_request === null ||
                current_request.time === null ||
                current_request.query !== msg.query
            ) {
                console.log("Response doesn't match current request.");
                return;
            }

            console.log("Updating request queue.");
            request_queue.shift();

            if (current_request.type == "registration") {
                console.log("Sending registration response to coordinator...");
                let res = await fetchPost("register", {
                    proxy_type: "browser",
                    pseudonym: signature_public_key_str,
                    qid: current_request.qid,
                    encryption_key: encryption_public_key_str,
                    response: msg.response,
                });
                if (res.ok) {
                    res = await res.json();
                    ecash_key = res["ecash_key"];
                    coordinator_ecash_key = await importEcashKey(ecash_key);
                    await browser.storage.local.set({
                        registered: true,
                        ecash_key: ecash_key,
                    });
                    console.log("Registration successful!");
                } else {
                    console.log("Registration failed. Retrying...");
                    await configRegistration(true);
                    return;
                }
            } else {
                await sendResponseToServer(current_request, msg);
            }

            if (request_queue.length === 0) {
                await getQueriesFromServer();
            } else {
                setTimeout(sendRequestToClient, client_interval);
            }
        });

        port.onDisconnect.addListener((p) => {
            console.log(`Tab ${p.sender.tab.id} is disconnected.`);
            ports.delete(p.sender.tab.id);
        });

        await getQueriesFromServer();
        if (request_queue.length > 0 && ports.size == 1) {
            sendRequestToClient();
        }
    };

    async function sendResponseToServer(current_request, msg) {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            current_request["aes_key"],
            textEncoder.encode(msg.response)
        );

        console.log("Creating e-cash...");
        const ecash_msg = base64encode(
            crypto.getRandomValues(new Uint8Array(32))
        );
        const { blinded, r } = blindSig.blind(
            ecash_msg,
            coordinator_ecash_key.e,
            coordinator_ecash_key.n
        );

        console.log("Sending response to server...");
        let res = await fetchPost(
            "request",
            {
                qid: current_request.qid,
                pseudonym: signature_public_key_str,
                iv: base64encode(iv),
                response: base64encode(new Uint8Array(encrypted)),
                ecash: blindSig.bigIntToBase64(blinded),
            },
            {
                "Content-Type": "application/json",
                Authorization: `Bearer ${auth_token}`,
            }
        );

        if (!res.ok) {
            console.log(`Failed to send response: ${res.statusText}`);
            if (res.status === 401) {
                try {
                    console.log("Attempting to re-authenticate and re-send");
                    await authenticate();
                    await sendResponseToServer(current_request);
                    return;
                } catch (e) {
                    throw e;
                }
            }
        }

        console.log("Response successfully delivered.");
        let data = await browser.storage.local.get({
            requests: {},
            ecash_wallet: [],
        });
        data.requests[current_request.qid] = {
            response: msg.response,
            thread_id: msg.thread_id,
            user_pseudonym: current_request.user_pseudonym,
        };
        res = await res.json();
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
                data.ecash_wallet.push({
                    msg: ecash_msg,
                    signature: blindSig.bigIntToBase64(unblinded),
                });
                console.log("Obtained e-cash!");
            } catch (e) {
                console.log(`Failed to obtain e-cash: ${e}`);
            }
        }

        await browser.storage.local.set({
            requests: data.requests,
            ecash_wallet: data.ecash_wallet,
        });
    }

    function configContentScriptConnection(enable) {
        if (enable) {
            if (!browser.runtime.onConnect.hasListener(csConnectListener)) {
                browser.runtime.onConnect.addListener(csConnectListener);
            }
            console.log("Started listening to content script side...");
        } else {
            if (browser.runtime.onConnect.hasListener(csConnectListener)) {
                browser.runtime.onConnect.removeListener(csConnectListener);
            }
            console.log("Stopped listening to content script side...");
        }
    }

    async function configRegistration(enable) {
        console.log("Configuring registration with coordinator...");

        if (!enable) {
            console.log(`Registration skipped since extension is disabled.`);
            return;
        }

        const data = await browser.storage.local.get({
            keys: null,
            registered: false,
            ecash_key: null,
        });
        if (data.keys != null && data.registered && data.ecash_key != null) {
            signature_public_key_str = data.keys.public;
            encryption_public_key_str = data.keys.encryption_public;
            signature_private_key = await idbKeyval.get("signature_key");
            encryption_private_key = await idbKeyval.get("encryption_key");
            coordinator_ecash_key = await importEcashKey(data.ecash_key);
            console.log(
                `Registration is already completed with public key: ${signature_public_key_str}`
            );
            try {
                await authenticate();
                return;
            } catch (e) {
                console.log(
                    `Authentication failed: ${e}. Continuing registration...`
                );
            }
        }

        console.log("Generating new keys...");
        const signatureKeyPair = await genKeyPair((sign = true));
        const encryptionKeyPair = await genKeyPair((sign = false));
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

        await browser.storage.local.set({
            keys: {
                public: signature_public_key_str,
                encryption_public: encryption_public_key_str,
            },
            registered: false,
        });
        await idbKeyval.set("signature_key", signature_private_key);
        await idbKeyval.set("encryption_key", encryption_private_key);

        console.log("Initiating registration with coordinator...");
        try {
            let res = await fetchPost("register", {
                proxy_type: "browser",
                pseudonym: signature_public_key_str,
                encryption_key: encryption_public_key_str,
            });
            if (res.ok) {
                res = await res.json();
                console.log("Registration started.");
                request_queue.push({
                    time: null,
                    qid: res.qid,
                    query: res.query,
                    type: "registration",
                });
                sendRequestToClient();
            } else {
                res = await res.text();
                console.log(`Failed to start registration: ${res}`);
                console.log("Retrying in a few seconds...");
                setTimeout(async () => await configRegistration(true), 10000);
            }
        } catch (e) {
            console.log(e);
        }
    }

    async function authenticate() {
        console.log("Attempting to authenticate...");
        if (
            signature_public_key_str === null ||
            signature_private_key === null
        ) {
            throw new Error("Invalid keys.");
        }
        let res = await fetchPost("auth", {
            pseudonym: signature_public_key_str,
        });
        if (!res.ok) {
            throw new Error(
                `Failed to start authentication; ${res.statusText}`
            );
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
            throw new Error(`Authentication failed: ${res.statusText}`);
        }
        res = await res.json();
        auth_token = res["token"];
        console.log("Authentication successful!");
    }

    function configRequestFromServer(enable) {
        console.log("Configuring requests to coordinator...");
        if (!enable) {
            if (request_timer !== null) {
                clearTimeout(request_timer);
                request_timer = null;
            }
            console.log(
                "Skipping requests to coordinator since extension is disabled."
            );
            return;
        }
        if (request_timer !== null) {
            clearTimeout(request_timer);
        }
        request_timer = setTimeout(getQueriesFromServer, request_interval);
    }

    async function getQueriesFromServer() {
        let data = await browser.storage.local.get({
            requests: {},
            registered: false,
        });
        if (!data.registered || ports.size === 0 || request_queue.length > 0) {
            return;
        }

        if (auth_token === null) {
            try {
                await authenticate();
            } catch (e) {
                throw e;
            }
        }

        let url = `${BASE_ENDPOINT}/request?pseudonym=${encodeURIComponent(
            signature_public_key_str
        )}`;
        let result = await fetch(url, {
            headers: { Authorization: `Bearer ${auth_token}` },
        });
        if (!result.ok) {
            if (result.status === 401) {
                console.log("Authorization token expired.");
                try {
                    await authenticate();
                } catch (e) {
                    throw e;
                }
            } else {
                throw Error(
                    `Requesting from server failed: ${result.statusText}`
                );
            }
        }

        result = await result.json();
        if (result.ok) {
            queries = result.requests.filter(
                (q) =>
                    !data.requests.hasOwnProperty(q.qid) &&
                    !request_queue.some((r) => r.qid == q.qid)
            );
            if (queries.length > 0) {
                console.log(
                    `Got ${queries.length} new ${
                        queries.length == 1 ? "query" : "queries"
                    }.`
                );
                for (q of queries) {
                    const content = base64decode(q.content);
                    const user_encryption_key = await crypto.subtle.importKey(
                        "spki",
                        base64decode(q.user_encryption_key),
                        { name: "ECDH", namedCurve: "P-256" },
                        false,
                        ["deriveKey"]
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
                    const decryptedJson = JSON.parse(
                        textDecoder.decode(decrypted)
                    );
                    let thread_id = null;
                    if (data.requests.hasOwnProperty(decryptedJson.prev_qid)) {
                        const prevQueryObj =
                            data.requests[decryptedJson.prev_qid];
                        thread_id = prevQueryObj.thread_id;
                        const prevQueryPublicSignKey =
                            await crypto.subtle.importKey(
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
                            textEncoder.encode(decryptedJson.prev_qid),
                        );
                        if (!valid) {
                            console.log("Follow-up query has invalid signature!");
                            continue;
                        }
                    }

                    request_queue.push({
                        time: null,
                        qid: q.qid,
                        query: decryptedJson.prompt_text,
                        thread_id: thread_id,
                        user_pseudonym: q.user_pseudonym,
                        aes_key: aes_key,
                    });
                }
                sendRequestToClient();
            }
        } else {
            console.log(
                `An error occurred when requesting from coordinator: ${result.msg}`
            );
        }
        request_timer = setTimeout(getQueriesFromServer, request_interval);
    }

    function configRequestToClient(enable) {
        console.log("Configuring requests to client...");
        if (enable) {
            sendRequestToClient();
        }
    }

    function sendRequestToClient() {
        if (request_queue.length === 0 || ports.size === 0) {
            return;
        }
        let current_request = request_queue[0];
        let cur_time = Date.now();
        console.log("Sending request to client.");
        current_request.time = cur_time;
        ports.values().next().value.postMessage({
            query: current_request.query,
            thread_id: current_request.thread_id,
        });
    }

    async function configExtension(enable) {
        configProxy(enable);
        await configRegistration(enable);
        configContentScriptConnection(enable);
        configRequestFromServer(enable);
        configRequestToClient(enable);
    }

    // Retrieve extension's data
    const data = await browser.storage.local.get({
        enabled: true,
        keys: null,
        registered: false,
    });

    await configExtension(data.enabled);

    browser.storage.local.onChanged.addListener(async (changes) => {
        for (const key of Object.keys(changes)) {
            const change = changes[key];
            switch (key) {
                case "enabled":
                    console.log(
                        `Extension has been manually ${
                            change.newValue ? "enabled" : "disabled"
                        }.`
                    );
                    await configExtension(change.newValue);
                    break;
                default:
                    continue;
            }
        }
    });
})();
