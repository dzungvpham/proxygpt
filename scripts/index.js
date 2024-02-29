(() => {
const fetchTimeout = 5000;
const chatConversationDiv = document.getElementById("chatConversation");
const chatHistoryDiv = document.getElementById("chatHistory");
const promptTextarea = document.getElementById("prompt");
const chatForm = document.getElementById("chatForm");
const submitButton = document.getElementById("submitButton");
let waitingForResponse = false; // Only 1 new message at a time
let newChat = null;
let newChatSelected = false;
const chatHistory = new Map();
const queryMap = new Map();
let currentChatQueryId = null;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function base64encode(arr) {
    return btoa(String.fromCharCode(...arr));
}

function base64decode(str) {
    return Uint8Array.from(atob(str), (s) => s.charCodeAt(0));
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

function fromHTML(html, trim = true) {
    // Process the HTML string.
    html = trim ? html.trim() : html;
    if (!html) return null;

    // Then set up a new template element.
    const template = document.createElement('template');
    template.innerHTML = html;
    const result = template.content.children;

    // Then return either an HTMLElement or HTMLCollection,
    // based on whether the input HTML had one or more roots.
    if (result.length === 1) return result[0];
    return result;
}

function render() {
    renderNewChat();
    renderChatHistory();
    renderCurrentChat();
}

function renderNewChat() {
    if (newChat === null) {
        document.getElementById("newChat").replaceChildren();
        return;
    }
    const div = fromHTML(`
        <li class="relative z-[15]" style="opacity: 1; height: auto;">
            <div class="group relative rounded-lg active:opacity-90 ${newChatSelected ? 'bg-token-sidebar-surface-secondary' : ''}">
                <a class="flex items-center gap-2 p-2 hover:bg-token-sidebar-surface-secondary" href="#">
                    <div class="relative grow overflow-hidden whitespace-nowrap">
                        New chat
                    </div>
                </a>
            </div>
        </li>
    `);
    if (div === null) {
        return;
    }
    div.addEventListener("click", (e) => {
        e.preventDefault();
        currentChatQueryId = null;
        newChatSelected = true;
        render();
    })
    document.getElementById("newChat").replaceChildren(div);
}

function renderChatHistory() {
    const divs = [];
    chatHistory.forEach((_, qid) => {
        const div = fromHTML(`
            <li class="relative z-[15]" style="opacity: 1; height: auto;">
                <div class="group relative rounded-lg active:opacity-90 ${currentChatQueryId == qid ? 'bg-token-sidebar-surface-secondary' : ''}">
                    <a class="flex items-center gap-2 p-2 hover:bg-token-sidebar-surface-secondary" href="#">
                        <div class="relative grow overflow-hidden whitespace-nowrap">
                            ${qid}
                        </div>
                    </a>
                </div>
            </li>
        `);
        if (div === null) {
            return;
        }
        div.addEventListener("click", (e) => {
            e.preventDefault();
            currentChatQueryId = qid;
            newChatSelected = false;
            render();
        })
        divs.unshift(div);
    });
    chatHistoryDiv.replaceChildren(...divs);
}

function renderCurrentChat() {
    if (currentChatQueryId === null && !newChatSelected) {
        chatConversationDiv.replaceChildren();
        return;
    }
    const divs = [];
    const queries = newChatSelected ? newChat : chatHistory.get(currentChatQueryId);
    queries.forEach(qid => {
        const query = newChatSelected ? qid : queryMap.get(qid);
        let response = query.hasOwnProperty('proxy_response')
            ? DOMPurify.sanitize(query.proxy_response)
            : "<div class='loadingContainer1'><div class='ball1'></div><div class='ball2'></div><div class='ball3'></div><div class='ball4'></div></div>";
        const div = fromHTML(`
            <div>
                <div class="w-full text-token-text-primary">
                    <div class="px-4 py-2 justify-center text-base md:gap-6 m-auto">
                        <div class="flex flex-1 text-base mx-auto gap-3 md:px-5 lg:px-1 xl:px-5 md:max-w-3xl lg:max-w-[40rem] xl:max-w-[48rem] group">
                            <div class="relative flex w-full flex-col">
                                <div class="font-semibold select-none">Query:</div>
                                <div class="flex-col gap-1 md:gap-3">
                                    <div class="flex flex-grow flex-col max-w-full">
                                        ${query.query}
                                    </div>
                                </div>
                            </div>                                            
                        </div>
                    </div>
                </div>
                <div class="w-full text-token-text-primary">
                    <div class="px-4 py-2 justify-center text-base md:gap-6 m-auto">
                        <div class="flex flex-1 text-base mx-auto gap-3 md:px-5 lg:px-1 xl:px-5 md:max-w-3xl lg:max-w-[40rem] xl:max-w-[48rem] group">
                            <div class="relative flex w-full flex-col">
                                <div class="font-semibold select-none">Response:</div>
                                <div class="flex-col gap-1 md:gap-3">
                                    <div class="flex flex-grow flex-col max-w-full">
                                        ${response}
                                    </div>
                                </div>
                            </div>                                            
                        </div>
                    </div>
                </div>
            </div>
        `);
        divs.push(div);
    });
    chatConversationDiv.replaceChildren(...divs);
}

async function fetchResults(pseudonym) {
    let res = await fetch(`/result?pseudonym=${encodeURIComponent(pseudonym)}`);
    if (res.ok) {
        res = await res.json();
        if (res.results.length > 0) {
            for (r of res.results) {
                const currentQuery = queryMap.get(r.qid);
                if (currentQuery.hasOwnProperty("proxy_response")) {
                    continue;
                }
                const response = base64decode(r.proxy_response);
                const decrypted = await crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: base64decode(r.proxy_iv) },
                    currentQuery.aes_key,
                    response,
                );
                currentQuery['proxy_response'] = textDecoder.decode(decrypted);
            }

            let hasPendingResponse = false;
            for ([k, v] of queryMap.entries()) {
                if (!v.hasOwnProperty("proxy_response")) {
                    hasPendingResponse = true;
                    break;
                }
            }
            waitingForResponse = hasPendingResponse;
            if (!waitingForResponse) {
                promptTextarea.setCustomValidity("");
            }
            render();
            return;
        }
    }
    setTimeout(fetchResults, fetchTimeout, pseudonym);
}

fetch('/proxies')
    .then(res => res.json())
    .then(res => {
        const list = document.getElementById('proxy');
        res.forEach(item => {
            const option = document.createElement("option");
            option.value = JSON.stringify(item);
            option.text = `(${item.type}) ${item.pseudonym}`;
            list.appendChild(option);
        });
    })
    .catch(e => alert(`Failed to retrieve list of proxies: ${e}. Please try again later.`))

document.getElementById('newConversationButton').addEventListener('click', (e) => {
    e.preventDefault();
    currentChatQueryId = null;
    newChatSelected = false;
    render();
});

promptTextarea.addEventListener("keydown", (event) => {
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        chatForm.requestSubmit(submitButton);
    }
});

chatForm.addEventListener('submit', async function (event) {
    event.preventDefault();
    if (waitingForResponse) {
        promptTextarea.setCustomValidity("Still waiting for a pending response, please retry later.");
        promptTextarea.reportValidity();
        return;
    }

    waitingForResponse = true;
    const currentQueryId = currentChatQueryId;
    const proxy = JSON.parse(document.getElementById('proxy').value);
    const proxy_pseudonym = proxy.pseudonym;
    const proxy_encryption_key = proxy.encryption_key;
    const proxy_type = proxy.type;
    const payment = document.getElementById('payment').value;
    const prompt = promptTextarea.value;
    promptTextarea.value = "";
    const data = {
        proxy_pseudonym,
        proxy_type,
        payment
    };

    if (currentQueryId == null) {
        newChat = [{query: prompt}];
        newChatSelected = true;
        render();
    }    

    if (proxy_type == "browser") {
        const signatureKeyPair = await genKeyPair(true);
        const encryptionKeyPair = await genKeyPair(false);
        const signaturePublicKeySpki = await crypto.subtle.exportKey('spki', signatureKeyPair.publicKey);
        const encryptionPublicKeySpki = await crypto.subtle.exportKey('spki', encryptionKeyPair.publicKey);
        const pseudonym = base64encode(new Uint8Array(signaturePublicKeySpki));
        const encryption_pub_key = base64encode(new Uint8Array(encryptionPublicKeySpki));
        const iv = crypto.getRandomValues(new Uint8Array(12));

        let signature = null;
        if (currentQueryId != null) {
            const prevQuerySignKey = queryMap.get(currentQueryId).user_signature_keys.privateKey;
            signature = await crypto.subtle.sign(
                { name: "ECDSA", hash: "SHA-256" },
                prevQuerySignKey,
                textEncoder.encode(currentQueryId),
            );
        }

        const payload = JSON.stringify({
            prompt_text: prompt,
            prev_qid: currentQueryId,
            signature: signature === null ? null : base64encode(new Uint8Array(signature)),
        });

        const proxy_encryption_pub_key = await crypto.subtle.importKey(
            "spki",
            base64decode(proxy_encryption_key),
            { name: "ECDH", namedCurve: "P-256" },
            false,
            ["deriveKey"]
        );
        const aes_key = await crypto.subtle.deriveKey(
            { name: "ECDH", public: proxy_encryption_pub_key },
            encryptionKeyPair.privateKey,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
        const encrypted = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            aes_key,
            textEncoder.encode(payload),
        );

        data["pseudonym"] = pseudonym;
        data["encryption_key"] = encryption_pub_key;
        data["iv"] = base64encode(iv);
        data["content"] = base64encode(new Uint8Array(encrypted));

        let res = await fetch('/query', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });
        if (res.ok) {
            res = await res.json();
            if (res.ok) {
                const queryObj = {
                    'query': prompt,
                    'user_pseudonym': pseudonym,
                    'user_encryption_pub_key': encryption_pub_key,
                    'aes_key': aes_key,
                    'proxy_pseudonym': proxy_pseudonym,
                    'user_signature_keys': signatureKeyPair,
                    'parent_query': currentQueryId,
                }
                queryMap.set(res.qid, queryObj);                
                if (currentQueryId === null) {
                    if (currentChatQueryId === null && newChatSelected) {
                        currentChatQueryId = res.qid;
                        newChatSelected = false;
                    }
                    if (newChat != null) {
                        newChat = null;
                    }
                    chatHistory.set(res.qid, [res.qid]);
                } else {
                    chatHistory.get(currentQueryId).push(res.qid);
                }
                render();
                setTimeout(fetchResults, fetchTimeout, pseudonym);
            }
        } else {
            newChat = null;
            render();
            res = await res.text();
            alert(res);
        }

    } else if (proxy_type == "server") {
        data["currency"] = 'ETH';
        data["messages"] = [
            { role: "user", content: prompt },
        ];
        fetch(`${proxy_pseudonym}/query`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        })
            .then(res => {
                waitingForResponse = false;
                return res.text();
            })
            .then(res => alert(res))
            .catch(err => alert(err));
    } else {
        alert("Invalid proxy type.");
        return;
    }
});

// document.getElementById('requestPaymentBtn').addEventListener('click', function () {
//     fetch('/pay')
//         .then(res => res.json())
//         .then(res => alert(JSON.stringify(res, null, 2)))
//         .catch(err => alert(err));
// });
})();