(async () => {
const fetchTimeout = 5000;
const chatbotSelector = document.getElementById("chatbot");
const chatConversationDiv = document.getElementById("chatConversation");
const chatHistoryDiv = document.getElementById("chatHistory");
const promptTextarea = document.getElementById("prompt");
const chatForm = document.getElementById("chatForm");
const submitButton = document.getElementById("submitButton");
const proxyList = document.getElementById("proxy");
const refreshProxyBtn = document.getElementById("refreshProxyBtn");

let waitingForResponse = false; // Only 1 new message at a time
let newChat = null;
let newChatSelected = false;
let refreshingProxyList = false;
let refreshProxyInterval;
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
    renderChatHistory();
    renderCurrentChat();
}

function createChatHistoryItem(text, selected) {
    return fromHTML(`
        <li class="relative z-[15]" style="opacity: 1; height: auto;">
            <div class="group relative rounded-lg active:opacity-90 ${selected ? 'bg-token-sidebar-surface-secondary' : ''}">
                <div class="flex items-center gap-2 p-2 hover:bg-token-sidebar-surface-secondary rounded-lg cursor-pointer">
                    <div class="relative grow overflow-hidden text-ellipsis whitespace-nowrap">
                        ${text.slice(0, 64)}
                    </div>
                </div>
            </div>
        </li>
    `);
}

function renderChatHistory() {
    const items = [];
    chatHistory.forEach((_, qid) => {
        const query = queryMap.get(qid);
        const item = createChatHistoryItem(query.query, currentChatQueryId == qid);
        if (item === null) {
            return;
        }
        item.addEventListener("click", (e) => {
            e.preventDefault();
            currentChatQueryId = qid;
            newChatSelected = false;
            render();
        })
        items.unshift(item);
    });

    if (newChat != null) {
        const item = createChatHistoryItem(newChat[0].query, newChatSelected);
        if (item != null) {
            item.addEventListener("click", (e) => {
                e.preventDefault();
                currentChatQueryId = null;
                newChatSelected = true;
                render();
            });
            items.unshift(item);
        }
    }

    chatHistoryDiv.replaceChildren(...items);
}

async function downvoteQuery(e, qid) {
    const query = queryMap.get(qid);
    const data = {
        pseudonym: query.user_pseudonym,
        qid,
        downvote: true,
    }
    const btn = e.target;
    btn.style.color = "black";
    btn.setAttribute("disabled", "");
    btn.setAttribute("title", "Downvoted");
    try {
        const res = await fetch('/feedback', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });
        if (res.ok) {
            query.downvote = !query.downvote;
        } else {
            btn.style.color = "grey";
            btn.removeAttribute("disabled");
            btn.setAttribute("title", "Downvote response");
        }
    } catch (e) {
        console.log(`Failed to downvote: ${e}`);
        btn.style.color = "grey";
        btn.removeAttribute("disabled");
        btn.setAttribute("title", "Downvote response");
    }
}

function createChatSnippetDiv(label, text, downvote=false) {
    const downvote_btn = downvote
        ? ` <button class="downvote rounded-lg text-token-text-secondary hover:bg-token-main-surface-secondary"
            type="button" title="Downvote response">
                &#8681;
            </button>`
        : '';
    return `
    <div class="w-full text-token-text-primary">
        <div class="px-4 py-2 justify-center text-base md:gap-6 m-auto">
            <div class="flex flex-1 text-base mx-auto gap-3 md:px-5 lg:px-1 xl:px-5 md:max-w-3xl lg:max-w-[40rem] xl:max-w-[48rem] group">
                <div class="relative flex w-full flex-col chat-snippet">
                    <div class="font-semibold select-none">${label}${downvote_btn}</div>
                    <div class="flex-col gap-1 md:gap-3">
                        <div class="flex flex-grow flex-col max-w-full">
                            ${text}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    `;
}

function renderEmptyChat() {
    chatConversationDiv.replaceChildren();
    chatbotSelector.disabled = false;
    proxyList.disabled = false;
    proxyList.removeAttribute("data-state-locked");
    refreshProxyBtn.disabled = false;
}

function renderCurrentChat() {
    if (currentChatQueryId === null && !newChatSelected) {
        return renderEmptyChat();
    }
    const queries = newChatSelected ? newChat : chatHistory.get(currentChatQueryId);
    if (queries == null) {
        return renderEmptyChat();
    }

    const firstQuery = newChatSelected ? queries[0] : queryMap.get(queries[0]);
    const chatbot = firstQuery?.chatbot;
    const loadingDiv = "<div class='loadingContainer1'><div class='ball1'></div><div class='ball2'></div><div class='ball3'></div><div class='ball4'></div></div>";
    const divs = [];
    queries.forEach(q => {
        const query = newChatSelected ? q : queryMap.get(q);
        const has_response = query.proxy_response != null;
        let response = has_response
            ? DOMPurify.sanitize(query.proxy_response, {ALLOWED_TAGS: ["div", "p", "pre", "span", "code", "ol", "li", "ul"]})
            : loadingDiv
        const div = fromHTML(`
            <div>
                ${createChatSnippetDiv("Query:", query.query)}
                ${createChatSnippetDiv(`${chatbot}:`, response, has_response)}
            </div>
        `);
        const btn = div.querySelector("button");
        if (btn) {
            btn.addEventListener("click", async (e) => await downvoteQuery(e, q));
            btn.style.color = query.downvote ? "black" : "grey";
            if (query.downvote) {
                btn.setAttribute("disabled", "");
                btn.setAttribute("title", "Downvoted");
            }
        }
        divs.push(div);
    });
    if (!newChatSelected) {
        const next_pending_query = queryMap.get(queries.slice(-1)[0])?.next_query;
        if (next_pending_query) {
            const div = fromHTML(`
                <div>
                    ${createChatSnippetDiv("Query:", next_pending_query)}
                    ${createChatSnippetDiv(`${chatbot}:`, loadingDiv)}
                </div>
            `);
            divs.push(div);
        }
    }

    chatConversationDiv.replaceChildren(...divs);
    chatConversationDiv.querySelectorAll('.dark').forEach(e => e.classList.replace('dark', 'light'));
    chatConversationDiv.scrollIntoView({behavior: "smooth", block: "end"});

    // Metadata
    chatbotSelector.value = chatbot;
    chatbotSelector.disabled = true;
    const pid = firstQuery.pid;
    if (proxyList.querySelector(`[value='${pid}']`) == null) {
        const option = document.createElement("option");
        option.text = `${pid} | Unavailable`;
        option.value = pid;
        option.disabled = true;
        proxyList.appendChild(option);
    }
    proxyList.value = pid;
    proxyList.disabled = true;
    proxyList.setAttribute("data-state-locked", "");
    refreshProxyBtn.disabled = true;
}

async function fetchResults(pseudonym) {
    if (Array.from(queryMap.entries()).every(([k, v]) => v.hasOwnProperty("proxy_response"))) {
        return;
    }

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

function handleSubmissionError(err, reset=true) {
    waitingForResponse = false;
    promptTextarea.setCustomValidity(err);
    promptTextarea.reportValidity();
    if (reset) {
        promptTextarea.setCustomValidity("");
    }
    return;
}

chatForm.addEventListener('submit', async function (event) {
    event.preventDefault();
    if (waitingForResponse) {
        return handleSubmissionError("Still waiting for a pending response, please retry later.", false);
    }

    waitingForResponse = true;
    const currentQueryId = currentChatQueryId;
    const proxy = JSON.parse(proxyList.options[proxyList.selectedIndex].getAttribute("data"));
    const pid = proxyList.value;
    const proxy_pseudonym = proxy.pseudonym;
    const proxy_encryption_key = proxy.encryption_key;
    const proxy_type = proxy.type;
    if (!proxy_pseudonym || !proxy_encryption_key || !proxy_type) {
        return handleSubmissionError("Invalid proxy. Please refresh proxy list and retry.");
    }

    const chatbot = chatbotSelector.value;
    if (chatbot != "ChatGPT" && chatbot != "Claude") {
        return handleSubmissionError("Invalid chatbot selected.");
    }
    
    const query = promptTextarea.value;
    let lastQueryId;
    if (currentQueryId == null) {
        newChat = [{query, pid, chatbot}];
        newChatSelected = true;
    } else {
        if (queryMap.get(currentQueryId).proxy_pseudonym !== proxy_pseudonym) {
            return handleSubmissionError("Chosen proxy does not match current thread's proxy. Please create a new conversation.");
        }
        lastQueryId = chatHistory.get(currentQueryId).slice(-1)[0];
        queryMap.get(lastQueryId).next_query = query;
    }

    const payment = document.getElementById('payment').value;
    const data = {
        proxy_pseudonym,
        proxy_type,
        payment
    };
    promptTextarea.value = "";
    render();

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
            chatbot,
            prompt_text: query,
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

        let res;
        try {
            res = await fetch('/query', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data),
            });
        } catch (e) {
            return handleSubmissionError("Cannot contact coordinator. Please report and try again later.");
        }

        if (res.ok) {
            res = await res.json();
            const queryObj = {
                query,
                pid,
                chatbot,
                'user_pseudonym': pseudonym,
                'user_encryption_pub_key': encryption_pub_key,
                'aes_key': aes_key,
                'proxy_pseudonym': proxy_pseudonym,
                'user_signature_keys': signatureKeyPair,
                'parent_query': currentQueryId,
                'downvote': false,
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
                render();
            } else {
                chatHistory.get(currentQueryId).push(res.qid);
            }
            setTimeout(fetchResults, fetchTimeout, pseudonym);
        } else {
            newChat = null;
            if (lastQueryId) {
                queryMap.get(lastQueryId).next_query = null;
            }
            render();
            res = await res.text();
            return handleSubmissionError(`Query submission failed: ${res}`);
        }
    } else if (proxy_type == "server") { // TODO: server proxy not fully implemented
        data["currency"] = 'ETH';
        data["messages"] = [
            { role: "user", content: query },
        ];
        fetch(`${proxy_pseudonym}/query`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        })
            .then(res => res.text())
            .then(res => alert(res))
            .catch(err => alert(err));
    } else {
        alert("Invalid proxy type.");
    }
});

// document.getElementById('requestPaymentBtn').addEventListener('click', function () {
//     fetch('/pay')
//         .then(res => res.json())
//         .then(res => alert(JSON.stringify(res, null, 2)))
//         .catch(err => alert(err));
// });

async function fetchProxies() {
    if (proxyList.hasAttribute("data-state-locked")) {
        return;
    }

    try {
        let res = await fetch('/proxies');
        if (res.ok) {
            res = await res.json();
            const divs = res.map(item => {
                const option = document.createElement("option");
                option.value = item.pid;
                option.setAttribute("data", JSON.stringify(item));
                let stats = "Statistics not available";
                if (
                    item.sla_1min_7d != null &&
                    item.mean_ttr_7d != null &&
                    item.load_1h != null &&
                    item.avg_daily_load_7d != null &&
                    item.downvote_rate_7d != null
                ) {
                    const sla = Math.round(item.sla_1min_7d * 100);
                    const mttr = Math.round(item.mean_ttr_7d);
                    const load_1h = item.load_1h;
                    const avg_load = Math.round(item.avg_daily_load_7d);
                    const downvote_rate = Math.round(item.downvote_rate_7d * 100);
                    stats = `SLA: ${sla}%; MTTR: ${mttr}s; Load: ${load_1h} last hr, ${avg_load}/day; Downvote: ${downvote_rate}%`;
                }
                option.text = `${item.pid} | ${stats}`;
                return option;
            });
            proxyList.replaceChildren(...divs);
            proxyList.removeAttribute("disabled");
            submitButton.removeAttribute("disabled");
        } else {
            throw new Error("No proxies");
        }
    } catch (e) {
        const option = document.createElement("option");
        option.text = "Not available";
        option.disabled = true;
        proxyList.replaceChildren(option);
        proxyList.setAttribute("disabled", "");
        submitButton.setAttribute("disabled", "");
    }
}
await fetchProxies();
refreshProxyInterval = setInterval(fetchProxies, 60000);

refreshProxyBtn.addEventListener("click", async (e) => {
    e.preventDefault();
    if (refreshingProxyList) {
        return;
    }
    refreshingProxyList = true;
    refreshProxyBtn.classList.remove("stop-spin-animation");
    clearInterval(refreshProxyInterval);
    await fetchProxies();
    refreshingProxyList = false;
    refreshProxyBtn.classList.add("stop-spin-animation");
    refreshProxyInterval = setInterval(fetchProxies, 60000);
});


})();