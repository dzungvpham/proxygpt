import {
    CHATBOT_CHATGPT,
    CHATBOT_CLAUDE,
    CONTENT_SCRIPT_PORT,
    REQUEST_TYPE_PROOF,
    REQUEST_TYPE_REGISTRATION_PROOF,
} from "./constants";
import browser from "webextension-polyfill";

(() => {
    function getChatbot() {
        const hostname = new URL(window.location.href).hostname;
        if (hostname.startsWith(CHATBOT_CHATGPT.toLowerCase())) {
            return CHATBOT_CHATGPT;
        } else if (hostname.startsWith(CHATBOT_CLAUDE.toLowerCase())) {
            return CHATBOT_CLAUDE;
        } else {
            return null;
        }
    }

    const chatbot = getChatbot();
    if (!chatbot) {
        return;
    }

    let port = null;

    function goToNewChat() {
        let selectors = [];
        switch (chatbot) {
            case CHATBOT_CHATGPT:
                selectors = ["button:has([d^='M15.673'])", "a[href='/']"];
                break;
            case CHATBOT_CLAUDE:
                selectors = ["[data-value='new chat']", "button:has([d^='M228,128a12'])", "[href='/new']"];
                break;
            default:
                break;
        }

        let newChatBtn = null;
        for (const s of selectors) {
            newChatBtn = document.querySelector(s);
            if (newChatBtn != null) {
                break;
            }
        }
        if (!newChatBtn) {
            port.postMessage({ error: "Cannot create new chat." });
            return false;
        }
        newChatBtn.click();
        return true;
    }

    function findThreadLink(thread_id) {
        let path = "";
        switch (chatbot) {
            case CHATBOT_CHATGPT:
                path = "c";
                break;
            case CHATBOT_CLAUDE:
                path = "chat";
                break;
            default:
                return null;
        }

        const selector = `[href='/${path}/${thread_id}']`;
        let link = document.querySelector(selector);
        if (link == null) {
            const menu = findThreadMenu();
            if (menu != null) {
                menu.click();
                link = document.querySelector(selector);
            }
        }
        if (link == null) {
            const history = findChatHistory();
            if (history != null) {
                history.click();
                link = document.querySelector(selector);
            }
        }
        return link;
    }

    function findThreadMenu() {
        let selector = null;
        switch (chatbot) {
            case CHATBOT_CHATGPT:
                selector = "[d^='M3 8a1']";
                break;
            case CHATBOT_CLAUDE:
                selector = "[d^='M20 4h-4.3l7.7']";
                break;
        }
        return document.querySelector(`button:has(${selector})`);
    }

    function findChatHistory() {
        switch (chatbot) {
            case CHATBOT_CLAUDE:
                return document.querySelector("[href='/recents']");
            default:
                return null;
        }
    }

    function findPromptInputArea() {
        switch (chatbot) {
            case CHATBOT_CHATGPT:
                return document.getElementById("prompt-textarea");
            case CHATBOT_CLAUDE:
                return document.querySelector("[contenteditable='true']");
            default:
                return null;
        }
    }

    function findSubmitBtn() {
        switch (chatbot) {
            case CHATBOT_CHATGPT:
                return document.querySelector("[data-testid*='send-button']");
            case CHATBOT_CLAUDE:
                return document.querySelector(
                    "button:has([d^='M208.49,120.49a12'])"
                );
            default:
                return null;
        }
    }

    function enterInputPrompt(elem, prompt) {
        elem.focus();
        switch (elem.tagName) {
            case "TEXTAREA":
                elem.value = prompt;
                break;
            case "DIV":
                elem.innerText = prompt;
                break;
            default:
                return;
        }
        elem.dispatchEvent(new Event("input", { bubbles: true }));
    }

    function isStreamingResult() {
        let selectors = [];
        switch (chatbot) {
            case CHATBOT_CHATGPT:
                selectors = [
                    ".result-streaming",
                    ".result-thinking",
                    "[data-testid*='stop-button']",
                ];
                break;
            case CHATBOT_CLAUDE:
                selectors = ["[data-is-streaming='true']", "[d^='M128,20A108']"];
                break;
            default:
                return false;
        }
        return selectors.some((s) => document.querySelector(s) != null);
    }

    function findResponse() {
        // Check for error
        let error = null;
        switch (chatbot) {
            case CHATBOT_CHATGPT:
                error = document.querySelector("[d^='M4.472 2.5a1']");
                break;
            case CHATBOT_CLAUDE:
                break;
            default:
                break;                
        }
        if (error != null) {
            return null;
        }

        // Find latest response
        let selector = null;
        switch (chatbot) {
            case CHATBOT_CHATGPT:
                selector = "[data-message-author-role='assistant']";
                break;
            case CHATBOT_CLAUDE:
                selector = "[data-is-streaming='false']";
                break;
            default:
                break;
        }
        let responses = document.querySelectorAll(selector);
        return responses[responses.length - 1]?.firstChild?.innerHTML;
    }

    async function getProofRecord(msg) {
        const target_link = findThreadLink(msg.thread_id);
        if (!msg.thread_id || !target_link) {
            port.postMessage({
                error: `Cannot find proof record for ${msg.thread_id}.`,
            });
            return;
        }
        const currentUrl = new URL(window.location.href);
        if (currentUrl.href.endsWith(msg.thread_id)) {
            if (!goToNewChat()) {
                return;
            }
        }
        setTimeout(() => {
            target_link.click();
            setTimeout(() => port.postMessage({ msg: "Success!" }), 1000);
        }, 1000);
    }

    function configConnection() {
        port = browser.runtime.connect({
            name: `${CONTENT_SCRIPT_PORT}-${chatbot}`,
        });
        port.onMessage.addListener(async (msg) => {
            if (
                msg.type == REQUEST_TYPE_PROOF ||
                msg.type == REQUEST_TYPE_REGISTRATION_PROOF
            ) {
                return await getProofRecord(msg);
            }

            // Create new chat thread or select existing thread
            if (!msg.thread_id) {
                if (!goToNewChat()) {
                    return;
                }
            } else {
                const chat_link = findThreadLink(msg.thread_id);
                if (!chat_link) {
                    port.postMessage({ error: "Cannot find thread." });
                    return;
                }
                chat_link.click();
            }

            setTimeout(() => {
                // Find input area and enter query
                const input_area = findPromptInputArea();
                if (input_area == null) {
                    port.postMessage({
                        error: "Cannot find input area.",
                    });
                    return;
                }
                const query = msg.query;
                enterInputPrompt(input_area, query);

                setTimeout(() => {
                // Submit
                    const submit_btn = findSubmitBtn();
                    if (submit_btn == null) {
                        port.postMessage({
                            error: "Cannot find submit button.",
                        });
                        return;
                    }
                    submit_btn.click();

                    // Get query result
                    let getResponse = () => {
                        // Check if result is still being streamed
                        if (
                            isStreamingResult() ||
                            input_area.value == query ||
                            input_area.innerText == query
                        ) {
                            input_area.focus();
                            setTimeout(getResponse, 1000);
                            return;
                        }

                        let responseObj;
                        const response = findResponse();
                        if (response == null) {
                            responseObj = { error: "Cannot find response." };
                        } else {
                            const thread_id = document.URL.split("/").pop();
                            responseObj = { query, response, thread_id };
                        }
                        port.postMessage(responseObj);
                    };
                    setTimeout(getResponse, 3000);
                }, 1000);
            }, 3000);
        });

        port.onDisconnect.addListener((_) => {
            setTimeout(configConnection, 1000);
        });
    }

    configConnection();
})();
