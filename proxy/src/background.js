import {
    COORDINATOR_HOST,
    MSG_TYPE_REQUEST_CAPTURE,
    MSG_TYPE_REQUEST_CAPTURE_RESULT,
} from "./constants";
import browser from "webextension-polyfill";

// Route all requests to the coordinator through Tor
const proxyConfig = {
    mode: "pac_script",
    pacScript: {
        data:
            "function FindProxyForURL(url, host) {\n" +
            `  if (host == '${COORDINATOR_HOST}')\n` +
            "    return 'SOCKS5 127.0.0.1:9150';\n" +
            "  return 'DIRECT';\n" +
            "}",
    },
};
browser.proxy.settings.set({ value: proxyConfig, scope: "regular" });

// Listen to messages
browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    switch (msg.type) {
        case MSG_TYPE_REQUEST_CAPTURE:
            if (!msg.data.thread_id) {
                return;
            }
            const listener = (details) => {
                if (details.method !== "GET") {
                    return;
                }
                browser.runtime.sendMessage({
                    type: MSG_TYPE_REQUEST_CAPTURE_RESULT,
                    data: { details, thread_id: msg.data.thread_id },
                });
                browser.webRequest.onSendHeaders.removeListener(listener);
            };
            browser.webRequest.onSendHeaders.addListener(
                listener,
                {
                    urls: [
                        `https://chatgpt.com/backend-api/conversation/${msg.data.thread_id}`,
                    ],
                    types: ["xmlhttprequest"],
                },
                ["requestHeaders", "extraHeaders"]
            );
            return true;
        default:
            break;
    }
});

// Create offscreen for TLSNotary
let creatingOffscreen;
async function createOffscreenDocument() {
    const offscreenUrl = browser.runtime.getURL("offscreen.html");
    const existingContexts = await browser.runtime.getContexts({
        contextTypes: ["OFFSCREEN_DOCUMENT"],
        documentUrls: [offscreenUrl],
    });

    if (existingContexts.length > 0) {
        return;
    }

    if (creatingOffscreen) {
        await creatingOffscreen;
    } else {
        creatingOffscreen = browser.offscreen.createDocument({
            url: "offscreen.html",
            reasons: ["WORKERS"],
            justification: "workers for multithreading",
        });
        await creatingOffscreen;
        creatingOffscreen = null;
    }
}
await createOffscreenDocument();
