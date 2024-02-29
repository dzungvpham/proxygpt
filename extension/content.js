let port = null;

function configConnection() {
    port = browser.runtime.connect({ name: "cs-port-init" });
    port.onMessage.addListener((msg) => {
        // Create new chat thread or select existing thread
        const link = "/" + (msg.thread_id == null ? "" : `c/${msg.thread_id}`);
        const links = [...document.getElementsByTagName("a")];
        const chat_link = links.find((e) => e.getAttribute("href") === link);
        if (chat_link === undefined) {
            port.postMessage({ error: "Cannot create thread." });
            return;
        }
        chat_link.click();

        setTimeout(() => {
            // Find input textarea
            let prompt_textarea = document.getElementById("prompt-textarea");
            let btns =
                prompt_textarea.parentElement.getElementsByTagName("button");
            if (prompt_textarea === null || btns.length === 0) {
                port.postMessage({
                    error: "Cannot interact with chat interface.",
                });
                return;
            }

            // Submit
            let submit_btn = btns[0];
            let query = msg.query;
            prompt_textarea.value = query;
            prompt_textarea.dispatchEvent(
                new Event("input", { bubbles: true })
            );
            submit_btn.click();

            // Get query result
            let getResponse = () => {
                // Check if result is still being streamed
                let stream_divs =
                    document.getElementsByClassName("result-streaming");
                if (stream_divs.length > 0) {
                    setTimeout(getResponse, 1000);
                    return;
                }

                let responses = document.querySelectorAll(
                    '[data-message-author-role="assistant"]'
                );
                let lastResponse =
                    responses.length > 0
                        ? responses[responses.length - 1]
                        : null;
                let response = lastResponse?.firstChild?.innerHTML ?? "";
                let responseObj;
                if (response.length === 0) {
                    responseObj = { error: "Cannot find response." };
                } else {
                    const thread_id = document.URL.split("/").pop();
                    responseObj = { query, response, thread_id };
                }
                port.postMessage(responseObj);
            };
            setTimeout(getResponse, 3000);
        }, 3000);
    });

    port.onDisconnect.addListener(_ => {
        setTimeout(configConnection, 1000);
    });
}

configConnection();
