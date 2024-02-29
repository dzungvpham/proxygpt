(async () => {
    // Render ecash list
    function renderEcash(ecash_wallet) {
        const list = document.getElementById("ecashList");
        list.replaceChildren();
        ecash_wallet.forEach(coin => {
            const item = document.createElement("li");
            const text = `${coin.msg}||${coin.signature}`;
            item.innerText = text;
            item.setAttribute("value", text);
            item.style.overflowX = 'hidden';
            item.style.whiteSpace = 'nowrap';
            item.style.textOverflow = 'ellipsis';
            item.title = "Copy to clipboard"

            const removeBtn = document.createElement("span");
            removeBtn.innerText = "X";
            removeBtn.className = "removeButton";
            removeBtn.title = "Remove";
            item.prepend(removeBtn);
            list.appendChild(item);
        });

        const listItems = document.querySelectorAll('ul#ecashList li');
        listItems.forEach(item => {
            item.addEventListener('click', async () => {
                try {
                    await navigator.clipboard.writeText(item.getAttribute("value"));
                } catch (err) {
                    console.error('Unable to copy to clipboard', err);
                }
            });
        });

        const removeBtns = document.querySelectorAll('.removeButton');
        removeBtns.forEach(btn => {
            btn.addEventListener('click', async () => {
                try {
                    const data = await browser.storage.local.get({ ecash_wallet: [] });
                    const curValue = btn.parentElement.getAttribute("value")
                    const new_wallet = data.ecash_wallet.filter(coin => `${coin.msg}||${coin.signature}` != curValue);
                    await browser.storage.local.set({ ecash_wallet: new_wallet });
                } catch (err) {
                    console.error('Unable to remove element', err);
                }
            });
        });
    }

    // Display current settings
    document.addEventListener("DOMContentLoaded", async () => {
        const data = await browser.storage.local.get({
            enabled: true,
            requests: {},
            ecash_wallet: [],
            registered: false,
        });
        document.getElementById("status").innerText = data.registered ? "Registered" : "Not registered";
        document.getElementById("enable-checkbox").checked = data.enabled;
        document.getElementById("stats_requests").innerText = Object.keys(data.requests).length;
        document.getElementById("stats_cash").innerText = data.ecash_wallet.length;
        renderEcash(data.ecash_wallet);
        
        document.getElementById("ecashList_toggle").addEventListener("click", () => {
            const container = document.getElementById("ecashContainer");
            container.style.display = container.style.display == "block" ? "none" : "block";
        })
    });    

    // Save settings
    document.getElementById("enable-checkbox").addEventListener("change", async (e) => {
        await browser.storage.local.set({
            enabled: e.currentTarget.checked,
        });
    });

    browser.storage.local.onChanged.addListener(async (changes) => {
        for (const key of Object.keys(changes)) {
            const change = changes[key];
            switch (key) {
                case "requests":
                    document.getElementById("stats_requests").innerText = Object.keys(change.newValue).length;
                    break;
                case "ecash_wallet":
                    renderEcash(change.newValue);
                case "registered":
                    document.getElementById("status").innerText = change.newValue ? "Registered" : "Not registered";
                default:
                    continue;
            }
        }
    })
})();