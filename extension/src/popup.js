import {
    MSG_TYPE_UPDATE_DB,
    MSG_TYPE_RESET,
    DEFAULT_HOURLY_LIMIT,
} from "./constants";
import * as db from "./db";
import browser from "webextension-polyfill";

(async () => {
    // Render ecash list
    function renderEcash(ecash_wallet) {
        document.getElementById("stats_cash").innerText = ecash_wallet.length;
        const list = document.getElementById("ecashList");
        list.replaceChildren();
        ecash_wallet.forEach((coin) => {
            if (!coin || !coin.msg || !coin.signature) {
                return;
            }
            const item = document.createElement("li");
            const text = `${coin.msg}||${coin.signature}`;
            item.innerText = text;
            item.title = "Copy to clipboard";
            item.setAttribute("value", text);

            const removeBtn = document.createElement("span");
            removeBtn.innerText = "X";
            removeBtn.className = "removeButton";
            removeBtn.title = "Remove";
            item.prepend(removeBtn);
            list.appendChild(item);
        });

        const listItems = document.querySelectorAll("ul#ecashList li");
        listItems.forEach((item) => {
            item.addEventListener("click", async () => {
                try {
                    await navigator.clipboard.writeText(
                        item.getAttribute("value")
                    );
                } catch (err) {
                    console.error("Unable to copy to clipboard", err);
                }
            });
        });

        const removeBtns = document.querySelectorAll(".removeButton");
        removeBtns.forEach((btn) => {
            btn.addEventListener("click", async () => {
                try {
                    const [ecash_wallet] = await db.queryDB(
                        ["ecash_wallet"],
                        [[]]
                    );
                    const curValue = btn.parentElement.getAttribute("value");
                    const new_wallet = ecash_wallet.filter(
                        (coin) => `${coin.msg}||${coin.signature}` != curValue
                    );
                    await db.updateDB({ ecash_wallet: new_wallet });
                    renderEcash(new_wallet);
                } catch (err) {
                    console.error("Unable to remove element", err);
                }
            });
        });
    }

    // Display current settings
    const [enabled, requests, ecash_wallet, registered, pid, hourly_limit] =
        await db.queryDB(
            [
                "enabled",
                "requests",
                "ecash_wallet",
                "registered",
                "pid",
                "hourly_limit",
            ],
            [true, {}, [], false, null, DEFAULT_HOURLY_LIMIT]
        );
    document.getElementById("pid").innerText = pid ?? "N/A";
    document.getElementById("status").innerText = registered
        ? "Registered"
        : pid != null
        ? "Registering"
        : "Not registered";
    document.getElementById("limit").value = hourly_limit;
    document.getElementById("enable-checkbox").checked = enabled;
    document.getElementById("stats_requests").innerText =
        Object.keys(requests).length;
    renderEcash(ecash_wallet);

    document
        .getElementById("ecashList_toggle")
        .addEventListener("click", () => {
            const container = document.getElementById("ecashContainer");
            container.style.display =
                container.style.display == "block" ? "none" : "block";
        });

    document
        .getElementById("enable-checkbox")
        .addEventListener("change", async (e) => {
            await db.updateDB({ enabled: e.currentTarget.checked });
        });

    document.getElementById("reset").addEventListener("click", async (e) => {
        const [registered] = await db.queryDB(["registered"], false);
        if (registered) {
            browser.runtime.sendMessage({ type: MSG_TYPE_RESET });
        }
    });

    document.getElementById("limit").addEventListener("change", async (e) => {
        const value = e.target.value;
        if (value < 0 || value > 99 || Math.floor(value) != value) {
            e.target.setCustomValidity("Invalid value. Please choose an integer between 0 and 99.");
            e.target.reportValidity();
            e.target.setCustomValidity("");
            return;
        }
        await db.updateDB({ hourly_limit: Math.floor(value) });
    });

    browser.runtime.onMessage.addListener(async (msg) => {
        if (msg.type != MSG_TYPE_UPDATE_DB) {
            return;
        }
        const keys = ["requests", "ecash_wallet", "registered", "pid"].filter(
            (k) => msg.data.keys.includes(k)
        );
        const values = await db.queryDB(keys);
        keys.forEach((key, idx) => {
            const value = values[idx];
            switch (key) {
                case "requests":
                    document.getElementById("stats_requests").innerText =
                        Object.keys(value).length;
                    break;
                case "ecash_wallet":
                    renderEcash(value);
                    break;
                case "registered":
                    document.getElementById("status").innerText = value
                        ? "Registered"
                        : "Not registered";
                    break;
                case "pid":
                    document.getElementById("pid").innerText = value ?? "N/A";
                    break;
                default:
                    break;
            }
        });
    });
})();
