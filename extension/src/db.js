import { MSG_TYPE_UPDATE_DB } from "./constants";
import * as idb from "idb-keyval";
import browser from "webextension-polyfill";

export async function queryDB(keys, defaults = undefined) {
    let values = await idb.getMany(keys);
    if (defaults) {
        return values.map((v, i) => (v !== undefined ? v : defaults[i]));
    } else {
        return values;
    }
}

export async function updateDB(updates) {
    await idb.setMany(Object.entries(updates));
    browser.runtime.sendMessage({
        type: MSG_TYPE_UPDATE_DB,
        data: { keys: Object.keys(updates) },
    });
}
