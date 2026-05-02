const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const { JSDOM } = require("jsdom");
const Worker = require("web-worker");

const app = express();
const port = 7175;

// Create a JSDOM instance to mock the document object with the proper URL
const { window } = new JSDOM(``, {
    url: `http://localhost:${port}/node_modules/tlsn-js/build/`,
});
global.document = window.document;

// Monkey-patch
global.Worker = function(url, options) {
    // from http://localhost:${port}/path to ./path since Node only accepts local file
    return new Worker("." + url.pathname);
};

 // Make sure to remove "use strict;" from in /node-modules/tlsn-js/build/27.js
const { verify } = require("tlsn-js");

// Middleware to parse JSON bodies
app.use(bodyParser.json());

app.use(
    "/node_modules/tlsn-js/build",
    express.static(path.join(__dirname, "node_modules/tlsn-js/build"))
);

app.post("/", async (req, res) => {
    const { proof, notaryPubKey } = req.body;
    if (!proof) {
        return res.status(400).json({ error: "Proof is not provided!" });
    }
    try {
        const result = await verify(JSON.parse(proof), notaryPubKey);
        return res.json({ result });
    } catch (e) {
        return res.status(400).json({ error: e });
    }
});

app.get("/");

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
