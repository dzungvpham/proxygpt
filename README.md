# ProxyGPT

This is the repo for the paper: ProxyGPT: Enabling Anonymous Queries in AI Chatbot Services

ProxyGPT lets you use ChatGPT, Claude, etc. anonymously by relaying your queries to proxies who are also chatbot users like you.
Unlike existing similar services (e.g., anonchatgpt.com), we use Tor by default. Multi-query conversation is also possible. And anyone can volunteer to become proxies by using our browser extension (which supports Chromium browsers).

The demo is accessible at: http://proxygpt6ruel6k7a6qu7ieoer6z2eudrlhlxlfdshm7w4xnmqqwwrad.onion

**Disclaimer:** This is a proof-of-concept for research/academic purposes only and is not ready for production use. It has not been audited for security. Use at your own risk.

**Repo organization:**
- The `coordinator` folder contains code for our coordinator service. Outside, we also have `app.sh` to help start/stop the service, and `index.html` which is the main entry for ProxyGPT users. The `css` and `scripts` folders are for the website.
- The `verifier` folder contains code for a local Node TLSNotary verifier, to be used by the coordinator server. (IMPORTANT: See instructions below on how to run this verifier.)
- The `extension` folder contains code for our browser-based proxies.

**How to use:**
- For users: Go to the onion link above with your Tor browser, input `test` for the payment (or your hard-earned e-cash from volunteering), then submit your prompt. Note that you will only get a response if there are active proxies. If there's no active proxy, you can become a proxy and test with your own account!
- For proxies (note that this is not ready for production!):
  - First, make sure that you have Tor running in the background (simplest is to open your Tor browser).
  - Download the zipped extension at https://drive.google.com/drive/folders/1z62657WPf0eHeu1WoUkxK8hx8HMWYmRM?usp=sharing
  - Unzip the downloaded file somewhere
  - Open Google Chrome, type `chrome://extensions` in the address bar, enable Developer Mode (top-right corner), then click on Load unpacked (top-left corner) and choose the unzipped extension folder
  - Now, open the ChatGPT website and log in to your account. The automatic registration/verification process will begin. You will receive a query, and the extension will automatically input it into your chatbot. It might take a couple of attempts. You can check if the registration is finished by clicking on the extension's icon to open its pop-up page. Alternatively, you can open the dev console: Go to `chrome://extensions`, click the Details button for the extension panel, then click `offscreen.html`.
  - That's it, you should be ready to proxy. You can find your hard-earned e-cash in the extension's pop-up page (make sure to pin the extension to make it easier to find).
  - To create a proof with TLSNotary, you will need to connect to a websocket proxy server and a notary server. You will want to use a VPN like Mullvad to secure your communications. On Linux, if you use a local websocket proxy (e.g. with websockify or websocat) with Mullvad, you will need to manually set up split tunneling (https://mullvad.net/en/help/split-tunneling-with-linux-advanced) (replace the IP in the first example with 127.0.0.1, make sure to confirm the nft rules list and reload the nftables service if needed).
- For coordinator: If you want to set up your own coordinator service using our code in the `coordinator` folder, here are some steps (assuming you are using Ubuntu server):
  - First, set up a tor hidden service by following the steps here: https://community.torproject.org/onion-services/setup/.
  - Copy the `index.html` file to your hidden service's directory, and see if you can access your hidden site over Tor to verify the installation.
  - Install a MySQL database
  - Run the following: `sudo apt-get install python3-dev default-libmysqlclient-dev build-essential pkg-config`
  - Create a Python virtual environment, activate it, then install everything in the `requirements.txt` file, e.g. `pip install -r requirements.txt`.
  - Make sure nginx is correctly configured. Refer to our sample `nginx.conf`, and make the appropriate changes to `/etc/nginx/nginx/conf`
  - Set up your `.env` file (for the envinronment variables). Refer to `sample_env` for the variables needed. You will need to generate the e-cash keys and JWT authentication keys (use our `keygen.py` file).
  - Use `gunicorn` to start the coordinator. Check out out `app.sh` for the commands (or you can just run `app.sh -s` to start, `-t` to terminate).
  - To run the TLSNotary verifier: cd inside the `verifier` folder (outside of `coordinator`), then run `npm install`. Then, navigate to `verifier/node_modules/tlsn-js/build/27.js`, and remove the `"use strict;"` string. Finally, run `npm run start` to start the local verifier server. Since `tlsn-js` is not written for Node, we have to perform a bit of (monkey-)patching with JSDom and web-worker to make it work properly with Node.
  - That's it. Of course, you will need to update the extension code if you want to proxy with your new coordinator instead of ours.
