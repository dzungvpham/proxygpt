# ProxyGPT

This is the repo for the paper: ProxyGPT: Enabling Anonymous Queries in LLM Chatbot via (Un)Trustworthy Volunteer Proxies

ProxyGPT is a research proof of concept that lets you use ChatGPT and Claude anonymously by relaying your queries to proxies who are also chatbot users like you.
Unlike existing similar services, we use Tor by default. Multi-query conversation is also possible. And anyone can volunteer to become proxies by using our Chromium browser extension.

**Disclaimer:** This is a proof-of-concept for research/academic purposes only and is not ready for production use. It has not been audited for security.

**Repo organization:**
- `broker`: code for our broker service, including the front-end.
- `notary`: code for a local Node.js TLSNotary server.
- `proxy`: code for our browser extension.
- `guard`: code for prompt safety LLM guard benchmark.
- `pii`: code for PII detection benchmark.
- `simulation`: code for simulating workload.
- `wildchat`: code for re-identification attack study on WildChat-4.8M


**How to set up:**
- Proxy:
  - Install Tor and make sure that you have Tor running in the background (simplest is to just install Tor browser and leave it running).
  - To create a proof with TLSNotary, you will need to connect to a websocket proxy server and a notary server. You will want to use a VPN like Mullvad to secure your communications. On Linux, if you use a local websocket proxy (e.g. with websockify or websocat) with Mullvad VPN, you will need to manually set up split tunneling (https://mullvad.net/en/help/split-tunneling-with-linux-advanced) (replace the IP in the first example with 127.0.0.1, make sure to confirm the nft rules list and reload the nftables service if needed).
  - Open Google Chrome, type `chrome://extensions` in the address bar, enable Developer Mode (top-right corner), then click on Load unpacked (top-left corner) and choose the unzipped extension folder
  - Now, open the ChatGPT website and log in to your account. The automatic registration/verification process will begin (can take a few minutes). You can check if the registration is finished by clicking on the extension's icon to open its pop-up page. Alternatively, you can open the dev console: Go to `chrome://extensions`, click the Details button for the extension panel, then click `offscreen.html`.
  - That's it, you should be ready to proxy. You can find your hard-earned tokens in the extension's pop-up page (make sure to pin the extension to make it easier to find).  
- Broker: To set up your own broker using our code in the `broker` folder, here are some steps (assuming you are using Ubuntu server):
  - First, set up a Tor hidden service by following the steps here: https://community.torproject.org/onion-services/setup/.
  - Copy the `index.html` file to your hidden service's directory, and see if you can access your hidden site over Tor to verify the installation.
  - Install a MySQL database
  - Run the following: `sudo apt-get install python3-dev default-libmysqlclient-dev build-essential pkg-config`
  - Create a Python virtual environment, activate it, then install everything in the `requirements.txt` file, e.g. `pip install -r requirements.txt`.
  - Make sure nginx is correctly configured. Refer to our sample `nginx.conf`, and make the appropriate changes to `/etc/nginx/nginx/conf`
  - Set up your `.env` file (for the envinronment variables). Refer to `sample_env` for the variables needed. You will need to generate the tokens keys and JWT authentication keys (use our `keygen.py` file).
  - Use `gunicorn` to start the coordinator. Check out out `app.sh` for the commands (or you can just run `app.sh -s` to start, `-t` to terminate).
  - To run the TLSNotary server: cd inside the `notary` folder, then run `npm install`. Then, navigate to `notary/node_modules/tlsn-js/build/27.js`, and remove the `"use strict;"` string. Finally, run `npm run start` to start the local verifier server. Since `tlsn-js` is not written for Node, we have to perform a bit of (monkey-)patching with JSDom and web-worker to make it work properly with Node.
  - You will need to update the Tor link in the extension code if you want to proxy with your new coordinator instead of ours.
- TLSNotary Server (for broker): If you want to set up your own TLSNotary server, follow the instructions here: https://tlsnotary.org/docs/extension/verifier. We changed the max-transcript-size to 32768 to support longer chat conversations and disabled tls since authentication is handled via our reverse proxy setup. Make sure to create new notary signature keys. You will probably also want to set up a websocket proxy server, e.g.:
  - ```
    git clone https://github.com/novnc/websockify && cd websockify
    ./docker/build.sh
    docker run -it --rm -p 55688:80 novnc/websockify 80 chatgpt.com:443
    ```
**In-browser prompt safety guard/PII detection**
- Open `guard/demo/index.html` or `pii/index.html` with your Google Chrome or Brave browser.
- Select which model and inference engine/quantization that you want to run, then click on "Load model".
- Type your input in the input text box, or click on "Run benchmark" to test the model's performance.

**WildChat analysis**
- Set up a new virtual environment and activate it (we used Python 3.12)
- Install Stylometrix (follow these steps precisely to avoid issues):
  - Install spacy (CUDA is highly recommended), e.g.,: `pip install -U 'spacy[cuda12x]'` (make sure to choose the right CUDA version. If you need version 13 instead of 12, omit the `[cuda12x]` option, run `pip install cupy-cuda13x[ctk]` afterwards). Then run `python -m spacy download en_core_web_trf` for the large English model.
  - Clone the StyloMetrix repo at https://github.com/NASK-NLP/StyloMetrix (do not run `pip install stylometrix` because its spacy requirement is broken).
  - Modify the repo's requirements.txt file by removing the version pin for spacy (e.g., remove the ==3.7.2)
  - Modify the repo's setup.cfg file by replacing {{VERSION_PLACEHOLDER}} with 1.0.0
  - Now, run `pip install -e .` in the repo
- Next, install the following: `pip install datasets google-genai huggingface_hub matplotlib python-dotenv seaborn tqdm`
- Download WildChat-4.8M dataset, e.g.,: `hf download allenai/WildChat-4.8M --repo-type dataset --local-dir /datasets/ai/` (might need to run `hf auth login` first)
- Now, cd into `wildchat/` and run the following scripts in order (it will take a while):
  - `preprocess.py`: This will create 320 files in the `wildchat_preprocessed/`.
  - `filter.py`: This will filter the dataset into a `wildchat_filtered_4o20240806_41mini20250414_device_deduped.csv`
  - `stylometrix.py`: Compute Stylometrix features for the filtered dataset into `wildchat_embeddings/wildchat_filtered_en_2048_stylometrix.csv`.
  - `get_embeddings.py`: Optional, only if you want Gemini embedding, but you will need to set up a credential file for Google Cloud. It will try to get Gemini embedding for the ENTIRE unfiltered WildChat-4.8M dataset.
  - `analyze_wildchat.ipynb`: Notebook for plotting some stats and running the linkage attack using the generated data.
