# ProxyGPT

This is the repo for the paper: ProxyGPT: Enabling Anonymous Queries in AI Chatbot Services

ProxyGPT lets you use ChatGPT anonymously by relaying your queries to proxies, who are ChatGPT users like you (or some servers).
Unlike existing similar services (e.g., anonchatgpt.com), we use Tor by default. Multi-query conversation is also possible. And anyone can volunteer to become proxies by using our Firefox extension.

The demo is accessible at: http://v6tlhwumds2qp2pnmyto6w73frg3ofcy3tya2ozkjs2tg24vrpdnb5yd.onion/ (We reuse ChatGPT's UI for simplicity)

**Disclaimer:** This is a proof-of-concept for research/academic purposes only and is not ready for production use. It has not been audited for security. Use at your own risk.

**Repo organization:**
- The `coordinator` folder contains code for our coordinator service. Outside, we also have `app.sh` to help start/stop the service, and `index.html` which is the main entry for ProxyGPT users. The `css` and `scripts` folders are for the website.
- The `extension` folder contains code for our browser-based proxies.

**How to use:**
- For users: Go to the onion link above with your Tor browser, input `test` for the payment (or your hard-earned e-cash from volunteering), then submit your prompt. Note that you will only get a response if there are active proxies. If there's no active proxy, you can become a proxy and test with your own account!
- For browser-based proxies:
  - First, make sure that you have Tor running in the background (simplest is to open your Tor browser).
  - Clone our repo to your machine.
  - Go to Firefox, type `about:debugging` in the address bar, click on the `This Firefox` tab, then click on `Load Temporary Add-on...`. Navigate to the repo, then select `extension/manifest.json` to load our extension.
  - Now, open the ChatGPT website and log in to your account. The automatic registration/verification process will begin. You will receive a query, and the extension will automatically input it into your chatbot. It might take a couple of attempts. You can check if the registration is finished by clicking on the extension's icon to open its pop-up page, or opening a dev console in Firefox's `about:debugging page`.
  - That's it, you should be ready to proxy. You can find your hard-earned e-cash in the extension's pop-up page.
- For coordinator: If you want to set up your own coordinator service using our code in the `coordinator` folder, here are some steps (assuming you are using Ubuntu server):
  - First, set up a tor hidden service by following the steps here: https://community.torproject.org/onion-services/setup/.
  - Copy the `index.html` file to your hidden service's directory, and see if you can access your hidden site over Tor verify the installation.
  - Install a MySQL database
  - Create a Python virtual environment, then install everything in the `requirements.txt` file, e.g. `pip install -r requirements.txt`. Activate the environment once finished (e.g., `source path/to/your/environment/bin/activate`)
  - Make sure nginx is correctly configured. Refer to our sample `nginx.conf`, and make the appropriate changes to `/etc/nginx/nginx/conf`
  - Set up your `.env` file (for the envinronment variables). Refer to `sample_env` for the variables needed. You will need to generate the e-cash keys and JWT authentication keys (use our `keygen.py` file).
  - Use `gunicorn` to start the coordinator. Check out out `app.sh` for the commands (or you can just run `app.sh -s` to start, `-t` to terminate).
  - That's it. Of course, you will need to update the extension code if you want to proxy with your new coordinator instead of ours.
- For server-based proxies: The steps are not detailed here, but the code is included in the coordinator folder. You will need your own OpenAI API key and your own crypto wallet.
