from flask import Flask, render_template, request
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from datetime import datetime
import json

app = Flask(__name__)
key = get_random_bytes(16)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/genAuthToken", methods=["POST"])
def genAuthToken():
    token = {"time_created": str(datetime.now()), "user_name": "guest"}
    token_bytes = json.dumps(token).encode()
    len_pad = 16 - len(token_bytes) % 16
    token_bytes = bytes([len_pad]) + b"\0" * (len_pad-1) + token_bytes

    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv.hex()
    enc_token = cipher.encrypt(token_bytes)
    return render_template("index.html", iv=iv, auth_token=enc_token.hex())


@app.route("/login", methods=["POST"])
def login():
    iv = bytes.fromhex(request.form['iv'])
    enc_token = bytes.fromhex(request.form['token'])

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    padded_token = cipher.decrypt(enc_token)
    pad_len = padded_token[0]
    token = padded_token[pad_len:]

    try:
        token_dict = json.loads(token.decode('iso-8859-1'), strict=False)
        is_admin = token_dict["user_name"] == "admin"
    except Exception:
        is_admin = False
    return render_template("index.html", token=token, is_admin=is_admin)


if __name__ == "__main__":
    app.run()
