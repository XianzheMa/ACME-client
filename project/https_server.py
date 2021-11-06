# %%
from flask import Flask
from project.constant import HTTPS_PRIVATE_KEY_PATH, HTTPS_CERT_PATH
import ssl

app = Flask(__name__)
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain(HTTPS_CERT_PATH, HTTPS_PRIVATE_KEY_PATH)


@app.route('/')
def index():
    return 'hello world!'


if __name__ == '__main__':
    app.run(ssl_context=context, port=5001)