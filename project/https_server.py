# %%
import os
import sys, errno
from flask import Flask
from project.constant import *
import ssl

app = Flask(__name__)
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain(HTTPS_CERT_PATH, HTTPS_PRIVATE_KEY_PATH)


@app.route('/')
def index():
    return 'hello world!'


@app.route('/shutdown')
def shutdown():
    sys.exit(errno.EINTR)


if __name__ == '__main__':
    ip_address = sys.argv[1]
    app.run(ssl_context=context, port=SERVER.HTTPS_SERVER_PORT, host=ip_address)