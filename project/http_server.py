# %%
from flask import Flask
import sys

app = Flask(__name__)

token = None
key_auth = None


@app.route('/.well-known/acme-challenge/<token_input>')
def acme_challenge(token_input):
    if token_input == token:
        return key_auth
    else:
        return 'hello world!'


if __name__ == '__main__':
    token = sys.argv[1]
    key_auth = sys.argv[2]
    app.run(port=5002)