# %%
import sys
from flask import Flask, abort
from project.constant import TOKEN2KEYAUTH_PATH
import json

app = Flask(__name__)

token2key_auth = None



@app.route('/.well-known/acme-challenge/<token>')
def acme_challenge(token):
    global token2key_auth
    if token2key_auth is None:
        # de-serialize the dict
        with open(TOKEN2KEYAUTH_PATH) as f:
            token2key_auth = json.load(f)

    if token in token2key_auth:
        return token2key_auth[token]
    else:
        return abort(404)


@app.route('/shutdown')
def shutdown():
    sys.exit(1)