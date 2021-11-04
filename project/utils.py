from project.constant import *
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from typing import Dict
from Crypto.PublicKey.ECC import EccKey
from base64 import urlsafe_b64encode, urlsafe_b64decode
import json

def generate_ES256_keys():
    private_key = ECC.generate(curve='P-256')
    public_key = private_key.public_key()
    return private_key, public_key


def ES256_sign(private_key, msg: bytes) -> bytes:
    h = SHA256.new(msg)
    signer = DSS.new(private_key, 'fips-186-3')
    signature = signer.sign(h)
    return signature


def base64url_encode(msg: bytes) -> bytes:
    encoded = urlsafe_b64encode(msg)
    return encoded.rstrip('='.encode())


def bytes2raw_string(msg: bytes) -> str:
    return str(msg)[2:-1]


def EC256_pub_key2JWK(public_key: ECC) -> Dict:
    x, y = public_key.pointQ.xy
    jwk = {
        'crv': 'P-256',
        'kty': 'EC',
        'x': bytes2raw_string(base64url_encode(int(x).to_bytes(32, 'big'))),
        'y': bytes2raw_string(base64url_encode(int(y).to_bytes(32, 'big'))),
    }
    return jwk


def SHA256hash(msg: bytes):
    return SHA256.new(msg).digest()


def EC256_pub_key2thumbprint(public_key: ECC) -> bytes:
    jwk = EC256_pub_key2JWK(public_key)
    msg = json.dumps(jwk, separators=(',', ':')).encode()
    thumbprint = SHA256hash(msg)
    return thumbprint


def base64url_decode(msg: bytes) -> bytes:
    equal_nums = 4 - len(msg) % 4
    msg = msg + '='.encode() * equal_nums
    return urlsafe_b64decode(msg)


def compute_key_authorization(token: str, public_key: ECC) -> str:
    thumbprint = EC256_pub_key2thumbprint(public_key)
    encoded_key = bytes2raw_string(base64url_encode(thumbprint))
    return token + '.' + encoded_key


def json_to_bytes(json_obj) -> bytes:
    return json.dumps(json_obj, ensure_ascii=False, separators=(',', ':')).encode('utf8')


def pretty_print_json(json_obj, sort_keys = False):
    print(json.dumps(json_obj, indent=4, sort_keys=sort_keys))