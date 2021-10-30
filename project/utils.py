from project.constant import *
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from base64 import urlsafe_b64encode, urlsafe_b64decode
import json
import math

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




def base64url_decode(msg: bytes) -> bytes:
    equal_nums = 4 - len(msg) % 4
    msg = msg + '='.encode() * equal_nums
    return urlsafe_b64decode(msg)

def json_to_bytes(json_obj) -> bytes:
    return json.dumps(json_obj, ensure_ascii=False).encode('utf8')

def pretty_print_json(json_obj, sort_keys = False):
    print(json.dumps(json_obj, indent=4, sort_keys=sort_keys))