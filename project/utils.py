from project.constant import *
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from typing import Dict
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


def base64url_encode_to_string(msg: bytes) -> str:
    return bytes2raw_string(base64url_encode(msg))


def EC256_pub_key2JWK(public_key: ECC) -> Dict:
    x, y = public_key.pointQ.xy
    jwk = {
        'crv': 'P-256',
        'kty': 'EC',
        'x': base64url_encode_to_string(int(x).to_bytes(32, 'big')),
        'y': base64url_encode_to_string(int(y).to_bytes(32, 'big')),
    }
    return jwk


def SHA256hash(msg: bytes):
    return SHA256.new(msg).digest()


def EC256_pub_key2thumbprint(public_key: ECC) -> bytes:
    jwk = EC256_pub_key2JWK(public_key)
    msg = json.dumps(jwk, separators=(',', ':')).encode('utf8')
    thumbprint = SHA256hash(msg)
    return thumbprint


def base64url_decode(msg: bytes) -> bytes:
    equal_nums = 4 - len(msg) % 4
    msg = msg + '='.encode() * equal_nums
    return urlsafe_b64decode(msg)


def compute_key_authorization(token: str, public_key: ECC) -> str:
    thumbprint = EC256_pub_key2thumbprint(public_key)
    encoded_key = base64url_encode_to_string(thumbprint)
    return token + '.' + encoded_key


def json_to_bytes(json_obj) -> bytes:
    return json.dumps(json_obj, ensure_ascii=False, separators=(',', ':')).encode('utf8')


def pretty_print_json(json_obj, sort_keys = False):
    print(json.dumps(json_obj, indent=4, sort_keys=sort_keys))


def generate_P256_key():
    return ec.generate_private_key(ec.SECP256R1())


def create_csr(private_key, domain_list):
    CN = domain_list[0]
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, CERTIFICATE.COUNTRY_NAME),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, CERTIFICATE.STATE_NAME),
        x509.NameAttribute(NameOID.LOCALITY_NAME, CERTIFICATE.LOCALITY_NAME),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, CERTIFICATE.ORGANIZATION_NAME),
        x509.NameAttribute(NameOID.COMMON_NAME, CN)
    ]))

    csr = csr.add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(other_domain) for other_domain in domain_list
        ]), critical=False)

    csr = csr.sign(private_key, hashes.SHA256())

    return base64url_encode_to_string(csr.public_bytes(serialization.Encoding.DER))


