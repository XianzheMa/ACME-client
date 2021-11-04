import requests
from typing import Dict, List, Tuple, Union
from project.constant import *
from datetime import datetime, timedelta
import project.utils as utils
import sys


class ACMEclient:

    def __init__(self, directory_url, ca_cert_path):
        self.directory_url = directory_url
        self.account_url = None
        self.ca_cert_path = ca_cert_path
        self.replay_nonce = None
        private_key, public_key = utils.generate_ES256_keys()
        self.private_key = private_key
        self.public_key = public_key
        directory_response = self.get_directory()
        self.directory = {
            RESOURCES.NEW_ACCOUNT: directory_response[RESOURCES.NEW_ACCOUNT],
            RESOURCES.NEW_NONCE: directory_response[RESOURCES.NEW_NONCE],
            RESOURCES.NEW_ORDER: directory_response[RESOURCES.NEW_ORDER],
            RESOURCES.REVOKE_CERT: directory_response[RESOURCES.REVOKE_CERT],
            RESOURCES.KEY_CHANGE: directory_response[RESOURCES.KEY_CHANGE]
        }

        self.refresh_replay_nonce()


    def request(self, verb, url, headers=None, **kwargs):
        try:
            response = requests.request(verb, url, verify=self.ca_cert_path, headers=headers, **kwargs)
        except requests.exceptions.SSLError:
            print('The certificate of the ACME server failed to be validated.')
            sys.exit(1)

        # set the new nonce
        if HEADERS.REPLAY_NONCE in response.headers:
            self.replay_nonce = response.headers[HEADERS.REPLAY_NONCE]

        return response


    def get_directory(self):
        response = self.request('GET', self.directory_url)
        return response.json()

    def refresh_replay_nonce(self):
        response = self.request('HEAD', self.directory[RESOURCES.NEW_NONCE])
        self.replay_nonce = response.headers[HEADERS.REPLAY_NONCE]

    def create_account(self):
        response = self.post_with_retry(self.directory[RESOURCES.NEW_ACCOUNT], payload={
            "termsOfServiceAgreed": True,
        }, usingJWK=True)
        self.account_url = response.headers[HEADERS.LOCATION]

    def apply_for_cert(self, domain_lists, not_before: datetime, not_after: datetime):
        payload = {
            'identifiers': [{
                'type': 'dns',
                'value': domain
            } for domain in domain_lists],
            'notBefore': not_before.isoformat(),
            'notAfter': not_after.isoformat()
        }

        response = self.post_with_retry(self.directory[RESOURCES.NEW_ORDER], payload=payload)
        response_body = response.json()
        return response.headers[HEADERS.LOCATION], response_body['authorizations'], response_body['finalize']

    def get_resource(self, resource_url):
        response = self.post_with_retry(resource_url)
        return response.json()


    def post_with_retry(self, url, headers=dict(), payload: Union[str, Dict]='', usingJWK=False, **kwargs):
        response = self.post_request(url, headers, payload, usingJWK, **kwargs)

        if response.status_code == 400:
            # retry
            response = self.post_request(url, headers, payload, usingJWK, **kwargs)

        if response.status_code // 100 in [4, 5]:
            print('Get a response with error status code.')
            sys.exit(1)

        return response

    def post_request(self, url, headers=dict(), payload: Union[str, Dict]='', usingJWK=False, **kwargs):
        headers[HEADERS.CONTENT_TYPE] = HEADER_VALS.JOSE_JSON_CONTENT_TYPE
        protected_headers = {
            'alg': 'ES256',
            'nonce': self.replay_nonce,
            'url': url
        }

        if usingJWK:
            protected_headers['jwk'] = utils.EC256_pub_key2JWK(self.public_key)
        else:
            protected_headers['kid'] = self.account_url
        encoded_protected_headers = utils.base64url_encode(utils.json_to_bytes(protected_headers))

        if payload == '':
            # POST-as-Get request
            encoded_payload = ''.encode()
        else:
            encoded_payload = utils.base64url_encode(utils.json_to_bytes(payload))

        content_to_sign = encoded_protected_headers + '.'.encode() + encoded_payload
        signature = utils.ES256_sign(self.private_key, content_to_sign)
        encoded_signature = utils.base64url_encode(signature)

        body = {
            'protected': utils.bytes2raw_string(encoded_protected_headers),
            'payload': utils.bytes2raw_string(encoded_payload),
            'signature': utils.bytes2raw_string(encoded_signature)
        }

        response = self.request('POST', url, headers, json=body, **kwargs)
        return response

