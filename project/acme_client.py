import requests
from typing import Dict, List, Tuple, Union
from project.constant import *
from datetime import datetime, timedelta
import project.utils as utils
import time
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

    def create_cert_order(self, domain_lists):
        payload = {
            'identifiers': [{
                'type': 'dns',
                'value': domain
            } for domain in domain_lists],
        }

        response = self.post_with_retry(self.directory[RESOURCES.NEW_ORDER], payload=payload)
        return response

    def get_challenge_info(self, auth_url, challenge_type):
        response_body = self.get_resource(auth_url)
        identifier = response_body['identifier']['value']
        challenges = response_body['challenges']
        token = None
        challenge_url = None
        for challenge in challenges:
            if challenge['type'] == challenge_type:
                token = challenge['token']
                challenge_url = challenge['url']
                break

        if token is None:
            return None

        key_auth = utils.compute_key_authorization(token, self.public_key)
        return {
            'identifier': identifier,
            'token': token,
            'key_auth': key_auth,
            'url': challenge_url
        }

    def apply_for_cert(self, domain_lists, challenge_type: str):
        response = self.create_cert_order(domain_lists)
        response_body = response.json()
        auth_urls = response_body['authorizations']
        challenge_infos = []
        for auth_url in auth_urls:
            challenge_info = self.get_challenge_info(auth_url, challenge_type)
            if challenge_info is not None:
                challenge_infos.append(challenge_info)

        return response.headers[HEADERS.LOCATION], challenge_infos

    def finish_cert_order(self, challenge_url_lists, cert_url, domain_list, time_to_sleep = 5):
        for challenge_url in challenge_url_lists:
            self.post_with_retry(challenge_url, payload={})

        while True:
            response = self.post_with_retry(cert_url)

            status = response.json()['status']
            print(f'examine order status {status} to post csr...')
            if status in ['ready', 'invalid']:
                break
            time.sleep(time_to_sleep)

        if status != 'ready':
            return None, None

        # get finalize url
        finalize_url = self.get_resource(cert_url)['finalize']
        server_private_key = utils.generate_P256_key()
        encoded_csr = utils.create_csr(server_private_key, domain_list)
        response = self.post_with_retry(finalize_url, payload={'csr': encoded_csr})
        if response.status_code != 200:
            return None, None

        response_body = response.json()
        status = response_body['status']
        while status != 'valid':
            if status != 'processing':
                return None, None
            print(f'examine status {status} for downloading certificate...')
            response_body = self.get_resource(cert_url)
            status = response_body['status']
            time.sleep(time_to_sleep)

        certificate_url = response_body['certificate']
        response = self.post_with_retry(certificate_url)
        return server_private_key, response.content

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
            print('response header is as follows:')
            utils.pretty_print_json(dict(response.headers))
            print('response content (if any) is as follows:')
            print(response.content)
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

