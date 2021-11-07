# %%
import sys
import time
from project.acme_client import ACMEclient
import project.utils as utils
import project.dns as dns
from project.constant import *
import json
import os
import argparse


def create_domain2TXT(challenge_infos):
    domain2TXT = {}
    for info in challenge_infos:
        domain = info['identifier']
        key_auth = info['key_auth']
        challenge_domain = '_acme-challenge.' + domain
        msg_to_hash = key_auth.encode()
        TXT_val = utils.base64url_encode_to_string(utils.SHA256hash(msg_to_hash))
        domain2TXT[challenge_domain] = TXT_val

    return domain2TXT


def create_token2keyauth(challenge_infos):
    token2keyauth = dict()
    for info in challenge_infos:
        token2keyauth[info['token']] = info['key_auth']

    return token2keyauth


def main(directory, challenge_type, domain_lists, A_answer, revoke):
    client = ACMEclient(directory, CA_CERT_PATH)
    client.create_account()
    cert_url, challenge_infos = client.apply_for_cert(domain_lists, challenge_type)

    if challenge_type == 'dns-01':
        domain2TXT = create_domain2TXT(challenge_infos)
        token2keyauth = dict()
    else:
        # http-01 challenge
        domain2TXT = dict()
        token2keyauth = create_token2keyauth(challenge_infos)

    dns_server = dns.create_dns_server(SERVER.DNS_ADDRESS, SERVER.DNS_PORT, A_answer, domain2TXT)
    dns_server.start_thread()

    with open(TOKEN2KEYAUTH_PATH, 'w') as f:
        json.dump(token2keyauth, f)

    # kill the previous process, if any
    os.system(f'kill -9 `lsof -t -i:{SERVER.HTTP_SERVER_PORT}`')
    os.system(f'gunicorn --daemon --bind {A_answer}:{SERVER.HTTP_SERVER_PORT} project.http_server:app')

    time.sleep(TIME_BEFORE_SBUMIT_CHALLENGE)
    challenge_urls = [info['url'] for info in challenge_infos]
    server_private_key, certificate = client.finish_cert_order(challenge_urls, cert_url, domain_lists)

    if server_private_key is None:
        dns_server.stop()
        os.system(f'kill -9 `lsof -t -i:{SERVER.HTTP_SERVER_PORT}`')
        sys.exit(1)

    if revoke:
        client.revoke_cert(certificate)

    # persist server_private_key and certificate to disk
    utils.persist_bytes(certificate, HTTPS_CERT_PATH)
    utils.PEM_persist_private_key(server_private_key, HTTPS_PRIVATE_KEY_PATH)

    # kill the previous process, if any
    os.system(f'kill -9 `lsof -t -i:{SERVER.SHUTDOWN_SERVER_PORT}`')
    os.system(f'gunicorn --daemon --bind {A_answer}:{SERVER.SHUTDOWN_SERVER_PORT} project.shutdown_server:app')

    # kill the previous process, if any
    os.system(f'kill -9 `lsof -t -i:{SERVER.HTTPS_SERVER_PORT}`')
    os.system(f'python -m project.https_server {A_answer}')
    dns_server.stop()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('challenge_type', type=str, choices=['dns01', 'http01'])
    parser.add_argument('--dir', type=str, required=True)
    parser.add_argument('--record', type=str, required=True)
    parser.add_argument('--domain', type=str, required=True, action='append')
    parser.add_argument('--revoke', action='store_true')
    args = parser.parse_args()
    challenge_type = 'dns-01' if args.challenge_type == 'dns01' else 'http-01'
    main(args.dir, challenge_type, args.domain, args.record, args.revoke)

