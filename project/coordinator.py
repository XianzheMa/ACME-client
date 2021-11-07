# %%
import sys
import time
from project.acme_client import ACMEclient
import project.utils as utils
import project.dns as dns
from project.constant import *
import json
import os



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

directory = 'https://localhost:14000/dir'
challenge_type = 'http-01'
domain_lists = ['syssec.ethz.ch', 'netsec.ethz.ch']
A_answer = '127.0.0.1'
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
os.system(f'gunicorn --daemon --bind {A_answer}:{SERVER.HTTP_SERVER_PORT} --workers=4 project.http_server:app')

time.sleep(TIME_BEFORE_SBUMIT_CHALLENGE)
print('DNS server and HTTP server have both been started.')
challenge_urls = [info['url'] for info in challenge_infos]

server_private_key, certificate = client.finish_cert_order(challenge_urls, cert_url, domain_lists)

if server_private_key is None:
    sys.exit(1)

# persist server_private_key and certificate to disk
utils.persist_bytes(certificate, HTTPS_CERT_PATH)
utils.PEM_persist_private_key(server_private_key, HTTPS_PRIVATE_KEY_PATH)


# kill the previous process, if any
os.system(f'kill -9 `lsof -t -i:{SERVER.HTTPS_SERVER_PORT}`')
os.system(f'gunicorn --daemon --bind localhost:{SERVER.HTTPS_SERVER_PORT} --workers=4 project.https_server:app')
# %%
dns_server.stop()