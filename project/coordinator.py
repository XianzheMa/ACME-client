# %%
import sys

from project.acme_client import ACMEclient
from project.constant import *
import project.utils as utils
import project.dns as dns
from project.constant import *
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


directory = 'https://localhost:14000/dir'
challenge_type = 'dns-01'
domain_lists = ['syssec.ethz.ch', 'netsec.ethz.ch']
A_answer = '127.0.0.1'
client = ACMEclient(directory, CA_CERT_PATH)
client.create_account()
cert_url, challenge_infos = client.apply_for_cert(domain_lists, challenge_type)


if challenge_type == 'dns-01':
    domain2TXT = create_domain2TXT(challenge_infos)
    dns_server = dns.create_dns_server(DNS_SERVER.ADDRESS, DNS_SERVER.PORT, A_answer, domain2TXT)
else:
    # http-01 challenge
    dns_server = dns.create_dns_server(DNS_SERVER.ADDRESS, DNS_SERVER.PORT, A_answer)
    #
dns_server.start_thread()
print('DNS server has been started.')
challenge_urls = [info['url'] for info in challenge_infos]
server_private_key, certificate = client.finish_cert_order(challenge_urls, cert_url, domain_lists)



# persist server_private_key and certificate to disk
utils.persist_bytes(certificate, HTTPS_CERT_PATH)
utils.PEM_persist_private_key(server_private_key, HTTPS_PRIVATE_KEY_PATH)


dns_server.stop()