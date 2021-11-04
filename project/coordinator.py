# %%
import sys

from project.acme_client import ACMEclient
from project.constant import *
import project.utils as utils
import project.dns as dns
from project.constant import *
from datetime import datetime, timedelta


def create_domain2TXT(domain_lists, challenge_infos):
    domain2TXT = {}
    for pos, domain in enumerate(domain_lists):
        if challenge_infos[pos] is None:
            print(f"To certify for {domain}, a {challenge_type} challenge is not required.")
            sys.exit(1)

        challenge_info = challenge_infos[pos]
        domain = '_acme-challenge.' + domain
        msg_to_hash = challenge_info['key_auth'].encode()
        TXT_val = utils.bytes2raw_string(utils.base64url_encode(utils.SHA256hash(msg_to_hash)))
        domain2TXT[domain] = TXT_val

    return domain2TXT

directory = 'https://localhost:14000/dir'
challenge_type = 'dns-01'
domain_lists = ['netsec.ethz.ch', 'syssec.ethz.ch']
A_answer = '1.2.3.4'
client = ACMEclient(directory, CA_CERT_PATH)
client.create_account()
cert_url, challenge_infos = client.apply_for_cert(domain_lists, datetime.now(),
                                        datetime.now() + timedelta(weeks=1), challenge_type)

if challenge_type == 'dns-01':
    domain2TXT = create_domain2TXT(domain_lists, challenge_infos)
    dns_server = dns.create_dns_server(DNS_SERVER.ADDRESS, DNS_SERVER.PORT, A_answer, domain2TXT)
    dns_server.start_thread()
    print('DNS server has been started.')

# %%
challenge_urls = [info['url'] for info in challenge_infos]