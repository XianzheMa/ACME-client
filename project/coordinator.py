# %%
from project.acme_client import ACMEclient
import project.dns as dns
from project.constant import *
from datetime import datetime, timedelta

DIRECTORY = 'https://localhost:14000/dir'
print('hello')
client = ACMEclient(DIRECTORY, CA_CERT_PATH)
print('hey')
client.create_account()
order_loc, auths, finalize_url = client.apply_for_cert(['netsec.ethz.ch', 'syssec.ethz.ch'], datetime.now(),
                                                   datetime.now() + timedelta(weeks=1))


# %%
print(auths)