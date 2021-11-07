CA_CERT_PATH = './project/pebble.minica.pem'
HTTPS_PRIVATE_KEY_PATH = './project/https_privkey.pem'
HTTPS_CERT_PATH = './project/https_cert.pem'

HTTPS_SERVER_PATH = './project/https_server.py'
HTTP_SERVER_PATH = './project/http_server.py'
SHUTDOWN_SERVER_PATH = './project/shutdown_server.py'

TOKEN2KEYAUTH_PATH = './project/token2keyauth.txt'

TIME_BEFORE_SBUMIT_CHALLENGE = 5
class SERVER:
    DNS_ADDRESS = '0.0.0.0'
    DNS_PORT = 10053
    HTTPS_SERVER_PORT = 5001
    HTTP_SERVER_PORT = 5002
    SHUTDOWN_SERVER_PORT = 5003

class RESOURCES:
    NEW_ACCOUNT = 'newAccount'
    NEW_NONCE = 'newNonce'
    NEW_ORDER = 'newOrder'
    REVOKE_CERT = 'revokeCert'
    KEY_CHANGE = 'keyChange'


class HEADERS:
    REPLAY_NONCE = 'Replay-Nonce'
    CONTENT_TYPE = 'Content-Type'
    LOCATION = 'Location'
    RETRY_AFTER = 'Retry-After'


class HEADER_VALS:
    JOSE_JSON_CONTENT_TYPE = 'application/jose+json'


class CERTIFICATE:
    ORGANIZATION_NAME = 'ETH Zurich'
    LOCALITY_NAME = 'Zurich'
    STATE_NAME = 'Zurich'
    COUNTRY_NAME = 'CH'

