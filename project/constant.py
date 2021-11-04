CA_CERT_PATH = './project/pebble.minica.pem'

class DNS_SERVER:
    ADDRESS = '0.0.0.0'
    PORT = 10053

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


class HEADER_VALS:
    JOSE_JSON_CONTENT_TYPE = 'application/jose+json'

