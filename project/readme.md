# packages should be installed

* requests
* pycryptodome
* dnslib

# issues to be solved

* need to set user-agent, accept-language?
* what if the server does not support that signing alg?
* what is orders field for creating an account?
* wildcast is not supported currently
* serialize json: whitespace?

# TO-DO

# Note

* server auth is done by the cert, whereas client auth is done by JWS.
* All ACME requests with a non-empty body MUST encapsulate their payload in a JSON Web Signature object, signed by the
  private key.
* The server includes a replay-nonce header in every suceessful response to a POST request and should prived it in error
  responses as well.
* Every JWS sent by an ACME client MUST include, in its protected
   header, the "nonce" header parameter.
* Except for the directory resource, all ACME resources are addressed
   with URLs provided to the client by the server.  In POST requests
   sent to these resources, the client MUST set the "url" header
   parameter to the exact string provided by the server (rather than
   performing any re-encoding on the URL).