# ACME protocol
## Introduction
Public Key Infrastructures (PKIs) using X.509 certificates are used for many purposes, the most significant of which is the authentication of domain names. Certificate Authorities (CAs) are trusted to verify that an applicant for a certificate legitimately represents the domain name(s) in the certificate. Traditionally, this verification is done through various ad-hoc methods.
The [Automatic Certificate Management Environment (ACME) protocol](https://datatracker.ietf.org/doc/html/rfc8555) aims to facilitate the automation of certificate issuance by creating a standardized and machine-friendly protocol for certificate management.
More information about ACME and relevant background can be found in [RFC8555](https://datatracker.ietf.org/doc/html/rfc8555).

## Compile
First run `./project/compile` to install required python dependencies.

## Run

Run with `./project/run' with the following command-line arguments.

**Positional arguments:**
- `Challenge type`
_(required, `{dns01 | http01}`)_ indicates which ACME challenge type the client should perform. Valid options are `dns01` and `http01` for the `dns-01` and `http-01` challenges, respectively.

**Keyword arguments:**
- `--dir DIR_URL`
_(required)_ `DIR_URL` is the directory URL of the ACME server that should be used.
- `--record IPv4_ADDRESS` 
_(required)_ `IPv4_ADDRESS` is the IPv4 address which must be returned by your DNS server for all A-record queries. 
- `--domain DOMAIN`
_(required, multiple)_ `DOMAIN`  is the domain for  which to request the certificate. If multiple `--domain` flags are present, a single certificate for multiple domains should be requested. Wildcard domains have no special flag and are simply denoted by, e.g., `*.example.net`.
- `--revoke`
_(optional)_ If present, your application should immediately revoke the certificate after obtaining it. In both cases, your application should start its HTTPS server and set it up to use the newly obtained certificate.

**Example:**
Consider the following invocation of `run`:
```
run dns01 --dir https://example.com/dir --record 1.2.3.4 --domain netsec.ethz.ch --domain syssec.ethz.ch
```
When invoked like this, it obtains a single certificate valid for both `netsec.ethz.ch` and `syssec.ethz.ch`. It uses the ACME server at the URL `https://example.com/dir` and perform the `dns-01` challenge. The DNS server of the application responds with `1.2.3.4` to all requests for `A` records. Once the certificate has been obtained, it starts its certificate HTTPS server and installs the obtained certificate in this server.
