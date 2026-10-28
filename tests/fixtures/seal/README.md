# Seals of the tests: made by the Node.js library

The seals of this directory are made by the Node.js library [ezxmldsig-js](https://github.com/webcoder31/ezxmldsig-js), a creator apart from this library, so that the verification of seals is not tested on seals it made itself. `bin/gen-seal-fixtures` clones the Node.js library at the tag it names into `tests/.cache/`, builds it and runs `generate.ts` in the `node` Docker image; the test helpers of the Node.js library make the time-stamps, the CRLs and the OCSP responses. Each run makes other seals (their identifiers and times differ): commit the directory as a whole.

| Path | Content |
|---|---|
| `certs/` | The test PKI of the seals, copied from the Node.js library (see its README) |
| `containers/b-*.asice` | Level B, each signature algorithm (RSA-PSS, RSA PKCS#1 v1.5, ECDSA P-256 and P-384, RSA-PSS SHA-512), a revoked signer, and a seal without its intermediate CA |
| `containers/t-rsa-pss-sha256.asice` | Level T: the seal `b-rsa-pss-sha256`, time-stamped by the test authority of the Node.js library |
| `containers/lt-crl.asice`, `containers/lt-ocsp.asice` | Level LT: the seal of level T with its CRLs, or with OCSP responses for the signer and the authority |
| `revocation/` | The CRLs and OCSP responses `generate.ts` issued after the time-stamp |
| `verdicts.json` | What `verifySeal()` of the Node.js library said of each seal when it was made |
| `zip/` | ZIP archives written by the zipfile module of Python, for the tests of the ZIP reader (`generate.py`) |

The times are relative to the run of the generator: the seals are signed a minute before it, time-stamped 50 seconds before, and their CRLs and OCSP responses are issued 40 seconds before. Data issued after the time-stamp keep proving the status of the signer at that time, so that the seals of levels T and LT stay valid as long as the certificates of the PKI (2036). A seal of level B needs current CRLs: the tests issue them with the `openssl ca` command when they run.

The other direction is checked by hand, not by the test suite, which runs PHP only: the seals this library makes, at levels B, T and LT, are verified by `verifySeal()` of the Node.js library and validated by DSS, the validator of the European Commission, with the scripts and the DSS that the Node.js library runs for its own tests (`bin/dss start` there).
