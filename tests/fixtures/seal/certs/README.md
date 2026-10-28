# Certificates of the seal tests: public keys, never use them elsewhere

**The private keys of this directory are public.** Use them for the tests only, never in an application, a test environment reachable by others, or a production system, and never trust these certificates.

The files are copied from `test/fixtures/seal/certs/` of the Node.js library [ezxmldsig-js](https://github.com/webcoder31/ezxmldsig-js), which generates them with `bin/gen-seal-test-certs`, in Docker (`alpine:3.22`). Each certificate is valid for 10 years from its generation: copy them again when they are generated again. This PKI is apart from the one of `tests/fixtures/certs/`, shared with the Node.js library: its certificates name a CRL distribution point and an OCSP responder under `http://pki.ezxmlseal.test/`, a host name of the reserved top-level domain `.test`. The libraries never call them; the tests of the Node.js library that send seals to DSS serve them at that name. The `offline` branch names `http://offline.ezxmlseal.test/` instead, which nobody serves: DSS can validate its seals by the data they embed only.

The keys of the signers are encrypted with the password `signKeyPassword`; the keys of the CAs and of the time-stamping authority are not.

| File | Content |
|---|---|
| `root` | Root CA, RSA 3072, self-signed |
| `intermediate` | Intermediate CA, RSA 3072, issued by the root; CRL at `/root.crl` |
| `rsa3072` | Seal certificate, RSA 3072, issued by the intermediate |
| `rsa2048` | The same, RSA 2048 (legacy size, still accepted) |
| `rsa1024` | The same, RSA 1024 (refused) |
| `p256`, `p384` | The same, ECDSA on P-256 and P-384 |
| `revoked` | The same, ECDSA on P-256: the CRL of the intermediate the tests publish for DSS revokes it |
| `tsa-root` | Root CA of the time-stamping authority, RSA 3072, self-signed |
| `tsa` | Time-stamping authority, RSA 3072, issued by `tsa-root`: extended key usage `timeStamping`, critical |
| `tsa-no-eku` | The same without the extended key usage, ECDSA P-256 (refused) |
| `ocsp` | OCSP responder the intermediate delegates, ECDSA P-256: extended key usage `OCSPSigning`, extension `id-pkix-ocsp-nocheck` |
| `ocsp-checked` | The same without `id-pkix-ocsp-nocheck` (refused: the library does not check the revocation of responders) |
| `intermediate-offline` | Intermediate CA, ECDSA P-256, issued by the root; CRL at `http://offline.ezxmlseal.test/root.crl` |
| `offline` | Seal certificate, ECDSA P-256, issued by `intermediate-offline`; CRL at `http://offline.ezxmlseal.test/intermediate-offline.crl`, no OCSP responder |
| `tsa-offline` | Time-stamping authority, ECDSA P-256, issued by `tsa-root`; CRL at `http://offline.ezxmlseal.test/tsa-root.crl` |

The seal certificates but `offline` have the key usage `digitalSignature, nonRepudiation`, a CRL at `/intermediate.crl`, an OCSP responder at `/ocsp`, and their issuer at `/intermediate.cer`.

