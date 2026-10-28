# Certificates of the trust tests: public keys, never use them elsewhere

**The private keys of this directory are public.** Use them for the tests only, never in an application, a test environment reachable by others, or a production system, and never trust these certificates.

The files are copied from `test/fixtures/trust/` of the Node.js library [ezxmldsig-js](https://github.com/webcoder31/ezxmldsig-js), which generates them with `bin/gen-test-certs`, in Docker (`alpine:3.22`), from the root and intermediate CAs of `tests/fixtures/certs/`. Unless said otherwise below, each certificate is valid for 10 years from its generation: copy them again when they are generated again. Each one is a case of the trust in a signing certificate; the tests compare the chain `X509Cert::getTrustedChain()` builds and verifies with what OpenSSL decides (`isTrustedBy()`, and the `openssl verify` command at a given date).

| File | Case |
|---|---|
| `issued` | Signing certificate issued by the trusted intermediate (control) |
| `expired` | The same, valid in 2020 only |
| `not-yet-valid` | The same, valid in 2099 only |
| `nonrepudiation` | Key usage `nonRepudiation` only |
| `no-keyusage` | No key usage extension |
| `critical-unknown`, `noncritical-unknown` | An unknown extension, critical or not |
| `by-root` | Issued by the trusted root directly |
| `rogue` | Issued by `sign.cert.pem`, which is not a CA |
| `other-intermediate`, `other-signer` | Another intermediate CA of the root, and a certificate it issued |
| `no-certsign-intermediate`, `no-certsign-signer` | An intermediate CA whose key usage does not allow `keyCertSign`, and a certificate it issued |
| `no-bc-intermediate`, `no-bc-signer` | An intermediate CA without basic constraints, and a certificate it issued |
| `expired-intermediate`, `expired-intermediate-signer` | An intermediate CA valid in 2020 only, and a certificate it issued |
| `sub-intermediate`, `sub-signer` | A CA issued by the trusted intermediate, whose path length (0) the certificate it issued exceeds |
| `noext-root`, `noext-signer` | A root without any extension (version 3), which is no CA, and a certificate it issued |
| `forged` | The name of the trusted intermediate as issuer, no authority key identifier, signed by another key |
| `twin-a`, `twin-b`, `twin-b-signer` | Two CAs with the same name, and a certificate of the second one, told apart by its authority key identifier |
| `twin-rsa`, `twin-ec`, `twin-ec-signer` | Two CAs with the same name, RSA and EC keys, and a certificate of the EC one without authority key identifier, told apart by its signature algorithm |
| `twin-old`, `twin-new`, `twin-new-signer` | Two CAs with the same name, the first one valid in 2020 only, and a certificate of the second one without authority key identifier, told apart by the validity dates |
| `ec-signer` | Self-signed signing certificate with an EC key (P-256), and its key |
| `dsa` | Self-signed, with a DSA key and the subject of `sign.cert.pem` (its key is not kept) |
| `names` | Self-signed, not a CA: repeated and multi-valued fields, `/` and `+` in values, fields of less usual types (its key is not kept) |
| `utf8` | Self-signed: characters out of ASCII, in UTF8String (its key is not kept) |
| `bmp` | Self-signed: characters out of ASCII, in BMPString (its key is not kept) |
