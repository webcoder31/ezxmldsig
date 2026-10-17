# Security policy

## Reporting a vulnerability

Report a vulnerability privately, never in a public issue, pull request or discussion: until a fix is published, a public report lets anyone exploit it.

Use the private vulnerability reporting of GitHub on the repository [webcoder31/ezxmldsig](https://github.com/webcoder31/ezxmldsig): open the tab **Security**, then **Report a vulnerability** ([direct link](https://github.com/webcoder31/ezxmldsig/security/advisories/new)). Only the maintainers of the repository see the report.

Describe in the report:

* the version of ezxmldsig, of xmlseclibs, of PHP and of OpenSSL;
* what an attacker can do, and under which conditions (what they must be able to submit or observe);
* the steps or the code that reproduce it, with a token if possible. Never send a private key you use outside a test.

## Supported versions

| Version | Supported |
|---|---|
| 1.x | Yes: security fixes are published as 1.x versions. |
| 0.x | **No: do not use it any more.** |

**The 0.x versions must no longer be used.** Their verification of the signature has flaws that let anyone have forged data accepted as signed: a token signed with any key pair was valid unless the receiver also verified its certificate on its own, a copy of the signed content placed where the signature does not cover it was verified instead of the content read (signature wrapping), and a failed signature verification could be taken for a valid one. These flaws, and others (decryption oracles, unescaped HTML output, XML entity expansion), are fixed in 1.0.0: see `CHANGELOG.txt`, version 1.0.0, section "Security", and the section "Upgrading from 0.x" of the README.
