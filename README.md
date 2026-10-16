# EZXMLDSIG: An easy-to-use set of PHP classes for common use cases of XML Digital Signatures

Built on the library **xmlseclibs** developed by Rob Richards (https://github.com/robrichards/xmlseclibs), the library **ezxmldsig** is designed to make it easy to use XML digital signatures for various purposes such as Single Sign On login, token based authentication, document electronic signature, data integrity guarantee, and so on.

The author of the **ezxmldsig** library is Thierry Thiers.


## Requirements

The library **ezxmldsig** requires PHP version 7.4 or greater, with the OpenSSL extension, and the library **xmlseclibs** developed by Rob Richards, version ^3.1.5 (3.1.5 or a later 3.x version).


## How to Install?

The library **ezxmldsig** is available on [www.pakagist.org](https://packagist.org/packages/webcoder31/ezxmldsig) and you can nstall it for your project with [`composer.phar`](http://getcomposer.org).


```sh
php composer.phar require "webcoder31/ezxmldsig"
```

**NOTE:** As long as the library **ezxmldsig** is still a BETA version you should indicate the desired version tag to avoid **composer** issues due to stability requirements on package installation:

```sh
php composer.phar require "webcoder31/ezxmldsig:<beta-version-tag>" (i.e. v0.1.0-beta)
```

You can also clone it (or download it as a ZIP archive) from its [GitHub repositary](https://github.com/webcoder31/ezxmldsig.git) and load it the way you want in your project. In this case, you will have to do the same from the [**xmlseclib** GitHub repositary](https://github.com/robrichards/xmlseclibs) of Rob Richards.


## What's in the box?

### XMLDSigToken class

The ``XMLDSigToken`` class allows creating and analyzing enveloping XML Digital Signature containing timestamped user data that may also be encrypted, also called XML token. With such tokens, you may create your own Single Sign On solution. You can secure access to your Web Services, as with JSON Web Token. You can transmit data in a secure way without having SSL connection. Or anything you can think of that requires such kind of features.

**The ``XMLDSigToken`` class offers the following features:**

1) It build an XML token from a flat or multidimensional associative array representing the user data and retrieve it in the same way.

2) It allows chossing the various algorithms that should be used to build the XML Digital Signature. The ones used by default are the following:
    * Algorithm used to canonalize data before signing is: http://www.w3.org/TR/2001/REC-xml-c14n-20010315.
    * Algorithm used to generate the signature is: http://www.w3.org/2000/09/xmldsig#rsa-sha1.
    * Algorithm used to compute the hash of contained data is: http://www.w3.org/2000/09/xmldsig#sha1.
    * Algorithm used to encode user data values is: Base64.

3) It is also capable of encrypting / decrypting token data for safe use with an unsecured HTTP connection, providing the same level of security as an SSL connection. 
The class allows chosing the algorithms that should be used to perform data encryption. By default it uses the following ones:
    * Algorithm used to encrypt data is: http://www.w3.org/2001/04/xmlenc#aes128-cbc (symmetric ciphering).
    * Algorithm used to encrypt the session key that will be used to cypher data is: http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p (asymmetric ciphering).

4) It guarantees the integrity and the origin of the user data stored in the XMLDSig token by verifying that:
    * The XML digital signature meets the XMLDSIG specifications.
    * The algorithms used to construct the XML digital signature are those expected.
    * The token contained in the XML digital signature has not been altered.
    * The X.509 certificate included in the XML digital signature is trusted: it is valid at the current date, OpenSSL verifies its chain up to the CA certificates you trust and/or it is the very certificate you pinned, and its subject is the one you expect, if you ask for it (see [Trust anchor](#trust-anchor)).

5) It is also able to verify with confidence that the token is not out of date because the token timestamp is signed too.

6) It gives access to the information of the X.509 certificate included in the XML Digital Signature (subject, issuer, validity dates), and keeps individual checks on it:
    * Ensure that the certificate is not out of date.
    * Check the issuer names of the certificate.
    * Verify that the certificate was issued by a given CA certificate.


### X509Cert class

The ``X509Cert`` class provides a set of convenient methods for extracting essential information contained in an X.509 certificate and for performing some useful checkings, all of them with OpenSSL: whether the certificate was issued by a given CA certificate (``isValidCA()``), whether OpenSSL verifies its chain up to trusted CA certificates (``isTrustedBy()``), whether its key usage allows signing (``canSign()``). This class is used internaly by the ``XMLDSigToken`` class.


### Other classes coming soon...

More classes will be provided soon, in order to support other useful usages of XML Digital Signatures, i.e. signing an internet resource or a mail attachment.


## How to use?

**NOTE:** The library **ezxmldsig** is designed to work with cryptographic material in PEM format.


### XMLDSigToken: Creating a signed XML token

The example below shows basic usage of the ``XMLDSigToken`` class for creating a signed token enveloped in an XML Digital Signature.

To do so, the ``XMLDSigToken`` class requires an assymmetric cryptographic key pair:
* A private key the class will use to sign the token.
* The password that allows reading the private key (Optional - Depends on how the private key was created).
* The X.509 certificate related to the private key that will be included within the XML Digital Signature in order to allow the recipient verifying the token integrity.


#### Source code

```php
// Load required classes manualy.
// require(dirname(__DIR__) . '/vendor/robrichards/xmlseclibs/xmlseclibs.php');
// require(dirname(__DIR__) . '/ezxmldsig.php');

// Autoload required classes.
require dirname(__DIR__) . '/vendor/autoload.php';

// Use statements.
use webcoder31\ezxmldsig\XMLDSigToken;

// Asymmetric cryptographic key pair for signing (in PEM format).
$signKey = 'path/to/signing/private/key';
$signCert = 'path/to/signing/public/certificate';
$signKeyPassword = 'signing-key-password'; // Use null if it is not needed.

// User data.
$data = [
    'name' => 'Ragnar Lothbrock',
    'role' => 'Jarl',
    'location' => 'Kattegat'
];

// Create token for user data.
$token = XMLDSigToken::createXMLToken($data, $signKey, $signCert, $signKeyPassword);

// Get the XML Digital Signature. 
$sig = $token->getXML();

// Display the XML Digital Signature.
echo htmlentities($sig);
```

#### Result

```xml
<?xml version="1.0"?>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
    <ds:Reference URI="#Token">
      <ds:Transforms>
        <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      </ds:Transforms>
      <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <ds:DigestValue>Fg9V0dPJcVniGRZEWLefxuAqU7Y=</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>rmSevcH4 ... WsEX9A==</ds:SignatureValue>
  <ds:KeyInfo>
    <ds:X509Data>
      <ds:X509Certificate>MIIFbTCC ... jb5e4w==</ds:X509Certificate>
    </ds:X509Data>
  </ds:KeyInfo>
  <ds:Object Id="Token">
    <Token>
      <TokenTimestamp>2017-05-20T07:20:49Z</TokenTimestamp>
      <TokenData>
        <name Algorithm="base64">UmFnbmFyIExvdGhicm9jaw==</name>
        <role Algorithm="base64">S2luZyBvZiBWaWNraW5ncw==</role>
        <location Algorithm="base64">S2F0dGVnYXQsIEp5bGxhbmQgKERFTk1BUksp</location>
      </TokenData>
    </Token>
  </ds:Object>
</ds:Signature>
```

### XMLDSigToken: Creating a signed XML token with encrypted user data

The example below shows how to use the ``XMLDSigToken`` class for creating a signed token whose user data will be encrypted.

To do so, the ``XMLDSigToken`` class requires another assymmetric cryptographic key pair in order to perform user data encryption:
* An X.509 certificate whose public key will be used by the class to encrypt a session key that will be used to cypher user data.
* The private key related to the certificate. This key will be used by the class only to verify that it has correctly cyphered the user data once encryption is done. The token recipient must have this key in order to decrypt the user data.
* The password that allows reading the private key (Optional - Depends on how the private key was created).


#### Source code

```php
// Load required classes manualy.
// require(dirname(__DIR__) . '/vendor/robrichards/xmlseclibs/xmlseclibs.php');
// require(dirname(__DIR__) . '/ezxmldsig.php');

// Autoload required classes.
require dirname(__DIR__) . '/vendor/autoload.php';

// Use statements.
use webcoder31\ezxmldsig\XMLDSigToken;

// Asymmetric cryptographic key pair for signing (in PEM format).
$signKey = 'path/to/signing/private/key';
$signCert = 'path/to/signing/public/certificate';
$signKeyPassword = 'signing-key-password'; // Use null if it is not needed.

// Asymmetric cryptographic key pair for crypting (in PEM format).
$cryptKey = 'path/to/crypting/private/key';
$cryptCert = 'path/to/crypting/public/certificate';
$cryptKeyPassword = 'crypting-key-password'; // Use null if it is not needed.

// User data.
$data = [
    'name' => 'Ragnar Lothbrock',
    'role' => 'Jarl',
    'location' => 'Kattegat'
];

// Create token for user data.
$token = XMLDSigToken::createSecureXMLToken($data, $signKey, $signCert, $cryptKey, $cryptCert, $signKeyPassword, $cryptKeyPassword);

// Get the XML Digital Signature.
$sig = $token->getXML();

// Display the XML Digital Signature.
echo htmlentities($sig);
```


#### Result

```xml
<?xml version="1.0"?>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
    <ds:Reference URI="#Token">
      <ds:Transforms>
        <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      </ds:Transforms>
      <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <ds:DigestValue>ownzH5dZ9pjaekEoo/RxiUOLc3w=</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>oJsmcOx6 ... 1whi1w==</ds:SignatureValue>
  <ds:KeyInfo>
    <ds:X509Data>
      <ds:X509Certificate>MIIFbTCC ... jb5e4w==</ds:X509Certificate>
    </ds:X509Data>
  </ds:KeyInfo>
  <ds:Object Id="Token">
    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Content">
      <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
      <ds:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
        <xenc:EncryptedKey>
          <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
          <xenc:CipherData>
            <xenc:CipherValue>N0VUlXCG ... A5wPPw==</xenc:CipherValue>
          </xenc:CipherData>
        </xenc:EncryptedKey>
      </ds:KeyInfo>
      <xenc:CipherData>
        <xenc:CipherValue>9Bj3iB9y ... 5ohEIA==</xenc:CipherValue>
      </xenc:CipherData>
    </xenc:EncryptedData>
  </ds:Object>
</ds:Signature>
```


### XMLDSigToken: Checking an XML token

In the following example, we will assume that we will receive the XML digital signature (in a Base64 coded field of an HTTP POST request) from an approved source that we want to ensure is the issuer. We will extract the signature from the POST request and we will perform all checkings to make sure we can trust the received user data.

The analysis requires a trust anchor, described below: without it, no token is valid.


#### Source code

```php
// Load required classes manualy.
// require(dirname(__DIR__) . '/vendor/robrichards/xmlseclibs/xmlseclibs.php');
// require(dirname(__DIR__) . '/ezxmldsig.php');

// Autoload required classes.
require dirname(__DIR__) . '/vendor/autoload.php';

// Use statements.
use webcoder31\ezxmldsig\XMLDSigToken;

// Get the Base64 encoded XML Digital Signature and decode it.
if (!isset($_POST['xmltoken']))
{
    echo "Can't find XML token in HTTP POST request!";
    exit();
}
$sig = base64_decode($_POST['xmltoken']);

// Private key (and eventualy its passphrase) to be used 
// to decrypt token (required if user data is encrypted).
$cryptKey = 'path/to/crypting/private/key';
$cryptKeyPassword = 'crypting-key-password'; // Use null if it is not needed.

// Trust anchor (required): the CA that issued the signing certificate of the
// sender, and the certificates up to its root. Optionally, the subject the
// signing certificate must have.
$options = [
    'caCertPath' => [
        'path/to/ca/intermediate/certificate',
        'path/to/ca/root/certificate',
    ],
    'expectedSubject' => ['O' => 'Lothbrok Ltd', 'OU' => 'Signature Dept'],
];

// Create token object from the XML Digital Signature 
$token = XMLDSigToken::analyzeSecureXMLToken($sig, $cryptKey, $cryptKeyPassword, $options);

// NOTE: The above instruction works even if user data is not encrypted.
// However, if user data is not encrypted and you don't own a private key 
// then use the following method:
// $token = XMLDSigToken::analyzeXMLToken($sig, $options);

// Verify that:
// - the XML digital signature meets the XMLDSIG specifications.
// - the algorithms used to construct the XML digital signature are those 
//   expected (here, the default ones).
// - the token contained in the XML digital signature has not been altered.
// - the signing certificate is valid at the current date, has been issued
//   by a trusted CA and has the expected subject.
// - the token contained in the XML digital signature is correctly timestamped
//   and contains user data.
if (!$token->isSignatureValid())
{
    echo "ERROR: Invalid XML Digital Signature! " . $token->getError();
    exit();
}

// Verify that the XML token was issued less than 2 minutes ago.
if ($token->isOutOfDate(120)) 
{
    echo "ERROR: Token is out of date!";
    exit();
}

// All is fine ! We can trust user data.
echo "Token data:";
var_dump($token->getData());
```


### Trust anchor

The signature of a token is verified with the X.509 certificate the token carries. Anyone can sign a token with a key pair of their own and a certificate that copies the names (subject, issuer) of a legitimate one: the signature alone proves nothing. The analysis therefore requires a trust anchor, given in its ``$options``, and ``isSignatureValid()`` only returns ``TRUE`` if the certificate of the token is trusted:

* **``caCertPath``** (string or array of strings): PEM files holding the CA certificates you trust. OpenSSL must build and verify the chain of the signing certificate up to a self-signed certificate of these files: signature of each link, validity dates, CA constraints and key usage of each issuer.
* **``signerCertPath``** (string): a PEM certificate the token must be signed with (pinning). Given alone, it is the trust anchor; given with ``caCertPath``, both are required.
* **``expectedSubject``** (array or string, optional): the subject the signing certificate must have. Character case is significant. It does not replace ``caCertPath`` or ``signerCertPath``.
    * As an array, the fields to check, as returned by ``getCertSubject()``: ``['O' => 'Lothbrok Ltd', 'OU' => 'Signature Dept']``. Fields that are not given are not checked.
    * As a string, the full Distinguished Name, compared as is with the one ``getCertDN()`` returns. This is the OpenSSL "oneline" format: every field of the subject, in the order of the certificate, each written ``/<short name>=<value>`` with no space and no escaping:

      ```
      /C=DK/ST=Jylland/L=Kattegat/O=Lothbrok Ltd/OU=Signature Dept/CN=www.lothbrok.dk/emailAddress=ivar@lothbrok.dk
      ```

      It is neither the RFC 2253 form (``CN=...,O=...``) nor the form printed by the ``openssl`` command line (``C=DK, ST=...``): copy it from ``getCertDN()``.

In every case, the signing certificate must be valid at the current date and, if it has a ``keyUsage`` extension, allow ``digitalSignature`` or ``nonRepudiation``.

**Trusting an intermediate CA.** OpenSSL only accepts a chain that ends at a self-signed root. To trust the certificates issued by an intermediate CA, give its certificate **and** the certificates up to its root, as several files or as one file holding them all:

```php
$options = ['caCertPath' => ['path/to/intermediate.cert.pem', 'path/to/root.cert.pem']];
```

With the intermediate certificate alone, every token is rejected and ``getError()`` returns:

```
Signing certificate is not issued by a trusted CA: its chain could not be verified up to the CA certificates of the option 'caCertPath', which must hold the issuing CA and the certificates up to its root!
```

Only the signing certificate is taken from the token, never intermediate certificates: a certificate issued by another intermediate CA of the same root is rejected, since its issuer is not in your files. A certificate issued directly by one of the CA certificates you give (the root included) is accepted: add ``expectedSubject`` to narrow it down.

**Without a trust anchor**, ``isSignatureValid()`` returns ``FALSE`` and ``getError()`` returns ``No trust anchor! Pass the option 'caCertPath' (trusted CA certificates) and/or 'signerCertPath' (pinned signing certificate) to analyze a token: without them, no signing certificate can be trusted.``. An option of the wrong type, or naming a file that cannot be read, throws an exception.

``isCertTrusted()`` tells whether the certificate passed these checks. The individual checks ``isCertOutOfDate()``, ``isValidCertIssuer()`` and ``isValidCertCA()`` remain available, but ``isSignatureValid()`` does not need them. ``isValidCertIssuer()`` only compares names, which any certificate can copy.

When a token is created, it is analyzed right away to check it, with the certificate of its own signing key as trust anchor.

**Upgrading from 0.x.** ``analyzeXMLToken($xml)`` and ``analyzeSecureXMLToken($xml, $cryptKeyPath, $cryptKeyPassword)`` without a trust anchor now reject every token: pass ``caCertPath`` (and/or ``signerCertPath``) in their ``$options``. A call to ``isValidCertCA()`` with the intermediate CA, which used to be the way to check the origin of the certificate, becomes ``'caCertPath' => [intermediate, root]``.

## Examples

Similar examples are provided in the `examples` directory along with cryptographic material.
Simply visit the file `index.html` to see them in action (need to be hosted on an HTTP / PHP server).

**NOTE:** To work out of the box, theses examples require that you've installed the library **ezxmldsig** using **composer**.

The certificates of the examples (`examples/certs/`: a root CA, the intermediate CA that issued the signing and encryption certificates, and these certificates with their keys) are valid for 10 years from their generation. `examples/parse-xml-token.php` trusts the intermediate CA and its root. To issue new ones, run `bin/gen-test-certs --examples`.


## Tests

The PHPUnit test suite runs in Docker, so neither PHP nor PHPUnit has to be installed locally. Requirements: a running Docker daemon (e.g. Docker Desktop, or Colima with the repository under your home directory), `curl` and a POSIX shell.

```
bin/test                        # PHP 7.4, then PHP 8.3
bin/test 8.3                    # one PHP version
bin/test 7.4 -- --filter Secure # arguments after -- go to PHPUnit
```

The script uses the official `php:<version>-cli` images. On first run, it downloads the PHPUnit 9.6 PHAR into `tests/.cache/` (checked against a pinned SHA-256) and, when `vendor/` is missing, runs `composer install` in the `composer:2` image.

Tests that need a feature the current environment lacks are skipped, and PHPUnit prints the reason.

The certificates used by the tests live in `tests/fixtures/certs/`: a root CA, an intermediate CA, signing and encryption certificates issued by the intermediate, and a certificate signed by its own key that copies the subject and issuer names of the signing certificate. Run `bin/gen-test-certs` to generate them again (it runs OpenSSL in the `alpine:3.22` Docker image, whatever OpenSSL the host has). The tests of the trust anchor also issue certificates on the fly (expired, issued by another intermediate CA, issued by a certificate that is not a CA) in a temporary directory removed after each test.


## Documentation

Online documentation is available here : [EZXMLDSIG Documentation](https://webcoder31.github.io/ezxmldsig/).


## How to Contribute?

* [Open Issues](https://github.com/webcoder31/ezxmldsig/issues)
* [Open Pull Requests](https://github.com/webcoder31/ezxmldsig/pulls)
