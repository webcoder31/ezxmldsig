# ezxmldsig for PHP: signed and encrypted XML tokens, and sealed files

> **Documentation: [webcoder31.github.io/ezxmldsig-doc](https://webcoder31.github.io/ezxmldsig-doc/)**
>
> Why ezxmldsig exists, how a token works, a single sign-on, the duties of the receiver, encryption, certificates and keys, interoperability: the concepts of the tokens common to the PHP and Node.js libraries are explained there. The structure of the seals and the rules they follow are in their [design document](https://github.com/webcoder31/ezxmldsig-js/blob/main/design/seal.md). This README covers what is particular to the PHP library.

Built on the library **xmlseclibs** developed by Rob Richards (https://github.com/robrichards/xmlseclibs), the library **ezxmldsig** creates and verifies XML tokens: enveloping XML digital signatures that carry timestamped user data (a PHP associative array), optionally encrypted. Use them for token based authentication, Single Sign On, or to transmit data whose integrity and origin, and confidentiality when they are encrypted, are protected by the token itself. It also seals files, as an **experimental** feature: an ASiC-E container that holds the files and one XAdES signature over them proves who sealed them and that they have not changed since (see [Seals](#seals-experimental)).

A token signs its own content only: the library does not sign existing XML documents in place, nor parts of them; for these, use **xmlseclibs** directly. Files of any kind are signed by the seals, in a container that holds them: to sign a PDF inside the PDF itself, use a PAdES library.

The library exists for Node.js too: [**@webcoder31/ezxmldsig**](https://www.npmjs.com/package/@webcoder31/ezxmldsig) creates and verifies the same tokens and the same seals, with the same options and the same checks, so that a single sign-on can mix PHP and Node.js nodes. Each library reads the tokens and verifies the seals of the other: see [Interoperability](#interoperability) and [Compatible versions](#compatible-versions). The tokens being standard XML digital signatures and XML Encryption, other libraries can also create and read them, such as **xml-crypto** and **xml-encryption** for Node.js, provided the receiver makes the checks **ezxmldsig** makes besides the signature; the seals are validated by DSS, the validator of the European Commission.

The author of the **ezxmldsig** library is Thierry Thiers.


## Contents

* [Requirements](#requirements)
* [Installation](#installation)
* [What's in the box?](#whats-in-the-box)
* [Why?](#why)
* [How does it work?](#how-does-it-work)
* [How to use?](#how-to-use)
    * [Creating a signed XML token](#creating-a-signed-xml-token)
    * [Creating a signed XML token with encrypted user data](#creating-a-signed-xml-token-with-encrypted-user-data)
    * [Checking an XML token](#checking-an-xml-token)
    * [Replay](#replay)
    * [Audience and expiry](#audience-and-expiry)
    * [XML parsing](#xml-parsing)
    * [Trust anchor](#trust-anchor)
    * [Encryption](#encryption)
    * [Certificates and keys](#certificates-and-keys)
    * [Options](#options)
    * [Seals (experimental)](#seals-experimental)
    * [Interoperability](#interoperability)
    * [Compatible versions](#compatible-versions)
    * [Upgrading from 1.x](#upgrading-from-1x)
    * [Upgrading from 0.x](#upgrading-from-0x)
* [Signed token demo](#signed-token-demo)
* [Single sign-on demo](#single-sign-on-demo)
* [Differences with the Node.js library](#differences-with-the-nodejs-library)
* [Tests](#tests)
    * [What is checked, and by whom](#what-is-checked-and-by-whom)
* [Documentation](#documentation)
* [Releasing a version](#releasing-a-version)
* [Security](#security)
* [License](#license)
* [How to Contribute?](#how-to-contribute)


## Requirements

The library **ezxmldsig** requires PHP version 7.4 or greater, with the OpenSSL extension, and the library **xmlseclibs** developed by Rob Richards, version ^3.1.5 (3.1.5 or a later 3.x version). The seals also need the zlib extension; with the intl extension, the names of their files are compared in Unicode normalization form C, and as bytes without it (see [Seals](#seals-experimental)).

The [signed token demo](#signed-token-demo), the [single sign-on demo](#single-sign-on-demo) and the [tests](#tests) are not part of the Composer package and have their own requirements (a running Docker daemon).


## Installation

The library **ezxmldsig** is available on [Packagist](https://packagist.org/packages/webcoder31/ezxmldsig) and you can install it for your project with [`composer.phar`](http://getcomposer.org).


```sh
php composer.phar require "webcoder31/ezxmldsig"
```

To stay on the 1.x versions (no backward-incompatible change), pin the major version:

```sh
php composer.phar require "webcoder31/ezxmldsig:^1.0"
```

You can also clone it (or download it as a ZIP archive) from its [GitHub repository](https://github.com/webcoder31/ezxmldsig-php.git) and load it the way you want in your project. In this case, you will have to do the same from the [**xmlseclibs** GitHub repository](https://github.com/robrichards/xmlseclibs) of Rob Richards.


## What's in the box?

The library has three branches, each in its own namespace: the tokens, ``webcoder31\ezxmldsig\token`` (``XMLDSigToken``); the seals of files, ``webcoder31\ezxmldsig\seal`` (``Seal``, **experimental**, see [Seals](#seals-experimental)); and the core they are built on, ``webcoder31\ezxmldsig\core`` (``X509Cert``, and the identifiers of the algorithms of XML Signature in ``Algorithms``). The classes marked ``@internal`` serve the branches of the library only.

**``XMLDSigToken``** creates and analyzes XML tokens:

1. It builds a token from user data (a flat or multidimensional associative array) and reads them back the same way.
2. It lets you choose the algorithms of the signature (see [Options](#options)). By default: inclusive canonicalization (http://www.w3.org/TR/2001/REC-xml-c14n-20010315), RSA-SHA256 and an SHA-256 digest; the values of the data are encoded in Base64.
3. It encrypts and decrypts the token data, so that only the recipient can read them, even when the token travels over an unencrypted connection: AES-256-GCM for the data and RSA-OAEP for the session key by default. Only the token data are encrypted: this protects neither the rest of the request nor the response, does not authenticate the server, and does not prevent an intercepted token from being submitted again (see [Replay](#replay)).
4. It guarantees the integrity and the origin of the data by verifying that the signature has the structure of a token, that its algorithms are the expected ones, that the token has not been altered, and that the X.509 certificate of the token is trusted (see [Trust anchor](#trust-anchor)).
5. Each token holds a signed timestamp and a signed random identifier, so that the receiver can refuse a token that is too old or already accepted (see [Replay](#replay)). These two checks are up to the receiver: ``isSignatureValid()`` makes neither.
6. It gives access to the information of the certificate of the token: subject, issuer, validity dates.
7. It refuses, before parsing them, the XML documents that have a document type declaration (see [XML parsing](#xml-parsing)), and its HTML output (``getHTMLDump()``) escapes every value it shows and loads no external resource.

**``X509Cert``** reads an X.509 certificate (subject, issuer, Distinguished Name, validity dates, fingerprint) and makes the checks the analysis needs, all of them with OpenSSL: its key usage (``canSign()``), its chain up to trusted CA certificates (``isTrustedBy()``), whether a given CA certificate issued it (``isValidCA()``). For the seals, ``getTrustedChain()`` builds and verifies the chain at a given date, the time of a time-stamp, with the rules ``isTrustedBy()`` applies at the current date: OpenSSL verifies the signature of each link, and the chain is built from the certificates read in DER.

**``Seal``** seals files and verifies seals: an ASiC-E container (ETSI EN 319 162-1) that holds the files and one detached XAdES baseline signature over them (ETSI EN 319 132-1), at level B, T (a signature time-stamp, RFC 3161) or LT (the certificates, CRLs and OCSP responses that validate it, embedded). The Node.js library makes and verifies the same seals, and DSS, the validator of the European Commission, validates them.

The token protects its own content only: not the request that carries it (URL, headers, other fields), nor the response, nor the identity of the server it is sent to. Use an HTTPS connection for these.


## Why?

A signature proves that the data of a token were not changed; what matters most is to prove **who issued it**. A receiver accepts a token only if its signing certificate descends, through a chain of trust, from the CA certificates it declares and, when it asks for it, has the subject it expects or is the very certificate it pinned (see [Trust anchor](#trust-anchor)).

**The tokens do not check revocation**: for them, the library consults neither certificate revocation lists (CRL) nor OCSP responders, so a revoked certificate is accepted until it expires. The seals check it (see [Seals](#seals-experimental)). What to do when a key leaks, signing key, CA key or decryption key: see [When a key is compromised](https://webcoder31.github.io/ezxmldsig-doc/certificates/#when-a-key-is-compromised) on the documentation site.

The chain of trust, a root of a company's own for an internal single sign-on, and why this library exists: see [Why?](https://webcoder31.github.io/ezxmldsig-doc/why/) on the documentation site.


## How does it work?

A token is an enveloping XML digital signature: the node ``Token`` holds the user data, a timestamp and a random identifier; its digest is written in ``ds:SignedInfo``, which the sender signs with its private key; its certificate travels in ``ds:KeyInfo``. The receiver answers three questions: were the data changed (the digest), is the seal intact (the signature), and who sealed it (the trust in the certificate). The last one decides: an attacker who alters the data and signs them again with a key of their own passes the first two.

``isSignatureValid()`` also checks the algorithms and the audience; **the freshness, the expiry and the replay are up to the receiver** (see [Checking an XML token](#checking-an-xml-token)).

A token block by block, each check and the attack it stops: see [How does it work?](https://webcoder31.github.io/ezxmldsig-doc/how-it-works/) on the documentation site. The [signed token demo](#signed-token-demo) plays these checks out on real tokens, and replays the attacks the library rejects.


## How to use?

**NOTE:** The library **ezxmldsig** is designed to work with cryptographic material in PEM format.

To see it work before writing any code, open the [signed token demo](#signed-token-demo) online (https://ezxmldsig.wbcdr.dev/) or run it on your machine (`bin/demo`): it creates, explains and verifies tokens, and replays the attacks the library refuses.


### Creating a signed XML token

The example below shows basic usage of the ``XMLDSigToken`` class for creating a signed token enveloped in an XML Digital Signature.

To do so, the ``XMLDSigToken`` class requires an asymmetric cryptographic key pair:
* A private key the class will use to sign the token.
* The password that allows reading the private key (Optional - Depends on how the private key was created).
* The X.509 certificate related to the private key that will be included within the XML Digital Signature in order to allow the recipient to verify the token integrity.


#### Source code

```php
// Load required classes manually.
// require(dirname(__DIR__) . '/vendor/robrichards/xmlseclibs/xmlseclibs.php');
// require(dirname(__DIR__) . '/ezxmldsig.php');

// Autoload required classes.
require dirname(__DIR__) . '/vendor/autoload.php';

// Use statements.
use webcoder31\ezxmldsig\token\XMLDSigToken;

// Asymmetric cryptographic key pair for signing (in PEM format).
$signKey = 'path/to/signing/private/key';
$signCert = 'path/to/signing/public/certificate';
$signKeyPassword = 'signing-key-password'; // Use null if it is not needed.

// User data.
$data = [
    'name' => 'Ragnar Lothbrok',
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

The result below was produced by this code with the certificates of `demo/certs/`, then indented and its long Base64 values shortened to their first and last 8 characters. The user data are Base64 encoded: ``UmFnbmFyIExvdGhicm9r`` is ``Ragnar Lothbrok``.

```xml
<?xml version="1.0"?>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference URI="#Token">
      <ds:Transforms>
        <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      </ds:Transforms>
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      <ds:DigestValue>8TdHTRsJ ... FpKRsBk=</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>ANXIS2CZ ... CF/GYw==</ds:SignatureValue>
  <ds:KeyInfo>
    <ds:X509Data>
      <ds:X509Certificate>MIIFMTCC ... tV4guQ==</ds:X509Certificate>
    </ds:X509Data>
  </ds:KeyInfo>
  <ds:Object Id="Token">
    <Token>
      <TokenTimestamp>2026-10-17T06:58:55Z</TokenTimestamp>
      <TokenId>9e0325fac353152dd7c241a719da0f72</TokenId>
      <TokenData>
        <name Algorithm="base64">UmFnbmFyIExvdGhicm9r</name>
        <role Algorithm="base64">SmFybA==</role>
        <location Algorithm="base64">S2F0dGVnYXQ=</location>
      </TokenData>
    </Token>
  </ds:Object>
</ds:Signature>
```

### Creating a signed XML token with encrypted user data

The example below shows how to use the ``XMLDSigToken`` class for creating a signed token whose user data will be encrypted.

To do so, the ``XMLDSigToken`` class requires the encryption certificate of the recipient: an X.509 certificate whose public key will be used by the class to encrypt a session key that will be used to encrypt user data. Only the private key related to this certificate, which the recipient keeps, can decrypt the user data.

The sender does not need this private key: pass ``null`` in its place (the fourth parameter of ``createSecureXMLToken()``), as below. The created token is then checked right away up to its decryption: its structure, its algorithms, its digest, its signature and the trust in the signing certificate. ``isSignatureValid()`` and ``isDataEncrypted()`` return ``TRUE``, while ``getData()``, ``getTimestamp()``, ``getTokenId()``, ``getAudience()`` and ``getExpiry()`` return ``NULL``: they are inside the encrypted content, which is not decrypted.

When the sender does hold this private key (for instance, when it encrypts tokens for itself), it can pass it, with its password (or ``null``) as seventh parameter: the created token is then also decrypted and its content checked, and ``getData()``, ``getTimestamp()``, ``getTokenId()``, ``getAudience()`` and ``getExpiry()`` return what it holds.


#### Source code

```php
// Load required classes manually.
// require(dirname(__DIR__) . '/vendor/robrichards/xmlseclibs/xmlseclibs.php');
// require(dirname(__DIR__) . '/ezxmldsig.php');

// Autoload required classes.
require dirname(__DIR__) . '/vendor/autoload.php';

// Use statements.
use webcoder31\ezxmldsig\token\XMLDSigToken;

// Asymmetric cryptographic key pair for signing (in PEM format).
$signKey = 'path/to/signing/private/key';
$signCert = 'path/to/signing/public/certificate';
$signKeyPassword = 'signing-key-password'; // Use null if it is not needed.

// Encryption certificate of the recipient (in PEM format). Its private key
// stays with the recipient.
$cryptCert = 'path/to/encryption/public/certificate';

// User data.
$data = [
    'name' => 'Ragnar Lothbrok',
    'role' => 'Jarl',
    'location' => 'Kattegat'
];

// Create token for user data, without the private key of the recipient
// (null).
$token = XMLDSigToken::createSecureXMLToken($data, $signKey, $signCert, null, $cryptCert, $signKeyPassword);

// Get the XML Digital Signature.
$sig = $token->getXML();

// Display the XML Digital Signature.
echo htmlentities($sig);
```


#### Result

The result below was produced by this code with the certificates of `demo/certs/`, then indented and its long Base64 values shortened to their first and last 8 characters. The user data, the timestamp and the identifier of the token are in the last ``xenc:CipherValue``, encrypted.

```xml
<?xml version="1.0"?>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference URI="#Token">
      <ds:Transforms>
        <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      </ds:Transforms>
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      <ds:DigestValue>SiYOh23w ... TBgPfRA=</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>rN234Axi ... FBh6aA==</ds:SignatureValue>
  <ds:KeyInfo>
    <ds:X509Data>
      <ds:X509Certificate>MIIFMTCC ... tV4guQ==</ds:X509Certificate>
    </ds:X509Data>
  </ds:KeyInfo>
  <ds:Object Id="Token">
    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">
      <xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
      <ds:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
        <xenc:EncryptedKey>
          <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
          <xenc:CipherData>
            <xenc:CipherValue>pcZ/cEMe ... IHhH9g==</xenc:CipherValue>
          </xenc:CipherData>
        </xenc:EncryptedKey>
      </ds:KeyInfo>
      <xenc:CipherData>
        <xenc:CipherValue>lOKmB8Fv ... QFJ3MpQ=</xenc:CipherValue>
      </xenc:CipherData>
    </xenc:EncryptedData>
  </ds:Object>
</ds:Signature>
```


### Checking an XML token

In the following example, we will assume that we will receive the XML digital signature (in a Base64 coded field of an HTTP POST request) from an approved source that we want to ensure is the issuer. We will extract the signature from the POST request and we will perform all the checks needed to make sure we can trust the received user data.

The analysis requires a trust anchor, described below: without it, no token is valid.

**``isSignatureValid()`` checks neither the freshness of the token nor whether it is replayed.** A token that was valid once stays valid for it, however old it is and however many times it is submitted. Before trusting the data of a received token, the receiver must make three checks, as the example below does:

1. ``isSignatureValid()`` returns ``TRUE``: structure, algorithms, digest, signature, trust in the signing certificate, and audience when the token names one (see [Audience and expiry](#audience-and-expiry));
2. ``isOutOfDate($ttl)`` returns ``FALSE``, for the time to live the application accepts, and the expiry of the token if it has one (freshness);
3. the identifier returned by ``getTokenId()`` has not been accepted before: store it atomically, and refuse the token if it already is (replay, see [Replay](#replay)).

**Restrict the trust anchor to the sender.** ``caCertPath`` accepts any certificate its CA issues. As soon as this CA also issues certificates to others than the expected sender (a public CA, or a company CA that issues one per server or per partner), any of them can sign a token that ``isSignatureValid()`` accepts: add ``expectedSubject`` (the subject of the certificate of the sender), or pin the certificate of the sender with ``signerCertPath`` (see [Trust anchor](#trust-anchor)).


#### Source code

```php
// Load required classes manually.
// require(dirname(__DIR__) . '/vendor/robrichards/xmlseclibs/xmlseclibs.php');
// require(dirname(__DIR__) . '/ezxmldsig.php');

// Autoload required classes.
require dirname(__DIR__) . '/vendor/autoload.php';

// Use statements.
use webcoder31\ezxmldsig\token\XMLDSigToken;

// Get the Base64 encoded XML Digital Signature and decode it.
if (!isset($_POST['xmltoken']))
{
    echo "Can't find XML token in HTTP POST request!";
    exit();
}
$sig = base64_decode($_POST['xmltoken']);

// Private key (and possibly its passphrase) to be used
// to decrypt token (required if user data is encrypted).
$cryptKey = 'path/to/decryption/private/key';
$cryptKeyPassword = 'decryption-key-password'; // Use null if it is not needed.

// Trust anchor (required): the CA that issued the signing certificate of the
// sender, and the certificates up to its root. The subject the signing
// certificate must have restricts it to the sender: the CA may also issue
// certificates to others.
$options = [
    'caCertPath' => [
        'path/to/ca/intermediate/certificate',
        'path/to/ca/root/certificate',
    ],
    'expectedSubject' => ['O' => 'Lothbrok Ltd', 'OU' => 'Signature Dept'],
];

// Create token object from the XML Digital Signature.
$token = XMLDSigToken::analyzeSecureXMLToken($sig, $cryptKey, $cryptKeyPassword, $options);

// NOTE: The above instruction works even if user data is not encrypted.
// However, if user data is not encrypted and you don't own a private key
// then use the following method:
// $token = XMLDSigToken::analyzeXMLToken($sig, $options);

// Check 1 of 3. Verify that:
// - the XML digital signature has the structure of an XML token.
// - the algorithms used to construct the XML digital signature are those
//   expected (here, the default ones).
// - the token contained in the XML digital signature has not been altered.
// - the signing certificate is valid at the current date, has been issued
//   by a trusted CA and has the expected subject.
// - the token contained in the XML digital signature is correctly timestamped
//   and contains user data.
// It checks neither the freshness of the token nor whether it is replayed:
// see the two checks that follow.
if (!$token->isSignatureValid())
{
    // The error may quote what the token holds: escape it.
    echo "ERROR: Invalid XML Digital Signature! " . htmlspecialchars($token->getError(), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    exit();
}

// Check 2 of 3: verify that the XML token was issued less than 2 minutes
// ago.
if ($token->isOutOfDate(120))
{
    echo "ERROR: Token is out of date!";
    exit();
}

// Check 3 of 3: refuse a token already accepted (see Replay below). apcu_add() only adds
// the identifier if it is not stored yet, and keeps it for as long as the
// token could be accepted: 120 seconds of validity plus the clock tolerance.
if (!apcu_add('xmltoken-' . $token->getTokenId(), true, 120 + XMLDSigToken::DESYNC_TOLERANCE))
{
    echo "ERROR: Token already used!";
    exit();
}

// All is fine! We can trust user data.
echo "Token data:";
echo '<pre>' . htmlspecialchars(print_r($token->getData(), true), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</pre>';
```


### Replay

A valid token can be submitted again, by whoever intercepted it, for as long as ``isOutOfDate()`` accepts it. **The library keeps no list of the tokens it has analyzed**: refusing a token already accepted is up to the receiver.

Each token holds an identifier of 128 random bits (``random_bytes()``), written in hexadecimal in the node ``Token/TokenId`` and covered by the signature: altering it invalidates the token. ``getTokenId()`` returns it (32 hexadecimal characters) for a valid token only, and ``NULL`` otherwise. The receiver must:

* store the identifier of each token it accepts, atomically with the check that it is not stored yet (``apcu_add()``, a unique key in a database, ``SET NX`` in Redis...), in a store shared by all the servers that receive the tokens;
* refuse a token whose identifier is already stored;
* keep each identifier at least as long as the token can be accepted. ``isOutOfDate($ttl)`` accepts a token from ``XMLDSigToken::DESYNC_TOLERANCE`` seconds (30) before its timestamp to ``$ttl`` seconds after it: keep the identifier ``$ttl + XMLDSigToken::DESYNC_TOLERANCE`` seconds after accepting the token.

A token without identifier, as created by the 0.x versions, is rejected (``Token identifier is missing!``): the receiver could not tell it from a replayed one. So is a token whose identifier is not 32 lowercase hexadecimal characters (``Token identifier is malformed!``).

Why a receiver must check freshness, expiry, replay and audience, and the mistakes to avoid when storing the identifiers: see [The receiver's duties](https://webcoder31.github.io/ezxmldsig-doc/receiver/) on the documentation site.


### Audience and expiry

Available since version 1.1.

A token signed by a trusted issuer is valid for **every** receiver that trusts this issuer: a token issued for one application is accepted by another one, unless the token says who it is addressed to. Two creation options, both covered by the signature, address this, with the matching checks at analysis.

**Audience.** The option ``audience`` (a string, or a list of strings) names the receivers the token is addressed to: application names, URLs, any value the issuer and each receiver agree on. Each receiver gives its own with ``expectedAudience``, and ``isSignatureValid()`` checks it:

| Token | ``expectedAudience`` given | ``expectedAudience`` not given |
|---|---|---|
| Names audiences | Valid only if one of them is ``expectedAudience`` (compared as is, case included) | **Rejected**: a receiver that does not say who it is cannot accept a token addressed to someone |
| Names no audience | **Rejected**: the receiver asked for a token addressed to it | Valid, as in 1.0 |

```php
// The issuer addresses the token to the application "crm"...
$token = XMLDSigToken::createXMLToken($data, $signKey, $signCert, $signKeyPassword, [
    'audience' => 'crm',
    'validity' => 60,
]);

// ...which accepts it, while the application "mail" rejects it.
$token = XMLDSigToken::analyzeXMLToken($sig, [
    'caCertPath' => ['path/to/ca/intermediate/certificate', 'path/to/ca/root/certificate'],
    'expectedAudience' => 'crm',
]);
```

A rejected token gives the reason in ``getError()``, e.g. ``Token is not addressed to the expected audience! Expected: 'mail'. Token audience: 'crm'.``, and its data are not read. ``getAudience()`` returns the audiences of a valid token, ``NULL`` otherwise. An audience is a non-empty string, without surrounding white space or control characters: an option that breaks these rules throws an exception.

**Expiry.** The option ``validity`` (a number of seconds) writes in the token the date after which it is out of date. ``isOutOfDate($ttl)`` then rejects the token once this date is passed, whatever ``$ttl``: the shorter of the validity set by the issuer and the time to live set by the receiver applies. Like the time to live, the expiry is a check left to the caller: ``isSignatureValid()`` does not make it. ``getExpiry()`` returns the expiry of a valid token (format ``YYYY-MM-DDThh:mm:ssZ``, UTC), ``NULL`` otherwise. A token whose expiry is malformed, repeated or not after its timestamp is not valid.

Keep the identifiers stored against replay (see [Replay](#replay)) as long as the time to live of the receiver requires: the expiry can only shorten it.

**Compatibility with 1.0.** The audiences are in the nodes ``Token/TokenAudience`` and the expiry in ``Token/TokenExpiry``. Version 1.0 ignores these nodes: **a receiver still in 1.0 accepts a token addressed to another receiver, and a token whose expiry is passed**, applying only its own time to live. Upgrade every receiver before relying on these options. Tokens without audience nor expiry, those of 1.0 included, are analyzed as before.


### XML parsing

A document type declaration (``<!DOCTYPE ...>``) declares entities, which the XML parser expands where the document references them: nested entities make a small document grow to gigabytes, and external entities read local files or URLs. A token never has one: the analysis, like ``XMLDSigToken::alterXML()``, refuses any document holding ``<!DOCTYPE`` before parsing it (``XML Digital Signature must not have a document type declaration (DOCTYPE)!``).

This check reads the bytes of the document, which only show ``<!DOCTYPE`` as is in UTF-8, the encoding of the tokens. A document in another encoding is therefore refused too (``XML Digital Signature must be encoded in UTF-8!``): one that holds a NUL byte (UTF-16, UTF-32) or declares another encoding. The documents are parsed with ``LIBXML_NONET`` (no network access), and any XML error rejects them, without PHP warning.


### Trust anchor

The signature of a token is verified with the X.509 certificate the token carries. Anyone can sign a token with a key pair of their own and a certificate that copies the names (subject, issuer) of a legitimate one: the signature alone proves nothing. The analysis therefore requires a trust anchor, given in its ``$options``, and ``isSignatureValid()`` only returns ``TRUE`` if the certificate of the token is trusted:

* **``caCertPath``** (string or array of strings): PEM files holding the CA certificates you trust. OpenSSL must build and verify the chain of the signing certificate up to a self-signed certificate of these files: signature of each link, validity dates, CA constraints and key usage of each issuer.
* **``signerCertPath``** (string): a PEM certificate the token must be signed with (pinning). Given alone, it is the trust anchor; given with ``caCertPath``, both are required.
* **``expectedSubject``** (array or string, optional): the subject the signing certificate must have. Character case is significant. It does not replace ``caCertPath`` or ``signerCertPath``. **Give it, or ``signerCertPath``, whenever the CA of ``caCertPath`` also issues certificates to others than the expected sender**: without it, any certificate of this CA is accepted.
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

Only the signing certificate is taken from the token, never intermediate certificates: a certificate issued by another intermediate CA of the same root is rejected, since its issuer is not in your files. A certificate issued directly by one of the CA certificates you give (the root included) is accepted: add ``expectedSubject`` to narrow it down to the sender.

**Without a trust anchor**, ``isSignatureValid()`` returns ``FALSE`` and ``getError()`` returns ``No trust anchor! Pass the option 'caCertPath' (trusted CA certificates) and/or 'signerCertPath' (pinned signing certificate) to analyze a token: without them, no signing certificate can be trusted.``. An option of the wrong type, or naming a file that cannot be read, throws an exception.

``isCertTrusted()`` tells whether the certificate passed these checks. The individual checks ``isCertOutOfDate()``, ``isValidCertIssuer()`` and ``isValidCertCA()`` remain available, but ``isSignatureValid()`` does not need them. ``isValidCertIssuer()`` only compares names, which any certificate can copy.

When a token is created, it is analyzed right away to check it, with the certificate of its own signing key as trust anchor. An encrypted token created without the private key of the recipient is checked up to its decryption (see [Encryption](#encryption)).


### Encryption

The token data are encrypted with a session key generated for each token, and the session key is encrypted for the recipient with the encryption certificate (key transport). The encryption takes place before the signature, which therefore covers the encrypted data.

* **The sender needs no private key of the recipient.** ``createSecureXMLToken()`` takes the private key of the recipient (``$cryptKeyPath``) only to decrypt the created token and check its content: pass ``null`` instead, and the created token is checked up to its decryption (structure, algorithms, digest, signature, trust in the signing certificate), its content left unread (``getData()``, ``getTimestamp()``, ``getTokenId()``, ``getAudience()`` and ``getExpiry()`` return ``NULL``). A password (``$cryptKeyPassword``) given without this key throws an exception.

* **Default algorithms.** The data are encrypted with AES-256-GCM (``AES256_GCM``) and the session key with RSA-OAEP (``RSA_OAEP_MGF1P``, http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p). AES-GCM checks an authentication tag before returning any data: altered data are rejected as a whole. A 256-bit key costs no more than a 128-bit one for data of this size.
* **Type of the encrypted data.** Since version 1.2, the node ``xenc:EncryptedData`` replaces the node ``Token`` and declares the type http://www.w3.org/2001/04/xmlenc#Element: an element is encrypted, as other XML Encryption libraries declare it (xml-encryption for Node.js among them). The analysis reads both types XML Encryption 1.1 defines for an XML plaintext, ``Element`` and ``Content``, as the standard requires, and refuses any other. The plaintext is read as an XML fragment whatever its type, so that it cannot hold a document type declaration (see [XML parsing](#xml-parsing)). Versions up to 1.1 declared ``Content`` (the content of ``ds:Object``) for the same encrypted bytes, and refuse ``Element`` (``Encrypted data is malformed!``): upgrade the receivers before the senders.
* **Decryption after verification.** A token is only decrypted once its digest, its signature, the trust in its certificate (see [Trust anchor](#trust-anchor)) and its algorithms have been verified.
* **One error for every decryption failure.** Whatever fails once the decryption starts (session key, data, parsing of the decrypted XML), ``getError()`` returns ``Token decryption failed!``, with no reason, no anomaly and no PHP warning. Failures that do not depend on the encrypted content keep their own message (no decryption key, a key that cannot be loaded, a malformed ``xenc:EncryptedData``).
* **RSA 1.5 is refused.** The key transport algorithm http://www.w3.org/2001/04/xmlenc#rsa-1_5 is accepted neither at creation nor at analysis, and no option allows it. ezxmldsig always used RSA-OAEP by default; tokens created with RSA 1.5 on purpose must be created again with RSA-OAEP.
* **CBC is accepted only when declared.** AES-CBC and Triple DES CBC (``AES128_CBC``, ``AES192_CBC``, ``AES256_CBC``, ``TRIPLEDES_CBC``) have no integrity. An analysis decrypts a CBC token only if its option ``sessionKeyCipheringAlgorithm`` names this very algorithm, even when ``checkCryptingAlgorithms`` is ``FALSE``. Declare it only to read tokens of peers that cannot use AES-GCM yet:

  ```php
  $options = [
      'caCertPath' => ['path/to/ca/intermediate/certificate', 'path/to/ca/root/certificate'],
      'sessionKeyCipheringAlgorithm' => XMLDSigToken::AES128_CBC,
  ];
  $token = XMLDSigToken::analyzeSecureXMLToken($sig, $cryptKey, $cryptKeyPassword, $options);
  ```

What encryption protects and what it does not, and the attacks these choices stop (padding oracles, Bleichenbacher's attack on RSA 1.5, Jager and Somorovsky's attack on CBC): see [Encryption](https://webcoder31.github.io/ezxmldsig-doc/encryption/) on the documentation site.


### Certificates and keys

A token involves up to three kinds of certificates, all X.509 certificates in PEM format with **RSA keys**: the signing certificate of the sender, the CA certificates the recipient trusts (``caCertPath``), and, for encrypted tokens, the encryption certificate of the recipient. EC and DSA keys are not supported. A signing key of another type is refused: at creation (``The signing key is not an RSA key``), and at analysis, where the signature of a certificate whose key is not an RSA key is not verified (``Token hash signature verification failed!``). These rules are those of the tokens: the seals take RSA keys of 2048 bits or more, and EC keys on P-256, P-384 and P-521 (see [Seals](#seals-experimental)).

The signing certificate must be valid at the current date and, if it has a ``keyUsage`` extension, allow ``digitalSignature`` or ``nonRepudiation``. With ``caCertPath``, OpenSSL also checks every certificate of the chain: validity dates, signature, and, for each issuer, ``basicConstraints`` with ``CA:TRUE`` and a ``keyUsage`` that allows ``keyCertSign`` (see [Trust anchor](#trust-anchor)).

``expectedSubject`` takes the fields of the subject as an array, ``['O' => 'Lothbrok Ltd', 'OU' => 'Signature Dept']``; a field repeated in the subject (two ``OU``, for instance) is an array of its values in ``getCertSubject()``. A private key protected by a password is read with that password (``$signKeyPassword``, ``$cryptKeyPassword``). ``bin/gen-test-certs`` creates the certificates of the tests and of the demo.

Who holds which key, what is checked, the fields of a subject, and the OpenSSL commands that create a root CA, an intermediate CA, a signing and an encryption certificate: see [Certificates and keys](https://webcoder31.github.io/ezxmldsig-doc/certificates/) on the documentation site.


### Options

Each factory takes an associative array ``$options`` as its last parameter. Each option applies to a context: token creation (``createXMLToken()``, ``createSecureXMLToken()``), token analysis (``analyzeXMLToken()``, ``analyzeSecureXMLToken()``) or both. The encryption options only apply when an encryption certificate (``createSecureXMLToken()``) or a decryption key (``analyzeSecureXMLToken()``) is given. An unknown option (a misspelt name, for instance), an option given out of its context, or an option whose value is ``NULL`` or invalid throws an exception: none is ignored.

| Option | Context | Type | Default |
|---|---|---|---|
| ``base64Encode`` | creation | boolean | ``TRUE`` |
| ``xmldsigNsPrefix`` | creation | string (``''``: no prefix) | ``'ds'`` |
| ``canonicalizationAlgorithm`` | creation and analysis | string | ``C14N`` |
| ``signatureAlgorithm`` | creation and analysis | string | ``RSA_SHA256`` |
| ``digestAlgorithm`` | creation and analysis | string | ``SHA256`` |
| ``checkSigningAlgorithms`` | analysis | boolean | ``TRUE`` |
| ``caCertPath``, ``signerCertPath``, ``expectedSubject`` | analysis | see [Trust anchor](#trust-anchor) | none |
| ``audience`` | creation | string or list of strings, see [Audience and expiry](#audience-and-expiry) | none |
| ``validity`` | creation | integer (seconds), see [Audience and expiry](#audience-and-expiry) | none |
| ``expectedAudience`` | analysis | string, see [Audience and expiry](#audience-and-expiry) | none |
| ``sessionKeyCipheringAlgorithm`` | encryption: creation with an encryption certificate, analysis with a decryption key | string | ``AES256_GCM`` |
| ``cryptAlgorithm`` | encryption: creation with an encryption certificate, analysis with a decryption key | string | ``RSA_OAEP_MGF1P`` |
| ``checkCryptingAlgorithms`` | analysis with a decryption key | boolean | ``TRUE`` |

The algorithms are given with the constants of the ``XMLDSigToken`` class (e.g. ``XMLDSigToken::RSA_SHA512``), whose values are the URIs of the XMLDSIG and XML Encryption specifications. Each algorithm option only accepts the algorithms of its own list:

* ``canonicalizationAlgorithm``: ``C14N``, ``C14N_COMMENTS``, ``EXC_C14N``, ``EXC_C14N_COMMENTS``.
* ``signatureAlgorithm``: ``RSA_SHA1``, ``RSA_SHA256``, ``RSA_SHA384``, ``RSA_SHA512``.
* ``digestAlgorithm``: ``SHA1``, ``SHA256``, ``SHA384``, ``SHA512``, ``RIPEMD160``.
* ``sessionKeyCipheringAlgorithm`` (symmetric encryption of the token data): ``AES128_GCM``, ``AES192_GCM``, ``AES256_GCM``, and the algorithms without integrity ``TRIPLEDES_CBC``, ``AES128_CBC``, ``AES192_CBC``, ``AES256_CBC``, which an analysis only accepts when this option names them (see [Encryption](#encryption)).
* ``cryptAlgorithm`` (encryption of the session key with the encryption certificate, or key transport): ``RSA_OAEP_MGF1P``. RSA 1.5 is refused (see [Encryption](#encryption)).

Signature and key transport algorithms are both asymmetric, but a key transport algorithm is refused as a signature algorithm, and the reverse, whether given as an option or read from a token.

At creation, the algorithm options are the algorithms the token is built with. At analysis, they are the algorithms the token must have been built with: a token built with other algorithms is rejected, and ``getError()`` names them (``Unauthorized Signature algorithm! Expected: ..., Used: ...``). ``checkSigningAlgorithms`` (signature, digest, canonicalization) and ``checkCryptingAlgorithms`` (session key, key transport) set to ``FALSE`` turn this check off; an algorithm out of the lists above is rejected all the same, and so is an undeclared CBC algorithm.

```php
// Create a token signed with RSA-SHA512 and an SHA-512 digest...
$token = XMLDSigToken::createXMLToken($data, $signKey, $signCert, $signKeyPassword, [
    'signatureAlgorithm' => XMLDSigToken::RSA_SHA512,
    'digestAlgorithm' => XMLDSigToken::SHA512,
]);

// ...and analyze it, expecting these algorithms.
$token = XMLDSigToken::analyzeXMLToken($sig, [
    'caCertPath' => ['path/to/ca/intermediate/certificate', 'path/to/ca/root/certificate'],
    'signatureAlgorithm' => XMLDSigToken::RSA_SHA512,
    'digestAlgorithm' => XMLDSigToken::SHA512,
]);
```


### Seals (experimental)

A seal proves who sealed files, and that they have not changed since: contracts, PDF, text or Markdown files, any file. ``Seal::createSeal()`` writes an ASiC-E container (``.asice``, a ZIP archive) that holds the files, a manifest, and a XAdES signature of level B over them; ``Seal::verifySeal()`` verifies one. The seals are those of the Node.js library [@webcoder31/ezxmldsig](https://github.com/webcoder31/ezxmldsig-js#readme), whose design document, [design/seal.md](https://github.com/webcoder31/ezxmldsig-js/blob/main/design/seal.md), gives the structure and the rules followed. Each library verifies the seals of the other, and DSS validates the seals of both, at levels B, T and LT.

The seals are an **experimental** feature of the 2.x versions: their API may change in a minor version.

```php
use webcoder31\ezxmldsig\seal\Seal;

$container = Seal::createSeal(
    [
        ['name' => 'contract.pdf', 'content' => file_get_contents('contract.pdf')],
        ['name' => 'annexes/prices.csv', 'content' => file_get_contents('prices.csv')],
    ],
    'path/to/signing/key.pem',
    'path/to/signing/certificate.pem',
    'key password',
    ['chain' => ['path/to/intermediate/ca/certificate.pem']]
);
file_put_contents('contract.asice', $container);

$verification = Seal::verifySeal(file_get_contents('contract.asice'), [
    'caCertPath' => 'path/to/root/ca/certificate.pem',
    'crls' => [$crlOfTheIntermediateCa, $crlOfTheRootCa],
]);
if (!$verification->isValid()) {
    reject($verification->getError());
}
// $verification->getFiles(), getSigningCertificate(), getLevel(), getSigningTime()...
```

* **Algorithms.** An RSA key signs with RSA-PSS by default (SHA-256, the salt as long as the digest), an EC key with ECDSA on P-256, P-384 or P-521; RSA PKCS#1 v1.5 remains available (``'signatureAlgorithm'``), and accepted at verification. RSA keys of less than 2048 bits are refused, and so are SHA-1 and MD5. The OpenSSL extension of PHP signs with PKCS#1 v1.5 only: the encoding of RSA-PSS (RFC 8017, 9.1) is written by the library, over the raw RSA operation of OpenSSL, and its tests check it against the ``openssl`` command in both directions.
* **Everything is covered.** A seal is valid only if every file of the container outside ``META-INF/`` is covered by its signature, so that a file added to a sealed container cannot pass for a sealed one. The container is read strictly: a ZIP archive that two readers could see differently, an element of the signature this library does not process (a signature policy, a transform), make the seal invalid.
* **Trust.** ``'caCertPath'`` names the trusted CA certificates, as for the tokens. The signing certificate is trusted at the time of the signature time-stamp, if any, and at the current date otherwise: the time the signer claims (``getSigningTime()``) proves nothing.
* **Revocation.** It is checked by default, with CRLs (``'crls'``, in DER or PEM) or OCSP responses (``'ocspResponses'``) for each certificate of the chain, its trust anchor excepted. The library sends no request: ``Seal::validationDataRequests()`` lists the CRLs to fetch and the OCSP requests to send. ``'revocation' => false`` verifies a seal without, which ``isRevocationChecked()`` then tells.
* **Level T.** ``Seal::timestampRequest()`` gives the RFC 3161 request to send to a time-stamping authority of your choice (``application/timestamp-query``), and ``Seal::addSignatureTimestamp()`` checks its response and embeds the token; the verification then needs ``'tsaCertPath'``, the trusted certificates of the authority.
* **Level LT.** ``Seal::addValidationData()`` embeds the certificates, CRLs and OCSP responses that validate a seal of level T, issued after its time-stamp: the seal can then be validated without reaching the CAs, as long as the certificate of the time-stamping authority is valid (it is checked at the current date: only a time-stamp over the time-stamp, level LTA, which this library does not make, would check it at an earlier one).

The seals need the zlib extension of PHP besides OpenSSL; the ZIP extension is not used. Without the intl extension, two names of a container are compared as bytes rather than in Unicode normalization form C.


### Interoperability

**In Node.js, use the Node.js version of this library**, [@webcoder31/ezxmldsig](https://www.npmjs.com/package/@webcoder31/ezxmldsig) (Node.js 22.12 or later), which makes every check this one makes:

```sh
npm install @webcoder31/ezxmldsig
```

See its [README](https://github.com/webcoder31/ezxmldsig-js#readme) and its [API documentation](https://webcoder31.github.io/ezxmldsig-js/). A token created by either library is valid for the other, signed or encrypted, with every algorithm and option both share. Its tests check it against this library under PHP 7.4 and 8.3, and replay the attack lab of the [signed token demo](#signed-token-demo): every forged token gets the same verdict from both. The few cases where they differ are listed in its README (section "Differences with the PHP library"); those that came from defects of version 1.2.0 of this library (keys that are not RSA keys, values holding ``&`` without base64, certificates dated from 2050 on) are fixed in 1.2.1.

**Seals.** The seals of both libraries are the same: each library verifies the seals of the other, at levels B, T and LT, and DSS validates them (see [What is checked, and by whom](#what-is-checked-and-by-whom)).

**With other libraries.** A token is an XML digital signature and, when encrypted, XML Encryption: other libraries can create or read one, as long as they produce or check its exact format. Checked with [xml-crypto](https://www.npmjs.com/package/xml-crypto) 6.4.0 and [xml-encryption](https://www.npmjs.com/package/xml-encryption) 6.0.2 for Node.js, both ways. The format of a token, element by element, and the code that creates and reads one with these libraries: see [Interoperability](https://webcoder31.github.io/ezxmldsig-doc/interoperability/) on the documentation site.

These libraries only verify a signature, with the key they are given, and only decrypt: a receiver that uses them directly must make all the other checks of ``isSignatureValid()`` itself.


### Compatible versions

The versions of the two libraries that work together. A pair has the same features when each library creates and verifies what the other creates and verifies: the same tokens, and the same seals when both have them. In every pair, the cases listed in "[Differences with the PHP library](https://github.com/webcoder31/ezxmldsig-js#differences-with-the-php-library)" in the README of the Node.js library differ.

| PHP library | Node.js library | Tokens | Seals | Same features |
|---|---|---|---|---|
| **2.1.0** | **2.0.0** | exchanged both ways (1) | exchanged both ways, experimental (2) | **yes** |
| 2.0.0 | 2.0.0 | exchanged both ways | only in the Node.js library | no |
| 1.2.1 | 1.0.3 | exchanged both ways | in neither library | yes |
| 1.2.1 | 1.0.2 | exchanged both ways | in neither library | no: `getPrettyXML()` comes to the Node.js library in 1.0.3 |
| 1.2.0 | 1.0.0, 1.0.1 | exchanged both ways, but for three defects of the PHP library 1.2.0, fixed in 1.2.1 (3) | in neither library | no: `getPrettyXML()` comes to the Node.js library in 1.0.3 |

1. The tests of the Node.js library 2.0.0 exchange tokens with the PHP library 2.0.0; the PHP library 2.1.0 does not change the tokens.
2. The tests of the PHP library 2.1.0 verify seals made by the Node.js library 2.0.0. The seals of the PHP library 2.1.0 were verified by the Node.js library 2.0.0 and validated by DSS by hand (see [What is checked, and by whom](#what-is-checked-and-by-whom)).
3. Listed in "[Differences with the PHP library](https://github.com/webcoder31/ezxmldsig-js#differences-with-the-php-library)" in the README of the Node.js library.

Each pair of the table is the one the tests of these versions check. The tokens do not change from the PHP library 1.2.1 and the Node.js library 1.0.2 on: later versions exchange them too, although the tests do not check every pair. A receiver of the PHP library 1.0 or 1.1 refuses the encrypted tokens of the PHP library 1.2.0 and later, and those of every version of the Node.js library.


### Upgrading from 1.x

* **Namespaces.** ``XMLDSigToken`` moves to ``webcoder31\ezxmldsig\token``, ``X509Cert`` to ``webcoder31\ezxmldsig\core``: replace ``use webcoder31\ezxmldsig\XMLDSigToken;`` with ``use webcoder31\ezxmldsig\token\XMLDSigToken;``, and ``use webcoder31\ezxmldsig\X509Cert;`` with ``use webcoder31\ezxmldsig\core\X509Cert;``. Nothing else changes: the same methods, constants, options, verdicts and error messages, and the same tokens.
* **Loading without Composer.** ``ezxmldsig.php`` loads the new files of ``src/core/`` and ``src/token/``; a loader of your own must require them too.

### Upgrading from 0.x

* **Trust anchor.** ``analyzeXMLToken($xml)`` and ``analyzeSecureXMLToken($xml, $cryptKeyPath, $cryptKeyPassword)`` without a trust anchor now reject every token: pass ``caCertPath`` (and/or ``signerCertPath``) in their ``$options``. A call to ``isValidCertCA()`` with the intermediate CA, which used to be the way to check the origin of the certificate, becomes ``'caCertPath' => [intermediate, root]``.
* **Default algorithms.** Tokens are signed with RSA-SHA256 and an SHA-256 digest (RSA-SHA1 and SHA-1 before), and the analysis expects these algorithms by default. A token created with the 0.x defaults is rejected (``Unauthorized Signature algorithm! ...``) unless the analysis declares them:

  ```php
  $options = [
      'caCertPath' => ['path/to/ca/intermediate/certificate', 'path/to/ca/root/certificate'],
      'signatureAlgorithm' => XMLDSigToken::RSA_SHA1,
      'digestAlgorithm' => XMLDSigToken::SHA1,
  ];
  ```

  Conversely, a 0.x analysis that expects the 0.x defaults rejects the tokens of this version: upgrade the receiver first, or pass ``'signatureAlgorithm' => XMLDSigToken::RSA_SHA1`` and ``'digestAlgorithm' => XMLDSigToken::SHA1`` to the creation until it is upgraded.
* **Options of ``createXMLToken()``.** Its ``$options`` were ignored: they now apply. Check that the options you pass to it are the ones you want.
* **Option checks.** An unknown option, an option out of its context (``checkSigningAlgorithms``, ``checkCryptingAlgorithms`` or a trust option at creation, ``base64Encode`` or ``xmldsigNsPrefix`` at analysis, an encryption option without an encryption certificate or a decryption key), or an option whose value is ``NULL`` or of the wrong type now throws an exception instead of being ignored. Remove such options.
* **Algorithm lists.** ``signatureAlgorithm`` no longer accepts ``RSA_1_5`` and ``RSA_OAEP_MGF1P``, ``cryptAlgorithm`` no longer accepts the ``RSA_SHA*`` algorithms, and ``sessionKeyCipheringAlgorithm``, which used to refuse every encryption algorithm, now accepts them.
* **``createSecureXMLToken()``** throws an exception when ``$cryptCertPath`` is ``NULL``, instead of creating an unencrypted token.
* **Token identifier.** Each token holds a signed random identifier (``Token/TokenId``, see [Replay](#replay)). A token without identifier, as created by a 0.x version, is rejected (``Token identifier is missing!``), whatever the options: upgrade the senders together with the receivers. A token is valid for a few seconds or minutes (``isOutOfDate()``): no token created before the upgrade needs to be read after it. Receivers should refuse the identifiers they have already accepted.
* **XML parsing.** A document with a document type declaration (``<!DOCTYPE``), or not encoded in UTF-8, is rejected before it is parsed, and ``alterXML()`` returns ``FALSE`` for it without changing it (see [XML parsing](#xml-parsing)). The tokens created by the library are in UTF-8 and have none.
* **``getHTMLDump()``** escapes every value it shows and no longer loads the ``run_prettify.js`` script of Google Code Prettify from a CDN: the XML token is shown without syntax highlighting.
* **Encryption.**
    * The data are encrypted with AES-256-GCM (AES-128-CBC before), and the analysis rejects a token encrypted with CBC unless it declares the algorithm (see [Encryption](#encryption)).
    * A 0.x analysis rejects AES-GCM (``Session Key Ciphering algorithm is invalid!``): upgrade the receivers first, declaring ``'sessionKeyCipheringAlgorithm' => XMLDSigToken::AES128_CBC`` while the senders create tokens with the 0.x defaults, then upgrade the senders and remove the option.
    * With ``'checkCryptingAlgorithms' => false`` too, a receiver accepts both the declared CBC algorithm and AES-GCM during the transition.
    * A sender upgraded first can pass the same option to ``createSecureXMLToken()`` until its receivers are upgraded.
    * RSA 1.5 is refused and the constant ``XMLDSigToken::RSA_1_5`` is removed: use ``RSA_OAEP_MGF1P``, the default.
    * A decryption failure gives ``Token decryption failed!`` instead of ``Session key decryption failed! Reason: ...`` or ``Token data decryption failed! Reason: ...``.
    * The sender no longer needs the private key of the recipient: ``createSecureXMLToken()`` accepts ``null`` as ``$cryptKeyPath`` (see [Encryption](#encryption)). Calls that pass it keep working.


## Signed token demo

An interactive demo is online at **https://ezxmldsig.wbcdr.dev/**: nothing to install, and each visitor has a replay memory of their own. It also runs on your machine, which requires a running Docker daemon (e.g. Docker Desktop, or Colima with the repository under your home directory); neither PHP nor Composer has to be installed locally.

```
git clone https://github.com/webcoder31/ezxmldsig-php.git
cd ezxmldsig-php
bin/demo          # http://127.0.0.1:8080/
bin/demo 9000     # another port (or DEMO_PORT=9000)
```

The script first brings `vendor/` in line with `composer.json` with `bin/deps` (as `bin/test` does, see [Tests](#tests)), runs the PHP built-in web server in the official `php:8.3-cli` image, publishes it on `127.0.0.1` only, and opens the page in the browser when it can (`DEMO_NO_BROWSER=1` skips it). Ctrl-C stops it.

![The demo: its animated illustration of a token verified and accepted, the issuer, and the annotated token with the block SignedInfo selected](https://webcoder31.github.io/ezxmldsig-doc/assets/screenshots/token-lab.png)

Every token of the demo is created and analyzed by the library, in PHP; the page only displays them:

* **Issuer**: user data (nested values allowed), encryption on or off, the audiences the token is addressed to and its validity (by default, the receiver of the demo, `receiver`, and 300 seconds), and the signature, digest and encryption algorithms.
* **Token**: the XML token, highlighted, each block explained when you point at it or select it with the arrow keys: what it does, and whether the signature covers it. It can be copied, or edited by hand before it is verified. Below it, a collapsed section shows the PHP code of the issuer that created this token; it changes only when a token is created.
* **Receiver**: the trust anchor (`caCertPath`, `signerCertPath`, `expectedSubject`), its own audience (`expectedAudience`), the decryption key, the expected algorithms, the time to live and the replay protection. The verification is shown as a pipeline of checks: those of `isSignatureValid()` (structure, algorithms, digest, signature, trust in the certificate, decryption, content, audience), then the two checks left to the caller, freshness (`isOutOfDate()`, expiry included) and replay (`getTokenId()`, stored in a file of `demo/var/`, under a lock, one per visitor: a cookie names it). The PHP code of this receiver is shown.
* **Attack lab**: each attack alters the last token of the issuer (or a new one, when the last one does not suit the attack) on the server and submits it to the receiver, with a replay memory of its own: data tampering, signature wrapping, look-alike certificate, EC key substitution, replay, expired token, token addressed to another receiver, token past the expiry its issuer set, DOCTYPE with entities, altered ciphertext signed again by a trusted signer, certificate of an untrusted CA, and a script in the data. Each one shows what was changed (as a diff), the check that stops it, the exact message, and the security advisory of the 0.x versions it relates to. No vulnerable code runs: the lab shows what the current version does.

> **WARNING: the private keys of `demo/certs/` are public.** They are published with the source code of this library, with their passwords: anyone can sign tokens that the demo trusts, and decrypt the tokens it encrypts. Use them for the demo only, never in an application or on a server reachable by others, and never trust their CA certificates: generate your own keys and certificates (see `demo/certs/README.md`). The same goes for the keys of `tests/fixtures/certs/`, which only serve the tests.

The certificates of the demo (`demo/certs/`: a root CA, the intermediate CA that issued the signing and encryption certificates, these certificates with their keys, and the certificates of the attacks) are valid for 10 years from their generation. To issue new ones, run `bin/gen-test-certs --demo`.

To serve the demo online, `demo/Dockerfile` builds an image with Apache and PHP 8.3, which listens on port 8000 as user `www-data`, every request routed to `demo/public/index.php`, and `GET /health` answering `ok`. `DEMO_PUBLIC_HOST` names the host it answers on besides `127.0.0.1` and `localhost`, served over HTTPS by a proxy in front of it. Only `demo/var/`, `/var/run/apache2` and `/var/lock/apache2` need to be writable. Build it from the root of the repository:

```
docker build -f demo/Dockerfile -t ezxmldsig-demo .
docker run --rm -p 127.0.0.1:8000:8000 ezxmldsig-demo
```

The demo is not part of the Composer package: `.gitattributes` leaves `demo/`, `demo-sso/`, `tests/`, `docs/`, `bin/` and `.dockerignore` out of the archives Composer installs.


## Single sign-on demo

A second demo plays a single sign-on with ezxmldsig tokens, between three sites on three host names: **IDP**, the identity provider, which alone knows the users and their passwords and signs the tokens, and two applications, **MAIL** and **CRM**, which have no password and trust the tokens of IDP. It is online at **https://sso.wbcdr.dev/**, each visitor with sessions, a trace and protections of their own. It also runs on your machine, with the same requirements as the [signed token demo](#signed-token-demo); browsers resolve `*.localhost` to the local machine.

```
git clone https://github.com/webcoder31/ezxmldsig-php.git
cd ezxmldsig-php
bin/demo-sso          # http://localhost:8090/
bin/demo-sso 9090     # another port (or DEMO_SSO_PORT=9090)
```

1. Open `http://mail.localhost:8090/`: MAIL has no session, so it sends the browser to IDP.
2. Log in on IDP (the demo accounts are shown). IDP opens its own session, signs a token addressed to MAIL (`audience`), valid 60 seconds (`validity`), and the browser posts it to MAIL, in a form, as the HTTP-POST binding of SAML does.
3. MAIL verifies the token: the checks of the library (`isSignatureValid()`: signature, trust in the certificate of IDP, audience), then its own (freshness, replay). It opens its own session.
4. Open `http://crm.localhost:8090/`: IDP recognizes the user by its own session cookie and signs a token for CRM, without asking for the password again. That is single sign-on.

![The single sign-on demo: its home page, with its animated illustration of the flow, and the trace of a login on MAIL then of CRM entered without a new login](https://webcoder31.github.io/ezxmldsig-doc/assets/screenshots/single-sign-on.png)

The pages show what the library checks and what each application checks itself, the cookies of each site (each site has its own: a cookie is sent to the host that set it), and the trace of the flow: each hop between the browser, IDP, MAIL and CRM, with each token and each check.

The demo accounts show two kinds of rights. **Access to an application** is decided by IDP, which signs no token for an application the user may not enter: `bjorn` may only enter MAIL. **What a user may do in an application** is decided by the application, from an attribute IDP writes in the token: in CRM, `ragnar`, a Jarl, may delete a customer, and `lagertha`, a Shieldmaiden, may only read them. An attribute in a token stays as it is until the token expires, and so does the session the application opened with it: a right withdrawn in IDP only takes effect with the next token.

The home page (`http://localhost:8090/`) holds:

* **The protections of the live demo**, which turn off the code of IDP or of the applications that stops an attack: the audience, the registered return address, the freshness, the replay memory. And an option: IDP encrypts each token for its application, with the certificate of that application (`demo-sso/certs/`).
* **The attack lab**: each attack runs in a sandbox of its own, with a victim and an attacker, through the very code of the three sites. Four of them are stopped by a protection of IDP or of the applications, which can be turned off for a run to see the attack succeed: a token for another application, a replayed token, an old token, a hijacked return address. Three are stopped by the library itself, and have no switch: a tampered token, a token of another identity provider, and an encrypted token presented to another application.

> **For a single sign-on in production, prefer a standard, OpenID Connect or SAML, with a maintained library.** This demo shows the mechanisms, and what a receiver must check. Logging out of an application leaves IDP and the other application logged in: logging out of every site at once (single logout) is a separate mechanism, which the demo does not implement.

The private keys of `demo-sso/certs/` are public, like those of `demo/certs/` (see `demo-sso/certs/README.md`); to issue new ones, run `bin/gen-test-certs --demo-sso`. The sessions, the trace and the replay memories are kept in `demo-sso/var/` (ignored by git).

To serve it online, `demo-sso/Dockerfile` builds an image like the one of the [signed token demo](#signed-token-demo) (Apache and PHP 8.3, port 8000, user `www-data`, `GET /health`). `DEMO_SSO_PUBLIC_DOMAIN` names the domain whose subdomains are the sites, served over HTTPS by a proxy in front of it: with `sso.example.org`, the home page is `https://sso.example.org/`, and the sites `idp.sso.example.org`, `mail.sso.example.org` and `crm.sso.example.org`. Each visitor then has a directory of their own in `demo-sso/var/visitors/` (sessions, trace, protections, replay memories), named by a cookie set on that domain, which the browser sends to the four host names and to no other; "Reset the demo" only resets theirs. The directories left unwritten for two days are removed. Build it from the root of the repository: `docker build -f demo-sso/Dockerfile -t ezxmldsig-sso .`

## Differences with the Node.js library

The tokens and the seals of both libraries are the same, and so are their verdicts and error messages, but in the cases that the README of the Node.js library lists in [Differences with the PHP library](https://github.com/webcoder31/ezxmldsig-js#differences-with-the-php-library): the types of the values, which follow each language, a few checks of the certificates, and the display and test helpers of this library (``getHTMLDump()``, ``alterXML()``), which the Node.js library does not have.


## Tests

The PHPUnit test suite runs in Docker, so neither PHP nor PHPUnit has to be installed locally. Requirements: a running Docker daemon (e.g. Docker Desktop, or Colima with the repository under your home directory), `curl` and a POSIX shell.

```
bin/test                        # PHP 7.4, then PHP 8.3
bin/test 8.3                    # one PHP version
bin/test 7.4 -- --filter Secure # arguments after -- go to PHPUnit
```

The script uses the official `php:<version>-cli` images. On first run, it downloads the PHPUnit 9.6 PHAR into `tests/.cache/` (checked against a pinned SHA-256).

Before running anything, it calls `bin/deps`, which brings `vendor/` in line with `composer.json` in the `composer:2` image. `composer.lock` is not versioned, so each copy of the repository has its own, which may predate `composer.json`. `bin/deps` checks it without network: when `composer.lock` is missing or `composer validate` reports that it no longer matches `composer.json`, it runs `composer update`; when `vendor/` is missing or holds other versions than `composer.lock`, it runs `composer install`; otherwise it runs nothing else. It says on the terminal what it runs and why. When Composer refuses a dependency because of a security advisory, `COMPOSER_NO_BLOCKING=1` in front of the command overrides the refusal, at your own risk.

Tests that need a feature the current environment lacks are skipped, and PHPUnit prints the reason.

The continuous integration (`.github/workflows/ci.yml`) runs `bin/test` under PHP 7.4 and 8.3 on each push to `main` and each pull request, with `--fail-on-skipped`: there, a skipped test fails the run, so that a check that does not run never passes for one that does.

The suite also runs each attack of the attack lab of the [signed token demo](#signed-token-demo) with the code of the demo, and checks that its API never returns a value of a token as markup (`tests/Demo*Test.php`).

The seals of `tests/fixtures/seal/containers/` are made by the Node.js library, and the tests check that this library gives the verdicts the Node.js library gave on them (`tests/fixtures/seal/verdicts.json`). Run `bin/gen-seal-fixtures` to make them again: it clones the Node.js library at a tag into `tests/.cache/`, and runs it in the `node` Docker image (see `tests/fixtures/seal/README.md`). The seals the tests make are time-stamped by the `openssl ts` command, and their CRLs and OCSP responses are issued by the `openssl ca` and `openssl ocsp` commands. The faults these commands cannot write (a delta CRL, an altered TSTInfo, a responder without the right extension, an ambiguous ZIP archive...) are built by the helpers of `tests/helpers/`, written apart from the library and ported from those of the Node.js library: a DER writer, a CRL issuer, an OCSP responder, a time-stamping authority and a ZIP builder. The tests ported from the Node.js library (`SealAttacksTest`, `SealOcspTest`, `SealRevocationTest`, `SealStructureTest`, `SealTimestampTest`, `SealValidationTest`, `ZipRawTest`) keep its cases.

The certificates used by the tests live in `tests/fixtures/certs/`: a root CA, an intermediate CA, signing and encryption certificates issued by the intermediate, and a certificate signed by its own key that copies the subject and issuer names of the signing certificate. Run `bin/gen-test-certs` to generate them again (it runs OpenSSL in the `alpine:3.22` Docker image, whatever OpenSSL the host has). The tests of the trust anchor also issue certificates on the fly (expired, issued by another intermediate CA, issued by a certificate that is not a CA) in a temporary directory removed after each test.

### What is checked, and by whom

Each library checks, for its tokens and for its seals:

1. that it verifies what it creates;
2. that the other library verifies what it creates;
3. that third-party tools verify what it creates: xml-crypto and xml-encryption for the tokens, DSS (Digital Signature Service, the validator of the European Commission) for the seals;
4. that it verifies what these tools create.

Each check belongs in the tests of the library itself, and runs in its continuous integration. Where each one is made:

| Check | Tokens of the PHP library | Tokens of the Node.js library | Seals of the PHP library | Seals of the Node.js library |
|---|---|---|---|---|
| 1. It verifies what it creates | tests and continuous integration of the PHP library | tests and continuous integration of the Node.js library | tests and continuous integration of the PHP library | tests and continuous integration of the Node.js library |
| 2. The other library verifies what it creates | tests and continuous integration of the Node.js library, against the PHP library 2.0.0 | tests and continuous integration of the Node.js library, by the PHP library 2.0.0 | by hand | tests and continuous integration of the PHP library, on seals made by the Node.js library 2.0.0 |
| 3. Third-party tools verify what it creates | by hand | tests and continuous integration of the Node.js library | by hand | tests and continuous integration of the Node.js library |
| 4. It verifies what these tools create | by hand | tests and continuous integration of the Node.js library | tests and continuous integration of the PHP library, on a seal made by DSS | tests and continuous integration of the Node.js library, on a seal made by DSS |

The tests of the PHP library run with `bin/test`, on a developer machine and in its continuous integration. The Node.js library depends on xml-crypto, which canonicalizes its XML: for its tokens, xml-crypto is not a checker wholly apart from the code under test.


## Documentation

Online documentation is available here: [EZXMLDSIG Documentation](https://webcoder31.github.io/ezxmldsig-php/).

This site is published by GitHub Pages from the `docs/` directory of the branch `main` (home page: `docs/index.html`). Its pages are generated from the docblocks of `src/` by [ApiGen](https://github.com/ApiGen/ApiGen), in Docker: run `bin/gen-docs` after changing a docblock, and commit `docs/` with the code.

```
bin/gen-docs
```

The script runs the official `apigen/apigen` image, pinned by digest since ApiGen publishes no versioned image, and installs the dependencies with `composer install` when `vendor/` is missing (ApiGen also documents the classes of PHP and xmlseclibs the code refers to). ApiGen runs with the configuration of `bin/apigen/`, which keeps the blank lines and the indentation of the docblocks: ApiGen alone drops them, and with them the lists and code blocks of the docblocks. Docblocks are written in Markdown: a code example is a fenced code block (```` ```php ````, ```` ```xml ````), not a `<code>` tag. It replaces `docs/` as a whole, so that the pages of removed classes or methods do not remain, and refuses to do so if a generated file holds an absolute path. The pages load their style sheet and scripts from `docs/assets/` only: the site loads nothing from other servers.


## Releasing a version

A version is published on Packagist by its tag: Packagist reads the tags of the GitHub repository, and installs the version a tag names.

1. Set the version in the docblocks (``@version``) of ``ezxmldsig.php`` and of ``src/``, and describe it in ``CHANGELOG.txt``.
2. Regenerate the documentation (``bin/gen-docs``): its pages show the version.
3. Run ``bin/test``, under PHP 7.4 and 8.3, and make the checks that are made by hand (see [What is checked, and by whom](#what-is-checked-and-by-whom)).
4. Commit and push to ``main``, and wait for the continuous integration to pass.
5. Tag the commit, with an annotated tag ``v`` followed by the version, push the tag, and publish the release on GitHub: ``git tag -a v1.2.3 -m "ezxmldsig 1.2.3"``, ``git push origin v1.2.3``, ``gh release create v1.2.3 --title 1.2.3 --notes-file <notes>``.


## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md): report it privately, not in a public issue. It lists the supported versions; the 0.x versions must no longer be used.


## License

[CeCILL-C](LICENSE), the license of both libraries.


## How to Contribute?

* [Open Issues](https://github.com/webcoder31/ezxmldsig-php/issues)
* [Open Pull Requests](https://github.com/webcoder31/ezxmldsig-php/pulls)
