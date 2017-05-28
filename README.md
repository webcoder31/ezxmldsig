# EZXMLDSIG: An easy-to-use set of PHP classes for common use cases of XML Digital Signatures

Built on the library **xmlseclibs** developed by Rob Richards (https://github.com/robrichards/xmlseclibs), the **ezxmldsig** library is designed to make it easy to use XML digital signatures for various purposes such as Single Sign On login, token based authentication, electronic document signature, data integrity guarantee, and so on.

The author of the **ezxmldsig** library is Thierry Thiers.


## Requirements

The library **ezxmldsig** requires PHP version 5.6 or greater and the version 2.0.1 of the library **xmlseclibs** developed by Rob Richards.


## How to Install?

The library **ezxmldsig** is available on [www.pakagist.org](https://www.pakagist.org) and you can nstall it for your project with [`composer.phar`](http://getcomposer.org).

```sh
php composer.phar require "webcoder31/ezxmldsig"
```

You can also clone it (or download it as a ZIP archive) from its [GitHub repositary](https://github.com/webcoder31/ezxmldsig.git) and load it the way you want in your project. In this case, you will have to do the same from the [**xmlseclib** GitHub repositary](https://github.com/robrichards/xmlseclibs) of Rob Richards.


## What's in the box?

### XMLDSigToken class

The ``XMLDSigToken`` class allows creating and analyzing enveloping XML Digital Signature containing timestamped user data that may also be encrypted, also called XML token. With such tokens, you may create your own Single Sign On solution. You can secure access to your Web Services, as with JSON Web Token. You can transmit data in a secure way without having SSL connection. Or anything you can think of that requires such kind of features.

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

4) It guarantees the integrity of the user data stored in the XMLDSig token by verifying that:
    * The XML digital signature meets the XMLDSIG specifications.
    * The algorithms used to construct the XML digital signature are those expected.
    * The token contained in the XML digital signature has not been altered.

5) It is also able to verify with confidence that the token is not out of date because the token timestamp is signed too.

6) It may perform variuous checkings on the X.509 certificate included the XML Digital Signature:
    * Ensure that the certificate is not out of date.
    * Check the issuer of the certificate.
    * Verify the origin of the certificate. 


### X509Cert class

The ``X509Cert`` class provides a set of convenient methods for extracting essential information contained in an X.509 certificate and for performing some useful checkings. In particular, it can verify the origin of the X.509 certificate by using the intermediate certificate used by the CA to perform its signature (CSR). This class is used internaly by the ``XMLDSigToken`` class.


### Other classes coming soon...

More classes will be provided soon, in order to support other useful usages of XML Digital Signatures, i.e. signing an internet resource or a mail attachment.


## How to use?

NOTE: The **ezxmldsig** is designed to work with cryptographic material in PEM format.


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
$signKey = 'path/to/private/key';
$signCert = 'path/to/public/certificate';
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

// The issuer information of the sender to which the certificate transmitted
// in the XML digital signature should correspond to be declared valid.
$expectedIssuer = [
    'C'  => 'DK',
    'ST' => 'Jylland',
    'O'  => 'Lothbrok Ltd',
    'OU' => 'Shield Wall Dept',
    'CN' => 'www.lothbrok.dk',
    'emailAddress' => 'ivar@lothbrok.dk'
];

// CA intermediate certificate against which to verify origin of 
// the signing certificate transmitted in the XML Digital Signature.
$caCertPath = 'path/to/ca/intermediate/certificate';

// Create token object from the XML Digital Signature 
$token = XMLDSigToken::parseSecureXMLToken($sig, $cryptKey, $cryptKeyPassword);

// NOTE: The above instruction works even if user data is not encrypted.
// However, if user data is not encrypted and you don't own a private key 
// then use the following method:
// $token = XMLDSigToken::parseXMLToken($sig);

// Verify that:
// - the XML digital signature meets the XMLDSIG specifications.
// - the algorithms used to construct the XML digital signature are those 
//   expected (here, the default ones).
// - the token contained in the XML digital signature has not been altered.
// - the token contained in the XML digital signature is correctly timestamped
//   and contains user data.
if (!$token->isValid()) 
{
    echo "ERROR: Invalid XML Digital Signature!";
    exit();
}

// Verify that the X.509 certificate included in 
// the XML digital signature is not out of date.
if ($token->isCertOutOfDate()) 
{
    echo "ERROR: Signing certificate is out of date!";
    exit();
}

// Verify that the issuer of the X.509 certificate included 
// in the XML digital signature is indeed the one we expect.
if (!$token->checkCertIssuer($expectedIssuer)) 
{
    echo "ERROR: Issuer of signing certificate is not valid!";
    exit();
}

// Verify that the X.509 certificate included in the XML
// digital signature actualy comes from the CA we expect.
if (!$token->checkCertCA($caCertPath)) 
{
    echo "ERROR: Signing certificate not issued by the expected CA!";
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

## How to Contribute?

* [Open Issues](https://github.com/webcoder31/ezxmldsig/issues)
* [Open Pull Requests](https://github.com/webcoder31/ezxmldsig/pulls)
