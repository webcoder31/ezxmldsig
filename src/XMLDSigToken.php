<?php
/**
 * XMLDSigToken.php
 *
 * Copyright © 2017-2026 - Thierry Thiers <webcoder31@gmail.com>
 *
 * This  software  is governed  by  the CeCILL-C  license under French  law  and
 * abiding  by the rules of distribution of free  software. You can  use, modify
 * and/or redistribute the software under the terms  of the  CeCILL-C license as
 * circulated by CEA, CNRS and INRIA at the following URL:
 *
 * http://www.cecill.info
 *
 * As a counterpart to the access to the source code  and rights to copy, modify
 * and redistribute  granted by  the  license, users are  provided  only with  a
 * limited  warranty and  the software's author,  the  holder  of  the  economic
 * rights, and the successive licensors have only limited liability.
 *
 * In this respect, the user's  attention is drawn to the risks  associated with
 * loading, using, modifying and/or  developing or reproducing  the software  by
 * the user in light of its specific status of free software, that may mean that
 * it is complicated to manipulate,  and that also  therefore means  that it  is
 * reserved  for  developers   and  experienced  professionals  having  in-depth
 * computer  knowledge. Users  are  therefore  encouraged to load  and  test the
 * software's suitability as  regards  their requirements in conditions enabling
 * the security of their systems and/or data to be  ensured and, more generally,
 * to use and operate it in the same conditions as regards security.
 *
 * The  fact  that you are  presently  reading  this  means  that you  have  had
 * knowledge of the CeCILL-C license and that you accept its terms.
 *
 * @author    Thierry Thiers <webcoder31@gmail.com>
 * @copyright 2017-2026 - Thierry Thiers <webcoder31@gmail.com>
 * @license   http://www.cecill.info  CeCILL-C License
 * @version   1.1.0
 */


// Namespace.
namespace webcoder31\ezxmldsig;

// Use.
use DateTime;
use DateTimeZone;
use DOMDocument;
use DOMElement;
use DOMNode;
use DOMXPath;
use Exception;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/**
 * Build or analyze an XML token.
 *
 * An XML token is an enveloping XML Digital Signature (cf. RFC 3275)
 * containing signed and timestamped user data. These data may also be
 * encrypted. In this case we talk about Secure XML token.
 *
 * **This class uses the following default algorithms to operate:**
 *
 * - Algorithm used to canonicalize data before signing is:
 *   http://www.w3.org/TR/2001/REC-xml-c14n-20010315.
 *
 * - Algorithm used to generate the signature is:
 *   http://www.w3.org/2001/04/xmldsig-more#rsa-sha256.
 *
 * - Algorithm used to compute the hash of token data is:
 *   http://www.w3.org/2001/04/xmlenc#sha256.
 *
 * - Algorithm used to encode data's values is: Base64.
 *
 * The analysis expects these algorithms unless its options name others (see
 * `__construct()`), and it requires a trust anchor: the CA certificates
 * and/or the pinned certificate the signing certificate is verified against.
 * Without it, no token is valid.
 *
 * **An XML token looks like this:**
 *
 * ```xml
 * <?xml version="1.0"?>
 * <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
 *   <ds:SignedInfo>
 *     <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
 *     <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
 *     <ds:Reference URI="#Token">
 *       <ds:Transforms>
 *         <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
 *       </ds:Transforms>
 *       <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
 *       <ds:DigestValue>---- TOKEN HASH ----</ds:DigestValue>
 *     </ds:Reference>
 *   </ds:SignedInfo>
 *   <ds:SignatureValue>---- SIGNATURE VALUE ----</ds:SignatureValue>
 *   <ds:KeyInfo>
 *     <ds:X509Data>
 *       <ds:X509Certificate>---- X.509 CERTIFICATE ----</ds:X509Certificate>
 *     </ds:X509Data>
 *   </ds:KeyInfo>
 *   <ds:Object Id="Token">
 *     <Token>
 *       <TokenTimestamp>2026-10-17T04:43:05Z</TokenTimestamp>
 *       <TokenId>---- 128-BIT RANDOM IDENTIFIER (HEXADECIMAL) ----</TokenId>
 *       <TokenData>
 *         <data1 Algorithm="base64">---- BASE64 ENCODED DATA ----</data1>
 *         <data2 Algorithm="base64">---- BASE64 ENCODED DATA ----</data2>
 *         <data3>
 *           <data31 Algorithm="base64">---- BASE64 ENCODED DATA ----</data31>
 *           <data32 Algorithm="base64">---- BASE64 ENCODED DATA ----</data32>
 *         </data3>
 *         <data4 Algorithm="base64">---- BASE64 ENCODED DATA ----</data4>
 *       </TokenData>
 *     </Token>
 *   </ds:Object>
 * </ds:Signature>
 * ```
 *
 * **The signing process consists of the following actions:**
 *
 * - Load data from an associative array.
 *
 * - Encode data values using Base64.
 *
 * - Build a node from the encoded array of data (cf. node `<TokenData />`).
 *
 * - Compute an UTC timestamp and store it in a node `<TokenTimestamp />`.
 *
 * - Generate a random identifier of 128 bits (`random_bytes()`) and store
 *   it, in hexadecimal, in a node `<TokenId />`. Signed with the rest of the
 *   token, it lets the receiver refuse a token it has already accepted (see
 *   `getTokenId()`).
 *
 * - Aggregate the nodes `<TokenTimestamp />`, `<TokenId />` and
 *   `<TokenData />` inside a node `<Token />`.
 *
 * - Load the base DOM document representing an XML digital signature:
 *
 * ```xml
 * <ds:Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
 *   <ds:SignedInfo>
 *     <ds:SignatureMethod />
 *   </ds:SignedInfo>
 * </ds:Signature>
 * ```
 *
 * - Create a node `<ds:Object Id="Token" />` and append it to the node
 *   `<ds:Signature />`.
 *
 * - Add the node `<Token />` to the node `<ds:Object Id="Token" />`.
 *
 * - NOTE: If data encryption is requested, this process will take place here
 *   (this will be described later).
 *
 * - Build a node `<ds:Reference URI="#Token" />` and append it to the node
 *   `<ds:SignedInfo />`. This consists of:
 *
 *   - Canonicalizing the content of the node `<ds:Object Id="Token" />`.
 *
 *   - Computing the hash (SHA-256 by default) of the canonicalized node and
 *     storing it in the node `<ds:DigestValue />`.
 *
 * - Include, in the XML token, the X.509 certificate associated to the
 *   private key that will be used to perform the signing (see the next steps
 *   below). This certificate will be used to perform the signature validation
 *   process, avoiding the need, for the receiver of the XML Digital Signature,
 *   to own it on its side.
 *
 * - Canonicalize the content of the node `<ds:SignedInfo />`.
 *
 * - Compute the signature of the canonicalized node using the private key
 *   dedicated to perform signing.
 *
 * - Store the result in the node `<ds:SignatureValue />`.
 *
 * - Save the DOM document in XML format.
 *
 * **The signature validation process consists of the following actions:**
 *
 * - Load the XML Digital Signature in a DOM document. A document with a
 *   document type declaration (DOCTYPE), or not encoded in UTF-8, is
 *   refused before it is parsed, and the parser never accesses the network
 *   (see `_loadXML()`).
 *
 * - Verify that the algorithms of the XML Digital Signature are the
 *   expected ones.
 *
 * - Compute the hash of the content of the node `<ds:Object Id="Token" />`
 *   with the digest algorithm.
 *
 * - Compare the computed hash with the one stored in the node
 *   `<ds:DigestValue />`. If the hashes are different, this means that the
 *   content of the node `<ds:Object Id="Token" />` has been altered.
 *
 * - Canonicalize the content of the node `<ds:SignedInfo />`.
 *
 * - Compute the signature of the node `<ds:SignedInfo />` using the X.509
 *   certificate included in the XML token.
 *
 * - Compare the computed signature with the one stored in the node
 *   `<ds:SignatureValue>`. If the signatures are different, this means that
 *   the content of the node `<ds:SignedInfo />` has not been signed using the
 *   private key associated to the X.509 certificate included in the XML
 *   Digital Signature.
 *
 * - Verify that the X.509 certificate included in the XML Digital Signature
 *   is trusted, against the trust anchor given to the analysis: CA
 *   certificates up to which OpenSSL verifies the chain of the certificate,
 *   and/or the pinned certificate the token must be signed with. Without a
 *   trust anchor, no token is valid: anyone can sign a token with a
 *   certificate of their own.
 *
 * - NOTE: If data decryption is required, this process will take place here
 *   (this will be described later).
 *
 * - Extract the timestamp and the identifier stored in the content of the
 *   node `<ds:Object Id="Token" />` and memorise them. A token without
 *   identifier is rejected.
 *
 * - Extract the data stored in the content of the node
 *   `<ds:Object Id="Token" />`.
 *
 * - Decode data values using Base64.
 *
 * - Build an associative array containing the decoded data.
 *
 * **Token data encryption / decryption:**
 *
 * The token data may also be encrypted before signing. In this case the class
 * will use the following default algorithms to perform encryption and
 * decryption of data:
 *
 * - Algorithm used to encrypt / decrypt data is:
 *   http://www.w3.org/2009/xmlenc11#aes256-gcm (authenticated symmetric
 *   ciphering).
 *
 * - Algorithm used to encrypt / decrypt the session key is:
 *   http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p (asymmetric ciphering).
 *
 * **A secure (encrypted) XML token looks like this:**
 *
 * ```xml
 * <?xml version="1.0"?>
 * <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
 *   <ds:SignedInfo>
 *     <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
 *     <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
 *     <ds:Reference URI="#Token">
 *       <ds:Transforms>
 *         <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
 *       </ds:Transforms>
 *       <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
 *       <ds:DigestValue>---- TOKEN HASH ----</ds:DigestValue>
 *     </ds:Reference>
 *   </ds:SignedInfo>
 *   <ds:SignatureValue>---- SIGNATURE VALUE ----</ds:SignatureValue>
 *   <ds:KeyInfo>
 *     <ds:X509Data>
 *       <ds:X509Certificate>---- X.509 CERTIFICATE ----</ds:X509Certificate>
 *     </ds:X509Data>
 *   </ds:KeyInfo>
 *   <ds:Object Id="Token">
 *     <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Content">
 *       <xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
 *       <ds:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
 *         <xenc:EncryptedKey>
 *           <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
 *           <xenc:CipherData>
 *             <xenc:CipherValue>---- CIPHERED SESSION KEY ----</xenc:CipherValue>
 *           </xenc:CipherData>
 *         </xenc:EncryptedKey>
 *       </ds:KeyInfo>
 *       <xenc:CipherData>
 *         <xenc:CipherValue>---- ENCRYPTED DATA ----</xenc:CipherValue>
 *       </xenc:CipherData>
 *     </xenc:EncryptedData>
 *   </ds:Object>
 * </ds:Signature>
 * ```
 *
 * **The encryption process is the following:**
 *
 * - Randomly generate a session key.
 *
 * - Cipher the session key using the X.509 certificate dedicated to the
 *   encryption process, in order to transmit it safely in the XML Digital
 *   Signature.
 *
 * - Store the ciphered session key in the node `<xenc:CipherValue />` which is
 *   located inside the node `<xenc:EncryptedKey />`.
 *
 * - Encrypt the content of the node `<ds:Object Id="Token" />` using the
 *   non-ciphered session key and store the result in the last node
 *   `<xenc:CipherValue />`.
 *
 * **The decryption process is the following:**
 *
 * - Retrieve the node `<xenc:EncryptedData />`.
 *
 * - Decipher the ciphered session key stored in the node `<xenc:CipherValue />`
 *   (the one which is located inside the node `<xenc:EncryptedKey />`) using
 *   the private key associated to the X.509 certificate that has been used to
 *   perform the encryption.
 *
 * - Decrypt the content of the last node `<xenc:CipherValue />` using the
 *   deciphered session key.
 *
 * The decryption only takes place once the digest, the signature, the trust
 * in the signing certificate and the algorithms have been verified, and
 * every failure that depends on the encrypted content gives the same error,
 * `Token decryption failed!`. RSA 1.5 is refused, and a CBC algorithm is
 * only accepted when the analysis declares it (see `__construct()`).
 *
 * **Replay:**
 *
 * A valid token can be submitted again for as long as `isOutOfDate()`
 * accepts it. The class keeps no list of the tokens it has analyzed: the
 * caller must keep the identifiers it accepted (`getTokenId()`) and refuse a
 * token whose identifier is among them.
 */
class XMLDSigToken
{
    /* CONSTANTS */

    /** @const string The default XMLDSIG namespace prefix used in the XML digital
    signature. */
    const XMLDSIG_NS_PREFIX = 'ds';

    /** @const string The name of the token node. */
    const TOKEN_NAME = 'Token';

    /** @const string The name of the token data node. */
    const TOKEN_DATA_NAME = 'TokenData';

    /** @const string The name of the token timestamp node. */
    const TOKEN_TIMESTAMP_NAME = 'TokenTimestamp';

    /** @const string The name of the token identifier node. */
    const TOKEN_ID_NAME = 'TokenId';

    /** @const int The number of random bytes of the token identifier, written
    in hexadecimal (see getTokenId()). */
    const TOKEN_ID_BYTES = 16;

    /** @const string The name of the node that holds one audience of the
    token (see getAudience()). A token holds one such node per audience. */
    const TOKEN_AUDIENCE_NAME = 'TokenAudience';

    /** @const string The name of the token expiry node (see getExpiry()). */
    const TOKEN_EXPIRY_NAME = 'TokenExpiry';

    /** @const int The latest expiry the format of the timestamp can write
    (9999-12-31T23:59:59Z), as a UNIX timestamp. */
    private const MAX_EXPIRY_TIME = 253402300799;

    /** @const string The format of the token timestamp (YYYY-MM-DDThh:mm:ssZ).
    NOTE: The timestamp should always be expressed in UTC. */
    const TOKEN_TIMESTAMP_FORMAT = 'Y-m-d\TH:i:s\Z';

    /** @const int The default time to live (in seconds) used to check token
    peremption. */
    const TOKEN_DEFAULT_TTL = 60;

    /** @const int The synchronization offset (in seconds) allowed for verifying
    if token is out of date. */
    const DESYNC_TOLERANCE = 30;


    const C14N = XMLSecurityDSig::C14N;
    const C14N_COMMENTS = XMLSecurityDSig::C14N_COMMENTS;
    const EXC_C14N = XMLSecurityDSig::EXC_C14N;
    const EXC_C14N_COMMENTS = XMLSecurityDSig::EXC_C14N_COMMENTS;

    const SHA1 = XMLSecurityDSig::SHA1;
    const SHA256 = XMLSecurityDSig::SHA256;
    const SHA384 = XMLSecurityDSig::SHA384;
    const SHA512 = XMLSecurityDSig::SHA512;
    const RIPEMD160 = XMLSecurityDSig::RIPEMD160;

    const TRIPLEDES_CBC = XMLSecurityKey::TRIPLEDES_CBC;
    const AES128_CBC = XMLSecurityKey::AES128_CBC;
    const AES192_CBC = XMLSecurityKey::AES192_CBC;
    const AES256_CBC = XMLSecurityKey::AES256_CBC;
    const AES128_GCM = XMLSecurityKey::AES128_GCM;
    const AES192_GCM = XMLSecurityKey::AES192_GCM;
    const AES256_GCM = XMLSecurityKey::AES256_GCM;
    const RSA_OAEP_MGF1P = XMLSecurityKey::RSA_OAEP_MGF1P;
    const DSA_SHA1 = XMLSecurityKey::DSA_SHA1;
    const RSA_SHA1 = XMLSecurityKey::RSA_SHA1;
    const RSA_SHA256 = XMLSecurityKey::RSA_SHA256;
    const RSA_SHA384 = XMLSecurityKey::RSA_SHA384;
    const RSA_SHA512 = XMLSecurityKey::RSA_SHA512;
    const HMAC_SHA1 = XMLSecurityKey::HMAC_SHA1;

    /** @const array The context each option applies to (see
    _checkOptions()). */
    private const OPTION_CONTEXTS = [
        'base64Encode'                 => 'creation',
        'xmldsigNsPrefix'              => 'creation',
        'audience'                     => 'creation',
        'validity'                     => 'creation',
        'expectedAudience'             => 'analysis',
        'canonicalizationAlgorithm'    => 'any',
        'signatureAlgorithm'           => 'any',
        'digestAlgorithm'              => 'any',
        'checkSigningAlgorithms'       => 'analysis',
        'caCertPath'                   => 'analysis',
        'signerCertPath'               => 'analysis',
        'expectedSubject'              => 'analysis',
        'sessionKeyCipheringAlgorithm' => 'encryption',
        'cryptAlgorithm'               => 'encryption',
        'checkCryptingAlgorithms'      => 'decryption',
    ];

    /** @const string The error of every failure that depends on the
    decrypted content (see _decryptToken()). */
    private const DECRYPTION_FAILED = 'Token decryption failed!';


    /* PROPERTIES */

    /** @var string The XML namespace (xmlns) prefix to use in the XML digital
    signature tags. */
    private $xmldsigNsPrefix = self::XMLDSIG_NS_PREFIX;

    /** @var string The algorithm that should be used to canonicalize the node
    "ds:Signature/ds:SignedInfo" of the XML digital signature before signing
    it. */
    private $canonicalizationAlgorithm = self::C14N;

    /** @var string The algorithm that should be used to sign the computed hash
    of the token. */
    private $signatureAlgorithm = self::RSA_SHA256;

    /** @var string The algorithm that should be used to compute the hash of the
    token. */
    private $digestAlgorithm = self::SHA256;

    /** @var string The algorithm that should be used to canonicalize the token
    before computing its hash. NOTE: In our case, it is the same algorithm as
    the one used to canonicalize the node "ds:Signature/ds:signedInfo"
    (see: $canonicalizationAlgorithm property). */
    private $transformAlgorithm = self::C14N;

    /** @var boolean Whether to check the algorithms actually used (read from
    the XML digital signature) to sign the token or not. */
    private $checkSigningAlgorithms = true;

    /** @var string The algorithm that should be used to generate the session
    key which will be used to encrypt the token. */
    private $sessionKeyCipheringAlgorithm = self::AES256_GCM;

    /** @var string The algorithm that should be used to encrypt the token with
    the generated session key. */
    private $cryptAlgorithm = self::RSA_OAEP_MGF1P;

    /** @var boolean Whether to check the algorithms actually used (read from
    the XML digital signature) to encrypt the token or not. */
    private $checkCryptingAlgorithms = true;

    /** @var DOMXPath The DOMXPath object used to navigate through the XML
    digital signature enveloping the token. */
    private $xpath = null;

    /** @var string The content of the private key used to sign the token
    data. */
    private $signKey = null;

    /** @var string The password to access the private key used to sign the
    token data. */
    private $signKeyPassword = null;

    /** @var string The content of the X.509 certificate associated to the
    private key (cf. $signKey) used to sign the token. This certificate is
    included in the XML token, in order to verify that the XML
    Digital Signature is valid. */
    private $signCert = null;

    /** @var string The content of the private key used to decrypt the token. */
    private $cryptKey = null;

    /** @var string The password to access the private key used to decrypt the
    token. */
    private $cryptKeyPassword = null;

    /** @var string The content of the X.509 certificate associated to the
    private key used to encrypt the session key used to encrypt the token. */
    private $cryptCert = null;

    /** @var string The XML digital signature enveloping the token. */
    private $xml = null;

    /** @var array The token data (a flat or multidimensional associative
    array). */
    private $data = null;

    /** @var boolean Flag that indicates whether the token data should be base64
    encoded when building the XML token or not. */
    private $base64EncodeData = true;

    /** @var string The token timestamp (format: 'yyyy-MM-ddThh:mm:ssZ'). */
    private $timestamp = null;

    /** @var string The token identifier (see getTokenId()). */
    private $tokenId = null;

    /** @var array|null The audiences of the token to create (option
    "audience"). */
    private $audienceToWrite = null;

    /** @var array|null The audiences read from the token (see
    getAudience()). */
    private $audience = null;

    /** @var int|null The validity of the token to create, in seconds (option
    "validity"). */
    private $validity = null;

    /** @var string|null The token expiry (format: 'yyyy-MM-ddThh:mm:ssZ', see
    getExpiry()). */
    private $expiry = null;

    /** @var boolean Whether the analyzed token has a node "TokenExpiry",
    well formed or not (see isOutOfDate()). */
    private $hasExpiryNode = false;

    /** @var string|null The audience the analyzed token must be addressed to
    (option "expectedAudience"). */
    private $expectedAudience = null;

    /** @var X509Cert The X.509 certificate included in the XML Digital
    Signature. */
    private $x509Certificate = null;

    /** @var array|null The paths of the PEM files holding the trusted CA
    certificates (option "caCertPath"). */
    private $trustedCACertPaths = null;

    /** @var string|null The pinned signing certificate, in PEM format (option
    "signerCertPath"), or, when the object creates a token, the certificate
    of its own signing key. */
    private $pinnedSignerCert = null;

    /** @var array|string|null The subject expected for the signing
    certificate (option "expectedSubject"). */
    private $expectedSubject = null;

    /** @var boolean Flag that indicates whether the X.509 certificate included
    in the XML Digital Signature is trusted or not. */
    private $isCertTrusted = null;

    /** @var boolean Flag that indicates whether the token is encrypted or
    not. */
    private $isDataEncrypted = null;

    /** @var boolean Flag that indicates whether the token hash is valid or
    not. */
    private $isDigestValueOk = null;

    /** @var boolean Flag that indicates whether the token hash signature is
    valid or not. */
    private $isSignatureValueOk = null;

    /** @var string Error encountered during the analysis of
      the XML digital signature enveloping the token. */
    private $error = null;

    /** @var array List of the anomalies encountered during the analysis
      of the XML digital signature enveloping the token. */
    private $anomalies = array();

    /**
     * Defines a custom output for `print_r()` and `var_dump()` functions,
     * in order to hide cryptographic material used by the object for
     * security reasons.
     */
    public function __debugInfo()
    {
        return [
            'isValid'                => $this->isSignatureValid(),
            'isDigestValueOk'        => $this->isDigestValueOk,
            'isSignatureValueOk'     => $this->isSignatureValueOk,
            'isCertTrusted'          => $this->isCertTrusted,
            'isDataEncrypted'        => $this->isDataEncrypted,
            'timestamp'              => $this->timestamp,
            'tokenId'                => $this->getTokenId(),
            'audience'               => $this->getAudience(),
            'expiry'                 => $this->getExpiry(),
            'data'                   => $this->data,
            'error'                  => $this->error,
            'anomalies'              => $this->anomalies
        ];
    }


    /**
     * Instantiate an XMLDSigToken object.
     *
     * This constructor is `protected`. To get an instance of an XMLDSigToken
     * object use one of the following `static` functions according to what the
     * object is intended for:
     *
     * - `createXMLToken()`
     *
     * - `createSecureXMLToken()`
     *
     * - `analyzeXMLToken()`
     *
     * - `analyzeSecureXMLToken()`
     *
     * An XMLDSigToken object allows creating an XML token and also analyzing an
     * existing XML token. The type of the `$xmlOrData` parameter determines how
     * the object behaves.
     *
     * **XML token creation:**
     *
     * If `$xmlOrData` is an array (a flat or multidimensional associative
     * array), the object will create an enveloping XML digital signature
     * containing an XML token that holds the provided data and a timestamp
     * generated automatically, with a random identifier (see `getTokenId()`).
     * In this case, the `$signKeyPath` and `$signCertPath` parameters are
     * required. If the `$cryptCertPath` parameter is also provided, the XML
     * token will be encrypted for the owner of this certificate. The
     * `$cryptKeyPath` parameter, the private key of the recipient, is
     * optional: given, it is used to decrypt the created token and check its
     * content too. If this private key is protected by a password, this
     * password may be passed using the `$cryptKeyPassword` parameter.
     *
     * **XML token analysis:**
     *
     * If `$xmlOrData` is a string, the object will treat it as an enveloping
     * XML digital signature containing a token:
     *
     * - It will check that the signature is valid.
     *
     * - It will decrypt the token if this one is encrypted.
     *
     * - It will extract timestamp and data from the token.
     *
     * In this case, the `$xmlOrData` parameter and a trust anchor (the
     * options `caCertPath` and/or `signerCertPath`, see below) are required:
     * without a trust anchor, no token is valid. If the XML
     * token is encrypted, the `$cryptKeyPath` parameter must also be provided.
     * If the private key used for decryption (cf. `$cryptKeyPath` parameter) is
     * protected by a password, this password may be passed using the
     * `$cryptKeyPassword` parameter.
     *
     * When the object creates a token, it analyzes it right away to check it,
     * and trusts the certificate of its own signing key (`$signCertPath`) for
     * that: the trust options do not apply to token creation. An encrypted
     * token created without `$cryptKeyPath` is checked up to its decryption
     * (structure, algorithms, digest, signature, trust in the signing
     * certificate) and its content is not read (see `createSecureXMLToken()`).
     *
     * **Configuring the object:**
     *
     * The `$options` parameter of this function allows to override the default
     * configuration of the object passing it the desired options via an
     * associative array.
     *
     * Example:
     *
     * ```php
     * $options = [
     *   'base64Encode' => false,
     *   'xmldsigNsPrefix' => ''
     * ];
     * ```
     *
     * Each option applies to a context: token creation (`createXMLToken()`,
     * `createSecureXMLToken()`), token analysis (`analyzeXMLToken()`,
     * `analyzeSecureXMLToken()`), or both. The encryption options only apply
     * when an encryption certificate (creation) or a decryption key
     * (analysis) is given. An unknown option, an option given out of its
     * context, or an option whose value is NULL or invalid throws an
     * exception.
     *
     * The algorithm options apply to both contexts: at creation, they are the
     * algorithms the token is built with; at analysis, the algorithms the
     * token must have been built with. A token built with other algorithms is
     * rejected (`getError()` lists them), unless `checkSigningAlgorithms` or
     * `checkCryptingAlgorithms` is FALSE. To analyze a token built with
     * RSA-SHA1 and SHA-1:
     *
     * ```php
     * $options = [
     *   'caCertPath' => ['intermediate.cert.pem', 'root.cert.pem'],
     *   'signatureAlgorithm' => XMLDSigToken::RSA_SHA1,
     *   'digestAlgorithm' => XMLDSigToken::SHA1
     * ];
     * ```
     *
     * Available options are the following:
     *
     * - **`caCertPath`** [string|array] Analysis only. The path, or the list
     *   of paths, of PEM files holding the trusted CA certificates. The
     *   signing certificate is only trusted if OpenSSL builds and verifies
     *   its chain, from these certificates only, up to a self-signed
     *   certificate of these files (see `X509Cert::isTrustedBy()`). To trust
     *   the certificates issued by an intermediate CA, give its certificate
     *   and the certificates up to its root, in one file or in several:
     *   `['intermediate.cert.pem', 'root.cert.pem']`. A chain that stops at
     *   an intermediate CA is rejected: with the intermediate CA alone,
     *   `isSignatureValid()` returns FALSE and `getError()` returns "Signing
     *   certificate is not issued by a trusted CA: its chain could not be
     *   verified up to the CA certificates of the option 'caCertPath', which
     *   must hold the issuing CA and the certificates up to its root!".
     *   Only the signing certificate is taken from the token, so a
     *   certificate issued by another intermediate CA of the same root is
     *   rejected; a certificate issued directly by a CA of the files (the
     *   root included) is accepted.
     *   <br/>Default value: none.
     *
     * - **`signerCertPath`** [string] Analysis only. The path to the PEM
     *   certificate the token must be signed with (certificate pinning): the
     *   signing certificate must be this very certificate. Given alone, it is
     *   the trust anchor; given with `caCertPath`, both are required.
     *   <br/>Default value: none.
     *
     * - **`expectedSubject`** [string|array] Analysis only. The subject the
     *   signing certificate must have, either:
     *
     *   - an array of the subject fields to check, as returned by
     *     `getCertSubject()`: `['O' => 'Lothbrok Ltd', 'OU' => 'Jarl Dept']`.
     *     Fields that are not given are not checked.
     *
     *   - or a string, compared as is with the full Distinguished Name
     *     returned by `getCertDN()`. This is the OpenSSL "oneline" format
     *     (`openssl_x509_parse()`, key `name`): every field of the subject,
     *     in the order of the certificate, each written `/<short name>=<value>`
     *     with no space and no escaping, e.g.
     *     `'/C=DK/ST=Jylland/L=Kattegat/O=Lothbrok Ltd/OU=Signature Dept/CN=www.lothbrok.dk/emailAddress=ivar@lothbrok.dk'`.
     *     It is neither the RFC 2253 form (`CN=...,O=...`) nor the form
     *     printed by the `openssl` command line (`C=DK, ST=...`): copy it
     *     from `getCertDN()` or `X509Cert::getDN()`.
     *
     *   Character case is significant. It does not replace a trust anchor.
     *   <br/>Default value: none.
     *
     * - **`expectedAudience`** [string] Analysis only. The audience of this
     *   receiver, which the token must be addressed to (see `audience`):
     *   `isSignatureValid()` returns FALSE if the token names no audience or
     *   does not name this one. A token that names audiences is rejected
     *   when this option is not given, so that a receiver of the issuer
     *   cannot accept a token addressed to another one. Compared as is
     *   (character case included).
     *   <br/>Default value: none.
     *
     * - **`audience`** [string|array] Creation only. The audience, or the
     *   list of audiences, the token is addressed to: names of the receivers
     *   (an application name, a URL...), agreed between the issuer and each
     *   receiver. Each one is a non-empty string, with no surrounding white
     *   space and no control character. They are written in the token,
     *   covered by the signature (see `getAudience()`).
     *   <br/>Default value: none (the token names no audience).
     *
     * - **`validity`** [int] Creation only. The number of seconds after which
     *   the token is out of date, whatever the time to live the receiver
     *   gives to `isOutOfDate()`. The expiry date is written in the token,
     *   covered by the signature (see `getExpiry()`).
     *   <br/>Default value: none (only the receiver sets the time to live).
     *
     * - **`base64Encode`** [boolean] Creation only. Whether to base64 encode
     *   token data or not.
     *   <br/>Default value: **`TRUE`**.
     *
     * - **`xmldsigNsPrefix`** [string] Creation only. The XML namespace
     *   (xmlns) prefix to use in the XML digital signature tags. Set it to
     *   empty string to avoid prefix usage.
     *   <br/>Default value: **`'ds'`**.
     *
     * - **`checkSigningAlgorithms`** [boolean] Analysis only. Whether to
     *   check that the algorithms used to sign the token are the expected
     *   ones or not. Even when FALSE, an algorithm that is not in the lists
     *   below is rejected.
     *   <br/>Default value: **`TRUE`**.
     *
     * - **`checkCryptingAlgorithms`** [boolean] Analysis with a decryption
     *   key only. Whether to check that the algorithms used to encrypt the
     *   token are the expected ones or not. Even when FALSE, an algorithm
     *   that is not in the lists below is rejected.
     *   <br/>Default value: **`TRUE`**.
     *
     * - **`canonicalizationAlgorithm`** [string] Creation and analysis. The
     *   algorithm used to canonicalize the XML digital signature and to
     *   canonicalize token data before computing its hash.
     *   <br/>Possible values:
     *
     *   - **`C14N`** (Default value)
     *     <br/>cf. http://www.w3.org/TR/2001/REC-xml-c14n-20010315
     *
     *   - `C14N_COMMENTS`
     *     <br/>cf. http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments
     *
     *   - `EXC_C14N`
     *     <br/>cf. http://www.w3.org/2001/10/xml-exc-c14n#
     *
     *   - `EXC_C14N_COMMENTS`
     *     <br/>cf. http://www.w3.org/2001/10/xml-exc-c14n#WithComments
     *
     * - **`signatureAlgorithm`** [string] Creation and analysis. The
     *   asymmetric algorithm used to sign the hash of token data. Key
     *   transport algorithms (see `cryptAlgorithm`) are rejected.
     *   <br/>Possible values:
     *
     *   - `RSA_SHA1`
     *     <br/>cf. http://www.w3.org/2000/09/xmldsig#rsa-sha1
     *
     *   - **`RSA_SHA256`** (Default value)
     *     <br/>cf. http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
     *
     *   - `RSA_SHA384`
     *     <br/>cf. http://www.w3.org/2001/04/xmldsig-more#rsa-sha384
     *
     *   - `RSA_SHA512`
     *     <br/>cf. http://www.w3.org/2001/04/xmldsig-more#rsa-sha512
     *
     * - **`digestAlgorithm`** [string] Creation and analysis. The algorithm
     *   used to compute the hash of token data.
     *   <br/>Possible values:
     *
     *   - `SHA1`
     *     <br/>cf. http://www.w3.org/2000/09/xmldsig#sha1
     *
     *   - **`SHA256`** (Default value)
     *     <br/>cf. http://www.w3.org/2001/04/xmlenc#sha256
     *
     *   - `SHA384`
     *     <br/>cf. http://www.w3.org/2001/04/xmldsig-more#sha384
     *
     *   - `SHA512`
     *     <br/>cf. http://www.w3.org/2001/04/xmlenc#sha512
     *
     *   - `RIPEMD160`
     *     <br/>cf. http://www.w3.org/2001/04/xmlenc#ripemd160
     *
     * - **`sessionKeyCipheringAlgorithm`** [string] Encryption only
     *   (creation with an encryption certificate, analysis with a decryption
     *   key). The symmetric algorithm used to encrypt token data with a
     *   generated session key.
     *   <br/>Possible values:
     *
     *   - `AES128_GCM`
     *     <br/>cf. http://www.w3.org/2009/xmlenc11#aes128-gcm
     *
     *   - `AES192_GCM`
     *     <br/>cf. http://www.w3.org/2009/xmlenc11#aes192-gcm
     *
     *   - **`AES256_GCM`** (Default value)
     *     <br/>cf. http://www.w3.org/2009/xmlenc11#aes256-gcm
     *
     *   - `TRIPLEDES_CBC`
     *     <br/>cf. http://www.w3.org/2001/04/xmlenc#tripledes-cbc
     *
     *   - `AES128_CBC`
     *     <br/>cf. http://www.w3.org/2001/04/xmlenc#aes128-cbc
     *
     *   - `AES192_CBC`
     *     <br/>cf. http://www.w3.org/2001/04/xmlenc#aes192-cbc
     *
     *   - `AES256_CBC`
     *     <br/>cf. http://www.w3.org/2001/04/xmlenc#aes256-cbc
     *
     *   The CBC algorithms do not protect the integrity of the data: only
     *   the signature does. An analysis only decrypts a token encrypted with
     *   one of them if this option names it, even when
     *   `checkCryptingAlgorithms` is FALSE.
     *
     * - **`cryptAlgorithm`** [string] Encryption only (creation with an
     *   encryption certificate, analysis with a decryption key). The
     *   asymmetric algorithm used to encrypt the session key with the
     *   encryption certificate (key transport). Signature algorithms (see
     *   `signatureAlgorithm`) are rejected, and so is RSA 1.5
     *   (http://www.w3.org/2001/04/xmlenc#rsa-1_5), at creation as at
     *   analysis.
     *   <br/>Possible values:
     *
     *   - **`RSA_OAEP_MGF1P`** (Default value)
     *     <br/>cf. http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p
     *
     * @param mixed $xmlOrData An XML token (string) or token data (associative
     *     array).
     *
     * @param string $signKeyPath The path to the PEM private key file that will
     *     be used to sign the token.
     *
     * @param string $signKeyPassword The password, if needed, to access the
     *     private key that will be used to sign the token. Use NULL if no
     *     password needed.
     *
     * @param string $signCertPath The path to the PEM X.509 certificate file
     *     that will be included in the XML digital signature, in order to
     *     verify the signature.
     *
     * @param string|null $cryptKeyPath The path to the PEM private key file
     *     that will be used to decrypt the session key which was used to
     *     encrypt the token. Required to analyze an encrypted token, optional
     *     to create one.
     *
     * @param string|null $cryptKeyPassword The password to access the private
     *     key that will be used to decrypt the session key which was used to
     *     encrypt the token. Use NULL if no password needed.
     *
     * @param string $cryptCertPath The path to the PEM X.509 certificate file
     *     that will be used to encrypt the session key which will be used to
     *     encrypt the token.
     *
     * @param array $options Configuration options.
     *
     * @throws Exception
     *
     * @see createXMLToken(), createSecureXMLToken(), analyzeXMLToken(),
     *     analyzeSecureXMLToken()
     */
    protected function __construct(
            $xmlOrData,
            $signKeyPath = null,
            $signKeyPassword = null,
            $signCertPath = null,
            $cryptKeyPath = null,
            $cryptKeyPassword = null,
            $cryptCertPath = null,
            $options = []
        )
    {
        if (!is_array($xmlOrData) && !is_string($xmlOrData))
        {
            throw new Exception("Invalid parameter 'xmlOrData'! Parameter must be either an array or a string!");
        }

        // Check the options against what the object is created for: an
        // unknown option, or an option that does not apply here, throws
        // (see _checkOptions()).
        $isCreation = is_array($xmlOrData);
        self::_checkOptions($options, $isCreation, !is_null($isCreation ? $cryptCertPath : $cryptKeyPath));

        // Load configuration options.
        $base64Encode = isset($options['base64Encode']) ? $options['base64Encode'] : true;

        $xmldsigNsPrefix = isset($options['xmldsigNsPrefix']) ? $options['xmldsigNsPrefix'] : null;

        $checkSigningAlgorithms = isset($options['checkSigningAlgorithms']) ? $options['checkSigningAlgorithms'] : true;
        $checkCryptingAlgorithms = isset($options['checkCryptingAlgorithms']) ? $options['checkCryptingAlgorithms'] : true;

        $canonicalizationAlgorithm = isset($options['canonicalizationAlgorithm']) ? $options['canonicalizationAlgorithm'] : null;
        $signatureAlgorithm = isset($options['signatureAlgorithm']) ? $options['signatureAlgorithm'] : null;
        $digestAlgorithm = isset($options['digestAlgorithm']) ? $options['digestAlgorithm'] : null;
        $sessionKeyCipheringAlgorithm = isset($options['sessionKeyCipheringAlgorithm']) ? $options['sessionKeyCipheringAlgorithm'] : null;
        $cryptAlgorithm = isset($options['cryptAlgorithm']) ? $options['cryptAlgorithm'] : null;

        // If provided, set and store the canonicalization algorithm.
        if (!is_null($canonicalizationAlgorithm))
        {
            if (self::_isValidCanonicalizationAlgorithm($canonicalizationAlgorithm))
            {
                $this->canonicalizationAlgorithm = $canonicalizationAlgorithm;
                $this->transformAlgorithm        = $canonicalizationAlgorithm;
            }
            else
            {
                throw new Exception("Invalid parameter 'canonicalizationAlgorithm'! Unknown canonicalization algorithm.");
            }
        }

        // If provided, set and store the signature algorithm.
        if (!is_null($signatureAlgorithm))
        {
            if (self::_isValidSignatureAlgorithm($signatureAlgorithm))
            {
                $this->signatureAlgorithm = $signatureAlgorithm;
            }
            else
            {
                throw new Exception("Invalid parameter 'signatureAlgorithm'! Unknown signature algorithm.");
            }
        }

        // If provided, set and store the digest algorithm.
        if (!is_null($digestAlgorithm))
        {
            if (self::_isValidHashAlgorithm($digestAlgorithm))
            {
                $this->digestAlgorithm = $digestAlgorithm;
            }
            else
            {
                throw new Exception("Invalid parameter 'digestAlgorithm'! Unknown digest algorithm.");
            }
        }

        // If requested, disable check of signature algorithms.
        if (false === $checkSigningAlgorithms)
        {
            $this->checkSigningAlgorithms = false;
        }

        // Check what have to be done according to the type of $xmlOrData
        // parameter.
        if ($isCreation)
        {
            // $xmlOrData is an array, so we have to create an XML token.

            // Check that $data is a non-empty array.
            if (empty($xmlOrData))
            {
                throw new Exception("Invalid parameter 'data'! Token data should not be an empty array.");
            }

            // Check that $data is an associative array.
            if (count(array_filter(array_keys($xmlOrData), 'is_string')) == 0)
            {
                throw new Exception("Invalid parameter 'data'! Token data should be an associative array.");
            }

            // If requested, disable base64 encoding of token data.
            if (false === $base64Encode)
            {
                $this->base64EncodeData = false;
            }

            // If provided, store the audiences and the validity of the token
            // (checked by _checkOptions()).
            if (isset($options['audience']))
            {
                $this->audienceToWrite = (array) $options['audience'];
            }
            if (isset($options['validity']))
            {
                $this->validity = $options['validity'];
            }

            // Check that required private key and X.509 certificate
            // are provided, in order to sign the token.
            if (is_null($signKeyPath))
            {
                throw new Exception("Missing parameter 'signKeyPath'! A private key is required to sign token.");
            }

            // Check that required private key and X.509 certificate
            // are provided, in order to sign the token.
            if (is_null($signCertPath))
            {
                throw new Exception("Missing parameter 'signCertPath'! An X.509 certificate is required to sign token.");
            }

            // Get and store the private key that will be used to sign the token
            // data.
            $signKey = @file_get_contents($signKeyPath);
            if (false === $signKey)
            {
                throw new Exception("Invalid parameter 'signKeyPath'! Cannot read private key to sign token.");
            }
            $this->signKey = $signKey;

            // If provided, store the password to access the private key that
            // will be used to sign the token data.
            if (!is_null($signKeyPassword))
            {
                if (!is_string($signKeyPassword))
                {
                    throw new Exception("Invalid parameter 'signKeyPassword'! Parameter must be a string.");
                }
                $this->signKeyPassword = $signKeyPassword;
            }

            // Get and store the X.509 certificate that will be included in the
            // XML token.
            $signCert = @file_get_contents($signCertPath);
            if (false === $signCert)
            {
                throw new Exception("Invalid parameter 'signCertPath'! Cannot read X.509 certificate to sign token.");
            }
            $this->signCert = $signCert;

            // The created token is analyzed to check it (see _writeXML()): it
            // must be signed with this very certificate.
            $this->pinnedSignerCert = $signCert;

            // If provided, store the prefix namespace to use in the XML digital
            // signature tags.
            if (!is_null($xmldsigNsPrefix))
            {
                if (!is_string($xmldsigNsPrefix))
                {
                    throw new Exception("Invalid parameter 'xmldsigNsPrefix'! Parameter must be a string.");
                }
                $this->xmldsigNsPrefix = $xmldsigNsPrefix;
            }

            // If provided, get and store X.509 certificate that will be used
            // to encrypt the session key which will be used to encrypt the
            // token data.
            if (!is_null($cryptCertPath))
            {
                $cryptCert = @file_get_contents($cryptCertPath);
                if (false === $cryptCert)
                {
                    throw new Exception("Invalid parameter 'cryptCertPath'! Cannot read X.509 certificate to encrypt token.");
                }
                $this->cryptCert = $cryptCert;

                // If provided, get and store the private key of the recipient,
                // which decrypts the session key: it is only used to check
                // the decrypted content of the created token. Without it, the
                // created token is checked up to its decryption (see
                // _readXML()), so that the sender needs no private key of the
                // recipient.
                if (!is_null($cryptKeyPath))
                {
                    $cryptKey = @file_get_contents($cryptKeyPath);
                    if (false === $cryptKey)
                    {
                        throw new Exception("Invalid parameter 'cryptKeyPath'! Cannot read private key to decrypt token.");
                    }
                    $this->cryptKey = $cryptKey;
                }

                // If provided, store the password to access the private key
                // that will be used to decrypt the session key. A password
                // without a key would be ignored: it throws instead.
                if (!is_null($cryptKeyPassword))
                {
                    if (is_null($cryptKeyPath))
                    {
                        throw new Exception("Invalid parameter 'cryptKeyPassword'! It only applies with the parameter 'cryptKeyPath'.");
                    }
                    if (!is_string($cryptKeyPassword))
                    {
                        throw new Exception("Invalid parameter 'cryptKeyPassword'! Parameter must be a string.");
                    }
                    $this->cryptKeyPassword = $cryptKeyPassword;
                }

                // If provided, set and store the session key algorithm.
                if (!is_null($sessionKeyCipheringAlgorithm))
                {
                    if (self::_isValidSymmetricCipheringAlgorithm($sessionKeyCipheringAlgorithm))
                    {
                        $this->sessionKeyCipheringAlgorithm = $sessionKeyCipheringAlgorithm;
                    }
                    else
                    {
                        throw new Exception("Invalid parameter 'sessionKeyCipheringAlgorithm'! Unknown session key ciphering algorithm.");
                    }
                }

                // If provided, set and store the crypt algorithm.
                if (!is_null($cryptAlgorithm))
                {
                    if (self::_isValidKeyTransportAlgorithm($cryptAlgorithm))
                    {
                        $this->cryptAlgorithm = $cryptAlgorithm;
                    }
                    else
                    {
                        throw new Exception("Invalid parameter 'cryptAlgorithm'! Unknown crypt algorithm.");
                    }
                }

                // If requested, disable check of used crypt algorithms.
                if (false === $checkCryptingAlgorithms)
                {
                    $this->checkCryptingAlgorithms = false;
                }
            }

            // Create an XML token with the provided data.
            try
            {
                // NOTE: This function will call the _readXML() function which
                // will verify that the created token is correct and which will
                // terminate setting object properties.
                $this->_writeXML($xmlOrData);
            }
            catch (Exception $e)
            {
                // ERROR: XML token analysis failed on fatal error.
                $this->error = $e->getMessage();
            }
        }
        else
        {
            // $xmlOrData is a string, so we have to analyze the XML token.

            // Load the trust anchor. Its absence is not an error here: the
            // analysis then reports that no certificate can be trusted (see
            // _verifyCertTrust()).
            $this->_loadTrustOptions($options);

            // If provided, store the audience the token must be addressed to
            // (checked by _checkOptions(), see _verifyAudience()).
            if (isset($options['expectedAudience']))
            {
                $this->expectedAudience = $options['expectedAudience'];
            }

            // If provided, get and store the private key that will be used
            // to decrypt the session key which was used to encrypt the token.
            if (!is_null($cryptKeyPath))
            {
                $cryptKey = @file_get_contents($cryptKeyPath);
                if (false === $cryptKey)
                {
                    throw new Exception("Invalid parameter 'cryptKeyPath'! Cannot read private key to decrypt token.");
                }
                $this->cryptKey = $cryptKey;

                // If provided, store the password to access the private key
                // that will be used to decrypt the session key.
                if (!is_null($cryptKeyPassword))
                {
                    if (!is_string($cryptKeyPassword))
                    {
                        throw new Exception("Invalid parameter 'cryptKeyPassword'! Parameter must be a string.");
                    }
                    $this->cryptKeyPassword = $cryptKeyPassword;
                }

                // If provided, set and store the session key algorithm.
                if (!is_null($sessionKeyCipheringAlgorithm))
                {
                    if (self::_isValidSymmetricCipheringAlgorithm($sessionKeyCipheringAlgorithm))
                    {
                        $this->sessionKeyCipheringAlgorithm = $sessionKeyCipheringAlgorithm;
                    }
                    else
                    {
                        throw new Exception("Invalid parameter 'sessionKeyCipheringAlgorithm'! Unknown session key ciphering algorithm.");
                    }
                }

                // If provided, set and store the crypt algorithm.
                if (!is_null($cryptAlgorithm))
                {
                    if (self::_isValidKeyTransportAlgorithm($cryptAlgorithm))
                    {
                        $this->cryptAlgorithm = $cryptAlgorithm;
                    }
                    else
                    {
                        throw new Exception("Invalid parameter 'cryptAlgorithm'! Unknown crypt algorithm.");
                    }
                }

                // If requested, disable check of used crypt algorithms.
                if (false === $checkCryptingAlgorithms)
                {
                    $this->checkCryptingAlgorithms = false;
                }
            }

            // Parse the provided XML token to ensure all is correct and to
            // terminate initializing object properties.
            try
            {
                $this->_readXML($xmlOrData);
            }
            catch (Exception $e)
            {
                // ERROR: XML token analysis failed on fatal error.
                $this->error = $e->getMessage();
            }
        }
    }


    /**
     * Check the options given to the object against what it is created for.
     *
     * Each option is only read in its context (see `OPTION_CONTEXTS`): token
     * creation, token analysis, both ("any"), encryption (creation with an
     * encryption certificate, or analysis with a decryption key) or
     * decryption (analysis with a decryption key). A misspelt option, or an
     * option given out of its context, would be ignored without notice and
     * leave the token without the configuration the caller asked for: it
     * throws an exception instead, as does an option whose value is NULL or
     * of the wrong type. The values of the algorithm and trust options are
     * checked where they are loaded.
     *
     * @param array $options Configuration options.
     *
     * @param boolean $isCreation TRUE if the object creates a token, FALSE if
     *     it analyzes one.
     *
     * @param boolean $isEncryption TRUE if an encryption certificate (token
     *     creation) or a decryption key (token analysis) is given.
     *
     * @throws Exception
     */
    static private function _checkOptions($options, $isCreation, $isEncryption)
    {
        if (!is_array($options))
        {
            throw new Exception("Invalid parameter 'options'! Parameter must be an array.");
        }

        foreach ($options as $name => $value)
        {
            if (!isset(self::OPTION_CONTEXTS[$name]))
            {
                throw new Exception("Unknown option '" . $name . "'!");
            }

            switch (self::OPTION_CONTEXTS[$name])
            {
                case 'creation':
                    if (!$isCreation)
                    {
                        throw new Exception("Option '" . $name . "' only applies to token creation!");
                    }
                    break;
                case 'analysis':
                    if ($isCreation)
                    {
                        throw new Exception("Option '" . $name . "' only applies to token analysis! A created token is checked with the certificate of its own signing key.");
                    }
                    break;
                case 'encryption':
                    if (!$isEncryption)
                    {
                        throw new Exception("Option '" . $name . "' only applies to an encrypted token! Give the encryption certificate (createSecureXMLToken()) or the decryption key (analyzeSecureXMLToken()).");
                    }
                    break;
                case 'decryption':
                    if ($isCreation || !$isEncryption)
                    {
                        throw new Exception("Option '" . $name . "' only applies to the analysis of an encrypted token! Give the decryption key (analyzeSecureXMLToken()).");
                    }
                    break;
            }

            if (is_null($value))
            {
                throw new Exception("Invalid option '" . $name . "'! Its value must not be NULL.");
            }

            if (in_array($name, ['base64Encode', 'checkSigningAlgorithms', 'checkCryptingAlgorithms'], true) && !is_bool($value))
            {
                throw new Exception("Invalid option '" . $name . "'! It must be a boolean.");
            }

            if ('xmldsigNsPrefix' === $name && !is_string($value))
            {
                throw new Exception("Invalid option '" . $name . "'! It must be a string.");
            }

            if ('audience' === $name)
            {
                $audiences = is_array($value) ? $value : [$value];
                if (empty($audiences) || $audiences !== array_values($audiences) || $audiences !== array_filter($audiences, [self::class, '_isValidAudience']))
                {
                    throw new Exception("Invalid option 'audience'! It must be a non-empty string, or a non-empty list of them, without control characters.");
                }
                if (count(array_unique($audiences)) !== count($audiences))
                {
                    throw new Exception("Invalid option 'audience'! An audience is given twice.");
                }
            }

            if ('expectedAudience' === $name && !self::_isValidAudience($value))
            {
                throw new Exception("Invalid option 'expectedAudience'! It must be a non-empty string without control characters.");
            }

            if ('validity' === $name && !(is_int($value) && $value > 0))
            {
                throw new Exception("Invalid option 'validity'! It must be a number of seconds greater than 0.");
            }

            // The expiry is written with a four-digit year: a validity that
            // takes it past the year 9999 (or past the range of an integer)
            // could not be written, and would be computed wrong.
            if ('validity' === $name && $value > self::MAX_EXPIRY_TIME - time())
            {
                throw new Exception("Invalid option 'validity'! The expiry would be after 9999-12-31T23:59:59Z.");
            }
        }
    }


    /**
     * Indicates whether a value can be an audience of a token (options
     * "audience" and "expectedAudience"): a non-empty UTF-8 string, without
     * surrounding white space, made of characters XML 1.0 can hold as text.
     *
     * Control characters are refused: XML 1.0 cannot hold most of them, and
     * the others (tab, line feed, carriage return) are normalized by XML
     * parsers, so that the audience read back would differ from the one
     * written. So are U+FFFE and U+FFFF, which XML 1.0 cannot hold either.
     *
     * @param mixed $audience The value to check.
     *
     * @return boolean TRUE if the value can be an audience, FALSE otherwise.
     */
    static private function _isValidAudience($audience)
    {
        return is_string($audience)
            && '' !== $audience
            && trim($audience) === $audience
            && 1 === preg_match('//u', $audience)
            && 0 === preg_match('/[\x00-\x1F\x7F]|[^\x{20}-\x{D7FF}\x{E000}-\x{FFFD}\x{10000}-\x{10FFFF}]/u', $audience);
    }


    /**
     * Load and check the trust options of an analysis ("caCertPath",
     * "signerCertPath" and "expectedSubject", see `__construct()`).
     *
     * A trust option of the wrong type, or naming a file that cannot be read,
     * throws an exception instead of being ignored: ignoring it would leave
     * the token without the constraint the caller asked for.
     *
     * @param array $options Configuration options.
     *
     * @throws Exception
     */
    private function _loadTrustOptions($options)
    {
        if (isset($options['caCertPath']))
        {
            $caCertPaths = $options['caCertPath'];
            if (is_string($caCertPaths))
            {
                $caCertPaths = [$caCertPaths];
            }
            if (!is_array($caCertPaths) || empty($caCertPaths))
            {
                throw new Exception("Invalid option 'caCertPath'! It must be a path or a non-empty list of paths.");
            }
            foreach ($caCertPaths as $caCertPath)
            {
                if (!is_string($caCertPath) || !is_file($caCertPath) || !is_readable($caCertPath))
                {
                    throw new Exception("Invalid option 'caCertPath'! Cannot read CA certificate file: " . (is_string($caCertPath) ? $caCertPath : gettype($caCertPath)) . ".");
                }
            }
            $this->trustedCACertPaths = array_values($caCertPaths);
        }

        if (isset($options['signerCertPath']))
        {
            $signerCert = is_string($options['signerCertPath']) ? @file_get_contents($options['signerCertPath']) : false;
            if (false === $signerCert || false === @openssl_x509_read($signerCert))
            {
                throw new Exception("Invalid option 'signerCertPath'! Cannot read the pinned X.509 certificate.");
            }
            $this->pinnedSignerCert = $signerCert;
        }

        if (isset($options['expectedSubject']))
        {
            $expectedSubject = $options['expectedSubject'];
            if (!(is_string($expectedSubject) || is_array($expectedSubject)) || empty($expectedSubject))
            {
                throw new Exception("Invalid option 'expectedSubject'! It must be a non-empty string or array.");
            }
            $this->expectedSubject = $expectedSubject;
        }
    }


    /**
     * Creates an XML token for the given user data.
     *
     * The created XML token can be retrieved using the function `getXML()`.
     *
     * @param array $data Token data (an associative array that may be
     *     multi-dimensional).
     *
     * @param string $signKeyPath The path to the PEM private key file that will
     *     be used to sign the token.
     *
     * @param string $signCertPath The path to the PEM X.509 certificate file
     *     that will be included in the XML digital signature, in order to
     *     verify the signature.
     *
     * @param string $signKeyPassword The password to access the  private key
     *     that will be used to sign the token. Use NULL if no password needed.
     *
     * @param array $options Configuration options
     *     (see `__construct()` for details).
     *
     * @return XMLDSigToken An XMLDSigToken object. If the token cannot be
     *     created, `getError()` tells why.
     *
     * @throws Exception
     *
     * @see __construct()
     */
    public static function createXMLToken(
            $data,
            $signKeyPath,
            $signCertPath,
            $signKeyPassword = null,
            $options = []
        )
    {
        return new XMLDSigToken(
            $data,
            $signKeyPath,
            $signKeyPassword,
            $signCertPath,
            $cryptKeyPath = null,
            $cryptKeyPassword = null,
            $cryptCertPath = null,
            $options
        );
    }


    /**
     * Creates a secure (encrypted) XML token for the given user data.
     *
     * The created XML token can be retrieved using the function `getXML()`.
     *
     * The token is encrypted for the owner of the encryption certificate
     * (`$cryptCertPath`): only the private key of this certificate decrypts
     * it. The sender does not need this private key: pass NULL as
     * `$cryptKeyPath`.
     *
     * ```php
     * $token = XMLDSigToken::createSecureXMLToken($data, $signKeyPath, $signCertPath, null, $cryptCertPath, $signKeyPassword);
     * ```
     *
     * The created token is checked right away:
     *
     * - Without `$cryptKeyPath`, the check covers everything that can be
     *   verified without decrypting the token: its structure, its
     *   algorithms, its digest, its signature and the trust in the signing
     *   certificate. `isSignatureValid()` and `isDataEncrypted()` return
     *   TRUE, while `getData()`, `getTimestamp()` and `getTokenId()` return
     *   NULL: they are inside the encrypted content, which is not decrypted.
     *
     * - With `$cryptKeyPath`, the token is also decrypted and its content
     *   read, as by `analyzeSecureXMLToken()`: `getData()`, `getTimestamp()`
     *   and `getTokenId()` return what the decrypted token holds.
     *
     * @param array $data Token data (an associative array that may be
     *     multi-dimensional).
     *
     * @param string $signKeyPath The path to the PEM private key file that will
     *     be used to sign the token.
     *
     * @param string $signCertPath The path to the PEM X.509 certificate file
     *     that will be included in the XML digital signature, in order to
     *     verify the signature.
     *
     * @param string|null $cryptKeyPath The path to the PEM private key file of
     *     the recipient, associated to `$cryptCertPath`, used to decrypt the
     *     created token in order to check its content. Use NULL to create the
     *     token without it.
     *
     * @param string $cryptCertPath The path to the PEM X.509 certificate file
     *     that will be used to encrypt the session key which will be used to
     *     encrypt the token.
     *
     * @param string $signKeyPassword The password to access the private key
     *     that will be used to sign the token. Use NULL if no password needed.
     *
     * @param string|null $cryptKeyPassword The password to access the private
     *     key `$cryptKeyPath`. Use NULL if no password needed, and when
     *     `$cryptKeyPath` is NULL.
     *
     * @param array $options Configuration options
     *     (see `__construct()` for details).
     *
     * @return XMLDSigToken An XMLDSigToken object. If the token cannot be
     *     created, `getError()` tells why.
     *
     * @throws Exception
     *
     * @see __construct()
     */
    public static function createSecureXMLToken(
            $data,
            $signKeyPath,
            $signCertPath,
            $cryptKeyPath,
            $cryptCertPath,
            $signKeyPassword = null,
            $cryptKeyPassword = null,
            $options = []
        )
    {
        // Without an encryption certificate, the constructor would create an
        // unencrypted token.
        if (is_null($cryptCertPath))
        {
            throw new Exception("Missing parameter 'cryptCertPath'! An X.509 certificate is required to encrypt token.");
        }

        return new XMLDSigToken(
            $data,
            $signKeyPath,
            $signKeyPassword,
            $signCertPath,
            $cryptKeyPath,
            $cryptKeyPassword,
            $cryptCertPath,
            $options
        );
    }


    /**
     * Parse an XML token.
     *
     * The options must hold a trust anchor, `caCertPath` and/or
     * `signerCertPath`; without it, `isSignatureValid()` returns FALSE.
     *
     * ```php
     * $token = XMLDSigToken::analyzeXMLToken($xml, [
     *     'caCertPath' => ['path/to/intermediate.cert.pem', 'path/to/root.cert.pem'],
     * ]);
     * ```
     *
     * @param string $xml An XML token.
     *
     * @param array $options Configuration options, trust anchor included
     *     (see `__construct()` for details).
     *
     * @return XMLDSigToken An XMLDSigToken object. If the token is not
     *     valid, `isSignatureValid()` returns FALSE and `getError()` tells
     *     why.
     *
     * @throws Exception
     *
     * @see __construct()
     */
    public static function analyzeXMLToken(
            $xml,
            $options = []
        )
    {
        return new XMLDSigToken(
            $xml,
            $signKeyPath = null,
            $signKeyPassword = null,
            $signCertPath = null,
            $cryptKeyPath = null,
            $cryptKeyPassword = null,
            $cryptCertPath = null,
            $options
        );
    }


    /**
     * Parse an XML token whose data are encrypted.
     *
     * NOTE: An unencrypted token can also be parsed using this function.
     *
     * The options must hold a trust anchor, `caCertPath` and/or
     * `signerCertPath`; without it, `isSignatureValid()` returns FALSE.
     *
     * @param string $xml An XML token.
     *
     * @param string $cryptKeyPath The path to the PEM private key file that
     *     will be used to decrypt the session key which was used to encrypt
     *     token data.
     *
     * @param string $cryptKeyPassword The password to access the private key
     *     that will be used to decrypt the session key which was used to
     *     encrypt the token. Use NULL if no password needed.
     *
     * @param array $options Configuration options, trust anchor included
     *     (see `__construct()` for details).
     *
     * @return XMLDSigToken An XMLDSigToken object. If the token is not
     *     valid, `isSignatureValid()` returns FALSE and `getError()` tells
     *     why.
     *
     * @throws Exception
     *
     * @see __construct()
     */
    public static function analyzeSecureXMLToken(
            $xml,
            $cryptKeyPath,
            $cryptKeyPassword = null,
            $options = []
        )
    {
        return new XMLDSigToken(
            $xml,
            $signKeyPath = null,
            $signKeyPassword = null,
            $signCertPath = null,
            $cryptKeyPath,
            $cryptKeyPassword,
            $cryptCertPath = null,
            $options
        );
    }


    /**
     * Write the XML Digital Signature representing the XML token for the
     * provided user data.
     *
     * The XML token can then be obtained using the `getXML()` function.
     *
     * @param array $data A flat or multidimensional associative array
     *     containing the token data.
     *
     * @throws Exception
     */
    private function _writeXML($data)
    {
        // Whether to base64 encode data or not.
        $base64Encode = $this->base64EncodeData;

        // Create an XML document to hold the token data.
        $xmlDoc = new DOMDocument('1.0', 'UTF-8');

        // Do not format the XML digital signature when it will be saved as an
        // XML string.
        $xmlDoc->formatOutput = false;

        // Create the root node "Token" that holds the whole content of the
        // token.
        // NOTE: This node is explicitly created without namespace if no
        // namespace is used for XML digital signature tags.
        if ($this->xmldsigNsPrefix === '')
        {
            $tokenElement = $xmlDoc->createElementNS('', self::TOKEN_NAME);
        }
        else
        {
            $tokenElement = $xmlDoc->createElement(self::TOKEN_NAME);
        }
        $tokenNode = $xmlDoc->appendChild($tokenElement);

        // Create a node "timestamp" that holds the token timestamp in the
        // format "YYYY-MM-DDThh:mm:ssZ", using UTC timezone, and append it to
        // the node "Token".
        $dt = new DateTime();
        $dt->setTimeZone(new DateTimeZone('UTC'));
        $tokenTimestampElement = $xmlDoc->createElement('TokenTimestamp', $dt->format(self::TOKEN_TIMESTAMP_FORMAT));
        $tokenTimestampNode = $tokenNode->appendChild($tokenTimestampElement);

        // Create a node "TokenId" that holds a random identifier, in
        // hexadecimal, and append it to the node "Token". The signature
        // covers it: the receiver can refuse a token whose identifier it has
        // already accepted (see getTokenId()).
        $tokenIdElement = $xmlDoc->createElement(self::TOKEN_ID_NAME, bin2hex(random_bytes(self::TOKEN_ID_BYTES)));
        $tokenNode->appendChild($tokenIdElement);

        // If a validity is given, create a node "TokenExpiry" that holds the
        // date after which the token is out of date (see isOutOfDate()), in
        // the format of the timestamp, and append it to the node "Token".
        if (!is_null($this->validity))
        {
            $expiry = clone $dt;
            $expiry->modify('+' . $this->validity . ' seconds');
            $tokenNode->appendChild($xmlDoc->createElement(self::TOKEN_EXPIRY_NAME, $expiry->format(self::TOKEN_TIMESTAMP_FORMAT)));
        }

        // Create a node "TokenAudience" per audience the token is addressed to
        // (see getAudience()), and append them to the node "Token". The value
        // is added as a text node: the second argument of createElement()
        // would read "&" as the start of an entity reference.
        foreach ((array) $this->audienceToWrite as $audience)
        {
            $audienceElement = $xmlDoc->createElement(self::TOKEN_AUDIENCE_NAME);
            $audienceElement->appendChild($xmlDoc->createTextNode($audience));
            $tokenNode->appendChild($audienceElement);
        }

        /**
         * Inline function to build a node tree, whose root node will be named
         * $nodeName, from the array $data and append it to the given
         * $parentNode node. The values of the leaves are base64 encoded by this
         * function.
         *
         * NOTE: This function is called recursively if $data is a
         * multi-dimensional associative array.
         *
         * @param array $data A flat or multi-dimensional associative array that
         *     holds the data to convert in a node tree.
         *
         * @param string $nodeName The name of the node that will hold the node
         *     tree.
         *
         * @param DOMNode $parentNode An existing DOM node to which to append
         *     the node tree.
         */
        $dataToNodeTree = function($data, $nodeName, $parentNode) use (&$dataToNodeTree, $base64Encode)
        {
            if(is_array($data))
            {
                // Appends node.
                $element = $parentNode->ownerDocument->createElement($nodeName);
                $dataNode = $parentNode->appendChild($element);

                // Append child nodes/leaves recursively.
                array_walk($data, $dataToNodeTree, $dataNode);
            }
            else
            {
                // Appends leaf.
                $element = $parentNode->ownerDocument->createElement($nodeName, $base64Encode ? base64_encode($data) : $data);
                if ($base64Encode)
                {
                    $attribute = $parentNode->ownerDocument->createAttribute('Algorithm');
                    $attribute->value = 'base64';
                    $element->appendChild($attribute);
                }
                $dataNode = $parentNode->appendChild($element);
            }
        };

        // Create a node "TokenData" that holds a node tree representing the
        // token data encoded in base64 and append it to the node "Token".
        $dataToNodeTree($data, self::TOKEN_DATA_NAME, $tokenNode);

        // Create an XMLSecurityDSig object.
        // This object will hold the XML Digital Signature we are building.
        $XMLDSig = new XMLSecurityDSig($this->xmldsigNsPrefix);
        $XMLDSig->setCanonicalMethod($this->canonicalizationAlgorithm);

        // Add a node "ds:Object" to the XML Digital Signature and attach our
        // node "Token" to it.
        $objectNode = $XMLDSig->addObject($xmlDoc->documentElement);
        $objectNode->setAttribute('Id', self::TOKEN_NAME);

        // Encrypt our node "Token" if requested (if an X.509 certificate is
        // provided to perform encryption).
        if (!is_null($this->cryptCert))
        {
            // Randomly generate a session key for the symmetric algorithm.
            // This key will be used to cipher our node "Token" (the content of
            // the node "ds:Object").
            $sessionKey = new XMLSecurityKey($this->sessionKeyCipheringAlgorithm);
            $sessionKey->generateSessionKey();

            // Create an asymmetric key from the X.509 certificate using RSA-OAEP
            // algorithm. This key will be used to encrypt the session key.
            $asymKey = new XMLSecurityKey($this->cryptAlgorithm, array('type' => 'public'));
            $asymKey->loadKey($this->cryptCert, false, true);
            if (empty($asymKey->key))
            {
                // ERROR: Failed loading certificate to encrypt session key!
                throw new Exception("Failed loading certificate to encrypt session key!");
            }

            // Encrypt the session key using the asymmetric key.
            $objXMLSecEnc = new XMLSecEnc();
            $objXMLSecEnc->encryptKey($asymKey, $sessionKey);

            // Encrypt the content (cf. XMLSecEnc::Content) of the node
            // "ds:Object" that holds our node "Token" using the encrypted
            // session key.
            $objXMLSecEnc->setNode($objectNode);
            $objXMLSecEnc->type  = XMLSecEnc::Content;
            $encryptedObjectNode = $objXMLSecEnc->encryptNode($sessionKey);
        }

        // Add a reference to the node "ds:Object" which is contained in the
        // XML Digital Signature itself (case of an enveloping signature).
        // This consists of:
        //     - Adding a node "ds:Reference" to the node "ds:SignedInfo".
        //     - Computing a hash, using the digest algorithm, from the
        //       canonicalized XML string corresponding to the node "ds:Object".
        //     - Adding this hash in a child node named "ds:DigestValue".
        //
        // NOTE: Only the first child node of the node "ds:Object" is taken in
        // account to generate the hash which will then be signed.
        $XMLDSig->addReference($objectNode, $this->digestAlgorithm, NULL, array('overwrite' => false, 'force_uri' => true));

        // Create the private key object that will be used to sign the token
        // applying the signature algorithm. If a password is provided, use it
        // to access the private key.
        $privateKey = new XMLSecurityKey($this->signatureAlgorithm, array('type' => 'private'));
        if (!is_null($this->signKeyPassword))
        {
            $privateKey->passphrase = $this->signKeyPassword;
        }

        $privateKey->loadKey($this->signKey, false, false);
        if (empty($privateKey->key))
        {
            // ERROR: Failed loading private key to sign token data!
            throw new Exception("Failed loading private key to sign token data!");
        }

        // Add the X.509 certificate associated to the private key to the XML
        // Digital Signature. So, the recipient of the XML token will not need
        // to own it, in order to verify the signature. It will simply get it
        // from the XML token. This consists of adding a node "ds:KeyInfo" that
        // holds the content of the X.509 certificate.
        $XMLDSig->add509Cert($this->signCert);

        // Sign the token data using the private security key associated to the
        // X.509 certificate.
        // This consists of:
        //     - Computing the signature of the node "ds:SignedInfo".
        //     - Adding a node named "ds:SignatureValue" that contains the
        //       computed signature.
        $XMLDSig->sign($privateKey);

        // Check that the created XML token is well formed (if it's valid and if
        // timestamp and data can be retrieved from it) and, by the way,
        // terminate to initialize the properties of our XMLDSigToken object.
        $this->_readXML($XMLDSig->sigNode->ownerDocument->saveXML(), true);
    }


    /**
     * Read the XML Digital Signature representing an XML token.
     *
     * This function will check that the provided XML Digital Signature is
     * valid and that its certificate is trusted (see `_verifyCertTrust()`),
     * will decrypt the token data it contains if this one is encrypted
     * and then will extract timestamp and data.
     *
     * The data can then be obtained using the `getData()` function. Nevertheless,
     * you have to ensure that you can trust it using `isSignatureValid()` and
     * `isOutOfDate()`.
     *
     * NOTE: This function is called by the `_writeXML()` function to ensure the
     * XML token it built is correct and because this function sets most of the
     * properties of the XMLDSigToken object that are issued from the analysis
     * of the XML token. A token created encrypted without the private key of
     * the recipient is checked up to its decryption: structure, algorithms,
     * digest, signature and trust in the signing certificate. Its content is
     * not decrypted, and neither its timestamp, its identifier nor its data
     * are read.
     *
     * @param string $xml The XML Digital Signature representing an XML token.
     *
     * @param boolean $isCreation TRUE if the object has just created the
     *     token.
     *
     * @throws Exception
     */
    private function _readXML($xml, $isCreation = false)
    {
        // Store the provided XML Digital Signature.
        $this->xml = $xml;

        // Load the enveloping XML Digital Signature into a DOM document,
        // preserving its formatting. A document with a document type
        // declaration is refused before it is parsed (see _loadXML()).
        $xmlDoc = self::_loadXML($xml, "XML Digital Signature");

        // Instantiate and store a DOMXpath object to navigate through the DOM
        // document that holds the XML Digital Signature.
        $this->xpath = new DOMXPath($xmlDoc);
        $this->xpath->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
        $this->xpath->registerNamespace('xenc', XMLSecEnc::XMLENCNS);

        // xmlseclibs computes the digest over the first element of the
        // document whose attribute "Id" is "Token" and, when "ds:Signature" is
        // not the document element, it first detaches "ds:Signature" from the
        // document. A second element "Id=Token", or a "ds:Signature" wrapped
        // in another element, thus lets a copy of the signed "ds:Object",
        // placed where the signature does not cover it, be digested instead of
        // the "ds:Object" the token is read from (signature wrapping). Such
        // documents are rejected. The token is also read only from the node
        // xmlseclibs digested (see below).
        $root = $xmlDoc->documentElement;
        if (XMLSecurityDSig::XMLDSIGNS !== $root->namespaceURI || 'Signature' !== $root->localName)
        {
            // ERROR: XML Digital Signature is malformed!
            throw new Exception("XML digital signature is malformed! The document element must be ds:Signature.");
        }
        if ($this->xpath->query('//@*[local-name()="Id" and .="' . self::TOKEN_NAME . '"]')->length !== 1)
        {
            // ERROR: XML Digital Signature is malformed!
            throw new Exception("XML digital signature is malformed! Exactly one element must have the attribute Id=\"" . self::TOKEN_NAME . "\".");
        }

        // Verify that the XML Digital Signature is well formed.
        $queries = array(
            "//ds:Signature",
            "//ds:Signature/ds:SignedInfo",
            "//ds:Signature/ds:SignedInfo/ds:CanonicalizationMethod",
            "//ds:Signature/ds:SignedInfo/ds:SignatureMethod",
            "//ds:Signature/ds:SignedInfo/ds:Reference",
            "//ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms",
            "//ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform",
            "//ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod",
            "//ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue",
            "//ds:Signature/ds:SignatureValue",
            "//ds:Signature/ds:KeyInfo",
            "//ds:Signature/ds:KeyInfo/ds:X509Data",
            "//ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate",
            "//ds:Signature/ds:Object"
        );

        foreach ($queries as $query)
        {
            if ($this->xpath->query($query)->length !== 1)
            {
                // ERROR: XML Digital Signature is malformed!
                throw new Exception("XML digital signature is malformed!");
            }
        }

        $queries = array(
            // "//ds:Signature/@xmlns" => XMLSecurityDSig::XMLDSIGNS,
            "//ds:Signature/ds:SignedInfo/ds:Reference/@URI" => '#' . self::TOKEN_NAME,
            "//ds:Signature/ds:Object/@Id" => self::TOKEN_NAME
        );

        foreach ($queries as $query => $value)
        {
            if ($this->xpath->evaluate("string(" . $query . ")") !== $value)
            {
                // ERROR: XML digital signature is malformed!
                throw new Exception("XML digital signature is malformed!");
            }
        }

        // Verify the algorithms used to sign the token.
        $queries = array(
            "//ds:Signature/ds:SignedInfo/ds:CanonicalizationMethod/@Algorithm"
            => array(
                'name'             => 'Canonicalization',
                'validateFunction' => '_isValidCanonicalizationAlgorithm',
                'expectedValue'    => $this->canonicalizationAlgorithm
            ),
            "//ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm"
            => array(
                'name'             => 'Signature',
                'validateFunction' => '_isValidSignatureAlgorithm',
                'expectedValue'    => $this->signatureAlgorithm
            ),
            "//ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform/@Algorithm"
            => array(
                'name'             => 'Transform',
                'validateFunction' => '_isValidCanonicalizationAlgorithm',
                'expectedValue'    => $this->transformAlgorithm
            ),
            "//ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm"
            => array(
                'name'             => 'Digest',
                'validateFunction' => '_isValidHashAlgorithm',
                'expectedValue'    => $this->digestAlgorithm
            )
        );

        foreach ($queries as $query => $algorithm)
        {
            $usedAlgorithm = $this->xpath->evaluate("string(" . $query . ")");

            if (empty($usedAlgorithm))
            {
                // ERROR: Algorithm is missing!
                throw new Exception($algorithm['name'] . " algorithm is missing!");
            }

            if (!call_user_func(self::class . '::' . $algorithm['validateFunction'], $usedAlgorithm))
            {
                // ERROR: Algorithm is invalid!
                throw new Exception($algorithm['name'] . " algorithm is invalid!");
            }

            if ($usedAlgorithm !== $algorithm['expectedValue'] && $this->checkSigningAlgorithms)
            {
                // ANOMALY: Unauthorized algorithm!
                $this->anomalies[] = "Unauthorized " . $algorithm['name'] . " algorithm! Expected: " . $algorithm['expectedValue'] . ", Used: " . $usedAlgorithm . ".";
            }
        }

        // Check whether the token is encrypted or not.
        if ($this->xpath->query("//ds:Signature/ds:Object/xenc:EncryptedData")->length === 1)
        {
            // Verify that the encrypted data is well formed.
            $queries = array(
                "//ds:Signature/ds:Object/xenc:EncryptedData/xenc:EncryptionMethod",
                "//ds:Signature/ds:Object/xenc:EncryptedData/ds:KeyInfo",
                "//ds:Signature/ds:Object/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey",
                "//ds:Signature/ds:Object/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod",
                "//ds:Signature/ds:Object/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData",
                "//ds:Signature/ds:Object/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue",
                "//ds:Signature/ds:Object/xenc:EncryptedData/xenc:CipherData",
                "//ds:Signature/ds:Object/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue"
            );

            foreach ($queries as $query)
            {
                if ($this->xpath->query($query)->length !== 1)
                {
                    // ERROR: Encrypted data is malformed!
                    throw new Exception("Encrypted data is malformed!");
                }
            }

            $queries = array(
                "//ds:Signature/ds:Object/xenc:EncryptedData/@Type" => XMLSecEnc::Content
            );

            foreach ($queries as $query => $value)
            {
                if ($this->xpath->evaluate("string(" . $query . ")") !== $value)
                {
                    // ERROR: Encrypted data is malformed!
                    throw new Exception("Encrypted data is malformed!");
                }
            }

            // Verify the algorithms used to encrypt the token.
            $queries = array(
                "//ds:Signature/ds:Object/xenc:EncryptedData/xenc:EncryptionMethod/@Algorithm"
                => array(
                    'name'             => 'Session Key Ciphering',
                    'validateFunction' => '_isValidSymmetricCipheringAlgorithm',
                    'expectedValue'    => $this->sessionKeyCipheringAlgorithm
                ),
                "//ds:Signature/ds:Object/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/@Algorithm"
                => array(
                    'name'             => 'Crypt',
                    'validateFunction' => '_isValidKeyTransportAlgorithm',
                    'expectedValue'    => $this->cryptAlgorithm
                )
            );

            foreach ($queries as $query => $algorithm)
            {
                $usedAlgorithm = $this->xpath->evaluate("string(" . $query . ")");

                if (empty($usedAlgorithm))
                {
                    // ERROR: Algorithm is missing!
                    throw new Exception($algorithm['name'] . " algorithm is missing!");
                }

                if (!call_user_func(self::class . '::' . $algorithm['validateFunction'], $usedAlgorithm))
                {
                    // ERROR: Algorithm is invalid!
                    throw new Exception($algorithm['name'] . " algorithm is invalid!");
                }

                if ($usedAlgorithm !== $algorithm['expectedValue'] && $this->checkCryptingAlgorithms)
                {
                    // ANOMALY: Unauthorized algorithm!
                    $this->anomalies[] = "Unauthorized " . $algorithm['name'] . " algorithm! Expected: " . $algorithm['expectedValue'] . ", Used: " . $usedAlgorithm . ".";
                }
            }

            // An algorithm without integrity (CBC) is only accepted when it
            // is the declared one, even if the check of the algorithms is
            // turned off (see _isAuthenticatedCipheringAlgorithm()).
            $usedAlgorithm = $this->xpath->evaluate("string(//ds:Signature/ds:Object/xenc:EncryptedData/xenc:EncryptionMethod/@Algorithm)");
            if (!self::_isAuthenticatedCipheringAlgorithm($usedAlgorithm)
                && $usedAlgorithm !== $this->sessionKeyCipheringAlgorithm
                && !$this->checkCryptingAlgorithms)
            {
                // ANOMALY: Undeclared unauthenticated algorithm!
                $this->anomalies[] = "Unauthorized Session Key Ciphering algorithm! " . $usedAlgorithm . " has no integrity: declare it with the option 'sessionKeyCipheringAlgorithm' to accept it.";
            }
        }

        // Create an XMLSecurityDSig object that rejects empty or failed
        // canonicalizations (see _createVerifier()).
        $XMLDSig = self::_createVerifier();

        // Locate the node "ds:Signature".
        $nodeSignature = $XMLDSig->locateSignature($xmlDoc);
        if (is_null($nodeSignature))
        {
            // ERROR: Cannot locate signature!
            throw new Exception("Cannot locate signature!");
        }

        // Build an XMLSecurityKey object from the X.509 certificate which is
        // included in the XML Digital Signature.
        $objKeyX509 = $XMLDSig->locateKey();
        if (!$objKeyX509)
        {
            // ERROR: Cannot locate X.509 certificate!
            throw new Exception("Cannot locate X.509 certificate!");
        }

        // Configure the $objKeyX509 XMLSecurityKey object with its related
        // information which should be stored in the node
        // "ds:Signature/ds:KeyInfo".
        if (is_null(XMLSecEnc::staticLocateKeyInfo($objKeyX509, $nodeSignature)))
        {
            // ERROR: Cannot locate key information for X.509 certificate!
            throw new Exception("Cannot locate key information for X.509 certificate!");
        }

        // Create a new X509Cert object for the X.509 certificate found in the
        // XML Digital Signature.
        $this->x509Certificate = new X509Cert($objKeyX509->getX509Certificate());

        // Verify that the hash computed from the node "ds:Signature/ds:Object"
        // is the same as the one stored in the node
        // "ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue", and get
        // the node the hash was computed over. The token is read from this
        // node only, never by searching the document: data, timestamp and
        // encrypted content are then those the digest covers.
        $nodeObject = null;
        try
        {
            $XMLDSig->validateReference();

            $validatedNodes = $XMLDSig->getValidatedNodes();
            if (isset($validatedNodes[self::TOKEN_NAME]))
            {
                $nodeObject = $validatedNodes[self::TOKEN_NAME];
            }
            if (is_null($nodeObject) || !$nodeObject->isSameNode($this->xpath->query("/ds:Signature/ds:Object")->item(0)))
            {
                throw new Exception("The digested node is not the node ds:Signature/ds:Object!");
            }

            $this->isDigestValueOk = true;
        }
        catch (Exception $e)
        {
            // ANOMALY: Token hash verification failed!
            $nodeObject = null;
            $this->isDigestValueOk = false;
            $this->anomalies[] = "Token hash verification failed!";
        }

        // Canonicalize the node "ds:Signature/ds:SignedInfo". The signature is
        // verified against this canonical form; the verifier throws an
        // exception if it is empty (see _createVerifier()).
        $XMLDSig->canonicalizeSignedInfo();

        // Verifies that the signature held in the node
        // "ds:Signature/ds:SignatureValue" is correct for the node
        // "ds:Signature/ds:SignedInfo" using the key we've just built from the
        // X.509 certificate found in the XML Digital Signature.
        // The verification returns the value of openssl_verify(): 1 (valid),
        // 0 (invalid) or -1 (error). -1 is returned, whatever the signature
        // value, when the key of the certificate does not suit the signature
        // algorithm (e.g. an EC or DSA key with an RSA algorithm), and it is
        // TRUE in a boolean context: only a strict 1 makes the signature valid.
        try
        {
            $signatureVerification = $XMLDSig->verify($objKeyX509);
        }
        catch (\Throwable $e)
        {
            $signatureVerification = false;
        }

        if (1 === $signatureVerification)
        {
            // Token signature is valid.
            $this->isSignatureValueOk = true;
        }
        else
        {
            // ANOMALY: Token hash signature verification failed!
            $this->isSignatureValueOk = false;
            $this->anomalies[] = "Token hash signature verification failed!";
        }

        // Neither decrypt nor read a token whose hash or hash signature is not
        // valid: its content is not the signed one.
        if (!$this->isDigestValueOk || !$this->isSignatureValueOk)
        {
            $this->_throwAnomalies();
        }

        // The signature has only been verified with the certificate the token
        // carries, which anyone can produce. Neither decrypt nor read a token
        // whose certificate is not trusted.
        $this->_verifyCertTrust();

        // Check if the content of the node "ds:Object" is ciphered.
        $encryptedDataNode = $this->xpath->query("xenc:EncryptedData", $nodeObject)->item(0);

        if (is_null($encryptedDataNode))
        {
            // The node "ds:Object" is not ciphered.
            // Set encryption flag to FALSE.
            $this->isDataEncrypted = false;
        }
        else
        {
            // The node "ds:Object" is ciphered.
            // Set encryption flag to TRUE.
            $this->isDataEncrypted = true;

            // Do not decrypt a token encrypted with other algorithms than
            // the expected ones: the decryption itself is what an attacker
            // submitting altered tokens probes (see
            // _isValidKeyTransportAlgorithm() and
            // _isAuthenticatedCipheringAlgorithm()).
            if (!empty($this->anomalies))
            {
                $this->_throwAnomalies();
            }

            // A token created without the private key of the recipient
            // cannot be decrypted: everything that can be checked without
            // decrypting it has been, and its content is left unread.
            if ($isCreation && is_null($this->cryptKey))
            {
                return;
            }

            // Decrypt it now.
            $this->_decryptToken($encryptedDataNode);
        }

        // Verify that the token data is well formed. The token is read from the
        // digested node "ds:Signature/ds:Object" (see above).
        $queries = array(
            self::TOKEN_NAME,
            self::TOKEN_NAME . "/" . self::TOKEN_TIMESTAMP_NAME,
            self::TOKEN_NAME . "/" . self::TOKEN_DATA_NAME,
        );

        foreach ($queries as $query)
        {
            if ($this->xpath->query($query, $nodeObject)->length !== 1)
            {
                // ERROR: Malformed token! The structure of an encrypted
                // token is that of its decrypted content: it fails as the
                // decryption does (see _decryptToken()).
                throw new Exception($this->isDataEncrypted ? self::DECRYPTION_FAILED : "Malformed token!");
            }
        }

        // Get the node "ds:Signature/ds:Object/Token/TokenTimestamp".
        $query = self::TOKEN_NAME . "/" . self::TOKEN_TIMESTAMP_NAME;
        $nodeTokenTimestamp = $this->xpath->query($query, $nodeObject)->item(0);

        // Check that token timestamp node is a DOM element that contains solely
        // a text node.
        if (XML_ELEMENT_NODE === $nodeTokenTimestamp->nodeType
            && $nodeTokenTimestamp->hasChildNodes()
            && 1 === $nodeTokenTimestamp->childNodes->length
            && XML_TEXT_NODE === $nodeTokenTimestamp->childNodes->item(0)->nodeType)
        {
            // Compute the UTC UNIX timestamp from the token timestamp string.
            $timezone = new DateTimeZone('UTC');
            $UTCDate = DateTime::createFromFormat(self::TOKEN_TIMESTAMP_FORMAT, $nodeTokenTimestamp->nodeValue, $timezone);
            if (false !== $UTCDate)
            {
                // Store token timestamp.
                $this->timestamp = $nodeTokenTimestamp->nodeValue;
            }
            else
            {
                // ANOMALY: Token timestamp format is incorrect!
                $this->anomalies[] = "Token timestamp format is invalid!";
            }
        }
        else
        {
            // ANOMALY: Malformed token timestamp.
            $this->anomalies[] = "Token timestamp is malformed!";
        }

        // Get the node "ds:Signature/ds:Object/Token/TokenId". A token without
        // identifier (as created by the 0.x versions) is rejected: the
        // receiver could not tell it from a replayed one (see getTokenId()).
        $query = self::TOKEN_NAME . "/" . self::TOKEN_ID_NAME;
        $nodeTokenIds = $this->xpath->query($query, $nodeObject);
        if (0 === $nodeTokenIds->length)
        {
            // ANOMALY: Missing token identifier.
            $this->anomalies[] = "Token identifier is missing!";
        }
        elseif (1 === $nodeTokenIds->length
            && 1 === $nodeTokenIds->item(0)->childNodes->length
            && XML_TEXT_NODE === $nodeTokenIds->item(0)->firstChild->nodeType
            && preg_match('/\A[0-9a-f]{' . (2 * self::TOKEN_ID_BYTES) . '}\z/', $nodeTokenIds->item(0)->nodeValue))
        {
            // Store token identifier.
            $this->tokenId = $nodeTokenIds->item(0)->nodeValue;
        }
        else
        {
            // ANOMALY: Malformed token identifier.
            $this->anomalies[] = "Token identifier is malformed!";
        }

        // Get the node "ds:Signature/ds:Object/Token/TokenExpiry", if any: a
        // token created without the option "validity" has none.
        $query = self::TOKEN_NAME . "/" . self::TOKEN_EXPIRY_NAME;
        $nodeTokenExpiries = $this->xpath->query($query, $nodeObject);
        $this->hasExpiryNode = 0 < $nodeTokenExpiries->length;
        if ($this->hasExpiryNode)
        {
            $timezone = new DateTimeZone('UTC');
            $expiryDate = (1 === $nodeTokenExpiries->length && 1 === $nodeTokenExpiries->item(0)->childNodes->length && XML_TEXT_NODE === $nodeTokenExpiries->item(0)->firstChild->nodeType)
                ? DateTime::createFromFormat(self::TOKEN_TIMESTAMP_FORMAT, $nodeTokenExpiries->item(0)->nodeValue, $timezone)
                : false;
            $timestampDate = is_null($this->timestamp) ? false : DateTime::createFromFormat(self::TOKEN_TIMESTAMP_FORMAT, $this->timestamp, $timezone);
            if (false === $expiryDate || $expiryDate->format(self::TOKEN_TIMESTAMP_FORMAT) !== $nodeTokenExpiries->item(0)->nodeValue)
            {
                // ANOMALY: Malformed token expiry.
                $this->anomalies[] = "Token expiry is malformed!";
            }
            elseif (false !== $timestampDate && $expiryDate <= $timestampDate)
            {
                // ANOMALY: Token expiring before it was issued.
                $this->anomalies[] = "Token expiry is not after its timestamp!";
            }
            else
            {
                // Store token expiry.
                $this->expiry = $nodeTokenExpiries->item(0)->nodeValue;
            }
        }

        // Get the nodes "ds:Signature/ds:Object/Token/TokenAudience", if any,
        // and check them against the expected audience (see
        // _verifyAudience()) before the token data are read.
        $query = self::TOKEN_NAME . "/" . self::TOKEN_AUDIENCE_NAME;
        $nodeTokenAudiences = $this->xpath->query($query, $nodeObject);
        if (0 < $nodeTokenAudiences->length)
        {
            $audiences = [];
            foreach ($nodeTokenAudiences as $nodeTokenAudience)
            {
                if (1 !== $nodeTokenAudience->childNodes->length
                    || XML_TEXT_NODE !== $nodeTokenAudience->firstChild->nodeType
                    || !self::_isValidAudience($nodeTokenAudience->nodeValue))
                {
                    // ANOMALY: Malformed token audience. The token is
                    // rejected before its data are read: a malformed
                    // audience is not one the receiver can be sure of.
                    $this->anomalies[] = "Token audience is malformed!";
                    $this->_throwAnomalies();
                }
                $audiences[] = $nodeTokenAudience->nodeValue;
            }
            $this->audience = $audiences;
        }

        // A token whose timestamp, identifier or expiry is malformed is
        // rejected here, before its data are read and before its audience is
        // checked, so that the error lists these anomalies.
        if (!empty($this->anomalies))
        {
            $this->_throwAnomalies();
        }

        $this->_verifyAudience($isCreation);

        // Get the node "ds:Signature/ds:Object/Token/TokenData".
        $query = self::TOKEN_NAME . "/" . self::TOKEN_DATA_NAME;
        $nodeTokenData = $this->xpath->query($query, $nodeObject)->item(0);

        /**
         * Inline function to build a flat or multi-dimensional associative
         * array from a node tree whose leaf values are base64 encoded. The
         * values of the leaves are base64 decoded by this function.
         *
         * NOTE: This function is called recursively if the node tree is more
         * than one level deep.
         *
         * @param string $rootNode The node that holds the node tree.
         *
         * @param array $data The array to fill up with decoded data.
         */
        $nodeTreeToData = function($rootNode, &$data) use (&$nodeTreeToData)
        {
            if (!$rootNode->hasChildNodes())
            {
                // ANOMALY: Empty token data.
                $this->anomalies[] = "Token data is empty!";
            }
            else
            {
                foreach ($rootNode->childNodes as $node)
                {
                    if ((XML_TEXT_NODE === $node->nodeType && 1 !== $node->parentNode->childNodes->length))
                    {
                        // ANOMALY: Malformed token data.
                        $this->anomalies[] = "Token data is malformed!";
                    }
                    if (XML_ELEMENT_NODE === $node->nodeType && $node->hasChildNodes())
                    {
                        if (1 === $node->childNodes->length && XML_TEXT_NODE === $node->childNodes->item(0)->nodeType)
                        {
                            $decode = ("base64" === $node->getAttribute('Algorithm')) ? true : false;
                            $data[$node->nodeName] = $decode ? base64_decode($node->childNodes->item(0)->nodeValue) : $node->childNodes->item(0)->nodeValue;
                        }
                        else
                        {
                            $data[$node->nodeName] = array();

                            // Recursive call.
                            $nodeTreeToData($node, $data[$node->nodeName]);
                        }
                    }
                }
            }
        };

        // Check that token data is well formed and extract data.
        $tokenData = array();
        $nodeTreeToData($nodeTokenData, $tokenData);

        // Store token data.
        $this->data = $tokenData;

        // If any anomaly has been detected during analysis, set an error
        // message.
        if (!empty($this->anomalies))
        {
            $this->_throwAnomalies();
        }
    }


    /**
     * Load an XML document into a DOM document.
     *
     * A document type declaration (DOCTYPE) declares entities, which the
     * parser expands where the document references them: nested internal
     * entities make a small document expand into gigabytes ("billion
     * laughs"), and external entities read files or URLs. An XML token never
     * has one, so a document holding the bytes `<!DOCTYPE` is refused before
     * it is parsed, whatever it declares. This check reads the raw bytes: it
     * only holds for an encoding in which `<!DOCTYPE` can only be written as
     * these very bytes, which is why a document is also refused, before it is
     * parsed, when it is not in UTF-8, the encoding of the tokens: one that
     * holds a NUL byte (UTF-16, UTF-32), that declares another encoding, or
     * that does not start with `<` (EBCDIC, among others). The parsed document is refused too
     * if it has a document type node, should the check above miss one.
     *
     * The document is parsed with `LIBXML_NONET`: the parser never accesses
     * the network. Any libxml error refuses the document, and none is output.
     * Whitespace is preserved: digests are computed over the document as it
     * was signed.
     *
     * @param string $xml The XML document.
     *
     * @param string $what What the document is, for the error messages.
     *
     * @return DOMDocument The loaded document.
     *
     * @throws Exception If the document is refused.
     */
    static private function _loadXML($xml, $what)
    {
        if (!is_string($xml) || '' === $xml)
        {
            throw new Exception($what . " is not a valid XML document!");
        }

        $start = ltrim(preg_replace('/\A\xEF\xBB\xBF/', '', $xml), " \t\r\n");
        if (false !== strpos($xml, "\0")
            || (preg_match('/\A<\?xml\s[^>]*?\bencoding\s*=\s*(["\'])([^"\']*)\1/', $start, $matches)
                && 0 !== strcasecmp($matches[2], 'UTF-8')))
        {
            throw new Exception($what . " must be encoded in UTF-8!");
        }
        if ('<' !== substr($start, 0, 1))
        {
            throw new Exception($what . " is not a valid XML document!");
        }

        if (false !== strpos($xml, '<!DOCTYPE'))
        {
            throw new Exception($what . " must not have a document type declaration (DOCTYPE)!");
        }

        $xmlDoc = new DOMDocument('1.0', 'UTF-8');
        $xmlDoc->preserveWhiteSpace = true;

        $prevState = libxml_use_internal_errors(true);
        libxml_clear_errors();
        try
        {
            $loaded = $xmlDoc->loadXML($xml, LIBXML_NONET);
            $isValidXml = $loaded && 0 === count(libxml_get_errors());
        }
        finally
        {
            libxml_clear_errors();
            libxml_use_internal_errors($prevState);
        }

        if (!$isValidXml)
        {
            throw new Exception($what . " is not a valid XML document!");
        }

        foreach ($xmlDoc->childNodes as $node)
        {
            if (XML_DOCUMENT_TYPE_NODE === $node->nodeType)
            {
                throw new Exception($what . " must not have a document type declaration (DOCTYPE)!");
            }
        }

        return $xmlDoc;
    }


    /**
     * Decrypt the content of the node "ds:Object" in place.
     *
     * The failures that do not depend on the token content (no decryption
     * key, a key that cannot be loaded) or only on its structure have their
     * own message. Every failure that depends on the decrypted content
     * (session key, token data, parsing of the decrypted XML) gives the same
     * error, `DECRYPTION_FAILED`, without its reason, and raises no PHP
     * warning: a message or a warning per failure would tell an attacker who
     * can submit altered tokens which step failed, which is how padding
     * oracles (Bleichenbacher on RSA 1.5, Jager-Somorovsky on CBC) decrypt a
     * token step by step. `_readXML()` only calls this function once the
     * digest, the signature, the certificate and the algorithms of the token
     * have been verified.
     *
     * @param DOMElement $encryptedDataNode The node "xenc:EncryptedData",
     *     child of the digested node "ds:Signature/ds:Object".
     *
     * @throws Exception
     */
    private function _decryptToken($encryptedDataNode)
    {
        // Check that we have a private key to perform decryption.
        if (is_null($this->cryptKey))
        {
            // ERROR: No private key provided for decryption.
            throw new Exception("Token is encrypted but no private key is provided for decryption!");
        }

        // Passes the node containing the ciphered token to an XMLSecEnc
        // object, and indicates to it what is encrypted (the node element or
        // only its content) by reading the attribute "Type" of this node.
        $objXMLSecEnc = new XMLSecEnc();
        $objXMLSecEnc->setNode($encryptedDataNode);
        $objXMLSecEnc->type = $encryptedDataNode->getAttribute("Type");

        // Get an XMLSecurityKey object already configured with the algorithm
        // which was used to encrypt the token data with the session key.
        $objKeyCrypt = $objXMLSecEnc->locateKey();
        if (is_null($objKeyCrypt))
        {
            // ERROR: The algorithm cannot be found.
            throw new Exception("Cannot locate session key ciphering algorithm!");
        }

        // Retrieve the encrypted session key.
        $objKeyInfoCrypt = $objXMLSecEnc->locateKeyInfo($objKeyCrypt);
        if (is_null($objKeyInfoCrypt))
        {
            // ERROR: Session key cannot be found.
            throw new Exception("Cannot locate session key!");
        }
        if (!$objKeyInfoCrypt->isEncrypted)
        {
            // ERROR: Session key found but it is not encrypted.
            throw new Exception("Session key is not encrypted!");
        }

        // Loads the private key to be used for deciphering the encrypted
        // session key. If a password is provided, use it to access the
        // private key.
        if (!is_null($this->cryptKeyPassword))
        {
            $objKeyInfoCrypt->passphrase = $this->cryptKeyPassword;
        }
        $objKeyInfoCrypt->loadKey($this->cryptKey, false);
        if (empty($objKeyInfoCrypt->key))
        {
            // ERROR: Failed loading private key to decrypt session key!
            throw new Exception("Failed loading private key to decrypt session key!");
        }

        // Decipher the session key, then the token data with it, in place.
        // From here on, every failure gives the same error: exceptions are
        // caught, libxml errors are kept internal and PHP warnings are
        // intercepted (see above).
        $failed = false;
        $prevState = libxml_use_internal_errors(true);
        libxml_clear_errors();
        set_error_handler(function () use (&$failed) {
            $failed = true;
            return true;
        }, E_ALL & ~E_DEPRECATED & ~E_USER_DEPRECATED);
        try
        {
            $sessionKey = $objKeyInfoCrypt->encryptedCtx->decryptKey($objKeyInfoCrypt);
            $objKeyCrypt->loadKey($sessionKey);
            $objXMLSecEnc->decryptNode($objKeyCrypt, true);
            if (count(libxml_get_errors()) > 0)
            {
                $failed = true;
            }
        }
        catch (\Throwable $e)
        {
            $failed = true;
        }
        finally
        {
            restore_error_handler();
            libxml_clear_errors();
            libxml_use_internal_errors($prevState);
        }

        if ($failed)
        {
            // ERROR: Token decryption failed.
            throw new Exception(self::DECRYPTION_FAILED);
        }
    }


    /**
     * Verify that the X.509 certificate included in the XML token is trusted.
     *
     * The signature of the token is verified with the certificate the token
     * carries: any key pair can produce a valid one, with a certificate that
     * copies the names of a legitimate one. The token is only valid if the
     * certificate is also trusted:
     *
     * - A trust anchor is required: CA certificates (option `caCertPath`)
     *   and/or a pinned certificate (option `signerCertPath`). Without it, no
     *   certificate is trusted.
     *
     * - The certificate must be valid at the current date and its key usage
     *   must allow signing (see `X509Cert::canSign()`).
     *
     * - If a certificate is pinned, the certificate must be this very
     *   certificate (same fingerprint).
     *
     * - If CA certificates are given, OpenSSL must verify the chain of the
     *   certificate up to them (see `X509Cert::isTrustedBy()`). Only the
     *   signing certificate is taken from the token: the token cannot supply
     *   intermediate certificates.
     *
     * - If a subject is expected (option `expectedSubject`), the subject of
     *   the certificate must match it.
     *
     * Sets the flag returned by `isCertTrusted()`.
     *
     * @throws Exception If the certificate is not trusted, with the reason.
     */
    private function _verifyCertTrust()
    {
        $this->isCertTrusted = false;
        $cert = $this->x509Certificate;

        if (is_null($this->trustedCACertPaths) && is_null($this->pinnedSignerCert))
        {
            throw new Exception("No trust anchor! Pass the option 'caCertPath' (trusted CA certificates) and/or 'signerCertPath' (pinned signing certificate) to analyze a token: without them, no signing certificate can be trusted.");
        }

        if ($cert->isOutOfDate())
        {
            throw new Exception("Signing certificate is not valid at the current date (valid from " . $cert->getValidFrom(self::TOKEN_TIMESTAMP_FORMAT) . " to " . $cert->getValidTo(self::TOKEN_TIMESTAMP_FORMAT) . ")!");
        }

        if (!$cert->canSign())
        {
            throw new Exception("Signing certificate is not allowed to sign (key usage)!");
        }

        if (!is_null($this->pinnedSignerCert))
        {
            $pinned = new X509Cert($this->pinnedSignerCert);
            if (!hash_equals($pinned->getFingerprint(), $cert->getFingerprint()))
            {
                throw new Exception("Signing certificate is not the pinned certificate!");
            }
        }

        if (!is_null($this->trustedCACertPaths) && !$cert->isTrustedBy($this->trustedCACertPaths))
        {
            throw new Exception("Signing certificate is not issued by a trusted CA: its chain could not be verified up to the CA certificates of the option 'caCertPath', which must hold the issuing CA and the certificates up to its root!");
        }

        if (!is_null($this->expectedSubject))
        {
            $matches = is_string($this->expectedSubject)
                ? $cert->getDN() === $this->expectedSubject
                : self::_matchesName($cert->getSubject(), $this->expectedSubject);
            if (!$matches)
            {
                throw new Exception("Subject of the signing certificate is not the expected one! Subject: " . $cert->getDN() . ".");
            }
        }

        $this->isCertTrusted = true;
    }


    /**
     * Verify that the token is addressed to the expected audience.
     *
     * A token signed by a trusted issuer is valid for every receiver that
     * trusts this issuer: without an audience, a token issued for one
     * receiver is accepted by another. A token may therefore name the
     * receivers it is addressed to (option "audience" of its creation), and
     * the analysis then requires the receiver to say who it is (option
     * "expectedAudience"):
     *
     * - A token that names audiences is rejected unless `expectedAudience`
     *   is given and is one of them. Accepting it without this option would
     *   let any receiver of the issuer accept a token that is not addressed
     *   to it.
     *
     * - A token that names no audience is rejected when `expectedAudience` is
     *   given: the receiver asked for a token addressed to it.
     *
     * - A token that names no audience is accepted when `expectedAudience` is
     *   not given, as are the tokens of version 1.0, which have none.
     *
     * When the object has just created the token, the audiences read must be
     * those it wrote.
     *
     * @param boolean $isCreation TRUE if the object has just created the
     *     token, FALSE if it analyzes a given one.
     *
     * @throws Exception If the token is not addressed to the expected
     *     audience, with the reason.
     */
    private function _verifyAudience($isCreation)
    {
        $audiences = is_null($this->audience) ? [] : $this->audience;

        if ($isCreation)
        {
            if ($audiences !== (is_null($this->audienceToWrite) ? [] : $this->audienceToWrite))
            {
                throw new Exception("Token audience is not the one written!");
            }
            return;
        }

        if (is_null($this->expectedAudience))
        {
            if (!empty($audiences))
            {
                throw new Exception("Token is addressed to an audience ('" . implode("', '", $audiences) . "'), but the option 'expectedAudience' is not given: pass the audience of this receiver to accept it!");
            }
            return;
        }

        if (empty($audiences))
        {
            throw new Exception("Token is not addressed to any audience, but the audience '" . $this->expectedAudience . "' is expected!");
        }

        if (!in_array($this->expectedAudience, $audiences, true))
        {
            throw new Exception("Token is not addressed to the expected audience! Expected: '" . $this->expectedAudience . "'. Token audience: '" . implode("', '", $audiences) . "'.");
        }
    }


    /**
     * Indicates whether a name (the subject or the issuer of a certificate,
     * as returned by `openssl_x509_parse()`) holds the expected fields.
     *
     * Each expected field must be present with the very same value: character
     * case is significant, and a field repeated in the name (e.g. two "OU")
     * is an array of its values.
     *
     * @param array $name The name to check.
     *
     * @param array $expected The expected fields.
     *
     * @return boolean TRUE if every expected field matches, FALSE otherwise.
     */
    static private function _matchesName($name, $expected)
    {
        foreach ($expected as $key => $value)
        {
            if (!isset($name[$key]) || $name[$key] !== $value)
            {
                return false;
            }
        }

        return true;
    }


    /**
     * Throw an exception whose message lists the anomalies detected during
     * the analysis of the XML token.
     *
     * @throws Exception
     */
    private function _throwAnomalies()
    {
        $nb = count($this->anomalies);
        throw new Exception($nb . ($nb === 1 ? " anomaly" : " anomalies") . " detected: " . implode(" ; ", $this->anomalies));
    }


    /**
     * Indicates whether XML token signature is valid or not.
     *
     * This means that:
     *
     * - No error occurred during the analysis of the XML digital signature.
     *
     * - No anomaly detected during the analysis of the XML digital signature.
     *
     * - The token hash has been verified and is valid.
     *
     * - The token hash signature has been verified and is valid.
     *
     * - The X.509 certificate included in the XML token is trusted: it is
     *   valid at the current date, it is the pinned certificate and/or its
     *   chain has been verified up to the trusted CA certificates, and its
     *   subject is the expected one, if any (see `isCertTrusted()`).
     *
     * - The token is addressed to the audience given by the option
     *   `expectedAudience`, if it names audiences or if this option is given
     *   (see `getAudience()`).
     *
     * Without a trust anchor given to the analysis, it returns FALSE.
     *
     * **It checks neither the freshness of the token nor whether it is
     * replayed.** A token that was valid once stays valid here, however old
     * it is and however many times it is submitted. Before trusting the data
     * of a received token, the caller must check that:
     *
     * - `isSignatureValid()` returns TRUE;
     *
     * - `isOutOfDate($ttl)` returns FALSE, for the time to live the
     *   application accepts (it also checks the expiry of the token, if
     *   any);
     *
     * - the identifier returned by `getTokenId()` has not been accepted
     *   before: store it atomically, and refuse the token if it already is.
     *
     * The trust anchor `caCertPath` accepts any certificate its CA issues: if
     * this CA also issues certificates to others than the expected sender,
     * any of them can sign a token that passes this check. Restrict it then
     * to the sender with the option `expectedSubject`, or pin its certificate
     * with `signerCertPath`.
     *
     * For a token created encrypted without the private key of the
     * recipient, it tells whether the checks made without decrypting the
     * token passed (see `createSecureXMLToken()`).
     *
     * @return boolean TRUE if XML token is valid, FALSE otherwise.
     */
    public function isSignatureValid()
    {
        return true === $this->isDigestValueOk
            && true === $this->isSignatureValueOk
            && true === $this->isCertTrusted
            && is_null($this->error);
    }


    /**
     * Indicates whether the X.509 certificate included in the XML token is
     * trusted or not, according to the trust anchor given to the analysis
     * (options `caCertPath`, `signerCertPath` and `expectedSubject`).
     *
     * NOTE: If not evaluated (because an error occurred before), this function
     * returns NULL. When it returns FALSE, `getError()` gives the reason.
     *
     * @return boolean|null TRUE if the certificate is trusted, FALSE
     *     otherwise, NULL if cannot be evaluated.
     */
    public function isCertTrusted()
    {
        return $this->isCertTrusted;
    }


    /**
     * Indicates whether the XML token is out of date or not.
     *
     * The token is out of date if its timestamp is more than `$ttl` seconds
     * in the past, or more than `DESYNC_TOLERANCE` seconds in the future
     * (clocks of sender and receiver out of sync), or if it has no valid
     * timestamp. A token created with the option `validity` is also out of
     * date once its expiry is passed (see `getExpiry()`): the shorter of the
     * validity set by the issuer and the `$ttl` set by the receiver applies.
     *
     * The expiry is only checked here, with the timestamp: like the time to
     * live, it is a check left to the caller, and `isSignatureValid()` does
     * not make it. `DESYNC_TOLERANCE` does not apply to the expiry: a
     * receiver whose clock is ahead rejects the token a little earlier.
     * Version 1.0 of this class ignores the expiry: a receiver that has not
     * upgraded only applies its own `$ttl`.
     *
     * NOTE: A token that is not out of date can still be a replayed one: see
     * `getTokenId()`.
     *
     * @param int $ttl The time to live (in seconds) allowed for the token.
     *
     * @return boolean TRUE if token is out of date, FALSE otherwise.
     */
    public function isOutOfDate($ttl = self::TOKEN_DEFAULT_TTL)
    {
        if (is_null($this->timestamp))
        {
            // Timestamp is missing! So we assume token is expired.
            return true;
        }

        // We will compare date using UTC timezone.
        $timezone = new DateTimeZone('UTC');

        // Compute the UTC UNIX timestamp from the token timestamp string.
        $tokenUTCDate = DateTime::createFromFormat(self::TOKEN_TIMESTAMP_FORMAT, $this->timestamp, $timezone);
        if (false === $tokenUTCDate)
        {
            // Token timestamp format is incorrect! So we assume token is
            // expired.
            return true;
        }
        $tokenUTCTimestamp = $tokenUTCDate->getTimestamp();

        // Compute the UTC UNIX timestamp for the current date/time.
        $curUTCDate = new DateTime('now', $timezone);
        $curUTCTimestamp = $curUTCDate->getTimestamp();

        // A token whose expiry is passed is out of date, whatever $ttl. So
        // is a token whose expiry could not be read: it is not valid either
        // (see isSignatureValid()), but a caller that only calls this
        // function must not take it for a token without expiry.
        if ($this->hasExpiryNode && is_null($this->expiry))
        {
            return true;
        }
        if (!is_null($this->expiry))
        {
            $tokenUTCExpiry = DateTime::createFromFormat(self::TOKEN_TIMESTAMP_FORMAT, $this->expiry, $timezone);
            if (false === $tokenUTCExpiry || $tokenUTCExpiry->getTimestamp() < $curUTCTimestamp)
            {
                return true;
            }
        }

        // Return timestamps comparison result.
        return $tokenUTCTimestamp > ($curUTCTimestamp + self::DESYNC_TOLERANCE) || ($tokenUTCTimestamp + $ttl) < $curUTCTimestamp;
    }


    /**
     * Indicates whether token data is encrypted or not.
     *
     * For a token created encrypted, it returns TRUE, whether or not the
     * private key of the recipient was given (see `createSecureXMLToken()`).
     *
     * NOTE: If not evaluated (because an error occurred before), this function
     * returns NULL.
     *
     * @return boolean|null TRUE if token data is encrypted, FALSE otherwise,
     *     NULL if cannot be evaluated.
     */
    public function isDataEncrypted()
    {
        return $this->isDataEncrypted;
    }


    /**
     * Indicates whether the digest of token data (a hash) has been verified and
     * is valid or not.
     *
     * NOTE: If not evaluated (because an error occurred before), this function
     * returns NULL.
     *
     * @return boolean|null TRUE if token hash has been verified and is valid,
     *     FALSE otherwise, NULL if cannot be evaluated.
     */
    public function isDigestValueOk()
    {
        return $this->isDigestValueOk;
    }


    /**
     * Indicates whether signature of the digest of the token data has been
     * verified and is valid or not.
     *
     * NOTE: If not evaluated (because an error occurred before), this function
     * returns NULL.
     *
     * @return boolean|null TRUE if token hash signature has been verified and
     *     is valid, FALSE otherwise, NULL if cannot be evaluated.
     */
    public function isSignatureValueOk()
    {
        return $this->isSignatureValueOk;
    }


    /**
     * Get the XML token.
     *
     * @return string|null The XML token, NULL if not available.
     */
    public function getXML()
    {
        return $this->xml;
    }


    /**
     * Get the user data contained in the XML token.
     *
     * The data can only be trusted if `isSignatureValid()` returns TRUE (and
     * the token is neither out of date nor replayed). They are only read
     * once the digest, the signature and the signing certificate have been
     * verified.
     *
     * A token created encrypted without the private key of the recipient is
     * not decrypted: its data are not available (see
     * `createSecureXMLToken()`).
     *
     * @return array|null The associative array containing token data, NULL if
     *     not available.
     */
    public function getData()
    {
        return $this->data;
    }


    /**
     * Get the timestamp of the XML token.
     *
     * The timestamp of a token that is not valid is not given: nothing read
     * from such a token can be trusted. `isOutOfDate()` still reads it, and
     * rejects such a token anyway when its timestamp could not be read.
     *
     * @return string|null The token timestamp, NULL if the token is not
     *     valid (see `isSignatureValid()`), or if it was created encrypted
     *     without the private key of the recipient, which leaves its content
     *     unread (see `createSecureXMLToken()`).
     */
    public function getTimestamp()
    {
        return $this->isSignatureValid() ? $this->timestamp : null;
    }


    /**
     * Get the identifier of the XML token.
     *
     * Each token created by this class holds a random identifier of 128 bits
     * (32 hexadecimal characters), generated with `random_bytes()` and
     * covered by the signature. A valid token can be submitted again for as
     * long as `isOutOfDate()` accepts it: the class keeps no list of the
     * tokens it has analyzed, so the caller must refuse a token whose
     * identifier it has already accepted. A token is accepted from
     * `DESYNC_TOLERANCE` seconds before its timestamp to `$ttl` seconds after
     * it (see `isOutOfDate()`): keep each accepted identifier for at least
     * `$ttl + XMLDSigToken::DESYNC_TOLERANCE` seconds after accepting it.
     *
     * A token without identifier (as created by the 0.x versions) is not
     * valid.
     *
     * @return string|null The token identifier, NULL if the token is not
     *     valid (see `isSignatureValid()`), or if it was created encrypted
     *     without the private key of the recipient, which leaves its content
     *     unread (see `createSecureXMLToken()`).
     */
    public function getTokenId()
    {
        return $this->isSignatureValid() ? $this->tokenId : null;
    }


    /**
     * Get the audiences the XML token is addressed to.
     *
     * A token created with the option `audience` names the receivers it is
     * addressed to, and `isSignatureValid()` only accepts it if the analysis
     * gives one of them with the option `expectedAudience` (see
     * `__construct()`).
     *
     * @return array|null The list of the audiences of the token, NULL if the
     *     token is not valid (see `isSignatureValid()`), if it names no
     *     audience, or if it was created encrypted without the private key of
     *     the recipient, which leaves its content unread (see
     *     `createSecureXMLToken()`).
     */
    public function getAudience()
    {
        return $this->isSignatureValid() ? $this->audience : null;
    }


    /**
     * Get the expiry of the XML token.
     *
     * A token created with the option `validity` holds the date after which
     * it is out of date (see `isOutOfDate()`), in the format of the timestamp
     * (`TOKEN_TIMESTAMP_FORMAT`, UTC).
     *
     * @return string|null The token expiry, NULL if the token is not valid
     *     (see `isSignatureValid()`), if it has no expiry, or if it was
     *     created encrypted without the private key of the recipient, which
     *     leaves its content unread (see `createSecureXMLToken()`).
     */
    public function getExpiry()
    {
        return $this->isSignatureValid() ? $this->expiry : null;
    }


    /**
     * Get the message of the error that occurred while parsing the XML token.
     *
     * @return string|null The error message. If no error, NULL is returned.
     */
    public function getError()
    {
        return $this->error;
    }


    /**
     * Get the list of anomalies that occurred while parsing the XML token.
     *
     * @return array The list of anomalies, empty if none.
     */
    public function getAnomalies()
    {
        return $this->anomalies;
    }


    /**
     * Get the X.509 certificate that is included in the XML token (PEM format).
     *
     * @return string|null The content of the X.509 certificate, NULL if not
     *     available.
     */
    public function getCertificate()
    {
        if (is_null($this->x509Certificate))
        {
            return null;
        }

        return $this->x509Certificate->getPem();
    }


    /**
     * Get the issuer information of the X.509 certificate that is included in
     * the XML token.
     *
     * @return array|null The issuer information of the X.509 certificate, NULL
     *     if not available.
     */
    public function getCertIssuer()
    {
        if (is_null($this->x509Certificate))
        {
            return null;
        }

        return $this->x509Certificate->getIssuer();
    }


    /**
     * Get the subject information of the X.509 certificate that is included in
     * the XML token.
     *
     * @return array|null The subject information of the X.509 certificate, NULL
     *     if not available.
     */
    public function getCertSubject()
    {
        if (is_null($this->x509Certificate))
        {
            return null;
        }

        return $this->x509Certificate->getSubject();
    }


    /**
     * Get the Distinguished Name of the X.509 certificate that is included in
     * the XML token.
     *
     * @return string|null The Distinguished Name of the X.509 certificate, NULL
     *     if not available.
     */
    public function getCertDN()
    {
        if (is_null($this->x509Certificate))
        {
            return null;
        }

        return $this->x509Certificate->getDN();
    }


    /**
     * Get the UTC date from which the X.509 certificate that is included in the
     * XML token is valid.
     *
     * @param string $dateFormat The format of the returned date (Default:
     *     XMLDSigToken::TOKEN_TIMESTAMP_FORMAT).
     *
     * @return string|null|false The date from which the X.509 certificate is
     *     valid, NULL if not available, FALSE if $dateFormat is invalid.
     */
    public function getCertValidFrom($dateFormat = self::TOKEN_TIMESTAMP_FORMAT)
    {
        if (is_null($this->x509Certificate))
        {
            return null;
        }

        return $this->x509Certificate->getValidFrom($dateFormat);
    }


    /**
     * Get the UTC date to which the X.509 certificate that is included in the
     * XML token is valid.
     *
     * @param string $dateFormat The format of the returned date (Default:
     *     XMLDSigToken::TOKEN_TIMESTAMP_FORMAT).
     *
     * @return string|null|false The date to which the X.509 certificate is
     *     valid, NULL if
     *     not available, FALSE if $dateFormat is invalid.
     */
    public function getCertValidTo($dateFormat = self::TOKEN_TIMESTAMP_FORMAT)
    {
        if (is_null($this->x509Certificate))
        {
            return null;
        }

        return $this->x509Certificate->getValidTo($dateFormat);
    }


    /**
     * Indicates whether the X.509 certificate included in the XML token is out
     * of date or not.
     *
     * @return boolean TRUE if X.509 certificate is out of date, FALSE
     *     otherwise.
     */
    public function isCertOutOfDate()
    {
        if (is_null($this->x509Certificate))
        {
            return true;
        }

        return $this->x509Certificate->isOutOfDate();
    }


    /**
     * Check that the issuer information of the X.509 certificate that is
     * included in the XML token matches the expected one.
     *
     * The expected issuer information must be passed as an array to the
     * function:
     *
     * ```php
     * $ExpectedIssuerInfo = [
     *     'C' => 'DK',
     *     'ST' => 'Jylland',
     *     'O' => 'Lothbrok Ltd',
     *     'OU' => 'Jarl Dept',
     *     'CN' => 'www.Lothbrok.dk',
     *     'emailAddress' => 'ragnar@Lothbrok.dk'
     * ];
     * ```
     *
     * NOTE: Character case of data is significant.
     *
     * NOTE: This only compares names, which any certificate can copy: it
     * tells nothing about who issued the certificate. `isSignatureValid()`
     * verifies the certificate against the trust anchor of the analysis.
     *
     * @param array $expectedIssuerInfo The issuer information that the X.509
     * certificate should match.
     *
     * @return boolean TRUE if the issuer of the X.509 certificate holds the
     * expected information, FALSE otherwise.
     *
     * @throws Exception
     */
    public function isValidCertIssuer($expectedIssuerInfo)
    {
        // Check if the expected issuer information is an array.
        if (!is_array($expectedIssuerInfo))
        {
            throw new Exception("Invalid parameter 'issuerInfo'! Issuer information should be an array.");
        }

        // Verify that the information of the X.509 certificate matches the
        // expected one.
        $certIssuerInfo = $this->getCertIssuer();
        if (is_null($certIssuerInfo))
        {
            return false;
        }

        return self::_matchesName($certIssuerInfo, $expectedIssuerInfo);
    }


    /**
     * Check that the X.509 certificate included in the XML token comes from the
     * expected CA.
     *
     * Note that more than one CA certificate can give a positive result, some
     * CAs re-issue signing certificates after having only changed the
     * expiration dates.
     *
     * Note that it also works with self-signed certificates. In this case,
     * pass the X.509 certificate that is supposed to be included in the XML
     * token to the function.
     *
     * Only the link between the certificate and the given CA certificate is
     * checked (see `X509Cert::isValidCA()`). `isSignatureValid()` verifies the
     * whole chain against the trust anchor of the analysis.
     *
     * @param string $caCertPath The PEM certificate (public key) that is
     *     supposed to be used by the CA to sign the X.509 certificate included in
     *     the XML token.
     *
     * @return boolean TRUE if the X.509 certificate has been signed by the
     *     expected CA, FALSE otherwise (and when no certificate has been read
     *     from the token).
     *
     * @throws Exception
     */
    public function isValidCertCA($caCertPath)
    {
        if (is_null($this->x509Certificate))
        {
            return false;
        }

        // Get the CA public key that is supposed to be used to sign the X.509
        // certificate.
        $caCert = @file_get_contents($caCertPath);
        if (false === $caCert)
        {
            throw new Exception("Cannot read CA certificate to perform signer check! File: " . $caCertPath);
        }

        return $this->x509Certificate->isValidCA($caCert);
    }


    /**
     * Create the XMLSecurityDSig object used to verify an XML token.
     *
     * Digests and signatures are computed over canonicalized XML. If the
     * canonicalization fails, `DOMNode::C14N()` returns FALSE (on PHP 8, some
     * XPath failures throw an Error instead), and an XPath transform that
     * selects nothing yields an empty string. Depending on its version,
     * xmlseclibs then hashes an empty string: a forged reference only has to
     * carry the digest of the empty string to validate, whatever the content
     * of the referenced node. The returned object therefore makes the
     * canonicalization of the node "ds:SignedInfo" and of each referenced node
     * throw an exception unless it produces a non-empty string.
     *
     * This check is deliberately independent of the xmlseclibs version and
     * must not be removed, even if xmlseclibs performs a similar check.
     *
     * @return XMLSecurityDSig The verifier.
     */
    static private function _createVerifier()
    {
        return new class() extends XMLSecurityDSig
        {
            public function canonicalizeSignedInfo()
            {
                return $this->guard(function () {
                    return parent::canonicalizeSignedInfo();
                }, "ds:SignedInfo");
            }

            public function processTransforms($refNode, $objData, $includeCommentNodes = true)
            {
                return $this->guard(function () use ($refNode, $objData, $includeCommentNodes) {
                    return parent::processTransforms($refNode, $objData, $includeCommentNodes);
                }, "referenced node");
            }

            private function guard(callable $canonicalize, $what)
            {
                try
                {
                    $data = $canonicalize();
                }
                catch (\Throwable $e)
                {
                    throw new Exception("Canonicalization of " . $what . " failed! Reason: " . $e->getMessage());
                }

                if (!is_string($data) || '' === $data)
                {
                    throw new Exception("Canonicalization of " . $what . " failed or is empty!");
                }

                return $data;
            }
        };
    }


    /**
     * Check if an algorithm is valid to perform XML canonicalization
     * operations.
     *
     * @param string $algorithm The algorithm reference (URL).
     *
     * @return boolean TRUE if valid, FALSE otherwise.
     */
    static private function _isValidCanonicalizationAlgorithm($algorithm)
    {
        // switch compares loosely: TRUE would match any algorithm.
        if (!is_string($algorithm))
        {
            return(false);
        }

        switch ($algorithm)
        {
            case (self::C14N):
            case (self::C14N_COMMENTS):
            case (self::EXC_C14N):
            case (self::EXC_C14N_COMMENTS):
                return(true);
            default:
                return(false);
        }
    }


    /**
     * Check if an algorithm is valid to perform hash operations.
     *
     * @param string $algorithm The algorithm reference (URL).
     *
     * @return boolean TRUE if valid, FALSE otherwise.
     */
    static private function _isValidHashAlgorithm($algorithm)
    {
        // switch compares loosely: TRUE would match any algorithm.
        if (!is_string($algorithm))
        {
            return(false);
        }

        switch ($algorithm)
        {
            case (self::SHA1):
            case (self::SHA256):
            case (self::SHA384):
            case (self::SHA512):
            case (self::RIPEMD160):
                return(true);
            default:
                return(false);
        }
    }


    /**
     * Check if an algorithm is valid to sign the node "ds:SignedInfo".
     *
     * Signature and key transport algorithms (see
     * `_isValidKeyTransportAlgorithm()`) are both asymmetric, but each list
     * only holds its own: a key transport algorithm is not a signature
     * algorithm, and the reverse.
     *
     * @param string $algorithm The algorithm reference (URL).
     *
     * @return boolean TRUE if valid, FALSE otherwise.
     */
    static private function _isValidSignatureAlgorithm($algorithm)
    {
        // switch compares loosely: TRUE would match any algorithm.
        if (!is_string($algorithm))
        {
            return(false);
        }

        switch ($algorithm)
        {
            // case (self::DSA_SHA1): // Does not work.
            case (self::RSA_SHA1):
            case (self::RSA_SHA256):
            case (self::RSA_SHA384):
            case (self::RSA_SHA512):
            // case (self::HMAC_SHA1): // Does not work.
                return(true);
            default:
                return(false);
        }
    }


    /**
     * Check if an algorithm is valid to encrypt the session key that encrypts
     * the token (key transport).
     *
     * RSA 1.5 (PKCS #1 v1.5 padding) is not valid, neither to create nor to
     * analyze a token: whether the padding of a submitted session key is
     * valid can be told from the decryption (Bleichenbacher), which lets an
     * attacker who can submit altered tokens decrypt a session key.
     *
     * @param string $algorithm The algorithm reference (URL).
     *
     * @return boolean TRUE if valid, FALSE otherwise.
     *
     * @see _isValidSignatureAlgorithm()
     */
    static private function _isValidKeyTransportAlgorithm($algorithm)
    {
        // switch compares loosely: TRUE would match any algorithm.
        if (!is_string($algorithm))
        {
            return(false);
        }

        switch ($algorithm)
        {
            case (self::RSA_OAEP_MGF1P):
                return(true);
            default:
                return(false);
        }
    }


    /**
     * Check if an algorithm is valid to perform symmetric ciphering operations.
     *
     * @param string $algorithm The algorithm reference (URL).
     *
     * @return boolean TRUE if valid, FALSE otherwise.
     */
    static private function _isValidSymmetricCipheringAlgorithm($algorithm)
    {
        // switch compares loosely: TRUE would match any algorithm.
        if (!is_string($algorithm))
        {
            return(false);
        }

        switch ($algorithm)
        {
            case (self::TRIPLEDES_CBC):
            case (self::AES128_CBC):
            case (self::AES192_CBC):
            case (self::AES256_CBC):
            case (self::AES128_GCM):
            case (self::AES192_GCM):
            case (self::AES256_GCM):
                return(true);
            default:
                return(false);
        }
    }


    /**
     * Check if a symmetric algorithm authenticates the data it decrypts.
     *
     * AES-GCM checks an authentication tag before returning any decrypted
     * data: altered data fails as a whole. CBC has no integrity: altered
     * data is decrypted all the same, and how the decrypted content then
     * fails (padding, XML parsing) can tell an attacker who can submit
     * altered tokens what it holds (Jager-Somorovsky). A token encrypted
     * with CBC is therefore only decrypted if the analysis declares this
     * algorithm (option `sessionKeyCipheringAlgorithm`), whatever
     * `checkCryptingAlgorithms`.
     *
     * @param string $algorithm The algorithm reference (URL).
     *
     * @return boolean TRUE if the algorithm is authenticated, FALSE otherwise.
     */
    static private function _isAuthenticatedCipheringAlgorithm($algorithm)
    {
        return in_array($algorithm, [self::AES128_GCM, self::AES192_GCM, self::AES256_GCM], true);
    }


    /**
     * Utility function for modifying a node of an XML content.
     *
     * The XML content is loaded as an XML token is: a document with a
     * document type declaration (DOCTYPE), or not encoded in UTF-8, is
     * refused before it is parsed, and the parser never accesses the network
     * (see `_loadXML()`). A refused or invalid document is left unchanged and
     * the function returns FALSE.
     *
     * @param string $xml XML content, passed by reference.
     *
     * @param string $nodePath The xpath query to select the node to modify.
     *     This should be a full path that identifies a single node.
     *
     * @param string $nodeAttribute In case you want to modify an attribute of
     *     the specified node, provide its name here, otherwise set this
     *     parameter to NULL.
     *
     * @param string $newValue The value that will replace the original value of
     *     the node or of the attribute of the node if $nodeAttribute parameter
     *     is provided.
     *
     * @param boolean $delete If TRUE delete the specified node or attribute.
     *
     * @return string|false The value of the node or attribute before
     *     modification or deletion, FALSE otherwise.
     */
    static public function alterXML(&$xml, $nodePath, $nodeAttribute, $newValue, $delete = false)
    {
        // Assume modification will fail.
        $oldValue = false;

        // Load the XML content into a DOM document.
        try
        {
            $xmlDoc = self::_loadXML($xml, "XML content");
        }
        catch (Exception $e)
        {
            return false;
        }
        $xmlDoc->formatOutput = false;

        // Instantiate a DOMXpath object to navigate in the XML document.
        $xpath = new DOMXPath($xmlDoc);
        $xpath->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
        $xpath->registerNamespace('xenc', XMLSecEnc::XMLENCNS);

        // Locate the node.
        $nodeList = $xpath->query($nodePath);
        if (1 <= $nodeList->length)
        {
            // Node found.
            $node = $nodeList->item(0);

            if (is_null($nodeAttribute))
            {
                if ($delete)
                {
                    // Delete the node.
                    $oldValue = $node->nodeValue;
                    $node->parentNode->removeChild($node);
                }
                else
                {
                    // Replace node value with the given one.
                    $oldValue = $node->nodeValue;
                    $node->nodeValue = $newValue;
                }
            }
            else
            {
                if ($node->hasAttribute($nodeAttribute))
                {
                    if ($delete)
                    {
                        // Delete attribute.
                        $oldValue = $node->getAttribute($nodeAttribute);
                        $node->removeAttribute($nodeAttribute);
                    }
                    else
                    {
                        // Replace attribute value with the given one.
                        $oldValue = $node->getAttribute($nodeAttribute);
                        $node->removeAttribute($nodeAttribute);
                        $node->setAttribute($nodeAttribute, $newValue);
                    }
                }
            }
        }

        // Update the XML content with its modified version.
        if ($oldValue)
        {
            $xml = $xmlDoc->saveXML();
        }

        // Return the old value of the modified or deleted element (a node or
        // an attribute) or false on failure.
        return $oldValue;
    }


    /**
     * Return the XML token in a pretty readable format.
     *
     * This function is intended for display purposes only. Use the `getXML()`
     * function to obtain the raw XML token you want to work with.
     *
     * @return string The pretty formatted XMLDSigToken signature.
     */
    public function getPrettyXML()
    {
        $xml = $this->xml;
        $formatted = '';
        $pad = 0;
        $indent_size = 2;
        $matches = array();

        // Inline function that splits the value of a node
        // into multiple lines of 64 characters.
        $splitNodeValue = function(&$xml, $prefix, $xpathQuery)
        {
            $xpathQuery = str_replace('ds:', $prefix, $xpathQuery);
            $nodeValue = XMLDSigToken::alterXML($xml, $xpathQuery, null, 'placeholer', false);
            if (false === $nodeValue)
            {
                // No such node, or the XML token is not a valid XML document.
                return;
            }
            $nodeValue = PHP_EOL . implode(PHP_EOL, str_split($nodeValue, 64)) . PHP_EOL;
            XMLDSigToken::alterXML($xml, $xpathQuery, null, $nodeValue, false);
            // Remove XML encoded carriage return introduced when splitting node
            // value.
            $xml = str_replace('&#xD;', '', $xml);
        };

        // Split node values that are too long.
        $prefix = $this->xmldsigNsPrefix ? $this->xmldsigNsPrefix . ':' : '';
        $splitNodeValue($xml, $prefix, '//ds:Signature/ds:SignatureValue');
        $splitNodeValue($xml, $prefix, '//ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate');
        $splitNodeValue($xml, $prefix, '//ds:Signature/ds:Object/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue');
        $splitNodeValue($xml, $prefix, '//ds:Signature/ds:Object/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue');

        // Tokenise the XML string.
        $xml = preg_replace('/(>)[\s]*(<)(\/*)/', "$1\n$2$3", $xml);

        // Get the first token.
        $tok = strtok($xml, "\n");

        // Scan each token and adjust indent based on opening/closing tags.
        while ($tok !== false)
        {
            // Test for the various tag states
            if (preg_match('/.+<\/\w[^>]*>$/', $tok, $matches))
            {
                // Opening and closing tags on same line: no change.
                $indent = 0;
            }
            elseif (preg_match('/^<\/\w/', $tok, $matches))
            {
                // Closing tag: outdent now.
                $pad = $pad - $indent_size;
            }
            elseif (preg_match('/^<\w[^>]*[^\/]>.*$/', $tok, $matches))
            {
                // Opening tag: don't pad this one, only subsequent tags.
                $indent = $indent_size;
            }
            else
            {
                // No indentation needed.
                $indent = 0;
            }

            // Pad the line with the required number of leading spaces.
            $prettyLine = str_pad($tok, strlen($tok) + $pad, ' ', STR_PAD_LEFT);
            $formatted .= $prettyLine . "\n";

            // Get the next token
            $tok = strtok("\n");

            // Update the pad size for subsequent token.
            $pad += $indent;
        }

        // Return formatted XML string.
        return $formatted;
    }


    /**
     * Utility function that returns information on the XML token in HTML
     * format.
     *
     * The output shows what the token carries, valid or not: data,
     * certificate fields and error messages come from whoever sent the token.
     * Every value is therefore escaped with `htmlspecialchars()`
     * (`ENT_QUOTES | ENT_SUBSTITUTE`, UTF-8), the outputs of `var_dump()`
     * included, so that it can be displayed as is in an HTML page. The output
     * loads no external resource (script, style sheet, image).
     *
     * @return string An HTML fragment.
     */
    public function getHTMLDump()
    {
        // Inline function to escape a value for HTML output.
        $escape = function($value)
        {
            return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        };

        // Inline function to output var_dump() into a string.
        $dumpToString = function($var)
        {
            // Capture var_dump() output. When Xdebug overloads var_dump(), it
            // writes HTML if html_errors is on: turn it off so that the
            // output is plain text, which is then escaped like any value.
            $htmlErrors = ini_set('html_errors', '0');
            ob_start();
            var_dump($var);
            $res = ob_get_clean();
            if (false !== $htmlErrors)
            {
                ini_set('html_errors', $htmlErrors);
            }

            // Remove the location ("file:line:") Xdebug writes first.
            if (extension_loaded('xdebug'))
            {
                $res = preg_replace('@\A[^\n]*:\d+:\n@', '', $res, 1);
            }

            // Return result.
            return $res;
        };

        $results = array();
        $results['isSignatureValid()'] = $this->isSignatureValid() ? 'TRUE' : 'FALSE';
        $results['isDataEncrypted()'] = $this->isDataEncrypted() ? 'TRUE' : 'FALSE';
        $results['getTimestamp()'] = $this->getTimestamp();
        $results['getTokenId()'] = is_null($this->getTokenId()) ? 'NULL' : $this->getTokenId();
        $results['getAudience()'] = $dumpToString($this->getAudience());
        $results['getExpiry()'] = is_null($this->getExpiry()) ? 'NULL' : $this->getExpiry();
        $results['getData()'] = $dumpToString($this->getData());
        $results['getError()'] = is_null($this->getError()) ? 'NULL' : $this->getError();
        $results['getAnomalies()'] = $dumpToString($this->getAnomalies());
        $results['getCertDN()'] = $this->getCertDN();
        $results['getCertSubject()'] = $dumpToString($this->getCertSubject());
        $results['getCertIssuer()'] = $dumpToString($this->getCertIssuer());
        $results['getCertValidFrom()'] = $this->getCertValidFrom();
        $results['getCertValidTo()'] = $this->getCertValidTo();
        $results['isCertOutOfDate()'] = $this->isCertOutOfDate() ? 'TRUE' : 'FALSE';

        $html = '<table cellpadding="5">';
        $html .= '<tr><td colspan="2"><pre class="xdebug-var-dump"><b><span style="color: red">XML Digital Signature</span></b></pre></td></tr>';
        $html .= '<tr><td colspan="2"><pre>' . $escape($this->getPrettyXML()) . '</pre></td></tr>';
        $html .= '<tr><td width="1%"><pre><b><span style="color: red">METHOD CALLS</span></b></pre></td>';
        $html .= '<td valign="top" width="99%"><pre><b><span style="color: red">RESULTS</span></b></pre></td></tr>';
        foreach ($results as $key => $value) {
            $html .= '<tr><td valign="top"><pre><b>' . $escape($key) . '</b></pre></td>';
            $html .= '<td valign="top"><pre>' . $escape($value) . '</pre></td></tr>';
        }
        $html .= '</table>';

        return $html;
    }
}
