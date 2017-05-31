<?php
/**
 * XMLDSigToken.php
 *
 * Copyright © 2017 - Thierry Thiers <webcoder31@gmail.com>
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
 * @copyright 2017 - Thierry Thiers <webcoder31@gmail.com>
 * @license   http://www.cecill.info  CeCILL-C License
 * @version   1.0.0
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
use SimpleXMLElement;
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
 * - Algorithm used to canonalize data before signing is:
 *   http://www.w3.org/TR/2001/REC-xml-c14n-20010315.
 *
 * - Algorithm used to generate the signature is:
 *   http://www.w3.org/2000/09/xmldsig#rsa-sha1.
 *
 * - Algorithm used to compute the hash of token data is:
 *   http://www.w3.org/2000/09/xmldsig#sha1.
 *
 * - Algorithm used to encode data's values is: Base64.
 *
 * **An XML token looks like this:**
 *
 * <code>
 * <?xml version="1.0"?>
 * <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
 *   <ds:SignedInfo>
 *     <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
 *     <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
 *     <ds:Reference URI="#Token">
 *       <ds:Transforms>
 *         <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
 *       </ds:Transforms>
 *       <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
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
 *       <TokenTimestamp>2016-10-24T08:33:14Z</TokenTimestamp>
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
 * </code>
 *
 * **The signing process consists in the following actions:**
 *
 * - Load data from an associative array.
 *
 * - Encode data values using Base64.
 *
 * - Build a node from the encoded array of data (cf. node `<TokenData />`).
 *
 * - Compute an UTC timestamp and store it in a node `<TokenTimestamp />`.
 *
 * - Aggregate the nodes `<TokenTimestamp />` and `<TokenData />` inside a node 
 *   `<Token />`.
 *
 * - Load the base DOM document representing an XML digital signature:
 *   
 * <code>
 * <ds:Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
 *   <ds:SignedInfo>
 *     <ds:SignatureMethod />
 *   </ds:SignedInfo>
 * </ds:Signature>
 * </code>
 *
 * - Create a node `<ds:Object Id="Token" />` and append it to the node 
 *   `<ds:Signature />`.
 *
 * - Add the node `<Token />` to the node `<ds:Object Id="Token" />`.
 *
 * - NOTE : If data encryption is requested, this process will take place here
 *   (this will be described later).
 *
 * - Build a node `<ds:Reference URI="#Token" />` and append it to the node 
 *   `<ds:SignedInfo />`. This consists in:
 *
 *   - Canonicalizing the content of the node `<ds:Object Id="Token" />`.
 *
 *   - Computing the SHA1 hash of the canonicalized node and storing it in the
 *     node `<ds:DigestValue />`.
 *
 * - Includes, in the the XML token, the X.509 certificate associated to the 
 *   private key that will be used to perform the signing (see the next steps 
 *   below). This cerficate will be used to perform the signature validation 
 *   process, avoiding the need, for the receiver of the XML Digital Signature
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
 * **The signature validation process consist in the following actions:**
 *
 * - Load the XML Digital Singature in a DOM document.
 *
 * - Compute the SHA1 hash of the content of the node 
 *   `<ds:Object Id="Token" />`.
 *
 * - Compare the computed hash with the one stored in the node 
 *   `<ds:DigestValue />`. If the hash are different, this means that the 
 *   content of the node `<ds:Object Id="Token" />` has been altered.
 *
 * - Canonicalize the content of the node `<ds:SignedInfo />`.
 *
 * - Compute the signature of the node `<ds:SignedInfo />` using the X.509 
 *   certificate included in the XML token.
 *
 * - Compare the computed signature with the one stored in the node 
 *   `<ds:SignatureValue>`. If the signatures are different, this means that 
 *   content the node `<ds:SignedInfo />` has not been signed using the private 
 *   key associated to the X.509 certificate included in the XML Digital 
 *   Signature.
 *
 * - NOTE: If data decryption is required, this process will take place here
 *   (this will be described later).
 *
 * - Extract the timestamp stored in the content of the node 
 *   `<ds:Object Id="Token" />` and memorise it.
 *
 * - Extract the data stored in the content of the node 
 *   `<ds:Object Id="Token" />`.
 *
 * - Decode data values using Base64.
 *
 * - Buid an associative array containing the decoded data.
 *
 * **Token data encryption / decryption:**
 *
 * The token data may also be encrypted before signing. In this case the class 
 * will use the following default algorithms to perform encryption and 
 * decryption of data:
 *
 * - Algorithm used to encrypt / decrypt data is: 
 *   http://www.w3.org/2001/04/xmlenc#aes128-cbc (symetric ciphering).
 *
 * - Algorithm used to encrypt / decrypt the session key is: 
 *   http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p (asymetric ciphering).
 *
 * **A secure (crypted) XML token looks like this:**
 *
 * <code>
 * <?xml version="1.0"?>
 * <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
 *   <ds:SignedInfo>
 *     <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
 *     <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
 *     <ds:Reference URI="#Token">
 *       <ds:Transforms>
 *         <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
 *       </ds:Transforms>
 *       <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
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
 *       <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
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
 * </code>
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
    const RSA_1_5 = XMLSecurityKey::RSA_1_5;
    const RSA_OAEP_MGF1P = XMLSecurityKey::RSA_OAEP_MGF1P;
    const DSA_SHA1 = XMLSecurityKey::DSA_SHA1;
    const RSA_SHA1 = XMLSecurityKey::RSA_SHA1;
    const RSA_SHA256 = XMLSecurityKey::RSA_SHA256;
    const RSA_SHA384 = XMLSecurityKey::RSA_SHA384;
    const RSA_SHA512 = XMLSecurityKey::RSA_SHA512;
    const HMAC_SHA1 = XMLSecurityKey::HMAC_SHA1;


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
    private $signatureAlgorithm = self::RSA_SHA1;

    /** @var string The algorithm that should be used to compute the hash of the
    token. */
    private $digestAlgorithm = self::SHA1;

    /** @var string The algorithm that should be used to canonicalize the token
    before computing its hash. NOTE: In our case, it is the same algorithm as 
    the one used to canonicalize the node "ds:Signature/ds:signedInfo" 
    (see : $canonicalizationAlgorithm property). */
    private $transformAlgorithm = self::C14N;

    /** @var boolean Whether to check the algorithms actually used (read from
    the XML digital signature) to sign the token or not. */
    private $checkSigningAlgorithms = true;

    /** @var string The algorithm that should be used to generate the session 
    key which will be used to encrypt the token. */
    private $sessionKeyCipheringAlgorithm = self::AES128_CBC;

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

    /** @var string The token timestamp (format : 'yyyy-MM-ddThh:mm:ssZ'). */
    private $timestamp = null;

    /** @var X509Cert The X.509 certificate included in the XML Digital 
    Signature. */
    private $x509Certificate = null;

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
      the XML digital signature envoloping the token. */
    private $error = null;

    /** @var array List of the anomalies encountered during the analysis
      of the XML digital signature envoloping the token. */
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
            'isDataEncrypted'        => $this->isDataEncrypted,
            'timestamp'              => $this->timestamp,
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
     * existing XML token. The type of the `$xmlOrData` parameter determine how  
     * the object behave.
     *
     * **XML token creation:**
     *
     * If `$xmlOrData` is an array (a flat or multidimensional associative
     * array), the object will create an enveloping XML digital signature 
     * containing an XML token that holds the provided data and a timestamp 
     * generated automatically. The envoloped XML token will be encrypted if an 
     * X.509 certificate is provided for that. In this case, the `$signKeyPath` 
     * and `$signCertPath` parameters are required. If the `$cryptCertPath` 
     * parameter is also provided, the XML token will be encrypted. If the 
     * `$cryptCertPath` parameter is also provided, the $cryptKeyPath parameter 
     * must be provided too, in order to verify that the created XML Digital 
     * Signature is well formed. If the X.509 certificate used for encryption 
     * (cf. `$cryptCertPath` parameter) is protected by a password, this  
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
     * In this case, only the `$xmlOrData` parameters is required. If the XML 
     * token is encrypted, the `$cryptKeyPath` parameter must also be provided.
     * If the private key used for encryption (cf. `$cryptKeyPath` parameter) is 
     * protected by a password this password may be passed using the 
     * `$cryptKeyPassword` parameter.
     *
     * **Configuring the object:**
     *
     * The `$options` parameter of this function allows to override the default
     * configuration of the object passing it the desired options via an 
     * associative array.
     *
     * Example:
     *
     * <code>
     * $options = [
     *   'base64Encode' => false,
     *   'xmldsigNsPrefix' => '',
     *   'checkSigningAlgorithms' => false
     * ];
     * </code>
     *
     * Available options are the following:
     *
     * - **`base64Encode`** [boolean] Whether to base64 encode token data or 
     *   not.
     *   <br/>Default value: **`TRUE`**.
     *
     * - **`xmldsigNsPrefix`** [string] The XML namespace (xmlns) prefix to use  
     *   in the XML digital signature tags. Set it to empty string to avoid  
     *   prefix usage.
     *   <br/>Default value: **`'ds'`**.
     *
     * - **`checkSigningAlgorithms`** [boolean] Whether to check that the 
     *   algorithms used to sign the token are the expected ones or not.
     *   <br/>Default value: **`TRUE`**.
     *
     * - **`checkCryptingAlgorithms`** [boolean] Whether to check that the
     *   algorithms used to crypt the token are the expected ones or not.
     *   <br/>Default value: **`TRUE`**.
     *
     * - **`canonicalizationAlgorithm`** [string] The algorithm used to 
     *   canonicalize the XMLdigital signature and to canonicalize token data
     *   before computing its hash. 
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
     * - **`signatureAlgorithm`** [string] The asymmetric algorithm used to sign 
     *   the hash of token data. 
     *   <br/>Possible values:
     *
     *   - `RSA_1_5`
     *     <br/>cf. http://www.w3.org/2001/04/xmlenc#rsa-1_5
     *
     *   - `RSA_OAEP_MGF1P`
     *     <br/>cf. http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p
     *
     *   - `DSA_SHA1` (Does not work)
     *     <br/>cf. http://www.w3.org/2000/09/xmldsig#dsa-sha1)
     *
     *   - **`RSA_SHA1`** (Default value)
     *     <br/>cf. http://www.w3.org/2000/09/xmldsig#rsa-sha1
     *
     *   - `RSA_SHA256`
     *     <br/>cf. http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
     *
     *   - `RSA_SHA384`
     *     <br/>cf. http://www.w3.org/2001/04/xmldsig-more#rsa-sha384
     *
     *   - `RSA_SHA512`
     *     <br/>cf. http://www.w3.org/2001/04/xmldsig-more#rsa-sha512
     *
     *   - `HMAC_SHA1` (Does not work)
     *     <br/>cf. http://www.w3.org/2000/09/xmldsig#hmac-sha1
     *
     * - **`digestAlgorithm`** [string] The algorithm used to compute the hash
     *   of token data. 
     *   <br/>Possible values:
     *
     *   - **`SHA1`** (Default value)
     *     <br/>cf. http://www.w3.org/2000/09/xmldsig#sha1
     *
     *   - `SHA256`
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
     * - **`sessionKeyCipheringAlgorithm`** [string] The symmetric algorithm
     *   used to cipher the session key which will be used to encrypt token
     *   date. 
     *   <br/>Possible values:
     *
     *   - `TRIPLEDES_CBC`
     *     <br/>cf. http://www.w3.org/2001/04/xmlenc#tripledes-cbc
     *
     *   - **`AES128_CBC`** (Default value)
     *     <br/>cf. http://www.w3.org/2001/04/xmlenc#aes128-cbc
     *
     *   - `AES192_CBC`
     *     <br/>cf. http://www.w3.org/2001/04/xmlenc#aes192-cbc
     *
     *   - `AES256_CBC`
     *     <br/>cf. http://www.w3.org/2001/04/xmlenc#aes256-cbc
     *
     * - **`cryptAlgorithm`** [string] The asymmetric algorithm used to encrypt
     *   token data with the ciphered session key. 
     *   <br/>Possible values:
     *
     *   - `RSA_1_5`
     *     <br/>cf. http://www.w3.org/2001/04/xmlenc#rsa-1_5
     *
     *   - **`RSA_OAEP_MGF1P`** (Default value)
     *     <br/>cf. http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p
     *
     *   - `DSA_SHA1` (Does not work)
     *     <br/>cf. http://www.w3.org/2000/09/xmldsig#dsa-sha1
     *
     *   - `RSA_SHA1` (Does not work)
     *     <br/>cf. http://www.w3.org/2000/09/xmldsig#rsa-sha1
     *
     *   - `RSA_SHA256`
     *     <br/>cf. http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
     *
     *   - `RSA_SHA384`
     *     <br/>cf. http://www.w3.org/2001/04/xmldsig-more#rsa-sha384
     *
     *   - `RSA_SHA512`
     *     <br/>cf. http://www.w3.org/2001/04/xmldsig-more#rsa-sha512
     *
     *   - `HMAC_SHA1` (Does not work)
     *     <br/>cf. http://www.w3.org/2000/09/xmldsig#hmac-sha1
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
     * @param string $cryptKeyPath The path to the PEM private key file that
     *     will be used to decrypt the session key which was used to encrypt the 
     *     token.
     *
     * @param string $cryptKeyPassword The password to access the private key 
     *     that will be used to decrypt the session key which was used to 
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
        // Load configuration options.
        $base64Encode = (isset($options['base64Encode']) && is_bool($options['base64Encode'])) ? $options['base64Encode'] : true;

        $xmldsigNsPrefix = (isset($options['xmldsigNsPrefix']) && is_string($options['xmldsigNsPrefix'])) ? $options['xmldsigNsPrefix'] : null;

        $checkSigningAlgorithms = (isset($options['checkSigningAlgorithms']) && is_bool($options['checkSigningAlgorithms'])) ? $options['checkSigningAlgorithms'] : true;
        $checkCryptingAlgorithms = (isset($options['checkCryptingAlgorithms']) && is_bool($options['checkCryptingAlgorithms'])) ? $options['checkCryptingAlgorithms'] : true;

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
                throw new Exception("Invalid parameter 'canonicalizationAlgorithm'! Unknwon canonicalization algorithm.");
            }
        }

        // If provided, set and store the signature algorithm.
        if (!is_null($signatureAlgorithm))
        {
            if (self::_isValidAsymmetricCipheringAlgorithm($signatureAlgorithm))
            {
                $this->signatureAlgorithm = $signatureAlgorithm;
            }
            else
            {
                throw new Exception("Invalid parameter 'signatureAlgorithm'! Unknwon signature algorithm.");
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
                throw new Exception("Invalid parameter 'digestAlgorithm'! Unknwon digest algorithm.");
            }
        }

        // If requested, disable check of signature algorithms.
        if (false === $checkSigningAlgorithms)
        {
            $this->checkSigningAlgorithms = false;
        }

        // Check what have to be done according to the type of $xmlOrData 
        // parameter.
        if (is_array($xmlOrData))
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

                // Ensures the private key associated to the X.509 certificate 
                // that willbe used to perform encryption is also provided, in 
                // order to verify that the created XML token is well formed.
                if (is_null($cryptKeyPath)) {
                    throw new Exception("Missing parameter 'cryptKeyPath'! A private key must be provided to decrypt token.");
                }

                // Get and store the private key that will be used to decrypt
                // the session key which was used to encrypt the token data.
                // NOTE : This key will be used to verify that the generated
                //        XML token is well formed.
                $cryptKey = @file_get_contents($cryptKeyPath);
                if (false === $cryptKey)
                {
                    throw new Exception("Invalid parameter 'cryptKeyPath'! Cannot read private key to decrypt token.");
                }
                $this->cryptKey = $cryptKey;

                // If provided, store the password to access the private key 
                // that will be used used to decrypt the session key.
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
                    if (self::_isValidHashAlgorithm($sessionKeyCipheringAlgorithm))
                    {
                        $this->sessionKeyCipheringAlgorithm = $sessionKeyCipheringAlgorithm;
                    }
                    else
                    {
                        throw new Exception("Invalid parameter 'sessionKeyCipheringAlgorithm'! Unknwon session key ciphering algorithm.");
                    }
                }

                // If provided, set and store the crypt algorithm.
                if (!is_null($cryptAlgorithm))
                {
                    if (self::_isValidAsymmetricCipheringAlgorithm($cryptAlgorithm))
                    {
                        $this->cryptAlgorithm = $cryptAlgorithm;
                    }
                    else
                    {
                        throw new Exception("Invalid parameter 'cryptAlgorithm'! Unknwon crypt algorithm.");
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
                // terminate setting object preperties.
                $this->_writeXML($xmlOrData);
            }
            catch (Exception $e)
            {
                // ERROR : XML token analysis failed on fatal error.
                $this->error = $e->getMessage();
            }
        }
        elseif (is_string($xmlOrData))
        {
            // $xmlOrData is a string, so we have to analyze the XML token.

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
                // that will be used used to decrypt the session key.
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
                    if (self::_isValidHashAlgorithm($sessionKeyCipheringAlgorithm))
                    {
                        $this->sessionKeyCipheringAlgorithm = $sessionKeyCipheringAlgorithm;
                    }
                    else
                    {
                        throw new Exception("Invalid parameter 'sessionKeyCipheringAlgorithm'! Unknwon session key ciphering algorithm.");
                    }
                }

                // If provided, set and store the crypt algorithm.
                if (!is_null($cryptAlgorithm))
                {
                    if (self::_isValidAsymmetricCipheringAlgorithm($cryptAlgorithm))
                    {
                        $this->cryptAlgorithm = $cryptAlgorithm;
                    }
                    else
                    {
                        throw new Exception("Invalid parameter 'cryptAlgorithm'! Unknwon crypt algorithm.");
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
                // ERROR : XML token analysis failed on fatal error.
                $this->error = $e->getMessage();
            }
        }
        else
        {
            throw new Exception("Invalid parameter 'xmlOrData'! Parameter must be either an array or a string!");
        }
    }


    /**
     * Creates an XML token for the given user data.
     *
     * The created XML token can be retrieved using the fucnction `getXML()`.
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
     * @return XMLDSigToken An XMLDSigToken object or NULL if the object
     *     creation failed.
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
            $options
        );
    }


    /**
     * Creates a secure (crypted) XML token for the given user data.
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
     * @param string $cryptKeyPath The path to the PEM private key file that 
     *     will be used to decrypt the session key which was used to encrypt the
     *     token.
     *
     * @param string $cryptCertPath The path to the PEM X.509 certificate file 
     *     that will be used to encrypt the session key which will be used to 
     *     encrypt the token.
     *
     * @param string $signKeyPassword The password to access the private key 
     *     that will be used to sign the token. Use NULL if no password needed.
     *
     * @param string $cryptKeyPassword The password to access the private key 
     *     that will be used to decrypt the session key which was used to 
     *     encrypt the token. Use NULL if no password needed.
     *
     * @param array $options Configuration options
     *     (see `__construct()` for details). 
     *
     * @return XMLDSigToken An XMLDSigToken object or NULL if the object 
     *     creation failed.
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
     * @param string $xml An XML token.
     *
     * @param array $options Configuration options
     *     (see `__construct()` for details). 
     *
     * @return XMLDSigToken An XMLDSigToken object or NULL if the object 
     *     creation failed.
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
     * Parse an XML token whose data are crypted.
     *
     * NOTE: Uncrypted token can also be parsed using this function.
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
     * @param array $options Configuration options
     *     (see `__construct()` for details). 
     *
     * @return XMLDSigToken An XMLDSigToken object or NULL if the object 
     *     creation failed.
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
     * The XML token can then be obtained usind the `getXML()` function.
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

        /**
         * Inline function to build a node tree, whose root node will be named
         * $nodeName, from the array $data and appends it to the given 
         * $parentNode node. The value of the leaves are base64 encoded by this
         * function.
         *
         * NOTE : This function is called recursively if $data is a 
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
            // Randomly generate a session key using AES-128 algorithm.
            // This key will be used to cipher our node "Token" (the content of  
            // the node "ds:Object").
            $sessionKey = new XMLSecurityKey($this->sessionKeyCipheringAlgorithm);
            $sessionKey->generateSessionKey();

            // Create an asymetric key from the X.509 certificate using RSA-OAEP
            // algorithm. This key will be used to encrypt the session key.
            $asymKey = new XMLSecurityKey($this->cryptAlgorithm, array('type' => 'public'));
            $asymKey->loadKey($this->cryptCert, false, true);
            if (empty($asymKey->key))
            {
                // ERROR: Failed loading certificate to encrypt session key!
                throw new Exception("Failed loading certificate to encrypt session key!");
            }

            // Encrypt the session key using the asymetric key.
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
        // This consists in :
        //     - Adding a node "ds:Reference" to the node "ds:SignedInfo".
        //     - Computing a hash, using the digest algorithm, from the
        //       canonicalized XML sting corresponding to the node "ds:Object".
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
        // from the XML token. This consists in adding a node "ds:KeyInfo" that
        // holds the content of the X.509 certificate.
        $XMLDSig->add509Cert($this->signCert);

        // Sign the token data using the private security key associated to the
        // X.509 certificate.
        // This consists in :
        //     - Computing the signature of the node "ds:SignedInfo".
        //     - Adding a node named "ds:SignatureValue" that contains the 
        //       computed signature.
        $XMLDSig->sign($privateKey);

        // Check that the created XML token is well formed (if it's valid and if 
        // timestamp and data can be retrived from it) and, by the way, 
        // terminate to initialize the properties of our XMLDSigToken object.
        $this->_readXML($XMLDSig->sigNode->ownerDocument->saveXML());
    }


    /**
     * Read the XML Digital Signature representing an XML token.
     *
     * This function will check that the provided XML Digital Signature is 
     * valid, will decrypt the token data it contains if this one is encrypted 
     * and then will extract timestamp and data.
     *
     * The data can then be obtained using the `getData()` function. Neverless,
     * you have to ensure that you can trust it using functions provided for 
     * that (i.e. `isSignatureValid()`, `isOutOfDate()`, `isValidIssuer()`, 
     * `isValidCA()` and so on).
     *
     * NOTE: This function is called by the `_writeXML()` function to ensure the
     * XML token it built is correct and because this function set most of the 
     * properties of the XMLDSigToken object that are issued from the analysis
     * of the XML token.
     *
     * @param string $xml The XML Digital Signature representing an XML token.
     *
     * @throws Exception
     */
    private function _readXML($xml)
    {
        // Store the provided XML Digital Signature.
        $this->xml = $xml;

        // Check that the provided string is a valid XML document.
        $isValidXml = true;
        $prevState = libxml_use_internal_errors(true); // Told PHP to not output warnings on errors.

        try
        {
            new SimpleXMLElement($this->xml);
        }
        catch (Exception $e)
        {
            $isValidXml = false;
        }

        if (count(libxml_get_errors()) > 0)
        {
            // There has been XML errors.
            $isValidXml = false;
        }

        libxml_clear_errors(); // Clean up libxml errors.
        libxml_use_internal_errors($prevState); // Restore libxml to its previous state.

        if (!$isValidXml)
        {
            throw new Exception("XML Digital Signature is not a valid XML document!");
        }

        // Prepair a DOM document where to load the XML Digital Signature.
        $xmlDoc = new DOMDocument('1.0', 'UTF-8');

        // Load the enveloping XML Digital Signature into the DOM document
        // preserving its formatting.
        $xmlDoc->preserveWhiteSpaces = true;
        $xmlDoc->loadXML($xml);       

        // Instantiate and store a DOMXpath object to navigate through the DOM
        // document that holds the XML Digital Signature.
        $this->xpath = new DOMXPath($xmlDoc);
        $this->xpath->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
        $this->xpath->registerNamespace('xenc', XMLSecEnc::XMLENCNS);

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
                'validateFunction' => '_isValidAsymmetricCipheringAlgorithm',
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
                    'validateFunction' => '_isValidAsymmetricCipheringAlgorithm',
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
        }

        // Create an XMLSecurityDSig object.
        $XMLDSig = new XMLSecurityDSig();

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
        // informations which should be stored in the node 
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
        // "ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue".
        try
        {
            $XMLDSig->validateReference();
            $this->isDigestValueOk = true;
        }
        catch (Exception $e)
        {
            // ANOMALY: Token hash verification failed!
            $this->isDigestValueOk = false;
            $this->anomalies[] = "Token hash verification failed!";
        }

        // Canonicalize the node "ds:Signature/ds:SignedInfo".
        $XMLDSig->canonicalizeSignedInfo();

        // Verifies that the signature held in the node 
        // "ds:Signature/ds:SignatureValue" is correct for the node 
        // "ds:Signature/ds:SignedInfo" using the key we've just built from the
        // X.509 certificate found in the XML Digital Signature.
        if ($XMLDSig->verify($objKeyX509))
        {
            // Token signature is not valid!
            $this->isSignatureValueOk = true;
        }
        else
        {
            // ANOMALY: Token hash signature verification failed!
            $this->isSignatureValueOk = false;
            $this->anomalies[] = "Token hash signature verification failed!";
        }

        // Create an XMLSecEnc object.
        $objXMLSecEnc = new XMLSecEnc();

        // Check if the content of the node "ds:Object" is ciphered.
        $encryptedDataNode = $objXMLSecEnc->locateEncryptedData($xmlDoc);

        if (is_null($encryptedDataNode))
        {
            // The node "ds:Object" is not ciphered.
            // Set encryption flag to FALSE.
            $this->isDataEncrypted = false;
        }
        else
        {
            // The node "ds:Object" is ciphered. We will decrypt it now.
            // Set encryption flag to TRUE.
            $this->isDataEncrypted = true;

            // Check that we have a private key to perform decryption.
            if (is_null($this->cryptKey))
            {
                // ERROR: No private key provided for decryption.
                throw new Exception("Token is encrypted but no private key is provided for decryption!");
            }

            // Passes the node containing the ciphered token to the XMLSecEnc
            // object.
            $objXMLSecEnc->setNode($encryptedDataNode);

            // Indicates to the XMLSecEnc object what is encrypted (the node
            // element or only its content) by reading the attribute "Type" of 
            // the node containing the ciphered data (the child node of the 
            // node "ds:Object").
            $objXMLSecEnc->type = $encryptedDataNode->getAttribute("Type");

            // Get an XMLSecurityKey object already configured with the
            // algorithm which was used to encrypt the session key.
            $objKeyCrypt = $objXMLSecEnc->locateKey();
            if (is_null($objKeyCrypt))
            {
                // ERROR: The encrypted session key has been found but not the
                // algorithm.
                throw new Exception("Cannot locate session key ciphering algorithm!");
            }

            // Retrieve encrypted session key and decipher it using the private
            // key. We will use it later to decrypt the token data.
            $objKeyInfoCrypt = $objXMLSecEnc->locateKeyInfo($objKeyCrypt);
            if (is_null($objKeyInfoCrypt))
            {
                // ERROR: Session key cannot be found.
                throw new Exception("Cannot locate session key!");
            }
            else
            {
                if (!$objKeyInfoCrypt->isEncrypted)
                {
                    // ERROR: Session key found but it is not encrypted.
                    throw new Exception("Session key is not encrypted!");
                }
                else
                {
                    // Loads the private key to be be used for deciphering the
                    // crypted session key. If a password is provided, use it to
                    // access the private key.
                    if (!is_null($this->cryptKeyPassword))
                    {
                        $objKeyInfoCrypt->passphrase = $this->cryptKeyPassword;
                    }
                    $objKeyInfoCrypt->loadKey($this->cryptKey, false);

                    if (empty($objKeyInfoCrypt->key))
                    {
                        // ERROR: Failed loading private key to decrypt session
                        // key!
                        throw new Exception("Failed loading private key to decrypt session key!");
                    }

                    // Prepare the decryption key object that will be used to
                    // decipher the token data by passing the deciphered session
                    // key to it.
                    $objXMLSecCrypt = $objKeyInfoCrypt->encryptedCtx;
                    try
                    {
                        $decrypedtKey = $objXMLSecCrypt->decryptKey($objKeyInfoCrypt);
                    }
                    catch (Exception $e)
                    {
                        // ERROR: Session key decryption failed.
                        throw new Exception("Session key decryption failed! Reason: " . $e->getMessage() . ".");
                    }

                    $objKeyCrypt->loadKey($decrypedtKey);
                    if (empty($objKeyCrypt->key))
                    {
                        // ERROR: Failed loading decrypted session key to
                        // decrypt token data!
                        throw new Exception("Failed loading decrypted session key to decrypt token data!");
                    }
                }
            }

            // Decrypt the ciphered token data using the decryption key we've 
            // just prepared.
            try
            {
                $decryptedDataNode = $objXMLSecEnc->decryptNode($objKeyCrypt, true);
            }
            catch (Exception $e)
            {
                // ERROR: Token data decryption failed.
                throw new Exception("Token data decryption failed! Reason: " . $e->getMessage() . ".");
            }
        }

        // Verify that the token data is well formed.
        $queries = array(
            "//ds:Signature/ds:Object/" . self::TOKEN_NAME,
            "//ds:Signature/ds:Object/" . self::TOKEN_NAME . "/" . self::TOKEN_TIMESTAMP_NAME,
            "//ds:Signature/ds:Object/" . self::TOKEN_NAME . "/" . self::TOKEN_DATA_NAME,
        );

        foreach ($queries as $query)
        {
            if ($this->xpath->query($query)->length !== 1)
            {
                // ERROR: Malformed token!
                throw new Exception("Malformed token!");
            }
        }

        // Get the node "ds:Signature/ds:Object/Token/TokenTimestamp".
        $query = "//ds:Signature/ds:Object/" . self::TOKEN_NAME . "/" . self::TOKEN_TIMESTAMP_NAME;
        $nodeTokenTimestamp = $this->xpath->query($query)->item(0);

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

        // Get the node "ds:Signature/ds:Object/Token/TokenData".
        $query = "//ds:Signature/ds:Object/" . self::TOKEN_NAME . "/" . self::TOKEN_DATA_NAME;
        $nodeTokenData = $this->xpath->query($query)->item(0);

        /**
         * Inline function to build a flat or multi-dimensional associative
         * array from a node tree whose leaves values are base64 encoded. The
         * values of the leaves are base64 decoded by this function.
         *
         * NOTE : This function is called recursively if the node tree is more
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

        // Check that token data if well formed and extract data.
        $tokenData = array();
        $nodeTreeToData($nodeTokenData, $tokenData);

        // Store token data.
        $this->data = $tokenData;

        // If any anomaly has been detected during analysis, set an error
        // message.
        if (!empty($this->anomalies))
        {
            $nb = count($this->anomalies);
            throw new Exception($nb . ($nb === 1 ? " anomaly" : " anomalies") . " detected: " . implode(" ; ", $this->anomalies));
        }
    }


    /**
     * Indicates whether XML token signature is valid or not.
     *
     * This means that:
     *
     * - No error occured during the analysis of the XML digital signature.
     *
     * - No anomaly detected during the analysis of the XML digital signature.
     *
     * - The token hash has been verified and is valid.
     *
     * - The token hash signature has been verified and is valid.
     * 
     * NOTE: This function only guarantee the integrity of the token regarding
     * the X.509 certificate included in the XML token. It does not verify
     * whether this certificate is valid or not.
     *
     * @return boolean TRUE if XML token is valid, FALSE otherwise.
     */
    public function isSignatureValid()
    {
        return true === $this->isDigestValueOk && true === $this->isSignatureValueOk && is_null($this->error);
    }


    /**
     * Indicates whether the XML token is out of date or not.
     *
     * NOTE: If token timestamp is over the current date/time, we assume token
     * is peremted too.
     *
     * @param int $ttl The time to live (in seconds) allowed for the token.
     *
     * @return boolean TRUE if token is out of date, FALSE otherwise.
     */
    public function isOutOfDate($ttl = self::TOKEN_DEFAULT_TTL)
    {
        if (is_null($this->timestamp))
        {
            // Timestamp is missing! So we assume token is peremted.
            return true;
        }

        // We will compare date using UTC timezone.
        $timezone = new DateTimeZone('UTC');

        // Compute the UTC UNIX timestamp from the token timestamp string.
        $tokenUTCDate = DateTime::createFromFormat(self::TOKEN_TIMESTAMP_FORMAT, $this->timestamp, $timezone);
        if (false === $tokenUTCDate)
        {
            // Token timestamp format is incorrect! So we assume token is 
            // peremted.
            return true;
        }
        $tokenUTCTimestamp = $tokenUTCDate->getTimestamp();

        // Compute the UTC UNIX timestamp for the current date/time.
        $curUTCDate = new DateTime('now', $timezone);
        $curUTCTimestamp = $curUTCDate->getTimestamp();

        // Return timestamps comparison result.
        return $tokenUTCTimestamp > ($curUTCTimestamp + self::DESYNC_TOLERANCE) || ($tokenUTCTimestamp + $ttl) < $curUTCTimestamp;
    }


    /**
     * Indicates whether token data is encrypted or not.
     *
     * NOTE: If not evaluated (because an error occured before), this function
     * return NULL.
     *
     * @return boolean TRUE if token data is encrypted, FALSE otherwise.
     */
    public function isDataEncrypted()
    {
        return $this->isDataEncrypted;
    }


    /**
     * Indicates whether the digest of token data (a hash) has been verified and 
     * is valid or not.
     *
     * NOTE: If not evaluated (because an error occured before), this function
     * return NULL.
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
     * NOTE: If not evaluated (because an error occured before), this function 
     * return NULL.
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
     * @return string|null The token timestamp, NULL if not available.
     */
    public function getTimestamp()
    {
        return $this->timestamp;
    }


    /**
     * Get the message of the error that occured while parsing the XML token.
     *
     * @return string|null The error message. If no error, NULL is returned.
     */
    public function getError()
    {
        return $this->error;
    }


    /**
     * Get the list of anomalies that occured while parsing the XML token.
     *
     * @return array|null The list of anomalies if any, NULL otherwise.
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
     * @param string The format of the returned date (Default: 
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
     * @param string The format of the returned date (Default: 
     *     XMLDSigToken::TOKEN_TIMESTAMP_FORMAT).
     *
     * @return string|null|false The date to which the X.509 certificate, NULL 
     *     if not available, FALSE if $dateFormat is invalid.
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
     * The expected issuer information must me passed as an array to the 
     * function:
     * 
     * <code>
     * $ExpectedIssuerInfo = [
     *     'C' => 'DK',
     *     'ST' => 'Jylland',
     *     'O' => 'Lothbrok Ltd',
     *     'OU' => 'Jarl Dept',
     *     'CN' => 'www.Lothbrok.dk',
     *     'emailAddress' => 'ragnar@Lothbrok.dk'
     * ];
     * </code>
     *
     *  NOTE: Character case of data is significant.
     *
     * @param array $expectedIssuerInfo The issuer information that the X.509 
     * certificate should match.
     *
     * @return boolean TRUE if the X.509 certificate has been signed with the
     * provided CA certificate, FALSE otherwise.
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
        foreach ($expectedIssuerInfo as $key => $value)
        {
            if (!isset($certIssuerInfo[$key]) || $certIssuerInfo[$key] !== $value)
            {
                // Issuer information of the X.509 certificate does not match 
                // the expected one.
                return false;
            }
        }

        // Issuer is the expected one.
        return true;
    }


    /**
     * Check that the X.509 certificate included in the XML token comes from the
     * expected CA.
     *
     * Note that more than one CA certificate can give a positive result, some 
     * certificates re-issue signing certificates after having only changed the
     * expiration dates.
     *
     * Note that it also works with self-signed certificates. In this case, 
     * passes the X.509 certificate that is supposed been included in the XML 
     * token to the function.
     *
     * @param string $caCertPath The PEM certificate (public key) that is 
     *     supposed been used by CA to sign the X.509 certificate included in
     *     the XML token.
     *
     * @return boolean TRUE if the X.509 certificate has been signed by the
     *     expected CA, FALSE otherwise.
     *
     * @throws Exception
     */
    public function isValidCertCA($caCertPath)
    {
        // Get the CA public key that is supposed be used to sign the X.509 
        // certificate. 
        $caCert = @file_get_contents($caCertPath);
        if (false === $caCert)
        {
            throw new Exception("Cannot read CA certificate to perform signer check! File: " . $caCertPath);
        }

        return $this->x509Certificate->isValidCA($caCert);
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
     * Check if an algorithm is valid to perform asymmetric ciphering
     * operations.
     *
     * @param string $algorithm The algorithm reference (URL).
     *
     * @return boolean TRUE if valid, FALSE otherwise.
     */
    static private function _isValidAsymmetricCipheringAlgorithm($algorithm)
    {
        switch ($algorithm)
        {
            case (self::RSA_1_5):
            case (self::RSA_OAEP_MGF1P):
            // case (self::DSA_SHA1): // Does not work.
            case (self::RSA_SHA1): // Does not work as signature algorithm.
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
     * Check if an algorithm is valid to perform symmetric ciphering operations.
     *
     * @param string $algorithm The algorithm reference (URL).
     *
     * @return boolean TRUE if valid, FALSE otherwise.
     */
    static private function _isValidSymmetricCipheringAlgorithm($algorithm)
    {
        switch ($algorithm)
        {
            case (self::TRIPLEDES_CBC):
            case (self::AES128_CBC):
            case (self::AES192_CBC):
            case (self::AES256_CBC):
                return(true);
            default:
                return(false);
        }
    }


    /**
     * Utility function for modifying a node of an XML content.
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
     * @param string $newValue The value that will replace original the value of
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
        $xmlDoc = new DOMDocument();
        $xmlDoc->formatOutput = false;
        $xmlDoc->loadXML($xml);

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
     * This function is intented for display purpose only. Use the `getXML()` 
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

        // Inline function that split the value of a node 
        // into multiple lines of 64 characters long.
        $splitNodeValue = function(&$xml, $prefix, $xpathQuery)
        {
            $xpathQuery = str_replace('ds:', $prefix, $xpathQuery);
            $nodeValue = XMLDSigToken::alterXML($xml, $xpathQuery, null, 'placeholer', false);
            $nodeValue = PHP_EOL . implode(str_split($nodeValue, 64), PHP_EOL) . PHP_EOL;
            XMLDSigToken::alterXML($xml, $xpathQuery, null, $nodeValue, false);
            // Remove XML encoded carriage return introduced when spliting node 
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
                // Opening and closing tags on same line : no change.
                $indent = 0;
            }
            elseif (preg_match('/^<\/\w/', $tok, $matches))
            {
                // Closing tag : outdent now.
                $pad = $pad - $indent_size;
            }
            elseif (preg_match('/^<\w[^>]*[^\/]>.*$/', $tok, $matches))
            {
                // Opening tag : don't pad this one, only subsequent tags.
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
     */
    public function getHTMLDump()
    {

        // Inline function to output var_dump() into a string.
        $dumpToString = function($var)
        {
            ob_start();
            var_dump($var);
            return preg_replace('@<small>.+</small>.*\n@', '', ob_get_clean(), 1);
        };

        $results = array();
        $results['isSignatureValid()'] = $this->isSignatureValid() ? 'TRUE' : 'FALSE';
        $results['isDataEncrypted()'] = $this->isDataEncrypted() ? 'TRUE' : 'FALSE';
        $results['getTimestamp()'] = $this->getTimestamp();
        $results['getData()'] = $dumpToString($this->getData());
        $results['getError()'] = is_null($this->getError()) ? 'NULL' : $this->getError();
        $results['getAnomalies()'] = $dumpToString($this->getAnomalies());
        $results['getCertDN()'] = $this->getCertDN();
        $results['getCertSubject()'] = $dumpToString($this->getCertSubject());
        $results['getCertIssuer()'] = $dumpToString($this->getCertIssuer());
        $results['getCertValidFrom()'] = $this->getCertValidFrom();
        $results['getCertValidTo()'] = $this->getCertValidTo();
        $results['isCertOutOfDate()'] = $this->isCertOutOfDate() ? 'TRUE' : 'FALSE';

        $html = '<script src="https://cdn.rawgit.com/google/code-prettify/master/loader/run_prettify.js"></script>';
        $html .= '<table cellpadding="5">';
        $html .= '<tr><td colspan="2"><pre class="xdebug-var-dump"><b><span style="color: red">XML Digital Signature</span></b></pre></td></tr>';
        $html .= '<tr><td colspan="2"><pre class=\"prettyprint\">' . htmlentities($this->getPrettyXML()) . '</pre></td></tr>';
        $html .= '<tr><td width="1%"><pre class="xdebug-var-dump"><b><span style="color: red">METHOD CALLS</span></b></pre></td>';
        $html .= '<td valign="top" width="99%"><pre class="xdebug-var-dump"><b><span style="color: red">RESULTS</span></b></pre></td></tr>';
        foreach ($results as $key => $value) {
            $html .= '<tr><td valign="top"><pre class="xdebug-var-dump"><b>' . $key . '</b></pre></td>';
            $html .= '<td valign="top"><pre class="xdebug-var-dump">' . $value . '</pre></td></tr>';
        }
        $html .= '</table>';

        return $html;
    }
}
