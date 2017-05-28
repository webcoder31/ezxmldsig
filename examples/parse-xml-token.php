<?php 
/**
 * File: parse-xml-token.php
 */

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
$cryptKey = './certs/crypt.key.pem';
$cryptKeyPassword = 'cryptKeyPassword'; // Use null if it is not needed.

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
$caCertPath = './certs/intermediate.cert.pem';

// Create token object from the XML Digital Signature 
$token = XMLDSigToken::parseSecureXMLToken($sig, $cryptKey, $cryptKeyPassword);

// NOTE: The above instruction works even if user data is not encrypted.
// However, if user data is not encrypted and you don't own a private key 
// then use the following method:
// $token = XMLDSigToken::parseXMLToken($sig);

// Display analysis results.
echo '<html><body><h1>XMLDSig Token Analysis</h1>';

// Verify that:
// - the XML digital signature meets the XMLDSIG specifications.
// - the algorithms used to construct the XML digital signature are those 
//   expected (here, the default ones).
// - the token contained in the XML digital signature has not been altered.
// - the token contained in the XML digital signature is correctly timestamped
//   and contains user data.
if (!$token->isValid()) 
{
    echo "<h2>ERROR: Invalid XML Digital Signature!</h2>";
    echo "<h3>Token details:</h3>";
    echo $token->getHTMLDump();
    exit();
}

// Verify that the X.509 certificate included in 
// the XML digital signature is not out of date.
else if ($token->isCertOutOfDate()) 
{
    echo "<h2>ERROR: Signing certificate is out of date!</h2>";
    echo "<h3>Token details:</h3>";
    echo $token->getHTMLDump();
    exit();
}

// Verify that the issuer of the X.509 certificate included 
// in the XML digital signature is indeed the one we expect.
else if (!$token->checkCertIssuer($expectedIssuer)) 
{
    echo "<h2>ERROR: Issuer of signing certificate is not valid!</h2>";
    echo "<h3>Token details:</h3>";
    echo $token->getHTMLDump();
    exit();
}

// Verify that the X.509 certificate included in the XML
// digital signature actualy comes from the CA we expect.
else if (!$token->checkCertCA($caCertPath)) 
{
    echo "<h2>ERROR: Signing certificate not issued by the expected CA!</h2>";
    echo "<h3>Token details:</h3>";
    echo $token->getHTMLDump();
    exit();
}

// Verify that the XML token was issued less than 2 minutes ago.
else if ($token->isOutOfDate(120)) 
{
    echo "<h2>ERROR: Token is out of date!</h2>";
    echo "<h3>Token details:</h3>";
    echo $token->getHTMLDump();
    exit();
}

// All is fine ! We can trust user data.
else
{
    echo "<h2>Token successfully verified!</h2>";

    // Dump token data.
    echo "<h3>Token data:</h3>";
    var_dump($token->getData());
}

// Dump token object.
echo "<h3>Token details:</h3>";
echo $token->getHTMLDump();
echo '</body></html>';
