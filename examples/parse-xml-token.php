<?php 
/**
 * File: parse-xml-token.php
 *
 * WARNING: The private keys of examples/certs/ are public: they are
 * published with the source code of this library. Anyone can sign tokens
 * that these examples trust, and decrypt the tokens they encrypt. Use them
 * for this demonstration only, never in an application.
 */

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

// Trust anchor (required): the CA certificates up to which the chain of the
// signing certificate transmitted in the XML Digital Signature is verified.
// To trust the certificates issued by an intermediate CA, give its
// certificate AND the certificates up to its root: OpenSSL rejects a chain
// that stops at an intermediate CA.
// Optionally, the subject of the signing certificate can be constrained too.
$options = [
    'caCertPath' => ['./certs/intermediate.cert.pem', './certs/root.cert.pem'],
    'expectedSubject' => ['O' => 'Lothbrok Ltd', 'OU' => 'Signature Dept'],
];

// Create token object from the XML Digital Signature
$token = XMLDSigToken::analyzeSecureXMLToken($sig, $cryptKey, $cryptKeyPassword, $options);

// NOTE: The above instruction works even if user data is not encrypted.
// However, if user data is not encrypted and you don't own a private key
// then use the following method:
// $token = XMLDSigToken::analyzeXMLToken($sig, $options);

// Send back response to POST request.
echo '<html><body>';
echo '<h1>XMLDSig Token Analysis</h1>';

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
    echo "<h2>ERROR: Invalid XML Digital Signature!</h2>";
    echo "<p>" . htmlspecialchars((string) $token->getError(), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . "</p>";
}

// Verify that the XML token was issued less than 2 minutes ago.
else if ($token->isOutOfDate(120)) 
{
    echo "<h2>ERROR: Token is out of date!</h2>";
}

// All is fine ! We can trust user data.
// NOTE: A valid token can be posted again for as long as it is not out of
// date. An application must also refuse a token whose identifier
// ($token->getTokenId()) it has already accepted: the library keeps no list
// of the tokens it has seen (see the README, section "Replay").
else
{
    echo "<h2>Token successfully verified!</h2>";
    echo "<p>Token identifier: " . htmlspecialchars($token->getTokenId()) . "</p>";

    // Dump token data. Like anything that comes from the token, they are
    // escaped before being written in the page.
    echo "<h3>Token data:</h3>";
    echo "<pre>" . htmlspecialchars(print_r($token->getData(), true), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . "</pre>";
}

// Dump token object. getHTMLDump() escapes every value it shows.
echo "<h3>Token details:</h3>";
echo $token->getHTMLDump();

// Close HTML tags.
echo '</body></html>';
