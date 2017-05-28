<?php 
/**
 * File: post-secure-xml-token.php
 */

// Autoload required classes.
require dirname(__DIR__) . '/vendor/autoload.php';

// Use statements.
use webcoder31\ezxmldsig\XMLDSigToken;

// Asymmetric cryptographic key pair for signing (in PEM format).
$signKey = './certs/sign.key.pem';
$signCert = './certs/sign.cert.pem';
$signKeyPassword = 'signKeyPassword'; // Use null if it is not needed.

// Asymmetric cryptographic key pair for crypting (in PEM format).
$cryptKey = './certs/crypt.key.pem';
$cryptCert = './certs/crypt.cert.pem';
$cryptKeyPassword = 'cryptKeyPassword'; // Use null if it is not needed.

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

// Base64 encode the XML Digital Signature.
$post = ['xmltoken' => base64_encode($sig)];

// Post the Base64 encoded XML Digital Signature over HTTP using CURL.
$serverUrl = dirname((isset($_SERVER['HTTPS']) ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]") . "/parse-xml-token.php";
$ch = curl_init($serverUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
$response = curl_exec($ch);
curl_close($ch);

// Display the HTTP POST response.
echo $response;