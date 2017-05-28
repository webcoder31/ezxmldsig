<?php 
/**
 * parse-xml-token.php
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
echo '<h1>XMLDSig Token Analysis</h1>';

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
if ($token->isCertOutOfDate()) 
{
    echo "<h2>ERROR: Signing certificate is out of date!</h2>";
    echo "<h3>Token details:</h3>";
    echo $token->getHTMLDump();
    exit();
}

// Verify that the issuer of the X.509 certificate included 
// in the XML digital signature is indeed the one we expect.
if (!$token->checkCertIssuer($expectedIssuer)) 
{
    echo "<h2>ERROR: Issuer of signing certificate is not valid!</h2>";
    echo "<h3>Token details:</h3>";
    echo $token->getHTMLDump();
    exit();
}

// Verify that the X.509 certificate included in the XML
// digital signature actualy comes from the CA we expect.
if (!$token->checkCertCA($caCertPath)) 
{
    echo "<h2>ERROR: Signing certificate not issued by the expected CA!</h2>";
    echo "<h3>Token details:</h3>";
    echo $token->getHTMLDump();
    exit();
}

// Verify that the XML token was issued less than 2 minutes ago.
if ($token->isOutOfDate(120)) 
{
    echo "<h2>ERROR: Token is out of date!</h2>";
    echo "<h3>Token details:</h3>";
    echo $token->getHTMLDump();
    exit();
}

// All is fine ! We can trust user data.
echo "<h2>Token successfully verified!</h2>";

// Dump token data.
echo "<h3>Token data:</h3>";
var_dump($token->getData());

// Dump token object.
echo "<h3>Token details:</h3>";
echo $token->getHTMLDump();
