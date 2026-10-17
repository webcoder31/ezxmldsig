<?php

namespace webcoder31\ezxmldsig\Tests;

use webcoder31\ezxmldsig\XMLDSigToken;

/**
 * The certificates of examples/certs/ let the examples create a token that
 * examples/parse-xml-token.php accepts.
 */
class ExampleCertsTest extends TestCase
{
    /** The issuer that examples/parse-xml-token.php expects. */
    const EXPECTED_ISSUER = [
        'C'  => 'DK',
        'ST' => 'Jylland',
        'O'  => 'Lothbrok Ltd',
        'OU' => 'Shield Wall Dept',
        'CN' => 'www.lothbrok.dk',
        'emailAddress' => 'ivar@lothbrok.dk',
    ];

    private static function exampleCert($name)
    {
        return dirname(__DIR__) . '/examples/certs/' . $name;
    }

    /** The trust anchor that examples/parse-xml-token.php passes. */
    private static function exampleTrustAnchor()
    {
        return [
            'caCertPath' => [self::exampleCert('intermediate.cert.pem'), self::exampleCert('root.cert.pem')],
            'expectedSubject' => ['O' => 'Lothbrok Ltd', 'OU' => 'Signature Dept'],
        ];
    }

    public function testSignedTokenPassesTheChecksOfTheParsingExample()
    {
        $data = self::sampleData();
        $sig = XMLDSigToken::createXMLToken(
            $data,
            self::exampleCert('sign.key.pem'),
            self::exampleCert('sign.cert.pem'),
            'signKeyPassword'
        )->getXML();

        $token = XMLDSigToken::analyzeXMLToken($sig, self::exampleTrustAnchor());

        $this->assertNull($token->getError());
        $this->assertTrue($token->isSignatureValid());
        $this->assertFalse($token->isCertOutOfDate());
        $this->assertTrue($token->isValidCertIssuer(self::EXPECTED_ISSUER));
        $this->assertTrue($token->isValidCertCA(self::exampleCert('intermediate.cert.pem')));
        $this->assertFalse($token->isOutOfDate(120));
        $this->assertSame($data, $token->getData());
    }

    public function testEncryptedTokenPassesTheChecksOfTheParsingExample()
    {
        $this->requireSymmetricEncryption();

        // As examples/post-secure-xml-token.php does, the sender creates the
        // token without the private key of the recipient.
        $data = self::sampleData();
        $sig = XMLDSigToken::createSecureXMLToken(
            $data,
            self::exampleCert('sign.key.pem'),
            self::exampleCert('sign.cert.pem'),
            null,
            self::exampleCert('crypt.cert.pem'),
            'signKeyPassword'
        )->getXML();

        $token = XMLDSigToken::analyzeSecureXMLToken(
            $sig,
            self::exampleCert('crypt.key.pem'),
            'cryptKeyPassword',
            self::exampleTrustAnchor()
        );

        $this->assertNull($token->getError());
        $this->assertTrue($token->isSignatureValid());
        $this->assertFalse($token->isCertOutOfDate());
        $this->assertTrue($token->isValidCertIssuer(self::EXPECTED_ISSUER));
        $this->assertTrue($token->isValidCertCA(self::exampleCert('intermediate.cert.pem')));
        $this->assertFalse($token->isOutOfDate(120));
        $this->assertSame($data, $token->getData());
    }
}
