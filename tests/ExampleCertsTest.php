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

    public function testSignedTokenPassesTheChecksOfTheParsingExample()
    {
        $data = self::sampleData();
        $sig = XMLDSigToken::createXMLToken(
            $data,
            self::exampleCert('sign.key.pem'),
            self::exampleCert('sign.cert.pem'),
            'signKeyPassword'
        )->getXML();

        $token = XMLDSigToken::analyzeXMLToken($sig);

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

        $data = self::sampleData();
        $sig = XMLDSigToken::createSecureXMLToken(
            $data,
            self::exampleCert('sign.key.pem'),
            self::exampleCert('sign.cert.pem'),
            self::exampleCert('crypt.key.pem'),
            self::exampleCert('crypt.cert.pem'),
            'signKeyPassword',
            'cryptKeyPassword'
        )->getXML();

        $token = XMLDSigToken::analyzeSecureXMLToken(
            $sig,
            self::exampleCert('crypt.key.pem'),
            'cryptKeyPassword'
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
