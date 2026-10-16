<?php

namespace webcoder31\ezxmldsig\Tests;

use DateTime;
use DateTimeZone;
use webcoder31\ezxmldsig\XMLDSigToken;

/**
 * Legitimate uses of XMLDSigToken: create a token, then analyze it.
 */
class XMLDSigTokenTest extends TestCase
{
    public function testCreatesASignedToken()
    {
        $token = self::createToken(self::sampleData());

        $this->assertNull($token->getError());
        $this->assertTrue($token->isSignatureValid());
        $this->assertFalse($token->isDataEncrypted());
        $this->assertStringContainsString('<ds:Signature', $token->getXML());
        $this->assertStringContainsString('Id="Token"', $token->getXML());
    }

    public function testAnalyzesASignedToken()
    {
        $data = self::sampleData();
        $xml = self::createToken($data)->getXML();

        $token = XMLDSigToken::analyzeXMLToken($xml);

        $this->assertNull($token->getError());
        $this->assertSame([], $token->getAnomalies());
        $this->assertTrue($token->isDigestValueOk());
        $this->assertTrue($token->isSignatureValueOk());
        $this->assertTrue($token->isSignatureValid());
        $this->assertFalse($token->isDataEncrypted());
        $this->assertSame($data, $token->getData());
    }

    public function testRoundTripsMultiDimensionalData()
    {
        $data = [
            'user' => [
                'name' => 'Lagertha',
                'roles' => ['shieldmaiden' => 'yes', 'earl' => 'Hedeby'],
            ],
            'location' => 'Kattegat',
        ];
        $xml = self::createToken($data)->getXML();

        $token = XMLDSigToken::analyzeXMLToken($xml);

        $this->assertTrue($token->isSignatureValid());
        $this->assertSame($data, $token->getData());
    }

    public function testTimestampsTheToken()
    {
        $before = time();
        $xml = self::createToken(self::sampleData())->getXML();
        $after = time();

        $token = XMLDSigToken::analyzeXMLToken($xml);

        $timestamp = DateTime::createFromFormat(
            XMLDSigToken::TOKEN_TIMESTAMP_FORMAT,
            $token->getTimestamp(),
            new DateTimeZone('UTC')
        );
        $this->assertNotFalse($timestamp, 'Unexpected timestamp format: ' . $token->getTimestamp());
        $this->assertGreaterThanOrEqual($before - 1, $timestamp->getTimestamp());
        $this->assertLessThanOrEqual($after + 1, $timestamp->getTimestamp());
        $this->assertFalse($token->isOutOfDate(120));
    }

    public function testExposesTheSigningCertificate()
    {
        $xml = self::createToken(self::sampleData())->getXML();

        $token = XMLDSigToken::analyzeXMLToken($xml);

        $this->assertFalse($token->isCertOutOfDate());
        $this->assertSame('Signature Dept', $token->getCertSubject()['OU']);
        $this->assertSame(self::INTERMEDIATE_DN, $token->getCertIssuer());
        $this->assertTrue($token->isValidCertIssuer(self::INTERMEDIATE_DN));
    }

    public function testValidatesTheIntermediateAsIssuingCA()
    {
        $xml = self::createToken(self::sampleData())->getXML();

        $token = XMLDSigToken::analyzeXMLToken($xml);

        $this->assertTrue($token->isValidCertCA(self::cert('intermediate.cert.pem')));
    }

    public function testDoesNotValidateTheRootAsIssuingCA()
    {
        $xml = self::createToken(self::sampleData())->getXML();

        $token = XMLDSigToken::analyzeXMLToken($xml);

        $this->assertFalse($token->isValidCertCA(self::cert('root.cert.pem')));
    }

    public function testCreatesAnEncryptedToken()
    {
        $token = $this->createSecureToken(self::sampleData());

        $this->assertNull($token->getError());
        $this->assertTrue($token->isSignatureValid());
        $this->assertTrue($token->isDataEncrypted());
        $this->assertStringContainsString('EncryptedData', $token->getXML());
        $this->assertStringNotContainsString('TokenData', $token->getXML());
    }

    public function testAnalyzesAnEncryptedToken()
    {
        $data = self::sampleData();
        $xml = $this->createSecureToken($data)->getXML();

        $token = XMLDSigToken::analyzeSecureXMLToken($xml, self::cert('crypt.key.pem'));

        $this->assertNull($token->getError());
        $this->assertSame([], $token->getAnomalies());
        $this->assertTrue($token->isSignatureValid());
        $this->assertTrue($token->isDataEncrypted());
        $this->assertSame($data, $token->getData());
        $this->assertFalse($token->isOutOfDate(120));
        $this->assertFalse($token->isCertOutOfDate());
        $this->assertTrue($token->isValidCertIssuer(self::INTERMEDIATE_DN));
        $this->assertTrue($token->isValidCertCA(self::cert('intermediate.cert.pem')));
    }

    public function testAnalyzesASignedTokenWithADecryptionKey()
    {
        $data = self::sampleData();
        $xml = self::createToken($data)->getXML();

        $token = XMLDSigToken::analyzeSecureXMLToken($xml, self::cert('crypt.key.pem'));

        $this->assertNull($token->getError());
        $this->assertTrue($token->isSignatureValid());
        $this->assertFalse($token->isDataEncrypted());
        $this->assertSame($data, $token->getData());
    }
}
