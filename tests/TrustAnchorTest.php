<?php

namespace webcoder31\ezxmldsig\Tests;

use webcoder31\ezxmldsig\X509Cert;
use webcoder31\ezxmldsig\XMLDSigToken;

/**
 * The signature of a token is verified with the certificate the token
 * carries: a token is only valid if this certificate is trusted, against the
 * trust anchor given to the analysis.
 */
class TrustAnchorTest extends TestCase
{
    /**
     * A token signed with attacker.cert.pem: a certificate signed by its own
     * key, whose subject and issuer names copy those of sign.cert.pem.
     */
    private static function createAttackerToken()
    {
        return XMLDSigToken::createXMLToken(
            self::sampleData(),
            self::cert('attacker.key.pem'),
            self::cert('attacker.cert.pem')
        )->getXML();
    }

    private static function assertRejected(XMLDSigToken $token, $reason)
    {
        self::assertFalse($token->isSignatureValid());
        self::assertFalse($token->isCertTrusted());
        self::assertStringContainsString($reason, (string) $token->getError());
        self::assertNull($token->getData());
    }

    private static function assertAccepted(XMLDSigToken $token)
    {
        self::assertNull($token->getError());
        self::assertTrue($token->isCertTrusted());
        self::assertTrue($token->isSignatureValid());
    }

    public function testRejectsATokenSignedWithACopiedCertificate()
    {
        $token = XMLDSigToken::analyzeXMLToken(self::createAttackerToken(), self::trustAnchor());

        // The signature matches the certificate the token carries, and the
        // names of this certificate are those of the legitimate one...
        $this->assertTrue($token->isSignatureValueOk());
        $this->assertTrue($token->isValidCertIssuer(self::INTERMEDIATE_DN));
        // ...but no trusted CA issued it.
        self::assertRejected($token, 'not issued by a trusted CA');
    }

    public function testRejectsATokenSignedWithACopiedCertificateWhenTheSignerIsPinned()
    {
        $token = XMLDSigToken::analyzeXMLToken(
            self::createAttackerToken(),
            ['signerCertPath' => self::cert('sign.cert.pem')]
        );

        self::assertRejected($token, 'not the pinned certificate');
    }

    public function testRejectsALegitimateTokenWithoutTrustAnchor()
    {
        $xml = self::createToken(self::sampleData())->getXML();

        $token = XMLDSigToken::analyzeXMLToken($xml);

        $this->assertTrue($token->isSignatureValueOk());
        self::assertRejected($token, 'No trust anchor');
    }

    public function testRejectsALegitimateEncryptedTokenWithoutTrustAnchor()
    {
        $xml = $this->createSecureToken(self::sampleData())->getXML();

        $token = XMLDSigToken::analyzeSecureXMLToken($xml, self::cert('crypt.key.pem'));

        self::assertRejected($token, 'No trust anchor');
    }

    public function testAcceptsALegitimateTokenWithTheTrustAnchor()
    {
        $data = self::sampleData();
        $xml = self::createToken($data)->getXML();

        $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor());

        $this->assertNull($token->getError());
        $this->assertTrue($token->isCertTrusted());
        $this->assertTrue($token->isSignatureValid());
        $this->assertSame($data, $token->getData());
    }

    public function testAcceptsALegitimateEncryptedTokenWithTheTrustAnchor()
    {
        $data = self::sampleData();
        $xml = $this->createSecureToken($data)->getXML();

        $token = XMLDSigToken::analyzeSecureXMLToken($xml, self::cert('crypt.key.pem'), null, self::trustAnchor());

        $this->assertNull($token->getError());
        $this->assertTrue($token->isCertTrusted());
        $this->assertTrue($token->isSignatureValid());
        $this->assertTrue($token->isDataEncrypted());
        $this->assertSame($data, $token->getData());
    }

    public function testAcceptsALegitimateTokenWithThePinnedSigner()
    {
        $data = self::sampleData();
        $xml = self::createToken($data)->getXML();

        $token = XMLDSigToken::analyzeXMLToken($xml, ['signerCertPath' => self::cert('sign.cert.pem')]);

        $this->assertNull($token->getError());
        $this->assertTrue($token->isCertTrusted());
        $this->assertTrue($token->isSignatureValid());
        $this->assertSame($data, $token->getData());
    }

    public function testRejectsAnotherPinnedCertificate()
    {
        $xml = self::createToken(self::sampleData())->getXML();

        $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor([
            'signerCertPath' => self::cert('crypt.cert.pem'),
        ]));

        self::assertRejected($token, 'not the pinned certificate');
    }

    public function testAcceptsTheExpectedSubject()
    {
        $xml = self::createToken(self::sampleData())->getXML();
        $dn = '/C=DK/ST=Jylland/L=Kattegat/O=Lothbrok Ltd/OU=Signature Dept/CN=www.lothbrok.dk/emailAddress=ivar@lothbrok.dk';

        $byFields = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor([
            'expectedSubject' => ['O' => 'Lothbrok Ltd', 'OU' => 'Signature Dept'],
        ]));
        $byDN = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor(['expectedSubject' => $dn]));

        self::assertAccepted($byFields);
        self::assertAccepted($byDN);
    }

    public function testRejectsAnotherSubject()
    {
        $xml = self::createToken(self::sampleData())->getXML();

        $byFields = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor([
            'expectedSubject' => ['O' => 'Lothbrok Ltd', 'OU' => 'Cryptography Dept'],
        ]));
        $byDN = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor([
            'expectedSubject' => '/C=DK/ST=Jylland/L=Kattegat/O=Lothbrok Ltd/OU=Cryptography Dept/CN=www.lothbrok.dk/emailAddress=ivar@lothbrok.dk',
        ]));

        self::assertRejected($byFields, 'Subject of the signing certificate is not the expected one');
        self::assertRejected($byDN, 'Subject of the signing certificate is not the expected one');
    }

    public function testRejectsAnExpiredSigningCertificate()
    {
        // Issued by the trusted intermediate, valid until the current second.
        $expired = $this->issueCertificate('expired', 'sign', 'intermediate', 0);
        $xml = self::createTokenWith($expired, self::sampleData())->getXML();
        $notAfter = openssl_x509_parse(file_get_contents($expired['cert']))['validTo_time_t'];
        for ($i = 0; $i < 30 && time() <= $notAfter; $i++)
        {
            usleep(100000);
        }
        $this->assertGreaterThan($notAfter, time(), 'The test certificate has not expired yet.');

        $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor());

        $this->assertTrue($token->isSignatureValueOk());
        self::assertRejected($token, 'not valid at the current date');
    }

    /**
     * From 2050 on, X.509 writes a date as GeneralizedTime (4-digit year).
     * long.cert.pem, issued by the trusted intermediate, ends in 2060.
     */
    public function testAcceptsACertificateValidAfter2049()
    {
        $created = XMLDSigToken::createXMLToken(self::sampleData(), self::cert('long.key.pem'), self::cert('long.cert.pem'));
        $this->assertNull($created->getError());

        $token = XMLDSigToken::analyzeXMLToken($created->getXML(), self::trustAnchor());

        self::assertAccepted($token);
        $this->assertSame('2060-01-01T00:00:00Z', $token->getCertValidTo());
    }

    /**
     * future.cert.pem, issued by the trusted intermediate, is valid in 2099
     * only: refused, not a fatal error.
     */
    public function testRejectsACertificateValidOnlyAfter2049()
    {
        $created = XMLDSigToken::createXMLToken(self::sampleData(), self::cert('future.key.pem'), self::cert('future.cert.pem'));
        $this->assertStringContainsString('valid from 2099-01-01T00:00:00Z to 2099-12-31T23:59:59Z', (string) $created->getError());

        $token = XMLDSigToken::analyzeXMLToken($created->getXML(), self::trustAnchor());

        $this->assertTrue($token->isSignatureValueOk());
        self::assertRejected($token, 'not valid at the current date (valid from 2099-01-01T00:00:00Z');
    }

    /**
     * Anyone can sign a token with a self-signed certificate valid after
     * 2049: the analysis refuses it, and does not stop on a fatal error.
     */
    public function testRejectsASelfSignedCertificateValidAfter2049()
    {
        $days = (int) ceil((strtotime('2060-06-01 00:00:00 UTC') - time()) / 86400);
        $selfSigned = $this->issueCertificate('self-signed', 'sign', null, $days);
        $xml = self::createTokenWith($selfSigned, self::sampleData())->getXML();

        $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor());

        $this->assertTrue($token->isSignatureValueOk());
        self::assertRejected($token, 'Signing certificate is not issued by a trusted CA');
    }

    public function testAcceptsACertificateIssuedOnTheFlyByTheTrustedIntermediate()
    {
        // Control of the test above and below: the certificates issued by
        // issueCertificate() are accepted when nothing else is wrong.
        $issued = $this->issueCertificate('issued', 'sign', 'intermediate');
        $xml = self::createTokenWith($issued, self::sampleData())->getXML();

        $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor());

        self::assertAccepted($token);
    }

    public function testRejectsACertificateOfAnotherIntermediateOfTheSameRoot()
    {
        $otherIntermediate = $this->issueCertificate('other-intermediate', 'ca', 'root');
        $issued = $this->issueCertificate('other-signer', 'sign', $otherIntermediate['prefix']);
        $xml = self::createTokenWith($issued, self::sampleData())->getXML();

        // The anchor holds the intermediate that issued sign.cert.pem and the
        // root: the other intermediate is not in it, and the token cannot
        // supply it.
        $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor());
        self::assertRejected($token, 'not issued by a trusted CA');

        // Control: trusting the other intermediate accepts the token.
        $control = XMLDSigToken::analyzeXMLToken($xml, [
            'caCertPath' => [$otherIntermediate['cert'], self::cert('root.cert.pem')],
        ]);
        self::assertAccepted($control);
    }

    public function testRejectsACertificateIssuedByANonCACertificate()
    {
        // sign.cert.pem is not a CA ("CA:FALSE"), but its key can still sign
        // a certificate.
        $issued = $this->issueCertificate('rogue', 'sign', 'sign', 30, self::SIGN_KEY_PASSWORD);
        $xml = self::createTokenWith($issued, self::sampleData())->getXML();

        $token = XMLDSigToken::analyzeXMLToken($xml, [
            'caCertPath' => [self::cert('sign.cert.pem'), self::cert('intermediate.cert.pem'), self::cert('root.cert.pem')],
        ]);

        self::assertRejected($token, 'not issued by a trusted CA');
    }

    /**
     * Provides the environment variables through which OpenSSL locates the
     * CA certificates of the system (default directory and default file).
     */
    public function provideDefaultCAStoreVariables()
    {
        return [
            'default directory' => ['SSL_CERT_DIR'],
            'default file' => ['SSL_CERT_FILE'],
        ];
    }

    /**
     * Only the CA certificates of the option 'caCertPath' are trusted, not
     * those of the system: a certificate issued by a CA of the system store
     * is rejected.
     *
     * @dataProvider provideDefaultCAStoreVariables
     */
    public function testIgnoresTheCAStoreOfTheSystem($variable)
    {
        // A CA of the system store, and a signing certificate it issued.
        $systemRoot = $this->issueCertificate('system-root', 'root', null);
        $foreign = $this->issueCertificate('foreign', 'sign', $systemRoot['prefix']);
        $hash = openssl_x509_parse(file_get_contents($systemRoot['cert']))['hash'];
        $storeFile = $this->tempFile($hash . '.0', file_get_contents($systemRoot['cert']));
        $xml = self::createTokenWith($foreign, self::sampleData())->getXML();
        $previous = getenv($variable);
        putenv($variable . '=' . ('SSL_CERT_DIR' === $variable ? dirname($storeFile) : $storeFile));
        try
        {
            // Control: OpenSSL does read the system store through the
            // variable (PHP falls back on it when given no CA file).
            $this->assertTrue(openssl_x509_checkpurpose(file_get_contents($foreign['cert']), X509_PURPOSE_ANY, []));

            $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor());
        }
        finally
        {
            putenv(false === $previous ? $variable : $variable . '=' . $previous);
        }

        self::assertRejected($token, 'not issued by a trusted CA');
    }

    public function testAnIntermediateAloneIsNotATrustAnchor()
    {
        $xml = self::createToken(self::sampleData())->getXML();

        $token = XMLDSigToken::analyzeXMLToken($xml, ['caCertPath' => self::cert('intermediate.cert.pem')]);

        // OpenSSL requires a chain up to a self-signed root: the error tells
        // the caller what the option must hold.
        self::assertRejected($token, "not issued by a trusted CA: its chain could not be verified up to the CA certificates of the option 'caCertPath', which must hold the issuing CA and the certificates up to its root!");
    }

    public function testTheRootAloneIsNotATrustAnchorForACertificateOfItsIntermediate()
    {
        $xml = self::createToken(self::sampleData())->getXML();

        $token = XMLDSigToken::analyzeXMLToken($xml, ['caCertPath' => self::cert('root.cert.pem')]);

        self::assertRejected($token, 'not issued by a trusted CA');
    }

    public function testAcceptsTheAnchorAsASingleFile()
    {
        $bundle = $this->tempFile('anchor.pem', file_get_contents(self::cert('intermediate.cert.pem')) . file_get_contents(self::cert('root.cert.pem')));
        $xml = self::createToken(self::sampleData())->getXML();

        $token = XMLDSigToken::analyzeXMLToken($xml, ['caCertPath' => $bundle]);

        self::assertAccepted($token);
    }

    public function testRejectsAnUnreadableTrustOption()
    {
        $xml = self::createToken(self::sampleData())->getXML();

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage("Invalid option 'caCertPath'");

        XMLDSigToken::analyzeXMLToken($xml, ['caCertPath' => self::cert('missing.cert.pem')]);
    }

    public function testIsValidCertCADoesNotFailWithoutCertificate()
    {
        $token = XMLDSigToken::analyzeXMLToken('not an XML token', self::trustAnchor());

        $this->assertNotNull($token->getError());
        $this->assertNull($token->getCertificate());
        $this->assertFalse($token->isValidCertCA(self::cert('intermediate.cert.pem')));
    }

    public function testIsValidCARequiresACACertificate()
    {
        $issued = $this->issueCertificate('rogue', 'sign', 'sign', 30, self::SIGN_KEY_PASSWORD);
        $cert = new X509Cert(file_get_contents($issued['cert']));

        // The signature of the certificate verifies with the key of
        // sign.cert.pem, which is not a CA.
        $this->assertSame(1, openssl_x509_verify(file_get_contents($issued['cert']), file_get_contents(self::cert('sign.cert.pem'))));
        $this->assertFalse($cert->isValidCA(file_get_contents(self::cert('sign.cert.pem'))));
    }
}
