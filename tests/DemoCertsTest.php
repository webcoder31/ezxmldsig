<?php

namespace webcoder31\ezxmldsig\Tests;

use webcoder31\ezxmldsig\Demo\Certs;
use webcoder31\ezxmldsig\Demo\Issuer;
use webcoder31\ezxmldsig\Demo\Receiver;
use webcoder31\ezxmldsig\Demo\ReplayStore;
use webcoder31\ezxmldsig\X509Cert;
use webcoder31\ezxmldsig\XMLDSigToken;

/**
 * The certificates of demo/certs/ let the issuer of the demo create tokens
 * that its receiver accepts, and give the attack lab the certificates it
 * needs.
 */
class DemoCertsTest extends TestCase
{
    /** The issuer of sign.cert.pem. */
    const EXPECTED_ISSUER = [
        'C'  => 'DK',
        'ST' => 'Jylland',
        'O'  => 'Lothbrok Ltd',
        'OU' => 'Shield Wall Dept',
        'CN' => 'www.lothbrok.dk',
        'emailAddress' => 'ivar@lothbrok.dk',
    ];

    public function testSignedTokenPassesTheChecksOfTheReceiver()
    {
        $data = self::sampleData();
        $sig = XMLDSigToken::createXMLToken(
            $data,
            Certs::path('sign.key.pem'),
            Certs::path('sign.cert.pem'),
            Certs::SIGN_KEY_PASSWORD
        )->getXML();

        $token = XMLDSigToken::analyzeXMLToken($sig, Receiver::fromArray([])->options());

        $this->assertNull($token->getError());
        $this->assertTrue($token->isSignatureValid());
        $this->assertFalse($token->isCertOutOfDate());
        $this->assertTrue($token->isValidCertIssuer(self::EXPECTED_ISSUER));
        $this->assertTrue($token->isValidCertCA(Certs::path('intermediate.cert.pem')));
        $this->assertFalse($token->isOutOfDate(120));
        $this->assertSame($data, $token->getData());
    }

    public function testEncryptedTokenPassesTheChecksOfTheReceiver()
    {
        $this->requireSymmetricEncryption();

        // The sender creates the token without the private key of the
        // recipient.
        $sig = Issuer::create(Issuer::DEFAULT_DATA, true)->getXML();

        $result = Receiver::fromArray([])->verify($sig, new ReplayStore());

        $this->assertTrue($result['accepted']);
        $this->assertTrue($result['token']['encrypted']);
        $this->assertSame(Issuer::DEFAULT_DATA, $result['data']);
    }

    public function testTheAttackCertificatesCopyTheSubjectOfTheSigningCertificate()
    {
        $subject = (new X509Cert(file_get_contents(Certs::path('sign.cert.pem'))))->getDN();
        foreach (['attacker.cert.pem', 'rogue.cert.pem', 'ec.cert.pem'] as $name)
        {
            $this->assertSame($subject, (new X509Cert(file_get_contents(Certs::path($name))))->getDN(), $name);
        }
    }

    public function testTheRogueCertificateChainsUpToItsOwnRootOnly()
    {
        $rogue = new X509Cert(file_get_contents(Certs::path('rogue.cert.pem')));

        $this->assertTrue($rogue->isTrustedBy([Certs::path('rogue-root.cert.pem')]));
        $this->assertFalse($rogue->isTrustedBy(Certs::trustedCAs()));
    }

    public function testTheEcCertificateHasAnEcKey()
    {
        $key = openssl_pkey_get_public(file_get_contents(Certs::path('ec.cert.pem')));

        $this->assertSame(OPENSSL_KEYTYPE_EC, openssl_pkey_get_details($key)['type']);
    }
}
