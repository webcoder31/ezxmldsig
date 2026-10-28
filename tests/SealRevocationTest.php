<?php

namespace webcoder31\ezxmldsig\Tests;

use webcoder31\ezxmldsig\Tests\helpers\SealPki;
use webcoder31\ezxmldsig\Tests\helpers\TestCrl;
use webcoder31\ezxmldsig\Tests\helpers\TestDer;
use webcoder31\ezxmldsig\seal\Seal;

/**
 * Revocation by CRLs: the status of every certificate of the chains of the
 * signer and of the time-stamping authority, at the current date for a seal
 * of level B, at the time of the time-stamp for a seal of level T. The CRLs
 * come from tests/helpers/TestCrl.php, not from the code under test. A port
 * of test/seal/revocation.test.ts of the Node.js library; the CRLs of
 * OpenSSL are in SealVerifyTest.
 */
class SealRevocationTest extends SealTestCase
{
    private function error($container, array $crls, array $options = [])
    {
        return Seal::verifySeal($container, self::trust($options + ['crls' => $crls]))->getError();
    }

    private static function root()
    {
        return TestCrl::make(['issuer' => 'root']);
    }

    /** A seal time-stamped by the test authority at the given time. */
    private static function timestamped($time)
    {
        return self::timestamp(self::seal(), ['time' => $time]);
    }

    // Level B: the status at the current date.

    public function testCurrentCrlsNoCertificateRevokedValidRevocationChecked()
    {
        $result = Seal::verifySeal(self::seal(), self::trust(['crls' => TestCrl::current()]));
        $this->assertNull($result->getError());
        $this->assertTrue($result->isRevocationChecked());
    }

    public function testTheSignerRevoked()
    {
        $this->assertMatchesRegularExpression('/The certificate ' . preg_quote(self::subject('RSA 3072 Seal Dept'), '/') . ' is revoked since/',
            $this->error(self::seal(), [TestCrl::make(['revoked' => [['cert' => 'rsa3072', 'date' => $this->ago(300)]]]), self::root()]));
    }

    public function testTwoCrlsOfTheSameSecondTheOneThatListsTheCertificateTellsItsStatus()
    {
        $thisUpdate = floor($this->now) - 5;
        $crls = [TestCrl::make(['thisUpdate' => $thisUpdate]), TestCrl::make(['thisUpdate' => $thisUpdate, 'revoked' => [['cert' => 'rsa3072', 'date' => $this->ago(300)]]])];
        $container = self::seal();
        foreach ([[0, 1], [1, 0]] as $order)
        {
            $this->assertMatchesRegularExpression('/is revoked since/', $this->error($container, [$crls[$order[0]], $crls[$order[1]], self::root()]));
        }
    }

    public function testAnotherCertificateRevoked()
    {
        $this->assertNull($this->error(self::seal(), [TestCrl::make(['revoked' => [['cert' => 'p256', 'date' => $this->ago(300)]]]), self::root()]));
    }

    public function testTheIntermediateCaRevokedByTheRoot()
    {
        $this->assertMatchesRegularExpression('/The certificate ' . preg_quote(self::subject('Seal Intermediate CA'), '/') . ' is revoked/',
            $this->error(self::seal(), [TestCrl::make(), TestCrl::make(['issuer' => 'root', 'revoked' => [['cert' => 'intermediate', 'date' => $this->ago(300)]]])]));
    }

    public function testNoCrlForTheIntermediateCa()
    {
        $this->assertMatchesRegularExpression('/No revocation data for the certificate ' . preg_quote(self::subject('Seal Intermediate CA'), '/') . ': no CRL of its issuer/',
            $this->error(self::seal(), [TestCrl::make()]));
    }

    public function testNoCrlAtAll()
    {
        $this->assertMatchesRegularExpression('/No revocation data for the certificate ' . preg_quote(self::subject('RSA 3072 Seal Dept'), '/') . '/',
            $this->error(self::seal(), []));
    }

    public function unusableCrls()
    {
        return [
            'past its next update' => [['thisUpdate' => -7200, 'nextUpdate' => -3600], '/No current revocation data/'],
            'without next update' => [['nextUpdate' => null], '/No current revocation data/'],
            'issued in the future' => [['thisUpdate' => 600], '/No current revocation data/'],
            'signed by another CA under the name of the issuer' => [['signer' => 'root'], '/no CRL of its issuer/'],
            'with an altered signature' => [['alterSignature' => true], '/no CRL of its issuer/'],
            'of another CA' => [['issuer' => 'tsa-root'], '/no CRL of its issuer/'],
            'restricted to CA certificates' => [['extensions' => [TestCrl::issuingDistributionPoint(['onlyCA' => true])]], '/no CRL of its issuer/'],
        ];
    }

    /**
     * A CRL that does not tell the status; its times are relative to now.
     *
     * @dataProvider unusableCrls
     */
    public function testACrlThatDoesNotTellTheStatus(array $options, $message)
    {
        foreach (['thisUpdate', 'nextUpdate'] as $time)
        {
            if (isset($options[$time]))
            {
                $options[$time] += $this->now;
            }
        }
        $this->assertMatchesRegularExpression($message, $this->error(self::seal(), [TestCrl::make($options), self::root()]));
    }

    public function testACrlRestrictedToEndEntityCertificatesTellsTheStatusOfTheSigner()
    {
        $this->assertNull($this->error(self::seal(), [TestCrl::make(['extensions' => [TestCrl::issuingDistributionPoint(['onlyUser' => true])]]), self::root()]));
    }

    public function testWithoutRevocationValidRevocationNotChecked()
    {
        $result = Seal::verifySeal(self::seal(), self::trust(['crls' => [], 'revocation' => false]));
        $this->assertNull($result->getError());
        $this->assertFalse($result->isRevocationChecked());
    }

    // CRLs this library does not use are refused.

    public function refusedCrls()
    {
        $entry = function (array $extensions) { return ['revoked' => [['cert' => 'p256', 'date' => time() - 60, 'extensions' => $extensions]]]; };
        return [
            'a delta CRL' => [TestCrl::make(['extensions' => [TestCrl::extension('2.5.29.27', true, "\x02\x01\x01")]]), '/delta CRLs are not supported/'],
            'an unknown critical extension' => [TestCrl::make(['extensions' => [TestCrl::extension('1.3.6.1.4.1.55555.9', true, "\x05\x00")]]), '/unsupported critical extension 1\.3\.6\.1\.4\.1\.55555\.9/'],
            'a CRL restricted to some reasons' => [TestCrl::make(['extensions' => [TestCrl::issuingDistributionPoint(['someReasons' => true])]]), '/restricted to some reasons/'],
            'an indirect CRL' => [TestCrl::make(['extensions' => [TestCrl::issuingDistributionPoint(['indirect' => true])]]), '/indirect CRLs/'],
            'an entry of another issuer (indirect CRL)' => [TestCrl::make($entry([TestCrl::extension('2.5.29.29', true, "\x30\x00")])), '/indirect CRLs are not supported/'],
            'a reason code that is not one' => [TestCrl::make($entry([TestCrl::extension('2.5.29.21', false, TestDer::der(0x02, "\x01"))])), '/malformed reason code/'],
            'bytes that are not a CRL' => ['not a CRL', '/DER: /'],
        ];
    }

    /**
     * @dataProvider refusedCrls
     */
    public function testACrlThisLibraryDoesNotUseIsRefused($crl, $message)
    {
        $this->assertThrowsMatching('/a CRL cannot be used\. CRL: .*' . substr($message, 1, -1) . '/', function () use ($crl)
        {
            Seal::verifySeal(self::seal(), self::trust(['crls' => [$crl]]));
        });
    }

    public function testAListThatIsNotOfStrings()
    {
        $this->assertThrowsMatching("/invalid option 'crls'/", function ()
        {
            Seal::verifySeal(self::seal(), self::trust(['crls' => [42]]));
        });
    }

    // Level T: the status at the time of the time-stamp. The time-stamps are
    // made a few seconds ago: the seal certificates are valid from their
    // generation only.

    private function authorityRevoked($container, $date, array $extensions = null)
    {
        $entry = ['cert' => 'tsa', 'date' => $date] + (null === $extensions ? [] : ['extensions' => $extensions]);
        return $this->error($container, [TestCrl::make(), self::root(), TestCrl::make(['issuer' => 'tsa-root', 'revoked' => [$entry]])]);
    }

    public function testLevelTCrlsIssuedAfterTheTimeStampValid()
    {
        $this->assertNull($this->error(self::timestamped($this->ago(20)), TestCrl::current()));
    }

    public function testLevelTACrlIssuedBeforeTheTimeStampDoesNotTellTheStatusAtThatTime()
    {
        $crls = [TestCrl::make(['thisUpdate' => $this->ago(30)]), self::root(), TestCrl::make(['issuer' => 'tsa-root'])];
        $this->assertMatchesRegularExpression('/issued after the time-stamp/', $this->error(self::timestamped($this->ago(20)), $crls));
    }

    public function testLevelTTheSignerRevokedAfterTheTimeStampValid()
    {
        $this->assertNull($this->error(self::timestamped($this->ago(20)), TestCrl::current([['cert' => 'rsa3072', 'date' => $this->ago(10)]])));
    }

    public function testLevelTTheSignerRevokedBeforeTheTimeStamp()
    {
        $this->assertMatchesRegularExpression('/The certificate ' . preg_quote(self::subject('RSA 3072 Seal Dept'), '/') . ' is revoked since .*, before the time-stamp/',
            $this->error(self::timestamped($this->ago(20)), TestCrl::current([['cert' => 'rsa3072', 'date' => $this->ago(25)]])));
    }

    public function testLevelTACrlPastItsNextUpdateStillTellsTheStatusAtTheTimeOfTheTimeStamp()
    {
        $crls = [TestCrl::make(['thisUpdate' => $this->ago(15), 'nextUpdate' => $this->ago(10)]), self::root(), TestCrl::make(['issuer' => 'tsa-root'])];
        $this->assertNull($this->error(self::timestamped($this->ago(20)), $crls));
    }

    public function testLevelTTheTimeStampingAuthorityRevoked()
    {
        $this->assertMatchesRegularExpression('/The certificate ' . preg_quote(self::subject('Time-Stamping Unit'), '/') . ' is revoked/',
            $this->authorityRevoked(self::timestamped($this->ago(20)), $this->ago(1)));
    }

    public function testLevelTTheAuthorityRevokedAfterTheTimeStampForCessationOfOperationValid()
    {
        $this->assertNull($this->authorityRevoked(self::timestamped($this->ago(20)), $this->ago(1), [TestCrl::reason(5)]));
    }

    public function testLevelTTheAuthorityRevokedAfterTheTimeStampForAKeyCompromise()
    {
        $this->assertMatchesRegularExpression('/The certificate ' . preg_quote(self::subject('Time-Stamping Unit'), '/') . ' is revoked since .*, after the time-stamp but for a compromise of a key/',
            $this->authorityRevoked(self::timestamped($this->ago(20)), $this->ago(1), [TestCrl::reason(1)]));
    }

    public function testLevelTTheAuthorityRevokedBeforeTheTimeStampForCessationOfOperation()
    {
        $this->assertMatchesRegularExpression('/, before the time-stamp/', $this->authorityRevoked(self::timestamped($this->ago(20)), $this->ago(25), [TestCrl::reason(5)]));
    }

    public function testLevelTNoCrlForTheTimeStampingAuthority()
    {
        $this->assertMatchesRegularExpression('/No revocation data for the certificate ' . preg_quote(self::subject('Time-Stamping Unit'), '/') . '/',
            $this->error(self::timestamped($this->ago(20)), [TestCrl::make(), self::root()]));
    }

    // Level T, a signer expired since the time-stamp: a CRL issued since
    // tells its status only if it keeps the expired certificates
    // (ExpiredCertsOnCRL), from a date before the expiry.

    private function expiredCase(array $crlOptions)
    {
        $certificate = $this->tempFile('expired.cert.pem', SealPki::expiredSigner($this->ago(3600), $this->ago(10)));
        $sealed = Seal::createSeal([['name' => 'contrat.pdf', 'content' => "%PDF-1.4\n"]], SealPki::key('rsa3072'), $certificate, SealPki::PASSWORD,
            ['chain' => [SealPki::cert('intermediate')], 'signingTime' => (int) $this->ago(20)]);
        $container = self::timestamp($sealed, ['time' => $this->ago(15)]);
        if (isset($crlOptions['revoked']))
        {
            $crlOptions['revoked'] = [['cert' => $certificate, 'date' => $this->ago(17)]];
        }
        return $this->error($container, [TestCrl::make($crlOptions), self::root(), TestCrl::make(['issuer' => 'tsa-root'])]);
    }

    private function keepsExpired($from)
    {
        return TestCrl::extension('2.5.29.60', false, TestDer::generalized($from));
    }

    public function testExpiredACrlIssuedAfterTheTimeStampWhileTheCertificateWasValidValid()
    {
        $this->assertNull($this->expiredCase(['thisUpdate' => $this->ago(12)]));
    }

    public function testExpiredACrlIssuedAfterTheExpiryProvesNothingOfTheCertificate()
    {
        $this->assertMatchesRegularExpression('/No revocation data for the certificate ' . preg_quote(self::subject('RSA 3072 Seal Dept'), '/') . ' issued after the time-stamp .*, while it was valid/',
            $this->expiredCase(['thisUpdate' => $this->ago(5)]));
    }

    public function testExpiredACrlThatKeepsTheCertificatesExpiredSinceBeforeValid()
    {
        $this->assertNull($this->expiredCase(['thisUpdate' => $this->ago(5), 'extensions' => [$this->keepsExpired($this->ago(3600))]]));
    }

    public function testExpiredACrlThatKeepsTheCertificatesExpiredSinceAfterItOnly()
    {
        $this->assertMatchesRegularExpression('/while it was valid/', $this->expiredCase(['thisUpdate' => $this->ago(5), 'extensions' => [$this->keepsExpired($this->ago(7))]]));
    }

    public function testExpiredACrlThatKeepsTheExpiredCertificatesAndListsTheSignerRevokedBeforeTheTimeStamp()
    {
        $this->assertMatchesRegularExpression('/, before the time-stamp/', $this->expiredCase(['thisUpdate' => $this->ago(5), 'extensions' => [$this->keepsExpired($this->ago(3600))], 'revoked' => true]));
    }
}
