<?php

namespace webcoder31\ezxmldsig\Tests;

use webcoder31\ezxmldsig\Tests\helpers\SealPki;
use webcoder31\ezxmldsig\Tests\helpers\TestCrl;
use webcoder31\ezxmldsig\seal\Seal;

/**
 * Level LT: the list of the CRLs a seal needs, their addition to a seal of
 * level T, and the verification of a seal by the data it embeds. The CRLs
 * come from tests/helpers/TestCrl.php, the tokens from
 * tests/helpers/TestTsa.php, not from the code under test. A port of
 * test/seal/validation.test.ts of the Node.js library.
 */
class SealValidationTest extends SealTestCase
{
    const PKI = 'http://pki.ezxmlseal.test';

    // The time-stamps are made a few seconds ago: the seal certificates are
    // valid from their generation only.
    private function timestamped($key = 'rsa3072', array $tsaOptions = [])
    {
        return self::timestamp(self::seal($key), $tsaOptions + ['time' => $this->ago(20)]);
    }

    private static function extended($container, array $crls = null)
    {
        return Seal::addValidationData($container, self::trust(['crls' => null === $crls ? TestCrl::current() : $crls]));
    }

    private static function check($container, array $options = [])
    {
        return Seal::verifySeal($container, self::trust($options));
    }

    private static function base64Of($name)
    {
        return base64_encode(SealPki::certificateDer($name));
    }

    // The CRLs a seal needs.

    public function testLevelTTheSignerItsIntermediateCaTheAuthorityFromTheirDistributionPoints()
    {
        $crls = Seal::validationDataRequests($this->timestamped(), self::trust())['crls'];
        $this->assertSame([
            ['RSA 3072 Seal Dept', 'Seal Intermediate CA', [self::PKI . '/intermediate.crl']],
            ['Seal Intermediate CA', 'Seal Root CA', [self::PKI . '/root.crl']],
            ['Time-Stamping Unit', 'TSA Root CA', [self::PKI . '/tsa-root.crl']],
        ], array_map(function ($r) { return [$r['certificate']->getSubject()['OU'], $r['issuer']->getSubject()['OU'], $r['urls']]; }, $crls));
    }

    public function testLevelBTheChainOfTheSignerOnly()
    {
        $crls = Seal::validationDataRequests(self::seal(), self::trust())['crls'];
        $this->assertSame([[self::PKI . '/intermediate.crl'], [self::PKI . '/root.crl']], array_column($crls, 'urls'));
    }

    public function testASealThatIsNotValid()
    {
        $this->assertThrowsMatching('/Validation data: the seal is not valid\. The signing certificate is not trusted/', function ()
        {
            Seal::validationDataRequests(self::seal(), ['caCertPath' => SealPki::cert('tsa-root'), 'tsaCertPath' => SealPki::cert('tsa-root')]);
        });
    }

    // The addition of the validation data.

    public function testTheSealBecomesOfLevelLtValidWithTheDataItEmbedsAlone()
    {
        $original = $this->timestamped();
        $result = self::check(self::extended($original));
        $this->assertNull($result->getError());
        $this->assertSame('LT', $result->getLevel());
        $this->assertTrue($result->isRevocationChecked());
        $this->assertEquals(self::check($original, ['crls' => TestCrl::current()])->getTimestampTime(), $result->getTimestampTime());
    }

    public function testTheSignedPartsAreLeftAsTheyWere()
    {
        $original = $this->timestamped();
        $before = self::signatureXml($original);
        $xml = self::signatureXml(self::extended($original));
        $end = strpos($before, '</xades:UnsignedSignatureProperties>');
        $this->assertSame(substr($before, 0, $end), substr($xml, 0, $end));
        $this->assertSame(substr($before, $end), substr($xml, strpos($xml, '</xades:UnsignedSignatureProperties>')));
    }

    public function testTheValidationDataOfTheTimeStampRightAfterItThenThoseOfTheSigner()
    {
        $this->assertMatchesRegularExpression('#</xades:SignatureTimeStamp><xades141:TimeStampValidationData xmlns:xades141="http://uri.etsi.org/01903/v1.4.1\#"><xades:CertificateValues[^>]*>.*</xades:CertificateValues><xades:RevocationValues[^>]*>.*</xades:RevocationValues></xades141:TimeStampValidationData><xades:CertificateValues[^>]*>.*</xades:CertificateValues><xades:RevocationValues[^>]*><xades:CRLValues>.*</xades:CRLValues></xades:RevocationValues></xades:UnsignedSignatureProperties>#s',
            self::signatureXml(self::extended($this->timestamped())));
    }

    public function testEachCertificateOnce()
    {
        // The roots added, the intermediate CA left in KeyInfo, the authority in its token.
        $compact = preg_replace('/\s/', '', self::signatureXml(self::extended($this->timestamped())));
        foreach (['root' => 1, 'tsa-root' => 1, 'intermediate' => 1, 'rsa3072' => 1, 'tsa' => 0] as $name => $count)
        {
            $this->assertSame($count, substr_count($compact, self::base64Of($name)), $name);
        }
    }

    public function testACrlForEachCertificateButTheRootsOnce()
    {
        preg_match_all('#<xades:EncapsulatedCRLValue>([^<]+)<#', self::signatureXml(self::extended($this->timestamped())), $matches);
        $this->assertCount(3, $matches[1]);
        $this->assertCount(3, array_unique($matches[1]));
    }

    public function testCrlsPastTheirNextUpdateIssuedAfterTheTimeStampStillTellTheStatus()
    {
        $later = ['thisUpdate' => $this->ago(15), 'nextUpdate' => $this->ago(5)];
        $crls = [TestCrl::make($later), TestCrl::make($later + ['issuer' => 'root']), TestCrl::make($later + ['issuer' => 'tsa-root'])];
        $this->assertSame('LT', self::check(self::extended($this->timestamped(), $crls))->getLevel());
    }

    public function testRefusedASealOfLevelB()
    {
        $this->assertThrowsMatching('/must be time-stamped first \(level T\)/', function () { self::extended(self::seal()); });
    }

    public function testRefusedASealOfLevelLt()
    {
        $container = self::extended($this->timestamped());
        $this->assertThrowsMatching('/already has validation data/', function () use ($container) { self::extended($container); });
    }

    public function testRefusedNoCrlOfTheTimeStampingAuthority()
    {
        $original = $this->timestamped();
        $this->assertThrowsMatching('/No revocation data for the certificate "[^"]*Time-Stamping Unit[^"]*": no CRL of its issuer/', function () use ($original)
        {
            self::extended($original, array_slice(TestCrl::current(), 0, 2));
        });
    }

    public function testRefusedACrlIssuedBeforeTheTimeStamp()
    {
        $original = $this->timestamped();
        $crls = array_merge([TestCrl::make(['thisUpdate' => $this->ago(30)])], array_slice(TestCrl::current(), 1));
        $this->assertThrowsMatching('/RSA 3072 Seal Dept[^"]*" issued after the time-stamp/', function () use ($original, $crls) { self::extended($original, $crls); });
    }

    public function testRefusedTheSignerRevokedBeforeTheTimeStamp()
    {
        $original = $this->timestamped();
        $crls = TestCrl::current([['cert' => 'rsa3072', 'date' => $this->ago(25)]]);
        $this->assertThrowsMatching('/the seal is not valid\. The certificate .* is revoked since .*, before the time-stamp/', function () use ($original, $crls) { self::extended($original, $crls); });
    }

    public function testRefusedNoOptionCrlsNorOcspResponses()
    {
        $original = $this->timestamped();
        $this->assertThrowsMatching("/'crls' or 'ocspResponses' is required/", function () use ($original) { Seal::addValidationData($original, self::trust()); });
    }

    public function testRefusedNoOptionTsaCertPath()
    {
        $original = $this->timestamped();
        $this->assertThrowsMatching("/'tsaCertPath' is required/", function () use ($original)
        {
            Seal::addValidationData($original, ['caCertPath' => SealPki::cert('root'), 'crls' => TestCrl::current()]);
        });
    }

    // The verification of a seal of level LT.

    public function testWithoutRevocationLevelLtRevocationNotChecked()
    {
        $result = self::check(self::extended($this->timestamped()), ['revocation' => false]);
        $this->assertSame('LT', $result->getLevel());
        $this->assertFalse($result->isRevocationChecked());
    }

    public function testNewerCrlsOfTheCallerTheSignerRevokedAfterTheTimeStampStillValid()
    {
        $this->assertNull(self::check(self::extended($this->timestamped()), ['crls' => TestCrl::current([['cert' => 'rsa3072', 'date' => $this->ago(1)]])])->getError());
    }

    public function testNewerCrlsOfTheCallerARevocationTheyTellBeforeTheTimeStamp()
    {
        $this->assertMatchesRegularExpression('/is revoked since .*, before the time-stamp/',
            self::check(self::extended($this->timestamped()), ['crls' => [TestCrl::make(['revoked' => [['cert' => 'rsa3072', 'date' => $this->ago(25)]]])]])->getError());
    }

    private function authority($date, array $extensions = null)
    {
        $entry = ['cert' => 'tsa', 'date' => $date] + (null === $extensions ? [] : ['extensions' => $extensions]);
        return self::check(self::extended($this->timestamped()), ['crls' => [TestCrl::make(['issuer' => 'tsa-root', 'revoked' => [$entry]])]])->getError();
    }

    public function testTheAuthorityRevokedAfterTheTimeStampForCessationOfOperationStillValid()
    {
        $this->assertNull($this->authority($this->ago(1), [TestCrl::reason(5)]));
    }

    public function testTheAuthorityRevokedAfterTheTimeStampForAKeyCompromise()
    {
        $this->assertMatchesRegularExpression('/Time-Stamping Unit.* is revoked since .*, after the time-stamp but for a compromise of a key/', $this->authority($this->ago(1), [TestCrl::reason(1)]));
    }

    public function testTheAuthorityRevokedAfterTheTimeStampWithoutAReason()
    {
        $this->assertMatchesRegularExpression('/after the time-stamp but without a reason/', $this->authority($this->ago(1)));
    }

    public function attacks()
    {
        return [
            'the CRLs of the signer removed' => [function ($x) { return preg_replace('#<xades:RevocationValues[^>]*><xades:CRLValues>(?:(?!</xades:RevocationValues>).)*</xades:RevocationValues></xades:UnsignedSignatureProperties>#s', '</xades:UnsignedSignatureProperties>', $x); },
                '/validation data of the seal do not suffice\. No revocation data for the certificate "[^"]*RSA 3072 Seal Dept/'],
            'the validation data of the time-stamp removed' => [function ($x) { return preg_replace('#<xades141:TimeStampValidationData.*</xades141:TimeStampValidationData>#s', '', $x); },
                '/do not suffice\. No revocation data for the certificate "[^"]*Time-Stamping Unit/'],
            'a CRL that is not one' => [function ($x) { return preg_replace('#<xades:EncapsulatedCRLValue>[^<]+<#', '<xades:EncapsulatedCRLValue>AAAA<', $x, 1); },
                '/A CRL of the validation data of the seal cannot be used\. CRL: /'],
            'a certificate that is not one' => [function ($x) { return preg_replace('#<xades:EncapsulatedX509Certificate>[^<]+<#', '<xades:EncapsulatedX509Certificate>AAAA<', $x, 1); },
                '/A certificate of the validation data of the seal cannot be read/'],
            'an OCSP response that is not one' => [function ($x) { return preg_replace('#</xades:CRLValues>#', '</xades:CRLValues><xades:OCSPValues><xades:EncapsulatedOCSPValue>AAAA</xades:EncapsulatedOCSPValue></xades:OCSPValues>', $x, 1); },
                '/An OCSP response of the validation data of the seal cannot be used/'],
            'revocation values without CRLs' => [function ($x) { return preg_replace('#(<xades:RevocationValues[^>]*>)<xades:CRLValues>(?:(?!</xades:RevocationValues>).)*(</xades:RevocationValues></xades:UnsignedSignatureProperties>)#s', '$1$2', $x); },
                '/Missing xades:CRLValues or xades:OCSPValues in xades:RevocationValues/'],
            'the validation data of the time-stamp after those of the signer' => [function ($x)
                {
                    preg_match('#<xades141:TimeStampValidationData.*</xades141:TimeStampValidationData>#s', $x, $data);
                    return str_replace('</xades:UnsignedSignatureProperties>', $data[0] . '</xades:UnsignedSignatureProperties>', str_replace($data[0], '', $x));
                }, '/Unexpected or misplaced element xades141:TimeStampValidationData/'],
        ];
    }

    /**
     * @dataProvider attacks
     */
    public function testNotValid(callable $change, $message)
    {
        $this->assertMatchesRegularExpression($message, (string) self::check($this->editSignature(self::extended($this->timestamped()), $change))->getError());
    }

    public function testNotValidTheValidationDataOfASealTimeStampedEarlierMovedToALaterOne()
    {
        $crls = array_map(function ($issuer) { return TestCrl::make(['issuer' => $issuer, 'thisUpdate' => $this->ago(18)]); }, ['intermediate', 'root', 'tsa-root']);
        $early = self::signatureXml(self::extended($this->timestamped('rsa3072', ['time' => $this->ago(20)]), $crls));
        preg_match('#<xades141:TimeStampValidationData.*</xades:RevocationValues>#s', $early, $data);
        $late = $this->editSignature($this->timestamped('rsa3072', ['time' => $this->ago(10)]), function ($x) use ($data)
        {
            return str_replace('</xades:UnsignedSignatureProperties>', $data[0] . '</xades:UnsignedSignatureProperties>', $x);
        });
        $this->assertMatchesRegularExpression('/do not suffice\. No revocation data for the certificate .* issued after the time-stamp/', (string) self::check($late)->getError());
    }

    // A seal whose CRLs nobody serves (offline.ezxmlseal.test).

    private function offline()
    {
        return $this->timestamped('offline', ['name' => 'tsa-offline']);
    }

    public function testOfflineListsTheDistributionPointsOfOfflineEzxmlsealTest()
    {
        $this->assertSame([
            ['http://offline.ezxmlseal.test/intermediate-offline.crl'], ['http://offline.ezxmlseal.test/root.crl'], ['http://offline.ezxmlseal.test/tsa-root.crl'],
        ], array_column(Seal::validationDataRequests($this->offline(), self::trust())['crls'], 'urls'));
    }

    public function testOfflineLevelLtItsCrlsPastTheirNextUpdateValidByWhatItEmbeds()
    {
        $crls = array_map(function ($issuer) { return TestCrl::make(['issuer' => $issuer, 'thisUpdate' => $this->ago(15), 'nextUpdate' => $this->ago(5)]); }, ['intermediate-offline', 'root', 'tsa-root']);
        $this->assertSame('LT', self::check(self::extended($this->offline(), $crls))->getLevel());
    }
}
