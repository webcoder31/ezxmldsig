<?php

namespace webcoder31\ezxmldsig\Tests;

use webcoder31\ezxmldsig\Tests\helpers\SealPki;
use webcoder31\ezxmldsig\Tests\helpers\TestCrl;
use webcoder31\ezxmldsig\Tests\helpers\TestOcsp;
use webcoder31\ezxmldsig\core\X509Cert;
use webcoder31\ezxmldsig\seal\Ocsp;
use webcoder31\ezxmldsig\seal\Seal;

/**
 * Revocation by OCSP: the requests a seal needs, the verification of the
 * responses (their responder, their signature, their dates), at levels B, T
 * and LT. The responses come from tests/helpers/TestOcsp.php, not from the
 * code under test. A port of test/seal/ocsp.test.ts of the Node.js library;
 * the responses of OpenSSL are in SealCreateTest.
 */
class SealOcspTest extends SealTestCase
{
    /** The status of the signer by OCSP, of the intermediate by the CRL of the root. */
    private function check($container, array $responses, array $options = [])
    {
        return Seal::verifySeal($container, self::trust($options + ['ocspResponses' => $responses, 'crls' => [TestCrl::make(['issuer' => 'root']), TestCrl::make(['issuer' => 'tsa-root'])]]));
    }

    private static function ocsp(array $options = [])
    {
        return TestOcsp::make($options + ['cert' => 'rsa3072']);
    }

    private static function certificate($name)
    {
        return new X509Cert(file_get_contents(SealPki::cert($name)));
    }

    private function timestamped()
    {
        return self::timestamp(self::seal(), ['time' => $this->ago(20)]);
    }

    public function testTheRequestsOneForEachCertificateThatNamesAResponderTheSigner()
    {
        $requests = Seal::validationDataRequests($this->timestamped(), self::trust())['ocsp'];
        $this->assertSame([['RSA 3072 Seal Dept', 'Seal Intermediate CA', ['http://pki.ezxmlseal.test/ocsp']]], array_map(function ($request)
        {
            return [$request['certificate']->getSubject()['OU'], $request['issuer']->getSubject()['OU'], $request['urls']];
        }, $requests));
    }

    // Level B: the status at the current date.

    public function goodResponses()
    {
        return [
            'signed by the issuer, which it names' => [[]],
            'signed by the issuer, which it names by its key' => [['responderBy' => 'key']],
            'signed by a responder the issuer delegated, with id-pkix-ocsp-nocheck' => [['signer' => 'ocsp']],
            'a CertID by SHA-256' => [['certIdHash' => 'sha256']],
        ];
    }

    /**
     * @dataProvider goodResponses
     */
    public function testGoodValid(array $options)
    {
        $result = $this->check(self::seal(), [self::ocsp($options)]);
        $this->assertNull($result->getError());
        $this->assertTrue($result->isRevocationChecked());
    }

    public function testTheSignerRevoked()
    {
        $this->assertMatchesRegularExpression('/RSA 3072 Seal Dept.* is revoked since/', $this->check(self::seal(), [self::ocsp(['status' => 'revoked', 'reason' => 1])])->getError());
    }

    public function unusableResponses()
    {
        return [
            'a status unknown' => [['status' => 'unknown'], '/its responder does not know the certificate/'],
            'about another certificate' => [['cert' => 'p256'], '/it is about another certificate/'],
            'a delegated responder without id-pkix-ocsp-nocheck' => [['signer' => 'ocsp-checked'], '/has not the extension id-pkix-ocsp-nocheck/'],
            'a certificate of the issuer that is not a responder' => [['signer' => 'p256'], '/has not the extended key usage OCSPSigning/'],
            'signed by another CA under the name of the issuer' => [['signer' => 'root', 'responder' => 'intermediate'], '/its signature is not valid/'],
            'signed by the CA of the time-stamping authority' => [['signer' => 'tsa-root'], '/its responder is not issued by the issuer of the certificate/'],
            'an altered signature' => [['alterSignature' => true], '/its signature is not valid/'],
        ];
    }

    /**
     * Each response is about the signer, but cannot tell its status, for the
     * reason given.
     *
     * @dataProvider unusableResponses
     */
    public function testAResponseThatDoesNotTellTheStatus(array $options, $reason)
    {
        $sources = Ocsp::sources(Ocsp::read(self::ocsp($options)));
        $this->assertMatchesRegularExpression($reason, (string) $sources[0]->covers(self::certificate('rsa3072'), self::certificate('intermediate')));
        $this->assertMatchesRegularExpression('/no CRL of its issuer, nor OCSP response/', $this->check(self::seal(), [self::ocsp($options)])->getError());
    }

    public function testAResponsePastItsNextUpdateDoesNotTellTheCurrentStatus()
    {
        $this->assertMatchesRegularExpression('/No current revocation data/', $this->check(self::seal(), [self::ocsp(['thisUpdate' => $this->ago(120), 'nextUpdate' => $this->ago(60)])])->getError());
    }

    public function testAResponseWithoutNextUpdateDoesNotTellTheCurrentStatus()
    {
        $this->assertMatchesRegularExpression('/No current revocation data/', $this->check(self::seal(), [self::ocsp(['nextUpdate' => null])])->getError());
    }

    public function refusedResponses()
    {
        return [
            'an answer tryLater' => [TestOcsp::make(['cert' => 'rsa3072', 'responseStatus' => 3]), 'the responder answered tryLater'],
            'bytes that are not a response' => ['not a response', 'DER: '],
        ];
    }

    /**
     * @dataProvider refusedResponses
     */
    public function testRefused($response, $message)
    {
        $this->assertThrowsMatching('/an OCSP response cannot be used\. OCSP response: .*' . preg_quote($message, '/') . '/', function () use ($response)
        {
            $this->check(self::seal(), [$response]);
        });
    }

    public function testRefusedAListThatIsNotOfStrings()
    {
        $this->assertThrowsMatching("/invalid option 'ocspResponses'/", function ()
        {
            $this->check(self::seal(), [42]);
        });
    }

    // Level T: the status at the time of the time-stamp.

    public function testLevelTAResponseIssuedAfterTheTimeStampValid()
    {
        $this->assertNull($this->check($this->timestamped(), [self::ocsp()])->getError());
    }

    public function testLevelTAResponseIssuedBeforeTheTimeStampDoesNotTellTheStatusAtThatTime()
    {
        $this->assertMatchesRegularExpression('/issued after the time-stamp/', $this->check($this->timestamped(), [self::ocsp(['thisUpdate' => $this->ago(30)])])->getError());
    }

    public function testLevelTTheSignerRevokedAfterTheTimeStampValid()
    {
        $this->assertNull($this->check($this->timestamped(), [self::ocsp(['status' => 'revoked', 'revocationTime' => $this->ago(10)])])->getError());
    }

    // Level T, a signer expired since the time-stamp: a response produced
    // since tells its status only if its responder keeps that of the expired
    // certificates, from an archive cutoff before the expiry.

    private function expiredStatus(array $options)
    {
        $certificate = $this->tempFile('expired.cert.pem', SealPki::expiredSigner($this->ago(3600), $this->ago(10)));
        $sealed = Seal::createSeal([['name' => 'contrat.pdf', 'content' => "%PDF-1.4\n"]], SealPki::key('rsa3072'), $certificate, SealPki::PASSWORD,
            ['chain' => [SealPki::cert('intermediate')], 'signingTime' => (int) $this->ago(20)]);
        $container = self::timestamp($sealed, ['time' => $this->ago(15)]);
        return $this->check($container, [self::ocsp($options + ['cert' => $certificate, 'thisUpdate' => $this->ago(5)])])->getError();
    }

    public function testExpiredAResponseProducedWhileTheCertificateWasValidValid()
    {
        $this->assertNull($this->expiredStatus(['thisUpdate' => $this->ago(12)]));
    }

    public function testExpiredAResponseProducedAfterTheExpiryWithoutArchiveCutoffProvesNothing()
    {
        $this->assertMatchesRegularExpression('/issued after the time-stamp .*, while it was valid/', $this->expiredStatus([]));
    }

    public function testExpiredAResponseProducedAfterTheExpiryOfAnArchiveCutoffBeforeItValid()
    {
        $this->assertNull($this->expiredStatus(['archiveCutoff' => $this->ago(3600)]));
    }

    public function testExpiredAResponseProducedAfterTheExpiryOfAnArchiveCutoffAfterIt()
    {
        $this->assertMatchesRegularExpression('/while it was valid/', $this->expiredStatus(['archiveCutoff' => $this->ago(7)]));
    }

    public function testExpiredAnArchiveCutoffBeforeTheExpiryTheSignerRevokedBeforeTheTimeStamp()
    {
        $this->assertMatchesRegularExpression('/, before the time-stamp/', $this->expiredStatus(['archiveCutoff' => $this->ago(3600), 'status' => 'revoked', 'revocationTime' => $this->ago(17)]));
    }

    // The certificate of the time-stamping authority by a response of its
    // root, the chain of the signer by CRLs.

    private function authorityError($container, array $options = [])
    {
        return Seal::verifySeal($container, self::trust(['crls' => [TestCrl::make(), TestCrl::make(['issuer' => 'root'])], 'ocspResponses' => [TestOcsp::make($options + ['cert' => 'tsa', 'issuer' => 'tsa-root'])]]))->getError();
    }

    public function testTheAuthorityLevelTGoodValid()
    {
        $this->assertNull($this->authorityError($this->timestamped()));
    }

    public function testTheAuthorityRevokedAfterTheTimeStampForCessationOfOperationValid()
    {
        $this->assertNull($this->authorityError($this->timestamped(), ['status' => 'revoked', 'revocationTime' => $this->ago(1), 'reason' => 5]));
    }

    public function testTheAuthorityRevokedAfterTheTimeStampForAKeyCompromise()
    {
        $this->assertMatchesRegularExpression('/after the time-stamp but for a compromise of a key/', $this->authorityError($this->timestamped(), ['status' => 'revoked', 'revocationTime' => $this->ago(1), 'reason' => 1]));
    }

    public function testTheAuthorityRevokedAfterTheTimeStampWithoutAReason()
    {
        $this->assertMatchesRegularExpression('/after the time-stamp but without a reason/', $this->authorityError($this->timestamped(), ['status' => 'revoked', 'revocationTime' => $this->ago(1)]));
    }

    public function testTheAuthorityLevelLtTheResponseInTheValidationDataOfTheTimeStamp()
    {
        $extended = Seal::addValidationData($this->timestamped(), self::trust(['crls' => [TestCrl::make(), TestCrl::make(['issuer' => 'root'])], 'ocspResponses' => [TestOcsp::make(['cert' => 'tsa', 'issuer' => 'tsa-root'])]]));
        $xml = self::signatureXml($extended);
        $this->assertMatchesRegularExpression('#<xades141:TimeStampValidationData[^>]*>(?:(?!</xades141:TimeStampValidationData>).)*<xades:OCSPValues><xades:EncapsulatedOCSPValue>[^<]+</xades:EncapsulatedOCSPValue></xades:OCSPValues>#s', $xml);
        $this->assertSame(1, substr_count($xml, '<xades:EncapsulatedOCSPValue>'));
        $result = Seal::verifySeal($extended, self::trust());
        $this->assertNull($result->getError());
        $this->assertSame('LT', $result->getLevel());
    }

    // Level LT: the responses embedded.

    private function extendedByOcsp()
    {
        return Seal::addValidationData($this->timestamped(), self::trust(['crls' => [TestCrl::make(['issuer' => 'root']), TestCrl::make(['issuer' => 'tsa-root'])], 'ocspResponses' => [self::ocsp(['signer' => 'ocsp'])]]));
    }

    public function testLevelLtValidByWhatTheSealEmbedsAlone()
    {
        $result = Seal::verifySeal($this->extendedByOcsp(), self::trust());
        $this->assertNull($result->getError());
        $this->assertSame('LT', $result->getLevel());
    }

    public function testLevelLtTheResponseOfTheSignerInOcspValuesTheCrlOfTheRootInCrlValues()
    {
        $this->assertMatchesRegularExpression('#<xades:CertificateValues[^>]*>.*</xades:CertificateValues><xades:RevocationValues[^>]*><xades:CRLValues><xades:EncapsulatedCRLValue>[^<]+</xades:EncapsulatedCRLValue></xades:CRLValues><xades:OCSPValues><xades:EncapsulatedOCSPValue>[^<]+</xades:EncapsulatedOCSPValue></xades:OCSPValues></xades:RevocationValues></xades:UnsignedSignatureProperties>#s',
            self::signatureXml($this->extendedByOcsp()));
    }

    public function testLevelLtACrlGivenBesidesAnOcspResponseThatTellsTheStatusIsNotEmbedded()
    {
        $both = Seal::addValidationData($this->timestamped(), self::trust([
            'crls' => [TestCrl::make(['issuer' => 'root']), TestCrl::make(['issuer' => 'tsa-root']), TestCrl::make(['thisUpdate' => $this->ago(1)])],
            'ocspResponses' => [self::ocsp(['thisUpdate' => $this->ago(2)])],
        ]));
        $xml = self::signatureXml($both);
        $this->assertSame(3, substr_count($xml, '<xades:EncapsulatedCRLValue>'));
        $this->assertSame(0, substr_count($xml, '<xades:EncapsulatedOCSPValue>'));
    }

    public function testLevelLtAnOcspResponseThatIsNotOneEmbedded()
    {
        $container = $this->editSignature($this->extendedByOcsp(), function ($x) { return preg_replace('#<xades:EncapsulatedOCSPValue>[^<]+<#', '<xades:EncapsulatedOCSPValue>AAAA<', $x, 1); });
        $this->assertMatchesRegularExpression('/An OCSP response of the validation data of the seal cannot be used\. OCSP response: /', Seal::verifySeal($container, self::trust())->getError());
    }
}
