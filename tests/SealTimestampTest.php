<?php

namespace webcoder31\ezxmldsig\Tests;

use DOMDocument;
use webcoder31\ezxmldsig\Tests\helpers\SealPki;
use webcoder31\ezxmldsig\Tests\helpers\TestTsa;
use webcoder31\ezxmldsig\core\Algorithms;
use webcoder31\ezxmldsig\seal\Seal;

/**
 * Level T: the time-stamp request of a seal, the addition of the token of a
 * response, and the verification of a time-stamped seal. The tokens come
 * from tests/helpers/TestTsa.php, not from the code under test. A port of
 * test/seal/timestamp.test.ts of the Node.js library; the tokens of OpenSSL
 * are in SealCreateTest.
 */
class SealTimestampTest extends SealTestCase
{
    private static function check($container, array $options = [])
    {
        return Seal::verifySeal($container, self::trust($options + ['revocation' => false]));
    }

    // The request.

    public function testTheRequestIsOverSignatureValueByExclusiveCanonicalization()
    {
        $container = self::seal();
        $doc = new DOMDocument();
        $doc->loadXML(self::signatureXml($container));
        $value = $doc->getElementsByTagNameNS(Seal::XMLDSIG_NS, 'SignatureValue')->item(0);
        $expected = hash('sha256', $value->C14N(true, false), true);
        $this->assertSame(['hash' => 'sha256', 'imprint' => $expected], TestTsa::readRequest(Seal::timestampRequest($container)));
    }

    public function testTheRequestWithAnotherDigest()
    {
        $this->assertSame('sha512', TestTsa::readRequest(Seal::timestampRequest(self::seal(), Algorithms::SHA512))['hash']);
        $this->assertThrowsMatching('/unsupported digest/', function () { Seal::timestampRequest(self::seal(), 'http://www.w3.org/2000/09/xmldsig#sha1'); });
    }

    // A time-stamped seal.

    public function testHoldsTheTokenInUnsignedSignaturePropertiesAfterTheSignedProperties()
    {
        $xml = self::signatureXml(self::timestamp(self::seal('p256'), ['time' => gmmktime(8, 0, 0, 6, 1, 2027)]));
        $this->assertMatchesRegularExpression('#</xades:SignedProperties><xades:UnsignedProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2\#"><xades:UnsignedSignatureProperties><xades:SignatureTimeStamp Id="[^"]+-TS"><ds:CanonicalizationMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig\#" Algorithm="http://www.w3.org/2001/10/xml-exc-c14n\#"/><xades:EncapsulatedTimeStamp>[A-Za-z0-9+/=]+</xades:EncapsulatedTimeStamp></xades:SignatureTimeStamp></xades:UnsignedSignatureProperties></xades:UnsignedProperties></xades:QualifyingProperties>#', $xml);
    }

    public function testKeepsTheSignedPartOfTheSignatureFileByteForByte()
    {
        $original = self::seal('p256');
        $after = self::signatureXml(self::timestamp($original));
        $this->assertSame(self::signatureXml($original), preg_replace('#<xades:UnsignedProperties.*</xades:UnsignedProperties>#s', '', $after));
    }

    public function testIsAValidSealOfLevelTAtTheTimeOfItsTimeStamp()
    {
        $time = gmmktime(8, 0, 0, 6, 1, 2027);
        $result = self::check(self::timestamp(self::seal('p256'), ['time' => $time]));
        $this->assertNull($result->getError());
        $this->assertSame('T', $result->getLevel());
        $this->assertSame($time, $result->getTimestampTime()->getTimestamp());
    }

    public function testWithAnEssSigningCertificateOfVersion1AndTheChainOfTheAuthorityInTheToken()
    {
        $this->assertNull(self::check(self::timestamp(self::seal(), ['ess' => 1, 'certificates' => 'chain']))->getError());
    }

    public function testNeedsTheTrustInItsTimeStampingAuthority()
    {
        $container = self::timestamp(self::seal('p256'));
        $this->assertMatchesRegularExpression("/'tsaCertPath' is needed/", Seal::verifySeal($container, ['caCertPath' => SealPki::cert('root'), 'revocation' => false])->getError());
        $this->assertMatchesRegularExpression('/time-stamping authority is not trusted/', self::check($container, ['tsaCertPath' => SealPki::cert('root')])->getError());
    }

    public function testChecksTheSigningCertificateAtTheTimeOfTheTimeStamp()
    {
        // The seal certificates are valid for ten years from their generation.
        foreach ([gmmktime(0, 0, 0, 1, 1, 2050), gmmktime(0, 0, 0, 1, 1, 2020)] as $time)
        {
            $this->assertMatchesRegularExpression('/not trusted.*at the time of the time-stamp/', self::check(self::timestamp(self::seal(), ['time' => $time]))->getError());
        }
    }

    // addSignatureTimestamp() refuses.

    public function refusedResponses()
    {
        return [
            'a refusal of the authority' => [['status' => 2], null, '/answered rejection: request refused/'],
            'a token over another seal' => [[], 'other', '/not over the signature of this seal/'],
            'an authority that is not trusted' => [[], 'root', '/authority is not trusted/'],
            'a certificate without the extended key usage timeStamping' => [['name' => 'tsa-no-eku'], null, '/extended key usage timeStamping/'],
            'a TSTInfo altered after signing' => [['alterTstInfo' => true], null, '/TSTInfo has been altered/'],
            'an altered signature' => [['alterSignature' => true], null, '/signature of the token is not valid/'],
            'a token without ESS signingCertificate' => [['ess' => 'none'], null, '/signingCertificate \(ESS\) is missing/'],
            'a token without the certificate of the authority' => [['certificates' => 'none'], null, '/certificate of the authority is not in the token/'],
            'a SHA-1 imprint' => [['hash' => 'sha1', 'imprint' => str_repeat("\x00", 20)], null, '/unsupported digest algorithm 1\.3\.14\.3\.2\.26/'],
        ];
    }

    /**
     * @dataProvider refusedResponses
     *
     * @param string|null $variant 'other': the token of another seal; 'root':
     *        the root of the signers as the authority trusted.
     */
    public function testAddSignatureTimestampRefuses(array $tsaOptions, $variant, $message)
    {
        $container = self::seal();
        $request = Seal::timestampRequest('other' === $variant ? self::seal() : $container);
        $tsa = SealPki::cert('root' === $variant ? 'root' : 'tsa-root');
        $this->assertThrowsMatching($message, function () use ($container, $request, $tsaOptions, $tsa)
        {
            Seal::addSignatureTimestamp($container, TestTsa::response($request, $tsaOptions), ['tsaCertPath' => $tsa]);
        });
    }

    public function testAddSignatureTimestampRefusesAResponseThatIsNotDer()
    {
        $this->assertThrowsMatching('/DER|malformed/', function () { Seal::addSignatureTimestamp(self::seal(), 'not a response', ['tsaCertPath' => SealPki::cert('tsa-root')]); });
    }

    public function testAddSignatureTimestampRefusesASealAlreadyTimeStamped()
    {
        $this->assertThrowsMatching('/already has unsigned properties/', function () { self::timestamp(self::timestamp(self::seal())); });
    }

    public function testAddSignatureTimestampRefusesNoTsaCertPath()
    {
        $container = self::seal();
        $this->assertThrowsMatching("/'tsaCertPath' is required/", function () use ($container) { Seal::addSignatureTimestamp($container, TestTsa::response(Seal::timestampRequest($container)), []); });
    }

    // Attacks on a time-stamped seal.

    private static function token($container)
    {
        preg_match('#<xades:EncapsulatedTimeStamp>([^<]+)<#', self::signatureXml($container), $match);
        return $match[1];
    }

    public function attacks()
    {
        $exc = Algorithms::EXC_C14N;
        return [
            'the token of another seal' => [function ($x, $token, $other) { return str_replace($token, $other, $x); }, '/not over the signature value of this seal/'],
            'the signature value changed' => [function ($x) { return preg_replace_callback('#<ds:SignatureValue([^>]*)>(.)#', function ($m) { return '<ds:SignatureValue' . $m[1] . '>' . ('A' === $m[2] ? 'B' : 'A'); }, $x, 1); }, '/signature value is not valid/'],
            'a corrupted token' => [function ($x, $token) { return str_replace($token, substr($token, 0, 200) . 'AAAA' . substr($token, 204), $x); }, '/signature time-stamp is not valid/'],
            'no canonicalization method' => [function ($x) { return preg_replace('#<ds:CanonicalizationMethod xmlns:ds="[^"]+" Algorithm="[^"]+"/><xades:Encapsulated#', '<xades:Encapsulated', $x); }, '/Missing ds:CanonicalizationMethod in xades:SignatureTimeStamp/'],
            'another canonicalization than the one time-stamped' => [function ($x) use ($exc) { return str_replace('xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="' . $exc . '"/><xades:Encapsulated', 'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/><xades:Encapsulated', $x); }, '/not over the signature value/'],
            'an XML encoding of the token' => [function ($x) { return str_replace('<xades:EncapsulatedTimeStamp>', '<xades:EncapsulatedTimeStamp Encoding="http://uri.etsi.org/01903/v1.2.2#XER">', $x); }, '/Unsupported encoding/'],
            'two time-stamps' => [function ($x) { return preg_replace_callback('#(<xades:SignatureTimeStamp.*</xades:SignatureTimeStamp>)#s', function ($m) { return $m[1] . preg_replace('# Id="[^"]+"#', '', $m[1], 1); }, $x); }, '/Too many xades:SignatureTimeStamp/'],
            'an unsigned property this library does not process' => [function ($x) { return str_replace('</xades:UnsignedSignatureProperties>', '<xades:CompleteRevocationRefs/></xades:UnsignedSignatureProperties>', $x); }, '/Unexpected or misplaced element xades:CompleteRevocationRefs/'],
            'empty certificate values' => [function ($x) { return str_replace('</xades:UnsignedSignatureProperties>', '<xades:CertificateValues/></xades:UnsignedSignatureProperties>', $x); }, '/Missing xades:EncapsulatedX509Certificate/'],
        ];
    }

    /**
     * @dataProvider attacks
     */
    public function testAnAttackOnATimeStampedSeal(callable $change, $message)
    {
        $valid = self::timestamp(self::seal());
        $token = self::token($valid);
        $other = self::token(self::timestamp(self::seal()));
        $altered = $this->editSignature($valid, function ($x) use ($change, $token, $other) { return $change($x, $token, $other); });
        $this->assertMatchesRegularExpression($message, (string) self::check($altered)->getError());
    }
}
