<?php

namespace webcoder31\ezxmldsig\Tests;

use webcoder31\ezxmldsig\Tests\helpers\SealPki;
use webcoder31\ezxmldsig\core\Algorithms;
use webcoder31\ezxmldsig\seal\Seal;

/**
 * The verification of seals at level B, on seals made here: the seal of
 * another producer (DSS), the trust in the signer, and the attacks on a
 * sealed container. Each attack starts from a valid seal and changes one
 * thing; the error says which rule refused it. A port of the cases of
 * test/seal/verify.test.ts of the Node.js library that SealVerifyTest, on
 * the seals of the Node.js library, does not have.
 */
class SealAttacksTest extends SealTestCase
{
    private static function files()
    {
        return [
            ['name' => 'contrat final.pdf', 'content' => "%PDF-1.4\n"],
            ['name' => "notes d'\u{e9}t\u{e9}.md", 'content' => "# Notes d'\u{e9}t\u{e9}\n"],
        ];
    }

    private static function sealed(array $options = [])
    {
        return self::seal('rsa3072', $options, self::files());
    }

    private static function error($container, array $options = [])
    {
        return Seal::verifySeal($container, $options + ['caCertPath' => SealPki::cert('root'), 'revocation' => false])->getError();
    }

    // Valid seals.

    public function testASealBuiltByDssWhoseCertificateIsTrusted()
    {
        $dss = dirname(__FILE__) . '/fixtures/seal/dss/';
        $result = Seal::verifySeal(file_get_contents($dss . 'dss-xades-b.asice'), ['caCertPath' => $dss . 'dss-signer.cert.pem', 'revocation' => false]);
        $this->assertNull($result->getError());
        $this->assertSame([
            ['name' => 'contrat final.pdf', 'mimeType' => 'application/pdf'],
            ['name' => "notes d'\u{e9}t\u{e9}.md", 'mimeType' => 'application/octet-stream'],
        ], $result->getFiles());
    }

    public function testAContainerWithoutMimetypeItIsOptional()
    {
        $this->assertNull(self::error(self::rebuild(self::sealed(), function ($entries) { return array_filter($entries, function ($e) { return 'mimetype' !== $e['name']; }); })));
    }

    // The trust in the signer.

    public function testARootEmbeddedInTheSealIsNotTrustedForThat()
    {
        $container = self::sealed(['chain' => [SealPki::cert('intermediate'), SealPki::cert('root')]]);
        $this->assertNull(self::error($container));
        $this->assertMatchesRegularExpression('/not trusted/', self::error($container, ['caCertPath' => dirname(__FILE__) . '/fixtures/certs/root.cert.pem']));
    }

    public function testAnotherCaIsNotTrusted()
    {
        $this->assertMatchesRegularExpression('/not trusted/', self::error(self::sealed(), ['caCertPath' => [dirname(__FILE__) . '/fixtures/certs/intermediate.cert.pem', dirname(__FILE__) . '/fixtures/certs/root.cert.pem']]));
    }

    public function testTheExpectedSubjectAsADn()
    {
        $container = self::seal('p256');
        $dn = Seal::verifySeal($container, ['caCertPath' => SealPki::cert('root'), 'revocation' => false])->getSigningCertificate()->getDN();
        $this->assertNull(self::error($container, ['expectedSubject' => $dn]));
        $this->assertMatchesRegularExpression('/not the expected one/', self::error($container, ['expectedSubject' => str_replace('P-256', 'P-384', $dn)]));
        $this->assertMatchesRegularExpression('/not the expected one/', self::error($container, ['expectedSubject' => ['OU' => 'P-384 Seal Dept']]));
    }

    // Attacks on the container.

    public function containerAttacks()
    {
        $map = function ($name, callable $change) { return function ($entries) use ($name, $change) { return array_map(function ($e) use ($name, $change) { return $e['name'] === $name ? $change($e) : $e; }, $entries); }; };
        $add = function ($name, $content) { return function ($entries) use ($name, $content) { $entries[] = ['name' => $name, 'content' => $content, 'stored' => false]; return $entries; }; };
        return [
            'a file added in a directory' => [$add('annexes/b.pdf', '%PDF'), '#"annexes/b.pdf" is in the container but not sealed#'],
            'a file renamed' => [$map('contrat final.pdf', function ($e) { $e['name'] = 'contrat.pdf'; return $e; }), '/points at no file of the container: "contrat%20final.pdf"/'],
            'the manifest replaced by another document' => [$map('META-INF/manifest.xml', function ($e) { $e['content'] = '<x/>'; return $e; }), '/not an ODF manifest/'],
            'the mimetype compressed' => [$map('mimetype', function ($e) { $e['stored'] = false; return $e; }), '/mimetype file must be the first entry, stored/'],
            'a time-stamp file (ASiC with CAdES)' => [$add('META-INF/timestamp.tst', 'x'), '/Unsupported file in META-INF/'],
            'no signature file' => [function ($entries) { return array_filter($entries, function ($e) { return self::SIGNATURE !== $e['name']; }); }, '/no signature file/'],
        ];
    }

    /**
     * @dataProvider containerAttacks
     */
    public function testAnAttackOnTheContainer(callable $change, $message)
    {
        $this->assertMatchesRegularExpression($message, (string) self::error(self::rebuild(self::sealed(), $change)));
    }

    public function testAContainerBeyondTheLimits()
    {
        $this->assertMatchesRegularExpression('/more than 3 entries/', (string) self::error(self::sealed(), ['maxEntries' => 3, 'maxTotalSize' => 1000000]));
    }

    // Attacks on the signature.

    public function signatureAttacks()
    {
        $file = 'URI="contrat%20final.pdf"';
        return [
            'a media type changed' => [function ($x) { return str_replace('<xades:MimeType>application/pdf<', '<xades:MimeType>text/html<', $x); }, '/signed properties have been altered/'],
            'a reference with a fragment' => [function ($x) use ($file) { return str_replace($file, 'URI="contrat%20final.pdf#page=1"', $x); }, '/relative URI inside the container/'],
            'a reference to META-INF' => [function ($x) use ($file) { return str_replace($file, 'URI="META-INF/manifest.xml"', $x); }, '/points at no file/'],
            'two references to the same file' => [function ($x) { return preg_replace_callback('#(<ds:Reference Id="[^"]+-R1"[^>]*>.*?</ds:Reference>)#s', function ($m) { return $m[1] . preg_replace('# Id="[^"]+"#', '', $m[1], 1); }, $x); }, '/Two references point at the same file/'],
            'a DataObjectFormat removed' => [function ($x) { return preg_replace('#<xades:DataObjectFormat ObjectReference="\#[^"]+-R2">.*?</xades:DataObjectFormat>#s', '', $x); }, '/has no DataObjectFormat/'],
            'empty unsigned properties' => [function ($x) { return str_replace('</xades:SignedProperties>', '</xades:SignedProperties><xades:UnsignedProperties/>', $x); }, '/Missing xades:UnsignedSignatureProperties/'],
            'SigningCertificate version 1' => [function ($x) { return str_replace('xades:SigningCertificateV2>', 'xades:SigningCertificate>', $x); }, '/Unexpected or misplaced element xades:SigningCertificate in/'],
            'a second ds:Object' => [function ($x) { return str_replace('</ds:Signature>', '<ds:Object Id="extra"/></ds:Signature>', $x); }, '/Too many ds:Object/'],
            'a wrong Target' => [function ($x) { return preg_replace('#Target="\#[^"]+"#', 'Target="#other"', $x); }, '/Target of QualifyingProperties/'],
            'SHA-1 digests' => [function ($x) { return preg_replace('#http://www.w3.org/2001/04/xmlenc\#sha256#', 'http://www.w3.org/2000/09/xmldsig#sha1', $x, 1); }, '/Unsupported digest algorithm/'],
            'inclusive canonicalization with comments' => [function ($x) { return str_replace('<ds:CanonicalizationMethod Algorithm="' . Algorithms::EXC_C14N . '"/>', '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"/>', $x); }, '/Unsupported canonicalization/'],
            'text in SignedInfo' => [function ($x) { return str_replace('<ds:SignedInfo>', '<ds:SignedInfo>text', $x); }, '/Unexpected text in ds:SignedInfo/'],
            'another root' => [function ($x) { return str_replace('asic:XAdESSignatures', 'asic:Signatures', $x); }, '/root of the signature file must be asic:XAdESSignatures/'],
            'an invalid signing time' => [function ($x) { return preg_replace('#<xades:SigningTime>[^<]+<#', '<xades:SigningTime>yesterday<', $x); }, '/SigningTime is not a date/'],
        ];
    }

    /**
     * @dataProvider signatureAttacks
     */
    public function testAnAttackOnTheSignature(callable $change, $message)
    {
        $this->assertMatchesRegularExpression($message, (string) self::error($this->editSignature(self::sealed(), $change)));
    }

    public function testAFileReplacedAndItsDigestInSignedInfoWithIt()
    {
        $forged = self::rebuild(
            $this->editSignature(self::sealed(), function ($x) { return preg_replace('#(URI="contrat%20final\.pdf">.*?<ds:DigestValue>)[^<]+#s', '${1}' . base64_encode(hash('sha256', 'forged', true)), $x, 1); }),
            function ($entries) { return array_map(function ($e) { if ('contrat final.pdf' === $e['name']) { $e['content'] = 'forged'; } return $e; }, $entries); }
        );
        $this->assertMatchesRegularExpression('/signature value is not valid/', (string) self::error($forged));
    }

    // Misuses throw.

    public function testNoCaCertificate()
    {
        $this->assertThrowsMatching("/'caCertPath' is required/", function () { Seal::verifySeal(self::sealed(), ['caCertPath' => []]); });
    }

    public function testAContainerThatIsNotAString()
    {
        $this->assertThrowsMatching('/must be bytes/', function () { Seal::verifySeal(42, ['caCertPath' => SealPki::cert('root')]); });
    }
}
