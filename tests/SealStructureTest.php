<?php

namespace webcoder31\ezxmldsig\Tests;

use DOMDocument;
use DOMXPath;
use webcoder31\ezxmldsig\Tests\helpers\SealPki;
use webcoder31\ezxmldsig\core\Algorithms;
use webcoder31\ezxmldsig\seal\Seal;
use webcoder31\ezxmldsig\seal\Zip;

/**
 * The seal createSeal() writes: the container (EN 319 162-1), the signature
 * (EN 319 132-1, 6.3), and the misuses it refuses. Read back by DOMXPath
 * and hash(), not by the verification of the library. A port of
 * test/seal/seal.test.ts of the Node.js library.
 */
class SealStructureTest extends SealTestCase
{
    private static function files()
    {
        return [
            ['name' => 'contrat final.pdf', 'content' => "%PDF-1.4\n"],
            ['name' => "notes d'\u{e9}t\u{e9}.md", 'content' => "# Notes d'\u{e9}t\u{e9}\n"],
            ['name' => 'docs/a#b%c.txt', 'content' => "odd name\n"],
            ['name' => 'data.bin', 'content' => "\x00\x01\x02\xff", 'mimeType' => 'application/x-test; charset="none"'],
        ];
    }

    private static function sealed(array $options = [])
    {
        return self::seal('rsa3072', $options + ['signingTime' => gmmktime(10, 20, 30, 3, 1, 2027)], self::files());
    }

    private static function xpath($xml)
    {
        $doc = new DOMDocument();
        $doc->loadXML($xml);
        $xpath = new DOMXPath($doc);
        foreach (['ds' => Seal::XMLDSIG_NS, 'xades' => Seal::XADES_NS, 'asic' => 'http://uri.etsi.org/02918/v1.2.1#', 'manifest' => 'urn:oasis:names:tc:opendocument:xmlns:manifest:1.0'] as $prefix => $uri)
        {
            $xpath->registerNamespace($prefix, $uri);
        }
        return $xpath;
    }

    private static function values(DOMXPath $xpath, $expression)
    {
        $values = [];
        foreach ($xpath->query($expression) as $node)
        {
            $values[] = $node->nodeValue;
        }
        return $values;
    }

    private function value(DOMXPath $xpath, $expression)
    {
        $values = self::values($xpath, $expression);
        $this->assertCount(1, $values, $expression);
        return $values[0];
    }

    // The container.

    public function testHoldsTheMimetypeFirstTheSealedFilesTheManifestAndTheSignature()
    {
        $entries = Zip::read(self::sealed());
        $this->assertSame(['mimetype', 'contrat final.pdf', "notes d'\u{e9}t\u{e9}.md", 'docs/a#b%c.txt', 'data.bin', 'META-INF/manifest.xml', self::SIGNATURE], array_column($entries, 'name'));
        $this->assertSame('application/vnd.etsi.asic-e+zip', $entries[0]['content']);
        $this->assertSame(0, $entries[0]['method']);
        $this->assertSame('', $entries[0]['extra']);
        foreach (self::files() as $index => $file)
        {
            $this->assertSame($file['content'], $entries[$index + 1]['content'], $file['name']);
        }
    }

    public function testTheManifestListsTheContainerAndEachSealedFileWithItsMediaType()
    {
        $manifest = self::xpath(Zip::read(self::sealed())[5]['content']);
        $this->assertSame(array_merge(['/'], array_column(self::files(), 'name')), self::values($manifest, '/manifest:manifest/manifest:file-entry/@manifest:full-path'));
        $this->assertSame(['application/vnd.etsi.asic-e+zip', 'application/pdf', 'text/markdown', 'text/plain', 'application/x-test; charset="none"'],
            self::values($manifest, '/manifest:manifest/manifest:file-entry/@manifest:media-type'));
        $this->assertSame('1.2', $this->value($manifest, '/manifest:manifest/@manifest:version'));
    }

    // The signature (EN 319 132-1, 6.3).

    public function testTheSignature()
    {
        $doc = self::xpath(self::signatureXml(self::sealed()));
        $id = $this->value($doc, '/asic:XAdESSignatures/ds:Signature/@Id');

        // One ds:Signature in asic:XAdESSignatures.
        $this->assertSame(1, $doc->query('/asic:XAdESSignatures/*')->length);
        $this->assertSame(1, $doc->query('//ds:Signature')->length);

        // Exclusive canonicalization, RSA-PSS by default for an RSA key.
        $this->assertSame(Algorithms::EXC_C14N, $this->value($doc, '//ds:SignedInfo/ds:CanonicalizationMethod/@Algorithm'));
        $this->assertSame(Algorithms::RSA_PSS_SHA256, $this->value($doc, '//ds:SignedInfo/ds:SignatureMethod/@Algorithm'));

        // One reference per sealed file, without transform, its URI percent-encoded, its digest that of the file.
        $references = $doc->query('//ds:SignedInfo/ds:Reference[not(@Type)]');
        $this->assertSame(['contrat%20final.pdf', "notes%20d'%C3%A9t%C3%A9.md", 'docs/a%23b%25c.txt', 'data.bin'], array_map(function ($r) { return $r->getAttribute('URI'); }, iterator_to_array($references)));
        foreach (self::files() as $index => $file)
        {
            $reference = $references->item($index);
            $this->assertSame(0, $reference->getElementsByTagNameNS(Seal::XMLDSIG_NS, 'Transforms')->length);
            $this->assertSame(base64_encode(hash('sha256', $file['content'], true)), $reference->getElementsByTagNameNS(Seal::XMLDSIG_NS, 'DigestValue')->item(0)->textContent);
        }

        // A reference to the signed properties, of the type of XAdES.
        $this->assertSame('#' . $this->value($doc, '//xades:SignedProperties/@Id'), $this->value($doc, '//ds:Reference[@Type="http://uri.etsi.org/01903#SignedProperties"]/@URI'));
        $this->assertSame(Algorithms::EXC_C14N, $this->value($doc, '//ds:Reference[@Type]/ds:Transforms/ds:Transform/@Algorithm'));

        // One QualifyingProperties whose Target is the signature.
        $this->assertSame('#' . $id, $this->value($doc, '/asic:XAdESSignatures/ds:Signature/ds:Object/xades:QualifyingProperties/@Target'));
        $this->assertSame(1, $doc->query('//xades:QualifyingProperties')->length);
        $this->assertSame(0, $doc->query('//xades:UnsignedProperties')->length);

        // SigningTime in UTC, to the second.
        $this->assertSame('2027-03-01T10:20:30Z', $this->value($doc, '//xades:SigningTime'));

        // SigningCertificateV2: the digest of the signing certificate, no IssuerSerialV2, no SigningCertificate.
        $this->assertSame(base64_encode(hash('sha256', SealPki::certificateDer('rsa3072'), true)), $this->value($doc, '//xades:SigningCertificateV2/xades:Cert/xades:CertDigest/ds:DigestValue'));
        $this->assertSame(0, $doc->query('//xades:IssuerSerialV2')->length);
        $this->assertSame(0, $doc->query('//xades:SigningCertificate')->length);

        // A DataObjectFormat with a MimeType per file, pointing at its reference.
        $this->assertSame(array_map(function ($r) { return '#' . $r; }, self::values($doc, '//ds:SignedInfo/ds:Reference[not(@Type)]/@Id')), self::values($doc, '//xades:DataObjectFormat/@ObjectReference'));
        $this->assertSame(['application/pdf', 'text/markdown', 'text/plain', 'application/x-test; charset="none"'], self::values($doc, '//xades:DataObjectFormat/xades:MimeType'));

        // The signing certificate first in KeyInfo, then the chain.
        $this->assertSame([SealPki::certificateDer('rsa3072'), SealPki::certificateDer('intermediate')], array_map('base64_decode', self::values($doc, '//ds:KeyInfo/ds:X509Data/ds:X509Certificate')));

        // The identifiers differ from one seal to the next.
        $this->assertNotSame($id, $this->value(self::xpath(self::signatureXml(self::sealed())), '/asic:XAdESSignatures/ds:Signature/@Id'));
    }

    // The algorithms follow the key.

    public function testTheDigestOfTheFilesOnRequest()
    {
        $doc = self::xpath(self::signatureXml(self::seal('p256', ['digestAlgorithm' => Algorithms::SHA512])));
        $this->assertSame([Algorithms::SHA512], array_values(array_unique(self::values($doc, '//ds:DigestMethod/@Algorithm'))));
    }

    // Misuses are refused.

    public function misuses()
    {
        $empty = function ($name) { return [['name' => $name, 'content' => '']]; };
        $file = [['name' => 'a', 'content' => 'a']];
        return [
            'the name mimetype' => [function () use ($empty) { self::seal('rsa3072', [], $empty('mimetype')); }, '/reserved by the container/'],
            'a path that leaves the container' => [function () use ($empty) { self::seal('rsa3072', [], $empty('../x.txt')); }, '/invalid entry name/'],
            'two files of the same name' => [function () { self::seal('rsa3072', [], [['name' => 'a', 'content' => ''], ['name' => 'a', 'content' => '']]); }, '/duplicate entry/'],
            'a content that is not a string' => [function () { self::seal('rsa3072', [], [['name' => 'a', 'content' => 42]]); }, '/must have a name and a content/'],
            'RSA-PSS with an EC key' => [function () { self::seal('p256', ['signatureAlgorithm' => Algorithms::RSA_PSS_SHA256]); }, '/needs an RSA key/'],
            'SHA-1 digests' => [function () { self::seal('rsa3072', ['digestAlgorithm' => 'http://www.w3.org/2000/09/xmldsig#sha1']); }, '/unsupported digest algorithm/'],
            'a signing time before the certificate' => [function () { self::seal('rsa3072', ['signingTime' => gmmktime(0, 0, 0, 1, 1, 2020)]); }, '/not valid at the signing time/'],
            'a certificate whose key usage does not allow signing' => [function () use ($file) { Seal::createSeal($file, SealPki::key('intermediate'), SealPki::cert('intermediate'), null); }, '/key usage/'],
        ];
    }

    /**
     * @dataProvider misuses
     */
    public function testAMisuseIsRefused(callable $run, $message)
    {
        $this->assertThrowsMatching($message, $run);
    }

    /**
     * A name not in normalization form C is refused with the intl extension
     * (class Normalizer); without it, the names are compared byte by byte,
     * and the name is sealed as given.
     */
    public function testANameNotInNormalizationFormC()
    {
        $files = [['name' => "e\u{301}te\u{301}.txt", 'content' => '']];
        if (class_exists('Normalizer'))
        {
            $this->assertThrowsMatching('/normalization form C/', function () use ($files) { self::seal('rsa3072', [], $files); });
            return;
        }
        $this->assertSame("e\u{301}te\u{301}.txt", Zip::read(self::seal('rsa3072', [], $files))[1]['name']);
    }
}
