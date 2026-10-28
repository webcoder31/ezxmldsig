<?php

namespace webcoder31\ezxmldsig\Tests;

use DOMDocument;
use Exception;
use webcoder31\ezxmldsig\seal\Seal;
use webcoder31\ezxmldsig\seal\Zip;

/**
 * The verification of seals, on seals made by the Node.js library
 * ezxmldsig-js (tests/fixtures/seal/, see bin/gen-seal-fixtures): the
 * verdicts are those of its verifySeal(), recorded in verdicts.json, and the
 * seals altered here are refused for the reason the alteration gives.
 *
 * A seal of level B is checked with CRLs issued when the test runs, by the
 * openssl command (`openssl ca -gencrl`); the seals of levels T and LT with
 * the CRLs and OCSP responses issued after their time-stamp, kept beside
 * them.
 */
class SealVerifyTest extends TestCase
{
    private static function fixture($path)
    {
        return __DIR__ . '/fixtures/seal/' . $path;
    }

    private static function container($name)
    {
        return file_get_contents(self::fixture('containers/' . $name . '.asice'));
    }

    private static function sealCert($name)
    {
        return self::fixture('certs/' . $name . '.cert.pem');
    }

    /** The CRLs issued after the time-stamp of the seals, by the generator. */
    private static function storedCrls()
    {
        return array_map(function ($name) { return file_get_contents(self::fixture('revocation/' . $name . '.crl')); }, ['intermediate', 'root', 'tsa-root']);
    }

    /**
     * A current CRL of a CA of the seal tests, issued by the openssl command,
     * which revokes the given certificates (on 2026-01-01).
     */
    private function opensslCrl($issuer, array $revoked = [])
    {
        $lines = '';
        foreach ($revoked as $name)
        {
            $parsed = openssl_x509_parse(file_get_contents(self::sealCert($name)));
            $lines .= "R\t" . gmdate('ymdHis', $parsed['validTo_time_t']) . "Z\t260101000000Z\t" . $parsed['serialNumberHex'] . "\tunknown\t/CN=" . $name . "\n";
        }
        $index = $this->tempFile('index.txt', $lines);
        $number = $this->tempFile('crlnumber', "01\n");
        $config = $this->tempFile('ca.cnf', "[ca]\ndefault_ca = test\n[test]\ndatabase = " . $index . "\ncrlnumber = " . $number . "\ndefault_md = sha256\ndefault_crl_days = 7\n");
        $out = $this->tempFile('crl-' . $issuer . '.pem', '');
        $command = implode(' ', array_map('escapeshellarg', ['openssl', 'ca', '-gencrl', '-config', $config,
            '-cert', self::sealCert($issuer), '-keyfile', self::fixture('certs/' . $issuer . '.key.pem'), '-out', $out]));
        exec($command . ' 2>&1', $output, $status);
        $this->assertSame(0, $status, implode("\n", $output));
        return file_get_contents($out);
    }

    private function currentCrls(array $revoked = [])
    {
        return [$this->opensslCrl('intermediate', $revoked), $this->opensslCrl('root'), $this->opensslCrl('tsa-root')];
    }

    private function options(array $more = [])
    {
        return $more + ['caCertPath' => self::sealCert('root'), 'tsaCertPath' => self::sealCert('tsa-root'), 'crls' => $this->currentCrls(['revoked'])];
    }

    public function verdicts()
    {
        $cases = [];
        foreach (json_decode(file_get_contents(self::fixture('verdicts.json')), true) as $name => $verdict)
        {
            $cases[$name] = [$name, $verdict];
        }
        return $cases;
    }

    /**
     * @dataProvider verdicts
     */
    public function testGivesTheVerdictsOfTheNodeJsLibrary($name, array $verdict)
    {
        $options = 0 === strpos($name, 'b-') ? $this->options() : $this->options(['crls' => self::storedCrls()]);
        $result = Seal::verifySeal(self::container($name), $options);

        $this->assertSame($verdict['valid'], $result->isValid(), (string) $result->getError());
        $this->assertSame($verdict['level'], $result->getLevel());
        $this->assertSame($verdict['files'], $result->getFiles());
        $this->assertSame($verdict['signer'], null === $result->getSigningCertificate() ? null : $result->getSigningCertificate()->getDN());
        $iso = function ($date) { return null === $date ? null : $date->format('Y-m-d\TH:i:s.v\Z'); };
        $this->assertSame($verdict['signingTime'], $iso($result->getSigningTime()));
        $this->assertSame($verdict['timestampTime'], $iso($result->getTimestampTime()));
        if (null === $verdict['error'])
        {
            $this->assertNull($result->getError());
            $this->assertTrue($result->isRevocationChecked());
        }
        elseif ('b-revoked' === $name)
        {
            // Revoked on another date by the openssl command: the same message, but the date.
            $this->assertSame('The certificate "/C=DK/O=Lothbrok Ltd/OU=Revoked Seal Dept/CN=Lothbrok Seal Test" is revoked since 2026-01-01T00:00:00.000Z.'
                . " (the option 'revocation' => false verifies the seal without revocation.)", $result->getError());
        }
        else
        {
            $this->assertSame($verdict['error'], $result->getError());
        }
    }

    public function testVerifiesWithTheIntermediateAsAnchorWhenTheSealDoesNotEmbedIt()
    {
        $result = Seal::verifySeal(self::container('b-no-chain'), $this->options(['caCertPath' => [self::sealCert('intermediate'), self::sealCert('root')]]));
        $this->assertTrue($result->isValid(), (string) $result->getError());
    }

    public function testChecksTheRevocationUnlessAskedNotTo()
    {
        $container = self::container('b-rsa-pss-sha256');
        $result = Seal::verifySeal($container, $this->options(['crls' => []]));
        $this->assertSame('No revocation data for the certificate "/C=DK/O=Lothbrok Ltd/OU=RSA 3072 Seal Dept/CN=Lothbrok Seal Test": no CRL of its issuer, nor OCSP response.'
            . " (the option 'revocation' => false verifies the seal without revocation.)", $result->getError());

        $result = Seal::verifySeal($container, $this->options(['crls' => [], 'revocation' => false]));
        $this->assertTrue($result->isValid());
        $this->assertFalse($result->isRevocationChecked());

        // The CRLs kept beside the seals were issued minutes after them: at
        // level B, they are no longer current once their next update passed.
        $result = Seal::verifySeal($container, $this->options(['crls' => self::storedCrls()]));
        exec(implode(' ', array_map('escapeshellarg', ['openssl', 'crl', '-inform', 'DER', '-in', self::fixture('revocation/intermediate.crl'), '-noout', '-nextupdate'])), $output);
        $nextUpdate = strtotime(substr($output[0], strlen('nextUpdate=')));
        $this->assertNotFalse($nextUpdate);
        if (time() > $nextUpdate)
        {
            $this->assertStringStartsWith('No current revocation data for the certificate', $result->getError());
        }
        else
        {
            $this->assertTrue($result->isValid(), (string) $result->getError());
        }
    }

    public function testEmbeddedValidationDataSufficeByThemselves()
    {
        foreach (['lt-crl', 'lt-ocsp'] as $name)
        {
            $result = Seal::verifySeal(self::container($name), ['caCertPath' => self::sealCert('root'), 'tsaCertPath' => self::sealCert('tsa-root')]);
            $this->assertTrue($result->isValid(), $name . ': ' . $result->getError());
            $this->assertSame('LT', $result->getLevel());
        }
        // Level T needs CRLs issued after its time-stamp: a current one is.
        $result = Seal::verifySeal(self::container('t-rsa-pss-sha256'), $this->options());
        $this->assertTrue($result->isValid(), (string) $result->getError());
        $this->assertSame('T', $result->getLevel());
        $result = Seal::verifySeal(self::container('t-rsa-pss-sha256'), $this->options(['crls' => []]));
        $this->assertStringStartsWith('No revocation data for the certificate "/C=DK/O=Lothbrok Ltd/OU=RSA 3072 Seal Dept/CN=Lothbrok Seal Test": no CRL of its issuer', (string) $result->getError());
    }

    public function testTrustsTheTimeStampingAuthorityGivenOnly()
    {
        $container = self::container('t-rsa-pss-sha256');
        $result = Seal::verifySeal($container, ['caCertPath' => self::sealCert('root'), 'revocation' => false]);
        $this->assertSame("The seal is time-stamped: the option 'tsaCertPath' is needed to trust its time-stamping authority.", $result->getError());
        $result = Seal::verifySeal($container, ['caCertPath' => self::sealCert('root'), 'tsaCertPath' => self::sealCert('root'), 'revocation' => false]);
        $this->assertSame('The time-stamping authority is not trusted.', $result->getError());
    }

    public function testChecksTheExpectedSubject()
    {
        $container = self::container('b-ecdsa-p256');
        $options = ['caCertPath' => self::sealCert('root'), 'revocation' => false];
        $this->assertTrue(Seal::verifySeal($container, $options + ['expectedSubject' => ['OU' => 'P-256 Seal Dept', 'C' => 'DK']])->isValid());
        $this->assertTrue(Seal::verifySeal($container, $options + ['expectedSubject' => '/C=DK/O=Lothbrok Ltd/OU=P-256 Seal Dept/CN=Lothbrok Seal Test'])->isValid());
        $this->assertSame('The subject of the signing certificate is not the expected one.', Seal::verifySeal($container, $options + ['expectedSubject' => ['OU' => 'P-384 Seal Dept']])->getError());
        $this->assertSame('The signing certificate is not trusted: no valid chain up to a trusted CA certificate.', Seal::verifySeal($container, ['caCertPath' => self::sealCert('tsa-root'), 'revocation' => false])->getError());
    }

    /**
     * The entries of a container, altered by a function, written again.
     */
    private static function rewrite($container, callable $alter)
    {
        $entries = [];
        foreach (Zip::read($container) as $entry)
        {
            $entries[$entry['name']] = $entry['content'];
        }
        $entries = $alter($entries);
        $inputs = [];
        foreach ($entries as $name => $content)
        {
            $inputs[] = ['name' => (string) $name, 'content' => $content, 'stored' => 'mimetype' === $name];
        }
        return Zip::write($inputs, gmmktime(12, 0, 0, 10, 28, 2026));
    }

    /**
     * The signature file of a container, altered as a DOM document.
     */
    private static function alterSignature($container, callable $alter)
    {
        return self::rewrite($container, function (array $entries) use ($alter)
        {
            $doc = new DOMDocument();
            $doc->loadXML($entries[Seal::SIGNATURE_PATH]);
            $alter($doc);
            $entries[Seal::SIGNATURE_PATH] = $doc->saveXML();
            return $entries;
        });
    }

    private static function first(DOMDocument $doc, $namespace, $name)
    {
        return $doc->getElementsByTagNameNS($namespace, $name)->item(0);
    }

    public function alterations()
    {
        $ds = Seal::XMLDSIG_NS;
        $xades = Seal::XADES_NS;
        return [
            'a file altered' => [function ($c) { return self::rewrite($c, function ($e) { $e['contract.txt'] .= '.'; return $e; }); }, 'The file "contract.txt" has been altered (digest mismatch).'],
            'a file added' => [function ($c) { return self::rewrite($c, function ($e) { $e['added.txt'] = 'not sealed'; return $e; }); }, 'The file "added.txt" is in the container but not sealed.'],
            'a file removed' => [function ($c) { return self::rewrite($c, function ($e) { unset($e['data.bin']); return $e; }); }, 'A reference points at no file of the container: "data.bin".'],
            'no file' => [function ($c) { return self::rewrite($c, function ($e) { return array_intersect_key($e, ['mimetype' => 1, Seal::MANIFEST_PATH => 1, Seal::SIGNATURE_PATH => 1]); }); }, 'The container has no file outside META-INF.'],
            'mimetype not first' => [function ($c) { return self::rewrite($c, function ($e) { $m = $e['mimetype']; unset($e['mimetype']); $e['mimetype'] = $m; return $e; }); }, 'The mimetype file must be the first entry, stored, without extra field.'],
            'another mimetype' => [function ($c) { return self::rewrite($c, function ($e) { $e['mimetype'] = 'application/vnd.etsi.asic-s+zip'; return $e; }); }, 'The container is not an ASiC-E container (mimetype "application/vnd.etsi.asic-s+zip").'],
            'no manifest' => [function ($c) { return self::rewrite($c, function ($e) { unset($e[Seal::MANIFEST_PATH]); return $e; }); }, 'The container has no META-INF/manifest.xml.'],
            'a CAdES signature' => [function ($c) { return self::rewrite($c, function ($e) { $e['META-INF/signature.p7s'] = 'x'; return $e; }); }, 'Unsupported file in META-INF: "META-INF/signature.p7s" (only XAdES signatures are supported).'],
            'two signature files' => [function ($c) { return self::rewrite($c, function ($e) { $e['META-INF/signatures002.xml'] = $e[Seal::SIGNATURE_PATH]; return $e; }); }, 'The container has several signature files: one seal per container is supported.'],
            'a DOCTYPE' => [function ($c) { return self::rewrite($c, function ($e) { $e[Seal::SIGNATURE_PATH] = str_replace('<asic:', '<!DOCTYPE x><asic:', $e[Seal::SIGNATURE_PATH]); return $e; }); }, 'The signature file is not valid: XAdES signature must not have a document type declaration (DOCTYPE)!'],
            'not a ZIP archive' => [function ($c) { return substr($c, 0, -1); }, 'The container is not a valid ZIP archive. ZIP: not a ZIP archive.'],
            'SigningTime altered' => [function ($c) use ($xades) { return self::alterSignature($c, function ($d) use ($xades) { self::first($d, $xades, 'SigningTime')->nodeValue = '2020-01-01T00:00:00Z'; }); }, 'The signed properties have been altered (digest mismatch).'],
            'signature value altered' => [function ($c) use ($ds) { return self::alterSignature($c, function ($d) use ($ds) { $v = self::first($d, $ds, 'SignatureValue'); $b = base64_decode($v->nodeValue); $b[10] = chr(ord($b[10]) ^ 1); $v->nodeValue = base64_encode($b); }); }, 'The signature value is not valid.'],
            'PSS swapped for PKCS#1' => [function ($c) use ($ds) { return self::alterSignature($c, function ($d) use ($ds) { self::first($d, $ds, 'SignatureMethod')->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'); }); }, 'The signature value is not valid.'],
            'ECDSA for an RSA key' => [function ($c) use ($ds) { return self::alterSignature($c, function ($d) use ($ds) { self::first($d, $ds, 'SignatureMethod')->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256'); }); }, 'The signature algorithm http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256 does not suit the key of the signing certificate.'],
            'RSA-SHA1' => [function ($c) use ($ds) { return self::alterSignature($c, function ($d) use ($ds) { self::first($d, $ds, 'SignatureMethod')->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'); }); }, 'Unsupported signature algorithm: http://www.w3.org/2000/09/xmldsig#rsa-sha1.'],
            'a transform on a file' => [function ($c) use ($ds) { return self::alterSignature($c, function ($d) use ($ds) { $r = self::first($d, $ds, 'Reference'); $t = $d->createElementNS($ds, 'ds:Transforms'); $r->insertBefore($t, $r->firstChild); $t->appendChild($d->createElementNS($ds, 'ds:Transform'))->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#'); }); }, 'A reference to a file must have no transform.'],
            'a reference outside' => [function ($c) use ($ds) { return self::alterSignature($c, function ($d) use ($ds) { self::first($d, $ds, 'Reference')->setAttribute('URI', '../contract.txt'); }); }, 'A reference points at no file of the container: "../contract.txt".'],
            'an absolute reference' => [function ($c) use ($ds) { return self::alterSignature($c, function ($d) use ($ds) { self::first($d, $ds, 'Reference')->setAttribute('URI', 'https://example.org/contract.txt'); }); }, 'A reference to a file must be a relative URI inside the container: "https://example.org/contract.txt".'],
            'two Ids alike' => [function ($c) use ($ds) { return self::alterSignature($c, function ($d) use ($ds) { self::first($d, $ds, 'SignatureValue')->setAttribute('Id', self::first($d, $ds, 'Signature')->getAttribute('Id')); }); }, null],
            'a comment' => [function ($c) use ($ds) { return self::alterSignature($c, function ($d) use ($ds) { self::first($d, $ds, 'SignedInfo')->appendChild($d->createComment('x')); }); }, 'Unexpected #comment in ds:SignedInfo.'],
            'a second signature' => [function ($c) use ($ds) { return self::alterSignature($c, function ($d) use ($ds) { $d->documentElement->appendChild(self::first($d, $ds, 'Signature')->cloneNode(true)); }); }, 'The signature file must hold one ds:Signature: one seal per container is supported.'],
            'a signature policy' => [function ($c) use ($xades) { return self::alterSignature($c, function ($d) use ($xades) { self::first($d, $xades, 'SignedSignatureProperties')->appendChild($d->createElementNS($xades, 'xades:SignaturePolicyIdentifier')); }); }, 'Unexpected or misplaced element xades:SignaturePolicyIdentifier in xades:SignedSignatureProperties.'],
            'another signing certificate' => [function ($c) use ($ds, $xades) { return self::alterSignature($c, function ($d) use ($ds, $xades) { $v = self::first($d, $xades, 'CertDigest')->getElementsByTagNameNS($ds, 'DigestValue')->item(0); $v->nodeValue = base64_encode(hash('sha256', 'x', true)); }); }, 'The signing certificate (SigningCertificateV2) is not in KeyInfo.'],
        ];
    }

    /**
     * @dataProvider alterations
     */
    public function testRefusesAlteredSeals($alter, $error)
    {
        $result = Seal::verifySeal($alter(self::container('b-rsa-pss-sha256')), ['caCertPath' => self::sealCert('root'), 'revocation' => false]);
        $this->assertFalse($result->isValid());
        if (null === $error)
        {
            $this->assertStringStartsWith('Two elements have the Id ', $result->getError());
            return;
        }
        $this->assertSame($error, $result->getError());
        $this->assertSame([], $result->getFiles());
        $this->assertNull($result->getLevel());
    }

    public function testRefusesATimeStampOfAnotherSignature()
    {
        // The time-stamp of a seal, moved into another seal of the same signer.
        $timestamped = Zip::read(self::container('t-rsa-pss-sha256'));
        $source = new DOMDocument();
        $source->loadXML(array_values(array_filter($timestamped, function ($e) { return Seal::SIGNATURE_PATH === $e['name']; }))[0]['content']);
        $unsigned = $source->getElementsByTagNameNS(Seal::XADES_NS, 'UnsignedProperties')->item(0);
        $container = self::alterSignature(self::container('b-rsa-sha256'), function ($d) use ($unsigned)
        {
            self::first($d, Seal::XADES_NS, 'QualifyingProperties')->appendChild($d->importNode($unsigned, true));
        });
        $result = Seal::verifySeal($container, ['caCertPath' => self::sealCert('root'), 'tsaCertPath' => self::sealCert('tsa-root'), 'revocation' => false]);
        $this->assertSame('The signature time-stamp is not over the signature value of this seal.', $result->getError());
    }

    public function testRefusesAMisuse()
    {
        foreach ([
            [[], "Seal verification: the option 'caCertPath' is required."],
            [['caCertPath' => '/nonexistent.pem'], "Seal verification: cannot read the certificate file /nonexistent.pem ('caCertPath')."],
            [['caCertPath' => self::sealCert('root'), 'revocation' => 'no'], "Seal verification: invalid option 'revocation'."],
            [['caCertPath' => self::sealCert('root'), 'crls' => ['not a CRL']], 'Seal verification: a CRL cannot be used. CRL: '],
            [['caCertPath' => self::sealCert('root'), 'expectedSubject' => ''], "Seal verification: invalid option 'expectedSubject'."],
        ] as list($options, $message))
        {
            try
            {
                Seal::verifySeal(self::container('b-ecdsa-p256'), $options);
                $this->fail('Accepted: ' . $message);
            }
            catch (Exception $e)
            {
                $this->assertStringStartsWith($message, $e->getMessage());
            }
        }
    }
}
