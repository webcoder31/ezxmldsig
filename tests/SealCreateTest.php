<?php

namespace webcoder31\ezxmldsig\Tests;

use Exception;
use webcoder31\ezxmldsig\core\Algorithms;
use webcoder31\ezxmldsig\core\X509Cert;
use webcoder31\ezxmldsig\seal\Seal;
use webcoder31\ezxmldsig\seal\Zip;

/**
 * The creation of seals and their extension to levels T and LT. The
 * time-stamping authority is the openssl command (`openssl ts -reply`), the
 * CRLs are issued by `openssl ca -gencrl` and the OCSP responses by
 * `openssl ocsp`: none of them comes from the library. The seals made here
 * are also verified by the Node.js library and by DSS (see the README of
 * tests/fixtures/seal/).
 */
class SealCreateTest extends TestCase
{
    const PASSWORD = 'signKeyPassword';

    private static function sealCert($name)
    {
        return __DIR__ . '/fixtures/seal/certs/' . $name . '.cert.pem';
    }

    private static function sealKey($name)
    {
        return __DIR__ . '/fixtures/seal/certs/' . $name . '.key.pem';
    }

    private static function files()
    {
        return [
            ['name' => 'contract.txt', 'content' => "The contract.\n"],
            ['name' => "annexes/r\u{e9}sum\u{e9} (1).md", 'content' => "# R\u{e9}sum\u{e9}\n"],
            ['name' => 'scan', 'content' => random_bytes(300), 'mimeType' => 'image/tiff'],
        ];
    }

    private static function seal($signer = 'rsa3072', array $options = [])
    {
        return Seal::createSeal(self::files(), self::sealKey($signer), self::sealCert($signer), self::PASSWORD, $options + ['chain' => [self::sealCert('intermediate')]]);
    }

    private function runCommand(array $arguments)
    {
        exec(implode(' ', array_map('escapeshellarg', $arguments)) . ' 2>&1', $output, $status);
        $this->assertSame(0, $status, implode("\n", $output));
    }

    /**
     * The response of the openssl command, as a time-stamping authority, to
     * a request.
     */
    private function opensslTimestamp($request)
    {
        $config = $this->tempFile('tsa.cnf', implode("\n", [
            '[tsa]', 'default_tsa = tsa_config', '[tsa_config]',
            'serial = ' . $this->tempFile('serial', "01\n"),
            'signer_cert = ' . self::sealCert('tsa'),
            'certs = ' . self::sealCert('tsa-root'),
            'signer_key = ' . self::sealKey('tsa'),
            'signer_digest = sha256', 'default_policy = 1.3.6.1.4.1.55555.3.1', 'digests = sha256, sha384, sha512',
            'accuracy = secs:1', 'ess_cert_id_alg = sha256', 'ess_cert_id_chain = no', 'ordering = no', 'tsa_name = no', '',
        ]));
        $out = $this->tempFile('response.tsr', '');
        $this->runCommand(['openssl', 'ts', '-reply', '-config', $config, '-queryfile', $this->tempFile('request.tsq', $request), '-out', $out]);
        return file_get_contents($out);
    }

    /**
     * A current CRL of a CA, issued by the openssl command, which revokes
     * rsa3072.cert.pem at the given UNIX time, if any.
     */
    private function opensslCrl($issuer, $revokedAt = null)
    {
        $index = '';
        if (null !== $revokedAt)
        {
            $parsed = openssl_x509_parse(file_get_contents(self::sealCert('rsa3072')));
            $index = "R\t" . gmdate('ymdHis', $parsed['validTo_time_t']) . "Z\t" . gmdate('ymdHis', $revokedAt) . "Z\t" . $parsed['serialNumberHex'] . "\tunknown\t/CN=rsa3072\n";
        }
        $config = $this->tempFile('ca.cnf', "[ca]\ndefault_ca = test\n[test]\ndatabase = " . $this->tempFile('index.txt', $index)
            . "\ncrlnumber = " . $this->tempFile('crlnumber', "01\n") . "\ndefault_md = sha256\ndefault_crl_days = 7\n");
        $out = $this->tempFile('crl-' . $issuer . '.pem', '');
        $this->runCommand(['openssl', 'ca', '-gencrl', '-config', $config, '-cert', self::sealCert($issuer), '-keyfile', self::sealKey($issuer), '-out', $out]);
        return file_get_contents($out);
    }

    /**
     * The response of the openssl command, as the OCSP responder the
     * intermediate CA delegates, to a request.
     */
    private function opensslOcsp($request, $responder = 'ocsp')
    {
        $parsed = openssl_x509_parse(file_get_contents(self::sealCert('rsa3072')));
        $index = $this->tempFile('ocsp-index.txt', "V\t" . gmdate('ymdHis', $parsed['validTo_time_t']) . "Z\t\t" . $parsed['serialNumberHex'] . "\tunknown\t/CN=rsa3072\n");
        $out = $this->tempFile('response.der', '');
        $this->runCommand(['openssl', 'ocsp', '-index', $index, '-CA', self::sealCert('intermediate'), '-rsigner', self::sealCert($responder),
            '-rkey', self::sealKey($responder), '-reqin', $this->tempFile('request.der', $request), '-respout', $out, '-ndays', '1']);
        return file_get_contents($out);
    }

    private function timestamped($container)
    {
        return Seal::addSignatureTimestamp($container, $this->opensslTimestamp(Seal::timestampRequest($container)), ['tsaCertPath' => self::sealCert('tsa-root')]);
    }

    private function trust(array $more = [])
    {
        return $more + ['caCertPath' => self::sealCert('root'), 'tsaCertPath' => self::sealCert('tsa-root')];
    }

    public function signers()
    {
        return [
            'RSA-PSS, by default' => ['rsa3072', [], Algorithms::RSA_PSS_SHA256],
            'RSA PKCS#1 v1.5' => ['rsa3072', ['signatureAlgorithm' => Algorithms::RSA_SHA256], Algorithms::RSA_SHA256],
            'RSA-PSS SHA-512' => ['rsa2048', ['signatureAlgorithm' => Algorithms::RSA_PSS_SHA512, 'digestAlgorithm' => Algorithms::SHA512], Algorithms::RSA_PSS_SHA512],
            'ECDSA P-256, by default' => ['p256', [], Algorithms::ECDSA_SHA256],
            'ECDSA P-384, by default' => ['p384', [], Algorithms::ECDSA_SHA384],
        ];
    }

    /**
     * @dataProvider signers
     */
    public function testSealsFiles($signer, array $options, $algorithm)
    {
        $container = self::seal($signer, $options + ['signingTime' => gmmktime(12, 0, 0, 10, 28, 2026)]);
        $result = Seal::verifySeal($container, $this->trust(['revocation' => false]));
        $this->assertTrue($result->isValid(), (string) $result->getError());
        $this->assertSame('B', $result->getLevel());
        $this->assertSame([
            ['name' => 'contract.txt', 'mimeType' => 'text/plain'],
            ['name' => "annexes/r\u{e9}sum\u{e9} (1).md", 'mimeType' => 'text/markdown'],
            ['name' => 'scan', 'mimeType' => 'image/tiff'],
        ], $result->getFiles());
        $this->assertSame('2026-10-28T12:00:00+00:00', $result->getSigningTime()->format('c'));

        $entries = Zip::read($container);
        $this->assertSame(['mimetype', 'contract.txt', "annexes/r\u{e9}sum\u{e9} (1).md", 'scan', Seal::MANIFEST_PATH, Seal::SIGNATURE_PATH], array_column($entries, 'name'));
        $this->assertSame(0, $entries[0]['method']);
        $signature = $entries[5]['content'];
        $this->assertStringContainsString('<ds:SignatureMethod Algorithm="' . $algorithm . '"/>', $signature);
        $this->assertStringContainsString('URI="annexes/r%C3%A9sum%C3%A9%20(1).md"', $signature);
        // The certificates of KeyInfo: the signer's, then the chain given.
        $this->assertSame(2, substr_count($signature, '<ds:X509Certificate>'));
    }

    public function testRefusesAMisuse()
    {
        $file = [['name' => 'a.txt', 'content' => 'a']];
        foreach ([
            [function () { return Seal::createSeal([], self::sealKey('p256'), self::sealCert('p256'), self::PASSWORD); }, 'Seal: no file to seal.'],
            [function () use ($file) { return Seal::createSeal([['name' => 'META-INF/x.xml', 'content' => 'x']], self::sealKey('p256'), self::sealCert('p256'), self::PASSWORD); }, 'Seal: "META-INF/x.xml" is reserved by the container.'],
            [function () use ($file) { return Seal::createSeal([['name' => 'mimetype', 'content' => 'x']], self::sealKey('p256'), self::sealCert('p256'), self::PASSWORD); }, 'Seal: "mimetype" is reserved by the container.'],
            [function () use ($file) { return Seal::createSeal([['name' => 'a.txt', 'content' => 'a', 'mimeType' => 'text']], self::sealKey('p256'), self::sealCert('p256'), self::PASSWORD); }, 'Seal: invalid media type for "a.txt".'],
            [function () use ($file) { return Seal::createSeal($file, self::sealKey('p256'), self::sealCert('p256'), 'wrong'); }, 'Seal: unable to load the signing key (wrong password?).'],
            [function () use ($file) { return Seal::createSeal($file, self::sealKey('p256'), self::sealCert('p384'), self::PASSWORD); }, 'Seal: the signing key does not match the signing certificate.'],
            [function () use ($file) { return Seal::createSeal($file, self::sealKey('rsa1024'), self::sealCert('rsa1024'), self::PASSWORD); }, 'Seal: RSA keys of less than 2048 bits are refused.'],
            [function () use ($file) { return Seal::createSeal($file, self::sealKey('rsa3072'), self::sealCert('rsa3072'), self::PASSWORD, ['signatureAlgorithm' => Algorithms::ECDSA_SHA256]); }, 'Seal: the signature algorithm http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256 needs an EC key.'],
            [function () use ($file) { return Seal::createSeal($file, self::sealKey('rsa3072'), self::sealCert('rsa3072'), self::PASSWORD, ['signatureAlgorithm' => Algorithms::RSA_SHA1]); }, 'Seal: unsupported signature algorithm http://www.w3.org/2000/09/xmldsig#rsa-sha1.'],
            [function () use ($file) { return Seal::createSeal($file, self::sealKey('p256'), self::sealCert('p256'), self::PASSWORD, ['signingTime' => gmmktime(0, 0, 0, 1, 1, 2040)]); }, 'Seal: the signing certificate is not valid at the signing time.'],
            [function () use ($file) { return Seal::createSeal($file, self::sealKey('p256'), '/nonexistent.pem', self::PASSWORD); }, 'Seal: unable to read the signing certificate (/nonexistent.pem).'],
        ] as list($call, $message))
        {
            try
            {
                $call();
                $this->fail('Accepted: ' . $message);
            }
            catch (Exception $e)
            {
                $this->assertSame($message, $e->getMessage());
            }
        }
    }

    public function testTimeStampsASeal()
    {
        $container = self::seal();
        $before = time();
        $timestamped = $this->timestamped($container);
        $result = Seal::verifySeal($timestamped, $this->trust(['crls' => [$this->opensslCrl('intermediate'), $this->opensslCrl('root'), $this->opensslCrl('tsa-root')]]));
        $this->assertTrue($result->isValid(), (string) $result->getError());
        $this->assertSame('T', $result->getLevel());
        $this->assertLessThanOrEqual(2, abs($result->getTimestampTime()->getTimestamp() - $before));

        // The signed part of the signature file is left byte for byte.
        $signature = function ($c) { return array_column(Zip::read($c), 'content', 'name')[Seal::SIGNATURE_PATH]; };
        $closing = '</xades:SignedProperties>';
        $original = $signature($container);
        $this->assertSame(substr($original, 0, strpos($original, $closing)), substr($signature($timestamped), 0, strpos($original, $closing)));

        try
        {
            Seal::addSignatureTimestamp($timestamped, $this->opensslTimestamp(Seal::timestampRequest($timestamped)), ['tsaCertPath' => self::sealCert('tsa-root')]);
            $this->fail('Time-stamped twice');
        }
        catch (Exception $e)
        {
            $this->assertSame('Time-stamp: the seal already has unsigned properties.', $e->getMessage());
        }
        try
        {
            Seal::addSignatureTimestamp(self::seal(), $this->opensslTimestamp(Seal::timestampRequest($container)), ['tsaCertPath' => self::sealCert('tsa-root')]);
            $this->fail('Time-stamp of another seal');
        }
        catch (Exception $e)
        {
            $this->assertSame('Time-stamp: the token is not over the signature of this seal.', $e->getMessage());
        }
        try
        {
            Seal::addSignatureTimestamp($container, $this->opensslTimestamp(Seal::timestampRequest($container)), ['tsaCertPath' => self::sealCert('root')]);
            $this->fail('Untrusted authority');
        }
        catch (Exception $e)
        {
            $this->assertSame('Time-stamp: the time-stamping authority is not trusted.', $e->getMessage());
        }
    }

    public function testListsTheValidationDataToFetch()
    {
        $requests = Seal::validationDataRequests($this->timestamped(self::seal()), $this->trust());
        $describe = function (array $request) { return [$request['certificate']->getSubject()['OU'], $request['issuer']->getSubject()['OU'], $request['urls']]; };
        $this->assertSame([
            ['RSA 3072 Seal Dept', 'Seal Intermediate CA', ['http://pki.ezxmlseal.test/intermediate.crl']],
            ['Seal Intermediate CA', 'Seal Root CA', ['http://pki.ezxmlseal.test/root.crl']],
            ['Time-Stamping Unit', 'TSA Root CA', ['http://pki.ezxmlseal.test/tsa-root.crl']],
        ], array_map($describe, $requests['crls']));
        $this->assertSame([['RSA 3072 Seal Dept', 'Seal Intermediate CA', ['http://pki.ezxmlseal.test/ocsp']]], array_map($describe, $requests['ocsp']));
        // The request, read by the openssl command.
        exec(implode(' ', array_map('escapeshellarg', ['openssl', 'ocsp', '-reqin', $this->tempFile('req.der', $requests['ocsp'][0]['request']), '-req_text'])), $output, $status);
        $this->assertSame(0, $status);
        $serial = strtoupper(openssl_x509_parse(file_get_contents(self::sealCert('rsa3072')))['serialNumberHex']);
        $this->assertStringContainsString('Serial Number: ' . $serial, implode("\n", $output));
    }

    public function testAddsValidationDataByCrls()
    {
        $timestamped = $this->timestamped(self::seal());
        $lt = Seal::addValidationData($timestamped, $this->trust(['crls' => [$this->opensslCrl('intermediate'), $this->opensslCrl('root'), $this->opensslCrl('tsa-root')]]));
        // Valid with what it embeds alone.
        $result = Seal::verifySeal($lt, $this->trust());
        $this->assertTrue($result->isValid(), (string) $result->getError());
        $this->assertSame('LT', $result->getLevel());
        $signature = array_column(Zip::read($lt), 'content', 'name')[Seal::SIGNATURE_PATH];
        $this->assertSame(3, substr_count($signature, '<xades:EncapsulatedCRLValue>'));
        // The root of the signer, which KeyInfo does not hold; not the root
        // of the authority, which the token of the openssl command holds.
        $this->assertSame(1, substr_count($signature, '<xades:EncapsulatedX509Certificate>'));
        $this->assertSame(1, substr_count($signature, '<xades141:TimeStampValidationData'));

        try
        {
            Seal::addValidationData($lt, $this->trust(['crls' => [$this->opensslCrl('intermediate')]]));
            $this->fail('Extended twice');
        }
        catch (Exception $e)
        {
            $this->assertSame('Validation data: the seal already has validation data.', $e->getMessage());
        }
        try
        {
            Seal::addValidationData(self::seal(), $this->trust(['crls' => [$this->opensslCrl('intermediate'), $this->opensslCrl('root')]]));
            $this->fail('Level B extended');
        }
        catch (Exception $e)
        {
            $this->assertSame('Validation data: the seal must be time-stamped first (level T).', $e->getMessage());
        }
        try
        {
            Seal::addValidationData($timestamped, $this->trust(['crls' => [$this->opensslCrl('intermediate')]]));
            $this->fail('Missing CRLs');
        }
        catch (Exception $e)
        {
            $this->assertStringStartsWith('Validation data: the seal is not valid. No revocation data for the certificate "/C=DK/O=Lothbrok Ltd/OU=Seal Intermediate CA/CN=Lothbrok Seal Test": no CRL of its issuer, nor OCSP response.', $e->getMessage());
        }
    }

    public function testAddsValidationDataByOcsp()
    {
        $timestamped = $this->timestamped(self::seal());
        $request = Seal::validationDataRequests($timestamped, $this->trust())['ocsp'][0]['request'];
        $lt = Seal::addValidationData($timestamped, $this->trust([
            'ocspResponses' => [$this->opensslOcsp($request)],
            'crls' => [$this->opensslCrl('root'), $this->opensslCrl('tsa-root')],
        ]));
        $result = Seal::verifySeal($lt, $this->trust());
        $this->assertTrue($result->isValid(), (string) $result->getError());
        $this->assertSame('LT', $result->getLevel());
        $signature = array_column(Zip::read($lt), 'content', 'name')[Seal::SIGNATURE_PATH];
        $this->assertSame(1, substr_count($signature, '<xades:EncapsulatedOCSPValue>'));
        $this->assertSame(2, substr_count($signature, '<xades:EncapsulatedCRLValue>'));
    }

    public function testARevocationAfterTheTimeStampLeavesTheSealValid()
    {
        $timestamped = $this->timestamped(self::seal());
        $crls = function ($revokedAt) { return [$this->opensslCrl('intermediate', $revokedAt), $this->opensslCrl('root'), $this->opensslCrl('tsa-root')]; };

        $result = Seal::verifySeal($timestamped, $this->trust(['crls' => $crls(time() + 60)]));
        $this->assertTrue($result->isValid(), (string) $result->getError());

        $result = Seal::verifySeal($timestamped, $this->trust(['crls' => $crls(gmmktime(0, 0, 0, 1, 1, 2026))]));
        $this->assertSame('The certificate "/C=DK/O=Lothbrok Ltd/OU=RSA 3072 Seal Dept/CN=Lothbrok Seal Test" is revoked since 2026-01-01T00:00:00.000Z, before the time-stamp.'
            . " (the option 'revocation' => false verifies the seal without revocation.)", $result->getError());

        // Without time-stamp, any revocation counts.
        $result = Seal::verifySeal(self::seal(), $this->trust(['crls' => $crls(time() + 60)]));
        $this->assertStringStartsWith('The certificate "/C=DK/O=Lothbrok Ltd/OU=RSA 3072 Seal Dept/CN=Lothbrok Seal Test" is revoked since ', $result->getError());
    }

    public function testRefusesADelegatedResponderWithoutNoCheck()
    {
        $timestamped = $this->timestamped(self::seal());
        $request = Seal::validationDataRequests($timestamped, $this->trust())['ocsp'][0]['request'];
        try
        {
            Seal::addValidationData($timestamped, $this->trust([
                'ocspResponses' => [$this->opensslOcsp($request, 'ocsp-checked')],
                'crls' => [$this->opensslCrl('root'), $this->opensslCrl('tsa-root')],
            ]));
            $this->fail('Accepted the responses of a responder without id-pkix-ocsp-nocheck');
        }
        catch (Exception $e)
        {
            $this->assertSame('Validation data: the seal is not valid. No revocation data for the certificate "/C=DK/O=Lothbrok Ltd/OU=RSA 3072 Seal Dept/CN=Lothbrok Seal Test": no CRL of its issuer, nor OCSP response.', $e->getMessage());
        }
    }
}
