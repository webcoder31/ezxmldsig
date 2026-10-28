<?php

namespace webcoder31\ezxmldsig\Tests;

use webcoder31\ezxmldsig\core\X509Cert;

/**
 * The chain X509Cert::getTrustedChain() builds and verifies, against
 * OpenSSL: at the current date, getTrustedChain() must trust exactly the
 * certificates isTrustedBy() (openssl_x509_checkpurpose()) trusts; at
 * another date, those the openssl command trusts (`openssl verify -attime`).
 * The cases are the certificates of tests/fixtures/trust/ (see its README).
 */
class X509ChainTest extends TestCase
{
    private static function trust($name)
    {
        return __DIR__ . '/fixtures/trust/' . $name . '.cert.pem';
    }

    private static function seal($name)
    {
        return __DIR__ . '/fixtures/seal/certs/' . $name . '.cert.pem';
    }

    private static function load($path)
    {
        return new X509Cert(file_get_contents($path));
    }

    /**
     * Every certificate of the trust cases, of the tests and of the seal
     * tests.
     */
    public function certificates()
    {
        $cases = [];
        foreach (array_merge(glob(__DIR__ . '/fixtures/trust/*.cert.pem'), glob(__DIR__ . '/fixtures/certs/*.cert.pem'), glob(__DIR__ . '/fixtures/seal/certs/*.cert.pem')) as $path)
        {
            $cases[basename(dirname($path)) . '/' . basename($path, '.cert.pem')] = [$path];
        }
        return $cases;
    }

    /**
     * @dataProvider certificates
     */
    public function testTrustsWhatOpenSslTrustsNow($path)
    {
        $cert = self::load($path);
        foreach ([
            [self::cert('intermediate.cert.pem'), self::cert('root.cert.pem')],
            [self::cert('root.cert.pem')],
            [self::cert('intermediate.cert.pem')],
            [self::seal('intermediate'), self::seal('root')],
            [self::seal('tsa-root')],
            [self::trust('twin-b'), self::cert('root.cert.pem')],
            [self::trust('twin-ec'), self::trust('twin-rsa'), self::cert('root.cert.pem')],
            [self::trust('twin-old'), self::trust('twin-new'), self::cert('root.cert.pem')],
            [self::trust('sub-intermediate'), self::cert('intermediate.cert.pem'), self::cert('root.cert.pem')],
            [self::trust('noext-root')],
            [$path],
        ] as $anchors)
        {
            $expected = $cert->isTrustedBy($anchors);
            $chain = $cert->getTrustedChain($anchors);
            $this->assertSame($expected, null !== $chain, basename($path) . ' with ' . implode(', ', array_map('basename', $anchors)));
            if (null !== $chain)
            {
                $this->assertSame($cert->getDer(), $chain[0]->getDer());
            }
        }
    }

    /**
     * Runs `openssl verify` at a time, with trusted and untrusted
     * certificates, and tells whether it trusts the certificate.
     */
    private function opensslTrusts($path, array $anchors, array $untrusted, $time)
    {
        $arguments = ['openssl', 'verify', '-attime', (string) $time, '-no-CApath', '-CAfile', $this->tempFile('anchors.pem', implode('', array_map('file_get_contents', $anchors)))];
        if (!empty($untrusted))
        {
            $arguments = array_merge($arguments, ['-untrusted', $this->tempFile('untrusted.pem', implode('', array_map('file_get_contents', $untrusted)))]);
        }
        $arguments[] = $path;
        exec(implode(' ', array_map('escapeshellarg', $arguments)) . ' 2>&1', $output, $status);
        return 0 === $status;
    }

    public function testTrustsWhatOpenSslTrustsAtAnotherTime()
    {
        $times = [
            gmmktime(0, 0, 0, 6, 1, 2020),
            gmmktime(0, 0, 0, 1, 1, 2030),
            gmmktime(0, 0, 0, 1, 1, 2037),
            gmmktime(0, 0, 0, 6, 1, 2099),
        ];
        $cases = [
            ['trust/expired', [self::cert('intermediate.cert.pem'), self::cert('root.cert.pem')], []],
            ['trust/not-yet-valid', [self::cert('intermediate.cert.pem'), self::cert('root.cert.pem')], []],
            ['trust/expired-intermediate-signer', [self::trust('expired-intermediate'), self::cert('root.cert.pem')], []],
            ['trust/twin-new-signer', [self::trust('twin-old'), self::trust('twin-new'), self::cert('root.cert.pem')], []],
            ['trust/issued', [self::cert('root.cert.pem')], [self::load(self::cert('intermediate.cert.pem'))]],
            ['seal/rsa3072', [self::seal('root')], [self::load(self::seal('intermediate'))]],
            ['seal/rsa3072', [self::seal('root')], []],
            ['seal/tsa', [self::seal('tsa-root')], []],
            ['seal/offline', [self::seal('root')], [self::load(self::seal('intermediate-offline'))]],
        ];
        $checked = 0;
        foreach ($cases as list($name, $anchors, $untrusted))
        {
            list($directory, $base) = explode('/', $name);
            $path = 'trust' === $directory ? self::trust($base) : self::seal($base);
            $cert = self::load($path);
            foreach ($times as $time)
            {
                $expected = $this->opensslTrusts($path, $anchors, array_map(function ($c) { return $this->tempFile('u' . md5($c->getPem()) . '.pem', $c->getPem()); }, $untrusted), $time);
                $this->assertSame($expected, null !== $cert->getTrustedChain($anchors, $untrusted, $time), $name . ' at ' . gmdate('Y-m-d', $time));
                $checked += $expected ? 1 : 0;
            }
        }
        // Some cases are trusted, others not: the comparison tells both apart.
        $this->assertGreaterThan(3, $checked);
        $this->assertLessThan(count($cases) * count($times) - 3, $checked);
    }

    public function testGivesTheChainUpToTheRoot()
    {
        $cert = self::load(self::seal('rsa3072'));
        $chain = $cert->getTrustedChain([self::seal('root')], [self::load(self::seal('intermediate'))]);
        $this->assertSame(['RSA 3072 Seal Dept', 'Seal Intermediate CA', 'Seal Root CA'], array_map(function ($c) { return $c->getSubject()['OU']; }, $chain));
        // PEM contents are anchors too.
        $this->assertCount(3, $cert->getTrustedChain([file_get_contents(self::seal('intermediate')) . file_get_contents(self::seal('root'))]));
    }

    public function testReadsTheFieldsOfTheDer()
    {
        $cert = self::load(self::seal('rsa3072'));
        $parsed = openssl_x509_parse($cert->getPem());
        $this->assertSame(strtolower($parsed['serialNumberHex']), ltrim(bin2hex($cert->getSerialNumber()), '0') === '' ? '0' : strtolower(bin2hex($cert->getSerialNumber())));
        $this->assertFalse($cert->isCA());
        $this->assertTrue(self::load(self::seal('intermediate'))->isCA());
        $this->assertFalse($cert->canSignCrls());
        $this->assertTrue(self::load(self::seal('intermediate'))->canSignCrls());
        $this->assertTrue($cert->getExtension('2.5.29.15')['critical']);
        $this->assertNull($cert->getExtension('1.2.3.4'));
        // The raw issuer of the certificate is the raw subject of its issuer.
        $this->assertSame(self::load(self::seal('intermediate'))->getRawSubject(), $cert->getRawIssuer());
        $this->assertSame(file_get_contents(self::seal('rsa3072')), X509Cert::derToPem($cert->getDer()));
    }
}
