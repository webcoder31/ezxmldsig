<?php

namespace webcoder31\ezxmldsig\Tests;

use Exception;
use webcoder31\ezxmldsig\seal\RsaPss;

/**
 * RSASSA-PSS against OpenSSL: the signatures of RsaPss are verified by the
 * openssl command, and the signatures of the openssl command by RsaPss, so
 * that neither side checks itself. The salt is as long as the digest, as
 * XML Signature takes it (RFC 6931, 2.3.10).
 */
class RsaPssTest extends TestCase
{
    const PASSWORD = 'signKeyPassword';

    private static function sealKey($name)
    {
        return __DIR__ . '/fixtures/seal/certs/' . $name . '.key.pem';
    }

    /**
     * A key without password in a temporary file, for the openssl command:
     * a key of the seal tests, or a new key of the given size.
     */
    private function keyFile($nameOrBits)
    {
        $key = is_int($nameOrBits)
            ? openssl_pkey_new(['private_key_bits' => $nameOrBits, 'private_key_type' => OPENSSL_KEYTYPE_RSA])
            : openssl_pkey_get_private(file_get_contents(self::sealKey($nameOrBits)), self::PASSWORD);
        openssl_pkey_export($key, $pem);
        return [$this->tempFile('key-' . $nameOrBits . '.pem', $pem), $key];
    }

    /**
     * Runs the openssl command, and returns its status.
     */
    private static function openssl(array $arguments)
    {
        exec('openssl ' . implode(' ', array_map('escapeshellarg', $arguments)) . ' 2>&1', $output, $status);
        return $status;
    }

    private static function pssOptions($hash)
    {
        return ['-' . $hash, '-sigopt', 'rsa_padding_mode:pss', '-sigopt', 'rsa_pss_saltlen:-1', '-sigopt', 'rsa_mgf1_md:' . $hash];
    }

    public function keysAndDigests()
    {
        // 2049 bits: the encoded message is one byte shorter than the modulus.
        return [
            'rsa3072, SHA-256' => ['rsa3072', 'sha256'],
            'rsa2048, SHA-384' => ['rsa2048', 'sha384'],
            'rsa3072, SHA-512' => ['rsa3072', 'sha512'],
            '2049 bits, SHA-256' => [2049, 'sha256'],
            '2055 bits, SHA-512' => [2055, 'sha512'],
        ];
    }

    /**
     * @dataProvider keysAndDigests
     */
    public function testOpenSslVerifiesItsSignatures($keyName, $hash)
    {
        list($keyPath, $key) = $this->keyFile($keyName);
        $data = 'The data of ' . $keyName . ' ' . random_bytes(16);
        $dataPath = $this->tempFile('data', $data);
        $signaturePath = $this->tempFile('signature', RsaPss::sign($data, $key, $hash));
        openssl_pkey_export($key, $unused);
        $publicPath = $this->tempFile('public.pem', openssl_pkey_get_details($key)['key']);

        $this->assertSame(0, self::openssl(array_merge(['dgst'], self::pssOptions($hash), ['-verify', $publicPath, '-signature', $signaturePath, $dataPath])));
        // The same command refuses a signature of other data.
        file_put_contents($dataPath, $data . '.');
        $this->assertNotSame(0, self::openssl(array_merge(['dgst'], self::pssOptions($hash), ['-verify', $publicPath, '-signature', $signaturePath, $dataPath])));
    }

    /**
     * @dataProvider keysAndDigests
     */
    public function testVerifiesTheSignaturesOfOpenSsl($keyName, $hash)
    {
        list($keyPath, $key) = $this->keyFile($keyName);
        $data = 'The data of ' . $keyName . ' ' . random_bytes(16);
        $dataPath = $this->tempFile('data', $data);
        $signaturePath = $this->tempFile('signature', '');
        $this->assertSame(0, self::openssl(array_merge(['dgst'], self::pssOptions($hash), ['-sign', $keyPath, '-out', $signaturePath, $dataPath])));
        $signature = file_get_contents($signaturePath);
        $public = openssl_pkey_get_public(openssl_pkey_get_details($key)['key']);

        $this->assertTrue(RsaPss::verify($data, $signature, $public, $hash));
        $this->assertFalse(RsaPss::verify($data . '.', $signature, $public, $hash));
        $other = $hash === 'sha256' ? 'sha384' : 'sha256';
        $this->assertFalse(RsaPss::verify($data, $signature, $public, $other));
        // A salt of another length is another signature scheme.
        $this->assertFalse(RsaPss::verify($data, $signature, $public, $hash, 0));
    }

    public function testRefusesAlteredSignatures()
    {
        $key = openssl_pkey_get_private(file_get_contents(self::sealKey('rsa2048')), self::PASSWORD);
        $public = openssl_pkey_get_public(openssl_pkey_get_details($key)['key']);
        $signature = RsaPss::sign('data', $key, 'sha256');
        $this->assertSame(256, strlen($signature));
        $this->assertTrue(RsaPss::verify('data', $signature, $public, 'sha256'));

        for ($i = 0; $i < strlen($signature); $i += 37)
        {
            $altered = $signature;
            $altered[$i] = chr(ord($altered[$i]) ^ 0x01);
            $this->assertFalse(RsaPss::verify('data', $altered, $public, 'sha256'), 'byte ' . $i);
        }
        $this->assertFalse(RsaPss::verify('data', substr($signature, 1), $public, 'sha256'));
        $this->assertFalse(RsaPss::verify('data', "\0" . $signature, $public, 'sha256'));
        $this->assertFalse(RsaPss::verify('data', str_repeat("\xff", 256), $public, 'sha256'));
        $this->assertFalse(RsaPss::verify('data', str_repeat("\0", 256), $public, 'sha256'));
        // A PKCS#1 v1.5 signature of the same data is not a PSS signature.
        openssl_sign('data', $pkcs1, $key, OPENSSL_ALGO_SHA256);
        $this->assertFalse(RsaPss::verify('data', $pkcs1, $public, 'sha256'));
    }

    public function testSignsWithARandomSalt()
    {
        $key = openssl_pkey_get_private(file_get_contents(self::sealKey('rsa2048')), self::PASSWORD);
        $this->assertNotSame(RsaPss::sign('data', $key, 'sha256'), RsaPss::sign('data', $key, 'sha256'));
    }

    public function testRefusesAKeyThatIsNotAnRsaKey()
    {
        $key = openssl_pkey_get_private(file_get_contents(self::sealKey('p256')), self::PASSWORD);
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('RSASSA-PSS: an RSA key is expected.');
        RsaPss::sign('data', $key, 'sha256');
    }

    public function testRefusesAKeyTooShortForTheDigest()
    {
        $key = openssl_pkey_new(['private_key_bits' => 1024, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('RSASSA-PSS: the key is too short for the digest and the salt.');
        RsaPss::sign('data', $key, 'sha512', 64);
    }
}
