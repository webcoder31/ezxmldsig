<?php

namespace webcoder31\ezxmldsig\Tests\helpers;

/**
 * The test PKI of the seals, tests/fixtures/seal/certs/ (copied from the
 * Node.js library), and the P-521 signer of tests/fixtures/seal/p521/: the
 * paths of the certificates and keys, the fields of a certificate, and a
 * signer whose certificate has expired.
 */
class SealPki
{
    /** The password of the keys of the signers; the keys of the CAs are not encrypted. */
    const PASSWORD = 'signKeyPassword';

    private static function dir($name)
    {
        return dirname(__DIR__) . '/fixtures/seal/' . ('p521' === $name ? 'p521' : 'certs');
    }

    /** A fixture certificate by its name, or any certificate by the path of its PEM file. */
    public static function cert($name)
    {
        return '.pem' === substr($name, -4) ? $name : self::dir($name) . '/' . $name . '.cert.pem';
    }

    public static function key($name)
    {
        return self::dir($name) . '/' . $name . '.key.pem';
    }

    /** The DER of a field of the TBSCertificate of a certificate (serial 0, issuer 2, subject 4). */
    public static function certificateField($name, $index)
    {
        return TestDer::tbsFields(file_get_contents(self::cert($name)))[$index];
    }

    public static function certificateDer($name)
    {
        return TestDer::certificateDer(file_get_contents(self::cert($name)));
    }

    /** The BIT STRING value of the public key of a certificate, without its unused-bits octet. */
    public static function keyBits($name)
    {
        $spki = TestDer::children(TestDer::children(self::certificateField($name, 5))[0]['content']);
        return substr($spki[1]['content'], 1);
    }

    /** sha256WithRSAEncryption, or ecdsa-with-SHA256 (no parameters), as the key. */
    public static function signatureAlgorithm($key)
    {
        return OPENSSL_KEYTYPE_EC === openssl_pkey_get_details($key)['type']
            ? TestDer::seq(TestDer::oid('1.2.840.10045.4.3.2'))
            : TestDer::seq(TestDer::oid('1.2.840.113549.1.1.11'), TestDer::der(0x05));
    }

    /**
     * A signer whose certificate has expired: the certificate of rsa3072
     * issued again by the intermediate, same key, subject and extensions,
     * with a new serial number and the given dates (UNIX times). It lets a
     * test seal while the certificate was valid, then check revocation data
     * issued after it expired. Written with TestDer and openssl_sign(), not
     * by `openssl x509 -not_before -not_after`: OpenSSL 3.0 does not have
     * these options.
     *
     * @return string The certificate, in PEM; its key is that of rsa3072.
     */
    public static function expiredSigner($notBefore, $notAfter)
    {
        $fields = TestDer::tbsFields(file_get_contents(self::cert('rsa3072')));
        $version = TestDer::der(0xa0, TestDer::int(2));
        $fields[0] = TestDer::int("\x01" . random_bytes(7));
        $fields[3] = TestDer::seq(TestDer::time($notBefore), TestDer::time($notAfter));
        $tbs = TestDer::seq($version, ...$fields);
        $key = openssl_pkey_get_private(file_get_contents(self::key('intermediate')));
        // The signature field of the certificate is sha256WithRSAEncryption, as the key of the intermediate.
        openssl_sign($tbs, $signature, $key, OPENSSL_ALGO_SHA256);
        $certificate = TestDer::seq($tbs, $fields[1], TestDer::der(0x03, "\x00" . $signature));
        return "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($certificate), 64, "\n") . "-----END CERTIFICATE-----\n";
    }
}
