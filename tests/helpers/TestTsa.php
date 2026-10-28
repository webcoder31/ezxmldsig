<?php

namespace webcoder31\ezxmldsig\Tests\helpers;

/**
 * A time-stamping authority for the tests (RFC 3161), written apart from
 * src/core/Der.php and src/seal/Timestamp.php so that the tokens the
 * library is tested on do not come from the code under test. Every field
 * can be set, so that each test builds one fault. The authority of
 * tests/fixtures/seal/certs/tsa.cert.pem signs by default, with RSA PKCS#1
 * v1.5 and SHA-256, and an ESS signingCertificateV2 attribute. A port of
 * test/helpers/tsa.ts of the Node.js library.
 */
class TestTsa
{
    const SHA256 = '2.16.840.1.101.3.4.2.1';
    const DIGESTS = ['sha256' => self::SHA256, 'sha384' => '2.16.840.1.101.3.4.2.2', 'sha512' => '2.16.840.1.101.3.4.2.3', 'sha1' => '1.3.14.3.2.26'];

    /** The imprint of a TimeStampReq: its algorithm (hash() name) and digest. */
    public static function readRequest($request)
    {
        $fields = TestDer::children(TestDer::children($request)[0]['content']);
        $imprint = TestDer::children($fields[1]['content']);
        $algorithm = TestDer::children($imprint[0]['content'])[0];
        $hash = null;
        foreach (self::DIGESTS as $name => $oid)
        {
            if (substr(TestDer::oid($oid), 2) === $algorithm['content'])
            {
                $hash = $name;
            }
        }
        return ['hash' => $hash, 'imprint' => $imprint[1]['content']];
    }

    /**
     * A TimeStampResp for a request, built by the test authority. Options:
     * - 'imprint', 'hash': the digest time-stamped (default that of the
     *   request);
     * - 'time' (UNIX time, default now);
     * - 'name': the authority, 'tsa' (default), 'tsa-no-eku' or 'tsa-offline';
     * - 'status': above 1, a refusal without token;
     * - 'ess': the ESS attribute, 2 (default), 1, or 'none';
     * - 'certificates': 'signer' (default), 'chain' or 'none';
     * - 'alterTstInfo': changes the TSTInfo after it is signed;
     * - 'alterSignature'.
     */
    public static function response($request, array $options = [])
    {
        if (isset($options['status']) && $options['status'] > 1)
        {
            return TestDer::seq(TestDer::seq(TestDer::int($options['status']), TestDer::seq(TestDer::der(0x0c, 'request refused by the test authority'))));
        }
        $fromRequest = self::readRequest($request);
        $hash = isset($options['hash']) ? $options['hash'] : $fromRequest['hash'];
        $imprint = isset($options['imprint']) ? $options['imprint'] : $fromRequest['imprint'];
        $name = isset($options['name']) ? $options['name'] : 'tsa';
        $cert = SealPki::certificateDer($name);
        $key = openssl_pkey_get_private(file_get_contents(SealPki::key($name)));
        $time = isset($options['time']) ? $options['time'] : microtime(true);

        $tstInfo = TestDer::seq(
            TestDer::int(1),
            TestDer::oid('1.3.6.1.4.1.55555.3.1'),
            TestDer::seq(TestDer::seq(TestDer::oid(self::DIGESTS[$hash]), TestDer::der(0x05)), TestDer::octets($imprint)),
            TestDer::int("\x01\x02\x03\x04\x05"),
            TestDer::generalized($time)
        );
        $ess = isset($options['ess']) ? $options['ess'] : 2;
        $attributes = TestDer::seq(TestDer::oid('1.2.840.113549.1.9.3'), TestDer::set(TestDer::oid('1.2.840.113549.1.9.16.1.4')))
            . TestDer::seq(TestDer::oid('1.2.840.113549.1.9.4'), TestDer::set(TestDer::octets(hash('sha256', $tstInfo, true))));
        if ('none' !== $ess)
        {
            $essId = hash(1 === $ess ? 'sha1' : 'sha256', $cert, true);
            $attributes .= TestDer::seq(TestDer::oid(1 === $ess ? '1.2.840.113549.1.9.16.2.12' : '1.2.840.113549.1.9.16.2.47'), TestDer::set(TestDer::seq(TestDer::seq(TestDer::seq(TestDer::octets($essId))))));
        }
        openssl_sign(TestDer::set($attributes), $signature, $key, OPENSSL_ALGO_SHA256);
        if (!empty($options['alterSignature']))
        {
            $signature[10] = chr(ord($signature[10]) ^ 1);
        }
        if (!empty($options['alterTstInfo']))
        {
            $at = strlen($tstInfo) - 2;
            $tstInfo[$at] = chr(ord($tstInfo[$at]) ^ 1);
        }

        // issuerAndSerialNumber, from the TBSCertificate of the authority.
        $fields = TestDer::tbsFields(file_get_contents(SealPki::cert($name)));
        $signerInfo = TestDer::seq(
            TestDer::int(1),
            TestDer::seq($fields[2], $fields[0]),
            TestDer::seq(TestDer::oid(self::SHA256), TestDer::der(0x05)),
            TestDer::der(0xa0, $attributes),
            SealPki::signatureAlgorithm($key),
            TestDer::octets($signature)
        );
        $certificates = isset($options['certificates']) ? $options['certificates'] : 'signer';
        $certs = 'none' === $certificates ? '' : $cert . ('chain' === $certificates ? SealPki::certificateDer('tsa-root') : '');
        $signedData = TestDer::seq(
            TestDer::int(3),
            TestDer::set(TestDer::seq(TestDer::oid(self::SHA256), TestDer::der(0x05))),
            TestDer::seq(TestDer::oid('1.2.840.113549.1.9.16.1.4'), TestDer::der(0xa0, TestDer::octets($tstInfo))),
            '' === $certs ? '' : TestDer::der(0xa0, $certs),
            TestDer::set($signerInfo)
        );
        $token = TestDer::seq(TestDer::oid('1.2.840.113549.1.7.2'), TestDer::der(0xa0, $signedData));
        return TestDer::seq(TestDer::seq(TestDer::int(isset($options['status']) ? $options['status'] : 0)), $token);
    }
}
