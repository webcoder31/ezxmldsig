<?php

namespace webcoder31\ezxmldsig\Tests\helpers;

/**
 * OCSP responses for the tests (RFC 6960, 4.2), signed by the CAs and the
 * responders of tests/fixtures/seal/certs/, written apart from
 * src/seal/Ocsp.php, so that the responses the library is tested on do not
 * come from the code under test. Every field can be set, so that each test
 * builds one fault. A port of test/helpers/ocsp.ts of the Node.js library.
 */
class TestOcsp
{
    /**
     * An OCSPResponse, in DER. Options:
     * - 'cert': the certificate whose status is given (a fixture name, or
     *   the path of a PEM file);
     * - 'issuer': its issuer (default intermediate);
     * - 'signer': whose key signs the response (default the issuer);
     * - 'responder': whom the ResponderID names (default the signer), and
     *   'responderBy': 'name' (default) or 'key';
     * - 'status': 'good' (default), 'revoked' or 'unknown'; 'revocationTime'
     *   (default a minute ago) and 'reason' (none by default);
     * - 'thisUpdate' (default 5 seconds ago), 'nextUpdate' (default a day
     *   later; NULL: none), 'producedAt' (default thisUpdate);
     * - 'archiveCutoff' (RFC 6960, 4.4.4), a single extension;
     * - 'certIdHash': 'sha1' (default) or 'sha256';
     * - 'certificates': the certificates of the response (default the
     *   signer, if it is not the issuer);
     * - 'responseStatus': other than successful (0), without response bytes;
     * - 'alterSignature'.
     */
    public static function make(array $options)
    {
        if (isset($options['responseStatus']))
        {
            return TestDer::seq(TestDer::der(0x0a, chr($options['responseStatus'])));
        }
        $option = function ($name, $default) use ($options) { return array_key_exists($name, $options) ? $options[$name] : $default; };
        $issuer = $option('issuer', 'intermediate');
        $signer = $option('signer', $issuer);
        $responder = $option('responder', $signer);
        $hash = $option('certIdHash', 'sha1');
        $hashOid = 'sha1' === $hash ? '1.3.14.3.2.26' : '2.16.840.1.101.3.4.2.1';
        $certId = TestDer::seq(
            TestDer::seq(TestDer::oid($hashOid), TestDer::der(0x05)),
            TestDer::octets(hash($hash, SealPki::certificateField($options['cert'], 2), true)),
            TestDer::octets(hash($hash, SealPki::keyBits($issuer), true)),
            SealPki::certificateField($options['cert'], 0)
        );
        $status = $option('status', 'good');
        if ('good' === $status)
        {
            $certStatus = TestDer::der(0x80);
        }
        elseif ('unknown' === $status)
        {
            $certStatus = TestDer::der(0x82);
        }
        else
        {
            $certStatus = TestDer::der(0xa1, TestDer::generalized($option('revocationTime', microtime(true) - 60)),
                isset($options['reason']) ? TestDer::der(0xa0, TestDer::der(0x0a, chr($options['reason']))) : '');
        }
        $thisUpdate = $option('thisUpdate', microtime(true) - 5);
        $nextUpdate = $option('nextUpdate', $thisUpdate + 86400);
        $single = TestDer::seq($certId, $certStatus, TestDer::generalized($thisUpdate),
            null === $nextUpdate ? '' : TestDer::der(0xa0, TestDer::generalized($nextUpdate)),
            isset($options['archiveCutoff']) ? TestDer::der(0xa1, TestDer::seq(TestDer::seq(TestDer::oid('1.3.6.1.5.5.7.48.1.6'), TestDer::octets(TestDer::generalized($options['archiveCutoff']))))) : '');
        $responderId = 'name' === $option('responderBy', 'name')
            ? TestDer::der(0xa1, SealPki::certificateField($responder, 4))
            : TestDer::der(0xa2, TestDer::octets(sha1(SealPki::keyBits($responder), true)));
        $tbs = TestDer::seq($responderId, TestDer::generalized($option('producedAt', $thisUpdate)), TestDer::seq($single));

        $key = openssl_pkey_get_private(file_get_contents(SealPki::key($signer)), SealPki::PASSWORD);
        $algorithm = SealPki::signatureAlgorithm($key);
        openssl_sign($tbs, $signature, $key, OPENSSL_ALGO_SHA256);
        if (!empty($options['alterSignature']))
        {
            $signature[5] = chr(ord($signature[5]) ^ 1);
        }
        $certs = $option('certificates', $signer === $issuer ? [] : [$signer]);
        $basic = TestDer::seq($tbs, $algorithm, TestDer::der(0x03, "\x00" . $signature),
            [] === $certs ? '' : TestDer::der(0xa0, TestDer::seq(...array_map([SealPki::class, 'certificateDer'], $certs))));
        return TestDer::seq(TestDer::der(0x0a, "\x00"), TestDer::der(0xa0, TestDer::seq(TestDer::oid('1.3.6.1.5.5.7.48.1.1'), TestDer::octets($basic))));
    }
}
