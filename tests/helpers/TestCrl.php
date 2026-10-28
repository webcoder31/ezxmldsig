<?php

namespace webcoder31\ezxmldsig\Tests\helpers;

/**
 * CRLs for the tests (RFC 5280, 5), issued by the CAs of
 * tests/fixtures/seal/certs/ and written apart from src/seal/Crl.php, so
 * that the CRLs the library is tested on do not come from the code under
 * test. Every field can be set, so that each test builds one fault. A port
 * of test/helpers/crl.ts of the Node.js library.
 */
class TestCrl
{
    /** An Extension: OID, criticality, value. */
    public static function extension($id, $critical, $value)
    {
        return TestDer::seq(TestDer::oid($id), $critical ? TestDer::der(0x01, "\xff") : '', TestDer::octets($value));
    }

    /** A reason code (CRLReason) entry extension. */
    public static function reason($code)
    {
        return self::extension('2.5.29.21', false, TestDer::der(0x0a, chr($code)));
    }

    /** An issuing distribution point: 'onlyUser', 'onlyCA', 'someReasons', 'indirect'. */
    public static function issuingDistributionPoint(array $fields)
    {
        $parts = (empty($fields['onlyUser']) ? '' : TestDer::der(0x81, "\xff"))
            . (empty($fields['onlyCA']) ? '' : TestDer::der(0x82, "\xff"))
            . (empty($fields['someReasons']) ? '' : TestDer::der(0x83, "\x07\x80"))
            . (empty($fields['indirect']) ? '' : TestDer::der(0x84, "\xff"));
        return self::extension('2.5.29.28', true, TestDer::seq($parts));
    }

    /**
     * A CRL, in DER. Options:
     * - 'issuer': the CA whose name the CRL bears (default intermediate);
     * - 'signer': the CA whose key signs it (default the issuer);
     * - 'thisUpdate' (UNIX time, default 5 seconds ago), 'nextUpdate' (default
     *   7 days later; NULL: none);
     * - 'revoked': the revoked certificates, each ['cert' => a fixture name or
     *   the path of a PEM file, 'date' => UNIX time, 'extensions' => [...]];
     * - 'extensions': extensions of the CRL (see extension());
     * - 'alterSignature'.
     */
    public static function make(array $options = [])
    {
        $issuer = isset($options['issuer']) ? $options['issuer'] : 'intermediate';
        $signer = isset($options['signer']) ? $options['signer'] : $issuer;
        $key = openssl_pkey_get_private(file_get_contents(SealPki::key($signer)), SealPki::PASSWORD);
        $algorithm = SealPki::signatureAlgorithm($key);
        $thisUpdate = isset($options['thisUpdate']) ? $options['thisUpdate'] : microtime(true) - 5;
        $nextUpdate = array_key_exists('nextUpdate', $options) ? $options['nextUpdate'] : $thisUpdate + 7 * 86400;
        $revoked = '';
        foreach (isset($options['revoked']) ? $options['revoked'] : [] as $entry)
        {
            $revoked .= TestDer::seq(
                SealPki::certificateField($entry['cert'], 0),
                TestDer::time($entry['date']),
                isset($entry['extensions']) ? TestDer::seq(...$entry['extensions']) : ''
            );
        }
        $tbs = TestDer::seq(
            TestDer::int(1),
            $algorithm,
            SealPki::certificateField($issuer, 4),
            TestDer::time($thisUpdate),
            null === $nextUpdate ? '' : TestDer::time($nextUpdate),
            '' === $revoked ? '' : TestDer::seq($revoked),
            TestDer::der(0xa0, TestDer::seq(self::extension('2.5.29.20', false, TestDer::int(1)), ...(isset($options['extensions']) ? $options['extensions'] : [])))
        );
        openssl_sign($tbs, $signature, $key, OPENSSL_ALGO_SHA256);
        if (!empty($options['alterSignature']))
        {
            $signature[5] = chr(ord($signature[5]) ^ 1);
        }
        return TestDer::seq($tbs, $algorithm, TestDer::der(0x03, "\x00" . $signature));
    }

    /** The CRLs of a valid seal of the tests: of the intermediate (the signers), of the root (the intermediate), of the TSA root (the authority). */
    public static function current(array $revoked = [])
    {
        return [self::make(['revoked' => $revoked]), self::make(['issuer' => 'root']), self::make(['issuer' => 'tsa-root'])];
    }
}
