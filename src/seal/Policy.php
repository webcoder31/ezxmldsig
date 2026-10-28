<?php
/**
 * Policy.php
 *
 * Copyright © 2017-2026 - Thierry Thiers <webcoder31@gmail.com>
 * 
 * This  software  is governed  by  the CeCILL-C  license under French  law  and
 * abiding  by the rules of distribution of free  software. You can  use, modify
 * and/or redistribute the software under the terms  of the  CeCILL-C license as
 * circulated by CEA, CNRS and INRIA at the following URL:
 * 
 * http://www.cecill.info
 * 
 * As a counterpart to the access to the source code  and rights to copy, modify
 * and redistribute  granted by  the  license, users are  provided  only with  a
 * limited  warranty and  the software's author,  the  holder  of  the  economic
 * rights, and the successive licensors have only limited liability.
 * 
 * In this respect, the user's  attention is drawn to the risks  associated with
 * loading, using, modifying and/or  developing or reproducing  the software  by
 * the user in light of its specific status of free software, that may mean that
 * it is complicated to manipulate,  and that also  therefore means  that it  is
 * reserved  for  developers   and  experienced  professionals  having  in-depth
 * computer  knowledge. Users  are  therefore  encouraged to load  and  test the
 * software's suitability as  regards  their requirements in conditions enabling
 * the security of their systems and/or data to be  ensured and, more generally,
 * to use and operate it in the same conditions as regards security.
 * 
 * The  fact  that you are  presently  reading  this  means  that you  have  had
 * knowledge of the CeCILL-C license and that you accept its terms.
 *
 * @author    Thierry Thiers <webcoder31@gmail.com>
 * @copyright 2017-2026 - Thierry Thiers <webcoder31@gmail.com>
 * @license   http://www.cecill.info  CeCILL-C License
 * @version   2.0.0
 */


// Namespace.
namespace webcoder31\ezxmldsig\seal;

// Use.
use Exception;
use webcoder31\ezxmldsig\core\Algorithms;
use webcoder31\ezxmldsig\core\Der;

/**
 * The algorithms of the seals: their digests and signature schemes, the
 * curves of the EC keys, the smallest RSA key. The identifiers are those of
 * the core; the digests are those of the tokens, SHA-1 and RIPEMD-160
 * excepted (ETSI TS 119 312).
 *
 * @internal
 */
class Policy
{
    /** The digests of the seals, as hash() names them, by their URI. */
    const DIGESTS = [
        Algorithms::SHA256 => 'sha256',
        Algorithms::SHA384 => 'sha384',
        Algorithms::SHA512 => 'sha512',
    ];

    /** The signature schemes of the seals, by their URI: the type of key, the digest, the padding. */
    const SIGNATURE_SCHEMES = [
        Algorithms::RSA_PSS_SHA256 => ['keyType' => 'rsa', 'hash' => 'sha256', 'padding' => 'pss'],
        Algorithms::RSA_PSS_SHA384 => ['keyType' => 'rsa', 'hash' => 'sha384', 'padding' => 'pss'],
        Algorithms::RSA_PSS_SHA512 => ['keyType' => 'rsa', 'hash' => 'sha512', 'padding' => 'pss'],
        Algorithms::RSA_SHA256 => ['keyType' => 'rsa', 'hash' => 'sha256', 'padding' => 'pkcs1'],
        Algorithms::RSA_SHA384 => ['keyType' => 'rsa', 'hash' => 'sha384', 'padding' => 'pkcs1'],
        Algorithms::RSA_SHA512 => ['keyType' => 'rsa', 'hash' => 'sha512', 'padding' => 'pkcs1'],
        Algorithms::ECDSA_SHA256 => ['keyType' => 'ec', 'hash' => 'sha256', 'padding' => 'ecdsa'],
        Algorithms::ECDSA_SHA384 => ['keyType' => 'ec', 'hash' => 'sha384', 'padding' => 'ecdsa'],
        Algorithms::ECDSA_SHA512 => ['keyType' => 'ec', 'hash' => 'sha512', 'padding' => 'ecdsa'],
    ];

    /** The curves of the EC keys accepted (TS 119 312, Table 2), and the signature algorithm each one takes by default. */
    const CURVES = [
        'prime256v1' => Algorithms::ECDSA_SHA256,
        'secp384r1' => Algorithms::ECDSA_SHA384,
        'secp521r1' => Algorithms::ECDSA_SHA512,
    ];

    /** The smallest RSA key accepted, in bits. TS 119 312 (Table 6) lists no size below 1 900 bits, and keys below 3 000 bits as legacy. */
    const MIN_RSA_BITS = 2048;


    /**
     * The type of a key and what the seals check of it.
     *
     * @param resource|\OpenSSLAsymmetricKey $key A key.
     *
     * @return array 'type' ("rsa", "ec" or NULL), 'bits', 'curve' (NULL
     *         unless EC).
     */
    public static function describeKey($key)
    {
        $details = @openssl_pkey_get_details($key);
        if (false === $details)
        {
            return ['type' => null, 'bits' => 0, 'curve' => null];
        }
        $type = OPENSSL_KEYTYPE_RSA === $details['type'] ? 'rsa' : (OPENSSL_KEYTYPE_EC === $details['type'] ? 'ec' : null);

        return [
            'type' => $type,
            'bits' => (int) $details['bits'],
            'curve' => 'ec' === $type && isset($details['ec']['curve_name']) ? $details['ec']['curve_name'] : null,
        ];
    }


    /**
     * Why a key is refused for the seals, or NULL: an RSA key of less than
     * MIN_RSA_BITS bits, an EC key on another curve than P-256, P-384 or
     * P-521.
     */
    public static function keyProblem($key, $what)
    {
        $description = self::describeKey($key);
        if ('rsa' === $description['type'] && $description['bits'] < self::MIN_RSA_BITS)
        {
            return 'the RSA key of ' . $what . ' has less than ' . self::MIN_RSA_BITS . ' bits.';
        }
        if ('ec' === $description['type'] && !isset(self::CURVES[$description['curve']]))
        {
            return 'the EC key of ' . $what . ' is not on P-256, P-384 or P-521.';
        }

        return null;
    }


    /**
     * Verify a signature value of XML Signature with a scheme of the seals:
     * RSASSA-PSS (see RsaPss), RSA PKCS#1 v1.5, or ECDSA whose value is
     * written as r || s (RFC 4050), converted to the DER OpenSSL verifies.
     *
     * @param array $scheme An entry of SIGNATURE_SCHEMES.
     *
     * @param string $data The signed data.
     *
     * @param string $signature The signature value.
     *
     * @param resource|\OpenSSLAsymmetricKey $publicKey The public key.
     *
     * @return boolean TRUE if the signature is valid.
     */
    public static function verifyValue(array $scheme, $data, $signature, $publicKey)
    {
        try
        {
            if ('pss' === $scheme['padding'])
            {
                return RsaPss::verify($data, $signature, $publicKey, $scheme['hash']);
            }
            if ('ecdsa' === $scheme['padding'])
            {
                $signature = self::rawToDer($signature, self::describeKey($publicKey)['curve']);
                if (null === $signature)
                {
                    return false;
                }
            }

            return 1 === @openssl_verify($data, $signature, $publicKey, $scheme['hash']);
        }
        catch (Exception $e)
        {
            return false;
        }
    }


    /**
     * An ECDSA signature in DER, as OpenSSL gives it, written as r || s,
     * each as long as the order of the curve.
     *
     * @throws Exception If the signature is malformed.
     */
    public static function derToRaw($signature, $curve)
    {
        $lengths = ['prime256v1' => 32, 'secp384r1' => 48, 'secp521r1' => 66];
        $parts = Der::childrenOf(Der::readElement($signature), Der::SEQUENCE);
        if (!isset($lengths[$curve]) || 2 !== count($parts))
        {
            throw new Exception('ECDSA: malformed signature.');
        }
        $raw = '';
        foreach ($parts as $part)
        {
            $value = ltrim(Der::decodeUnsigned($part), "\0");
            if (strlen($value) > $lengths[$curve])
            {
                throw new Exception('ECDSA: malformed signature.');
            }
            $raw .= str_pad($value, $lengths[$curve], "\0", STR_PAD_LEFT);
        }

        return $raw;
    }


    /**
     * The DER of an ECDSA signature written as r || s, each as long as the
     * order of the curve; NULL if its length does not suit the curve.
     */
    public static function rawToDer($signature, $curve)
    {
        $lengths = ['prime256v1' => 32, 'secp384r1' => 48, 'secp521r1' => 66];
        if (!isset($lengths[$curve]) || !is_string($signature) || strlen($signature) !== 2 * $lengths[$curve])
        {
            return null;
        }
        $half = $lengths[$curve];

        return Der::encode(Der::SEQUENCE, Der::encodeInteger(substr($signature, 0, $half)), Der::encodeInteger(substr($signature, $half)));
    }
}
