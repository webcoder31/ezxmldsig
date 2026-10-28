<?php
/**
 * RsaPss.php
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

/**
 * RSASSA-PSS (RFC 8017, 8.1), the signature scheme of the seals for an RSA
 * key, with MGF1 over the digest of the message (9.1, B.2.1).
 *
 * `openssl_sign()` and `openssl_verify()` take no padding parameter: they
 * sign and verify with PKCS#1 v1.5 only. The encoding EMSA-PSS is therefore
 * written here, and the RSA operation itself is left to OpenSSL, without
 * padding (`OPENSSL_NO_PADDING`): `openssl_private_encrypt()` computes the
 * signature of the encoded message, `openssl_public_decrypt()` gives back the
 * encoded message of a signature. The encoded message is one bit shorter than
 * the modulus, its leftmost bits cleared: as a number, it is smaller than the
 * modulus, which OpenSSL requires.
 *
 * @internal
 */
class RsaPss
{
    /** The trailer field of the encoded message (9.1.1, step 12). */
    const TRAILER = "\xbc";


    /**
     * Sign data.
     *
     * @param string $data The data, which is digested here.
     *
     * @param resource|\OpenSSLAsymmetricKey $privateKey An RSA private key
     *        (openssl_pkey_get_private()).
     *
     * @param string $hash The digest, as hash() names it: "sha256", "sha384"
     *        or "sha512". MGF1 uses it too.
     *
     * @param int|null $saltLength The length of the salt, in bytes; NULL for
     *        the length of the digest, as XML Signature takes it.
     *
     * @return string The signature, as long as the modulus.
     *
     * @throws Exception If the key is not an RSA key or is too short for
     *         the digest and the salt.
     */
    public static function sign($data, $privateKey, $hash, $saltLength = null)
    {
        $bits = self::modulusBits($privateKey);
        $hashLength = strlen(hash($hash, '', true));
        $saltLength = null === $saltLength ? $hashLength : $saltLength;
        $emBits = $bits - 1;
        $emLength = intdiv($emBits + 7, 8);
        if ($emLength < $hashLength + $saltLength + 2)
        {
            throw new Exception('RSASSA-PSS: the key is too short for the digest and the salt.');
        }

        // EMSA-PSS-ENCODE (9.1.1).
        $mHash = hash($hash, $data, true);
        $salt = $saltLength > 0 ? random_bytes($saltLength) : '';
        $h = hash($hash, str_repeat("\0", 8) . $mHash . $salt, true);
        $db = str_repeat("\0", $emLength - $saltLength - $hashLength - 2) . "\x01" . $salt;
        $maskedDb = $db ^ self::mgf1($h, $emLength - $hashLength - 1, $hash);
        $maskedDb[0] = chr(ord($maskedDb[0]) & (0xff >> (8 * $emLength - $emBits)));
        $em = $maskedDb . $h . self::TRAILER;

        // RSASP1 over the encoded message, as long as the modulus.
        $k = intdiv($bits + 7, 8);
        $signature = '';
        if (!openssl_private_encrypt(str_repeat("\0", $k - $emLength) . $em, $signature, $privateKey, OPENSSL_NO_PADDING))
        {
            throw new Exception('RSASSA-PSS: the RSA operation failed.');
        }

        return $signature;
    }


    /**
     * Verify a signature.
     *
     * @param string $data The data, which is digested here.
     *
     * @param string $signature The signature.
     *
     * @param resource|\OpenSSLAsymmetricKey $publicKey An RSA public key
     *        (openssl_pkey_get_public()).
     *
     * @param string $hash The digest, as hash() names it. MGF1 uses it too.
     *
     * @param int|null $saltLength The length of the salt, in bytes; NULL for
     *        the length of the digest.
     *
     * @return boolean TRUE if the signature is valid, FALSE otherwise.
     *
     * @throws Exception If the key is not an RSA key.
     */
    public static function verify($data, $signature, $publicKey, $hash, $saltLength = null)
    {
        $bits = self::modulusBits($publicKey);
        $hashLength = strlen(hash($hash, '', true));
        $saltLength = null === $saltLength ? $hashLength : $saltLength;
        $emBits = $bits - 1;
        $emLength = intdiv($emBits + 7, 8);
        $k = intdiv($bits + 7, 8);

        // RSAVP1 (8.1.2, step 2): a signature of the length of the modulus.
        if (!is_string($signature) || strlen($signature) !== $k)
        {
            return false;
        }
        $decrypted = '';
        if (!@openssl_public_decrypt($signature, $decrypted, $publicKey, OPENSSL_NO_PADDING)
            || strlen($decrypted) !== $k
            || str_repeat("\0", $k - $emLength) !== substr($decrypted, 0, $k - $emLength))
        {
            return false;
        }
        $em = substr($decrypted, $k - $emLength);

        // EMSA-PSS-VERIFY (9.1.2).
        if ($emLength < $hashLength + $saltLength + 2 || self::TRAILER !== substr($em, -1))
        {
            return false;
        }
        $maskedDb = substr($em, 0, $emLength - $hashLength - 1);
        $h = substr($em, $emLength - $hashLength - 1, $hashLength);
        $topMask = 0xff & ~(0xff >> (8 * $emLength - $emBits));
        if (0 !== (ord($maskedDb[0]) & $topMask))
        {
            return false;
        }
        $db = $maskedDb ^ self::mgf1($h, $emLength - $hashLength - 1, $hash);
        $db[0] = chr(ord($db[0]) & (0xff >> (8 * $emLength - $emBits)));
        $padding = $emLength - $hashLength - $saltLength - 2;
        if (str_repeat("\0", $padding) . "\x01" !== substr($db, 0, $padding + 1))
        {
            return false;
        }
        $salt = (string) substr($db, $padding + 1);

        return hash_equals(hash($hash, str_repeat("\0", 8) . hash($hash, $data, true) . $salt, true), $h);
    }


    /**
     * MGF1 (B.2.1): the mask of the given length, from a seed.
     */
    private static function mgf1($seed, $length, $hash)
    {
        $mask = '';
        for ($counter = 0; strlen($mask) < $length; $counter++)
        {
            $mask .= hash($hash, $seed . pack('N', $counter), true);
        }

        return substr($mask, 0, $length);
    }


    /**
     * The length of the modulus of an RSA key, in bits.
     *
     * @throws Exception If the key is not an RSA key.
     */
    private static function modulusBits($key)
    {
        $details = @openssl_pkey_get_details($key);
        if (false === $details || OPENSSL_KEYTYPE_RSA !== $details['type'])
        {
            throw new Exception('RSASSA-PSS: an RSA key is expected.');
        }

        return $details['bits'];
    }
}
