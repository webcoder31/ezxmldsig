<?php
/**
 * Pkix.php
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
use webcoder31\ezxmldsig\core\Der;

/**
 * What the signed structures of the PKI share (time-stamp tokens, CRLs, OCSP
 * responses): their algorithm identifiers, the verification of their
 * signature with the algorithms and key sizes of the seals. The functions
 * throw an Exception whose message says what is wrong, for the caller to
 * put in context.
 *
 * @internal
 */
class Pkix
{
    const OID_SHA1 = '1.3.14.3.2.26';
    const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
    const OID_SHA384 = '2.16.840.1.101.3.4.2.2';
    const OID_SHA512 = '2.16.840.1.101.3.4.2.3';
    const OID_RSA_PSS = '1.2.840.113549.1.1.10';
    const OID_MGF1 = '1.2.840.113549.1.1.8';

    /** The digests accepted, as hash() names them, by OID. */
    const DIGEST_OIDS = [
        self::OID_SHA256 => 'sha256',
        self::OID_SHA384 => 'sha384',
        self::OID_SHA512 => 'sha512',
    ];

    /** Signature algorithms but RSASSA-PSS: the type of key, and the digest the OID names (NULL: the one given beside, as in CMS). */
    const SIGNATURES = [
        '1.2.840.113549.1.1.1' => ['rsa', null],
        '1.2.840.113549.1.1.11' => ['rsa', 'sha256'],
        '1.2.840.113549.1.1.12' => ['rsa', 'sha384'],
        '1.2.840.113549.1.1.13' => ['rsa', 'sha512'],
        '1.2.840.10045.4.3.2' => ['ec', 'sha256'],
        '1.2.840.10045.4.3.3' => ['ec', 'sha384'],
        '1.2.840.10045.4.3.4' => ['ec', 'sha512'],
    ];


    /**
     * The elements of a SEQUENCE.
     *
     * @throws Exception If the element is not a SEQUENCE.
     */
    public static function sequenceOf($element, $what)
    {
        if (Der::SEQUENCE !== $element['tag'])
        {
            throw new Exception('malformed ' . $what . '.');
        }

        return Der::readElements($element['content']);
    }


    /**
     * A digest AlgorithmIdentifier: SHA-256, SHA-384 or SHA-512, parameters
     * absent or NULL.
     *
     * @return string The digest, as hash() names it.
     *
     * @throws Exception If the digest is not one of these.
     */
    public static function digestOf($algorithm)
    {
        $fields = self::sequenceOf($algorithm, 'AlgorithmIdentifier');
        $oid = isset($fields[0]) ? Der::decodeOid($fields[0]) : '';
        if (!isset(self::DIGEST_OIDS[$oid]) || count($fields) > 2
            || (isset($fields[1]) && (Der::NULL !== $fields[1]['tag'] || '' !== $fields[1]['content'])))
        {
            throw new Exception('unsupported digest algorithm ' . $oid . '.');
        }

        return self::DIGEST_OIDS[$oid];
    }


    /**
     * Verify a signature with its AlgorithmIdentifier, the algorithms and
     * key sizes of the seals.
     *
     * @param array $algorithm The AlgorithmIdentifier of the signature.
     *
     * @param string|null $digest The digest given beside the algorithm (CMS
     *        digestAlgorithm), or NULL when the algorithm alone must name it
     *        (a CRL, an OCSP response).
     *
     * @param resource|\OpenSSLAsymmetricKey $key The public key of the signer.
     *
     * @param string $data The signed data.
     *
     * @param string $signature The signature (DER for ECDSA).
     *
     * @return boolean TRUE if the signature is valid.
     *
     * @throws Exception If the algorithm or the key is not accepted.
     */
    public static function verifySignature($algorithm, $digest, $key, $data, $signature)
    {
        $fields = self::sequenceOf($algorithm, 'AlgorithmIdentifier');
        $oid = Der::decodeOid($fields[0]);
        $problem = Policy::keyProblem($key, 'the signer');
        if (null !== $problem)
        {
            throw new Exception($problem);
        }
        $keyType = Policy::describeKey($key)['type'];
        if (self::OID_RSA_PSS === $oid)
        {
            list($hash, $saltLength) = self::readPssParameters(isset($fields[1]) ? $fields[1] : null);
            if ('rsa' !== $keyType || (null !== $digest && $hash !== $digest))
            {
                throw new Exception('unsupported RSASSA-PSS parameters.');
            }
            return RsaPss::verify($data, $signature, $key, $hash, $saltLength);
        }
        if (!isset(self::SIGNATURES[$oid]))
        {
            throw new Exception('unsupported signature algorithm ' . $oid . '.');
        }
        list($schemeKeyType, $schemeHash) = self::SIGNATURES[$oid];
        $hash = null !== $schemeHash ? $schemeHash : $digest;
        if (null === $hash || $schemeKeyType !== $keyType || (null !== $digest && $hash !== $digest))
        {
            throw new Exception('the signature algorithm does not suit the key or the digest.');
        }

        return 1 === @openssl_verify($data, $signature, $key, $hash);
    }


    /**
     * RSASSA-PSS-params (RFC 4055): the digest, MGF1 with the same digest,
     * the salt length, trailer 1.
     *
     * @return array The digest, and the salt length.
     */
    private static function readPssParameters($parameters)
    {
        if (null === $parameters)
        {
            throw new Exception('RSASSA-PSS without parameters.');
        }
        $hash = 'sha1';
        $mgfHash = 'sha1';
        $saltLength = 20;
        foreach (Der::childrenOf($parameters, Der::SEQUENCE) as $field)
        {
            $inner = Der::readElement($field['content']);
            if (0xa0 === $field['tag'])
            {
                $hash = self::digestOf($inner);
            }
            elseif (0xa1 === $field['tag'])
            {
                $mgf = self::sequenceOf($inner, 'MaskGenAlgorithm');
                if (!isset($mgf[0], $mgf[1]) || self::OID_MGF1 !== Der::decodeOid($mgf[0]))
                {
                    throw new Exception('unsupported mask generation function.');
                }
                $mgfHash = self::digestOf($mgf[1]);
            }
            elseif (0xa2 === $field['tag'])
            {
                $saltLength = Der::decodeSmallInteger($inner);
            }
            elseif (0xa3 !== $field['tag'] || 1 !== Der::decodeSmallInteger($inner))
            {
                throw new Exception('unsupported RSASSA-PSS parameters.');
            }
        }
        if ($mgfHash !== $hash || 'sha1' === $hash)
        {
            throw new Exception('unsupported RSASSA-PSS parameters.');
        }

        return [$hash, $saltLength];
    }
}
