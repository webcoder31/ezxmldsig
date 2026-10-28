<?php
/**
 * Crl.php
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
 * @version   2.1.0
 */


// Namespace.
namespace webcoder31\ezxmldsig\seal;

// Use.
use Exception;
use webcoder31\ezxmldsig\core\Der;
use webcoder31\ezxmldsig\core\X509Cert;

/**
 * Certificate revocation lists (RFC 5280, 5): their reading, the
 * verification of their signature by the CA that issued the certificate,
 * and the status of a certificate.
 *
 * Only complete, direct CRLs are used: a delta CRL, an indirect CRL, a CRL
 * restricted to some reasons, or a critical extension this class does not
 * know, make the CRL unusable rather than partly read.
 *
 * A CRL read is an array: 'der', 'issuer' (the DER of its issuer name),
 * 'thisUpdate', 'nextUpdate' (UNIX times, NULL if none), 'revoked' (by the
 * serial number in hexadecimal: 'date' and 'reason'), 'onlyUserCerts',
 * 'onlyCACerts', 'expiredCertsOnCrl', 'tbs', 'signatureAlgorithm',
 * 'signature'.
 *
 * @internal
 */
class Crl
{
    const AUTHORITY_KEY_ID = '2.5.29.35';
    const CRL_NUMBER = '2.5.29.20';
    const DELTA_CRL_INDICATOR = '2.5.29.27';
    const ISSUING_DISTRIBUTION_POINT = '2.5.29.28';
    const FRESHEST_CRL = '2.5.29.46';
    const AUTHORITY_INFO_ACCESS = '1.3.6.1.5.5.7.1.1';
    const EXPIRED_CERTS_ON_CRL = '2.5.29.60';
    const REASON_CODE = '2.5.29.21';
    const INVALIDITY_DATE = '2.5.29.24';
    const CERTIFICATE_ISSUER = '2.5.29.29';
    const HOLD_INSTRUCTION_CODE = '2.5.29.23';

    /** The extensions of a CRL it may have, critical or not; any other critical one makes it unusable. */
    const KNOWN_CRL_EXTENSIONS = [
        self::AUTHORITY_KEY_ID, self::CRL_NUMBER, self::ISSUING_DISTRIBUTION_POINT,
        self::FRESHEST_CRL, self::AUTHORITY_INFO_ACCESS, self::EXPIRED_CERTS_ON_CRL,
    ];
    const KNOWN_ENTRY_EXTENSIONS = [self::REASON_CODE, self::INVALIDITY_DATE, self::HOLD_INSTRUCTION_CODE];


    /**
     * Read a CRL, in DER or in PEM.
     *
     * @param string $data The CRL.
     *
     * @return array The CRL, read but not verified.
     *
     * @throws Exception If it is malformed, or if it is not a complete,
     *         direct CRL.
     */
    public static function read($data)
    {
        $der = (string) $data;
        if (preg_match('/-----BEGIN X509 CRL-----(.*?)-----END X509 CRL-----/s', $der, $pem))
        {
            $der = (string) base64_decode(preg_replace('/\s/', '', $pem[1]));
        }
        try
        {
            return self::parse($der);
        }
        catch (Exception $e)
        {
            throw new Exception('CRL: ' . $e->getMessage());
        }
    }


    private static function parse($der)
    {
        // CertificateList: tbsCertList, signatureAlgorithm, signatureValue.
        $list = Pkix::sequenceOf(Der::readElement($der), 'CertificateList');
        if (3 !== count($list) || Der::BIT_STRING !== $list[2]['tag'] || '' === $list[2]['content'] || "\0" !== $list[2]['content'][0])
        {
            throw new Exception('malformed CertificateList.');
        }
        list($tbsElement, $signatureAlgorithm, $signatureValue) = $list;
        // TBSCertList: version (v2) OPTIONAL, signature, issuer, thisUpdate,
        // nextUpdate OPTIONAL, revokedCertificates OPTIONAL, [0] crlExtensions OPTIONAL.
        $fields = Pkix::sequenceOf($tbsElement, 'TBSCertList');
        if (isset($fields[0]) && Der::INTEGER === $fields[0]['tag'])
        {
            if (1 !== Der::decodeSmallInteger(array_shift($fields)))
            {
                throw new Exception('unsupported version.');
            }
        }
        if (count($fields) < 3 || Der::SEQUENCE !== $fields[1]['tag'] || Der::reencode($fields[0]) !== Der::reencode($signatureAlgorithm))
        {
            throw new Exception('malformed TBSCertList.');
        }
        list(, $issuer, $thisUpdate) = $fields;
        $optional = array_slice($fields, 3);
        $nextUpdate = null;
        if (isset($optional[0]) && (Der::UTC_TIME === $optional[0]['tag'] || Der::GENERALIZED_TIME === $optional[0]['tag']))
        {
            $nextUpdate = Der::decodeTime(array_shift($optional));
        }
        $revoked = [];
        if (isset($optional[0]) && Der::SEQUENCE === $optional[0]['tag'])
        {
            foreach (Der::childrenOf(array_shift($optional), Der::SEQUENCE) as $entry)
            {
                $parts = Pkix::sequenceOf($entry, 'revoked certificate');
                if (count($parts) < 2)
                {
                    throw new Exception('malformed revoked certificate.');
                }
                $reason = null;
                foreach (isset($parts[2]) ? self::readExtensions($parts[2]) : [] as $extension)
                {
                    if (self::REASON_CODE === $extension['oid'])
                    {
                        $reason = self::readReasonCode($extension['value']);
                    }
                    elseif (self::CERTIFICATE_ISSUER === $extension['oid'])
                    {
                        throw new Exception('indirect CRLs are not supported.');
                    }
                    if ($extension['critical'] && !in_array($extension['oid'], self::KNOWN_ENTRY_EXTENSIONS, true))
                    {
                        throw new Exception('unsupported critical extension ' . $extension['oid'] . ' of a revoked certificate.');
                    }
                }
                $key = bin2hex(Der::decodeUnsigned($parts[0]));
                if (isset($revoked[$key]))
                {
                    throw new Exception('a certificate is listed twice.');
                }
                $revoked[$key] = ['date' => Der::decodeTime($parts[1]), 'reason' => $reason];
            }
        }
        $onlyUserCerts = false;
        $onlyCACerts = false;
        $expiredCertsOnCrl = null;
        $extensions = array_shift($optional);
        if (null !== $extensions)
        {
            if (0xa0 !== $extensions['tag'] || !empty($optional))
            {
                throw new Exception('malformed TBSCertList.');
            }
            $seen = [];
            foreach (self::readExtensions(Der::readElement($extensions['content'])) as $extension)
            {
                if (isset($seen[$extension['oid']]))
                {
                    throw new Exception('extension ' . $extension['oid'] . ' repeated.');
                }
                $seen[$extension['oid']] = true;
                if (self::DELTA_CRL_INDICATOR === $extension['oid'])
                {
                    throw new Exception('delta CRLs are not supported.');
                }
                if ($extension['critical'] && !in_array($extension['oid'], self::KNOWN_CRL_EXTENSIONS, true))
                {
                    throw new Exception('unsupported critical extension ' . $extension['oid'] . '.');
                }
                if (self::ISSUING_DISTRIBUTION_POINT === $extension['oid'])
                {
                    list($onlyUserCerts, $onlyCACerts) = self::readIssuingDistributionPoint($extension['value']);
                }
                elseif (self::EXPIRED_CERTS_ON_CRL === $extension['oid'])
                {
                    $expiredCertsOnCrl = Der::decodeTime(Der::readElement($extension['value']));
                }
            }
        }

        return [
            'der' => $der,
            'issuer' => Der::reencode($issuer),
            'thisUpdate' => Der::decodeTime($thisUpdate),
            'nextUpdate' => $nextUpdate,
            'revoked' => $revoked,
            'onlyUserCerts' => $onlyUserCerts,
            'onlyCACerts' => $onlyCACerts,
            'expiredCertsOnCrl' => $expiredCertsOnCrl,
            'tbs' => Der::reencode($tbsElement),
            'signatureAlgorithm' => $signatureAlgorithm,
            'signature' => (string) substr($signatureValue['content'], 1),
        ];
    }


    /**
     * IssuingDistributionPoint (RFC 5280, 5.2.5): the distribution point
     * name and the restriction to user or CA certificates are read; a
     * restriction to some reasons, an indirect CRL, or a CRL of attribute
     * certificates make the CRL unusable.
     */
    private static function readIssuingDistributionPoint($value)
    {
        $onlyUserCerts = false;
        $onlyCACerts = false;
        foreach (Pkix::sequenceOf(Der::readElement($value), 'IssuingDistributionPoint') as $field)
        {
            $flag = 1 === strlen($field['content']) && "\0" !== $field['content'];
            if (0xa0 === $field['tag'])
            {
                continue;
            }
            elseif (0x81 === $field['tag'])
            {
                $onlyUserCerts = $flag;
            }
            elseif (0x82 === $field['tag'])
            {
                $onlyCACerts = $flag;
            }
            else
            {
                throw new Exception('CRLs restricted to some reasons, indirect CRLs and CRLs of attribute certificates are not supported.');
            }
        }

        return [$onlyUserCerts, $onlyCACerts];
    }


    /**
     * CRLReason (RFC 5280, 5.3.1): an ENUMERATED of one byte.
     */
    public static function readReasonCode($value)
    {
        $element = Der::readElement($value);
        if (Der::ENUMERATED !== $element['tag'] || 1 !== strlen($element['content']) || ord($element['content']) > 10)
        {
            throw new Exception('malformed reason code.');
        }

        return ord($element['content']);
    }


    private static function readExtensions($element)
    {
        $extensions = [];
        foreach (Der::childrenOf($element, Der::SEQUENCE) as $extension)
        {
            $fields = Pkix::sequenceOf($extension, 'Extension');
            $count = count($fields);
            if ($count < 2 || $count > 3 || Der::OCTET_STRING !== $fields[$count - 1]['tag'])
            {
                throw new Exception('malformed extension.');
            }
            $extensions[] = [
                'oid' => Der::decodeOid($fields[0]),
                'critical' => 3 === $count ? Der::decodeBoolean($fields[1]) : false,
                'value' => $fields[$count - 1]['content'],
            ];
        }

        return $extensions;
    }


    /**
     * Whether a CRL can tell the status of a certificate: issued by the
     * issuer of the certificate (its name, its signature, its key usage
     * cRLSign), and of a scope that includes it.
     *
     * @return string|null NULL if it can, or why it cannot.
     */
    public static function covers(array $crl, X509Cert $certificate, X509Cert $issuer)
    {
        if ($crl['issuer'] !== $certificate->getRawIssuer() || $crl['issuer'] !== $issuer->getRawSubject())
        {
            return 'its issuer is not the issuer of the certificate';
        }
        if ($crl['onlyUserCerts'] && $certificate->isCA())
        {
            return 'it covers the end-entity certificates only';
        }
        if ($crl['onlyCACerts'] && !$certificate->isCA())
        {
            return 'it covers the CA certificates only';
        }
        if (!$issuer->canSignCrls())
        {
            return 'the key usage of its issuer does not allow signing CRLs';
        }
        try
        {
            $valid = Pkix::verifySignature($crl['signatureAlgorithm'], null, openssl_pkey_get_public($issuer->getPem()), $crl['tbs'], $crl['signature']);
        }
        catch (Exception $e)
        {
            return 'its signature cannot be verified: ' . $e->getMessage();
        }

        return $valid ? null : 'its signature is not valid';
    }


    /**
     * A CRL as a source of revocation status.
     */
    public static function source(array $crl)
    {
        return new RevocationSource('crl', $crl['der'], $crl['thisUpdate'], $crl['nextUpdate'], $crl['expiredCertsOnCrl'],
            function (X509Cert $certificate, X509Cert $issuer) use ($crl) { return self::covers($crl, $certificate, $issuer); },
            function (X509Cert $certificate) use ($crl)
            {
                $key = bin2hex($certificate->getSerialNumber());
                return isset($crl['revoked'][$key]) ? $crl['revoked'][$key] : null;
            });
    }
}
