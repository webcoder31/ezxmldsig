<?php
/**
 * Timestamp.php
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
 * Time-stamps (RFC 3161, updated by RFC 5816): the request, the response,
 * and the verification of a time-stamp token, a CMS SignedData (RFC 5652)
 * whose content is a TSTInfo.
 *
 * No network access: the caller sends the request to the time-stamping
 * authority of its choice. The token is checked as a signature of its own:
 * one signer, the signed attributes that bind the content and the
 * certificate of the authority (ESS signing-certificate, RFC 2634 and
 * RFC 5035), the extended key usage timeStamping of that certificate
 * (RFC 3161, 2.3), the algorithms of the seals. Whether the authority is
 * trusted is decided by the caller, with the certificate returned.
 *
 * @internal
 */
class Timestamp
{
    const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
    const OID_TST_INFO = '1.2.840.113549.1.9.16.1.4';
    const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';
    const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
    const OID_SIGNING_CERTIFICATE = '1.2.840.113549.1.9.16.2.12';
    const OID_SIGNING_CERTIFICATE_V2 = '1.2.840.113549.1.9.16.2.47';
    const OID_EXTENDED_KEY_USAGE = '2.5.29.37';
    const OID_TIME_STAMPING = '1.3.6.1.5.5.7.3.8';

    const PKI_STATUS = ['granted', 'grantedWithMods', 'rejection', 'waiting', 'revocationWarning', 'revocationNotification'];

    /** The OID of a digest, by its hash() name. */
    const OIDS_OF_DIGESTS = ['sha256' => Pkix::OID_SHA256, 'sha384' => Pkix::OID_SHA384, 'sha512' => Pkix::OID_SHA512];


    /**
     * A TimeStampReq (RFC 3161, 2.4.1): version 1, the imprint, and the
     * request of the certificate of the authority in the token (certReq),
     * which the verifier needs.
     *
     * @param string $imprint The digest of the data to time-stamp.
     *
     * @param string $hash Its algorithm, as hash() names it: sha256, sha384, sha512.
     *
     * @return string The request, in DER.
     *
     * @throws Exception If the digest is not supported.
     */
    public static function buildRequest($imprint, $hash)
    {
        if (!isset(self::OIDS_OF_DIGESTS[$hash]))
        {
            throw new Exception('Time-stamp: unsupported digest ' . $hash . '.');
        }

        return Der::encode(Der::SEQUENCE,
            Der::encodeInteger(1),
            Der::encode(Der::SEQUENCE, Der::encode(Der::SEQUENCE, Der::encodeOid(self::OIDS_OF_DIGESTS[$hash]), Der::encode(Der::NULL)), Der::encode(Der::OCTET_STRING, $imprint)),
            Der::encode(Der::BOOLEAN, "\xff"));
    }


    /**
     * The token of a TimeStampResp (RFC 3161, 2.4.2), if the authority
     * granted it.
     *
     * @param string $response The response, in DER.
     *
     * @return string The token, in DER.
     *
     * @throws Exception If the response is malformed, or the authority did
     *         not grant the time-stamp.
     */
    public static function readResponse($response)
    {
        try
        {
            $fields = Pkix::sequenceOf(Der::readElement($response), 'TimeStampResp');
            if (!isset($fields[0]) || count($fields) > 2)
            {
                throw new Exception('Time-stamp: malformed TimeStampResp.');
            }
            $status = Pkix::sequenceOf($fields[0], 'PKIStatusInfo');
            $value = Der::decodeSmallInteger($status[0]);
            if (0 !== $value && 1 !== $value)
            {
                $reason = '';
                foreach (array_slice($status, 1) as $detail)
                {
                    if (Der::SEQUENCE === $detail['tag'])
                    {
                        $reason = ': ' . implode(' ', array_column(Der::readElements($detail['content']), 'content'));
                        break;
                    }
                }
                throw new Exception('Time-stamp: the authority answered ' . (isset(self::PKI_STATUS[$value]) ? self::PKI_STATUS[$value] : $value) . $reason . '.');
            }
            if (!isset($fields[1]))
            {
                throw new Exception('Time-stamp: the response grants a time-stamp but holds no token.');
            }

            return Der::reencode($fields[1]);
        }
        catch (Exception $e)
        {
            throw self::prefixed($e);
        }
    }


    /**
     * Verify a time-stamp token, and read it.
     *
     * @param string $token The token, in DER.
     *
     * @return array 'time' (float, UNIX time), 'imprintAlgorithm' (hash()
     *         name), 'imprint', 'certificate' (X509Cert of the authority),
     *         'chain' (the other certificates of the token), 'policy',
     *         'serialNumber'.
     *
     * @throws Exception Why the token is not valid.
     */
    public static function verifyToken($token)
    {
        try
        {
            return self::readToken($token);
        }
        catch (Exception $e)
        {
            throw self::prefixed($e);
        }
    }


    private static function prefixed(Exception $e)
    {
        $message = $e->getMessage();

        return 0 === strpos($message, 'Time-stamp: ') ? $e : new Exception('Time-stamp: ' . $message);
    }


    private static function readToken($token)
    {
        // ContentInfo: contentType signedData, [0] EXPLICIT SignedData.
        $contentInfo = Pkix::sequenceOf(Der::readElement($token), 'ContentInfo');
        if (2 !== count($contentInfo) || self::OID_SIGNED_DATA !== Der::decodeOid($contentInfo[0]) || 0xa0 !== $contentInfo[1]['tag'])
        {
            throw new Exception('Time-stamp: the token is not a CMS SignedData.');
        }
        // SignedData: version, digestAlgorithms, encapContentInfo, [0] certificates, [1] crls, signerInfos.
        $signedData = Pkix::sequenceOf(Der::readElement($contentInfo[1]['content']), 'SignedData');
        if (count($signedData) < 4)
        {
            throw new Exception('Time-stamp: malformed SignedData.');
        }
        $encapsulated = $signedData[2];
        $signerInfos = $signedData[count($signedData) - 1];
        $certificates = null;
        foreach (array_slice($signedData, 3, -1) as $element)
        {
            if (0xa0 === $element['tag'])
            {
                $certificates = $element;
                break;
            }
        }
        $eContentInfo = Pkix::sequenceOf($encapsulated, 'EncapsulatedContentInfo');
        if (!isset($eContentInfo[0], $eContentInfo[1]) || self::OID_TST_INFO !== Der::decodeOid($eContentInfo[0]) || 0xa0 !== $eContentInfo[1]['tag'])
        {
            throw new Exception('Time-stamp: the token does not hold a TSTInfo.');
        }
        $eContent = Der::readElement($eContentInfo[1]['content']);
        if (Der::OCTET_STRING !== $eContent['tag'])
        {
            throw new Exception('Time-stamp: malformed TSTInfo.');
        }
        $tstInfo = self::readTstInfo($eContent['content']);

        // The certificates of the token: the one of the signer, and the chain.
        $certs = [];
        try
        {
            foreach (null === $certificates ? [] : Der::readElements($certificates['content']) as $element)
            {
                if (Der::SEQUENCE === $element['tag'])
                {
                    $certs[] = new X509Cert(X509Cert::derToPem(Der::reencode($element)));
                }
            }
        }
        catch (Exception $e)
        {
            throw new Exception('Time-stamp: a certificate of the token cannot be read.');
        }

        // The one signer.
        $signers = Der::childrenOf($signerInfos, Der::SET);
        if (1 !== count($signers))
        {
            throw new Exception('Time-stamp: the token must have one signer.');
        }
        $signerInfo = Pkix::sequenceOf($signers[0], 'SignerInfo');
        if (count($signerInfo) < 6 || 0xa0 !== $signerInfo[3]['tag'] || Der::OCTET_STRING !== $signerInfo[5]['tag'])
        {
            throw new Exception('Time-stamp: malformed SignerInfo (the signed attributes are required).');
        }
        foreach (array_slice($signerInfo, 6) as $unsigned)
        {
            if (0xa1 !== $unsigned['tag'])
            {
                throw new Exception('Time-stamp: malformed SignerInfo (the signed attributes are required).');
            }
        }
        list(, $sid, $digestAlgorithm, $signedAttrs, $signatureAlgorithm, $signature) = $signerInfo;
        $certificate = null;
        foreach ($certs as $cert)
        {
            if (self::identifies($sid, $cert))
            {
                $certificate = $cert;
                break;
            }
        }
        if (null === $certificate)
        {
            throw new Exception('Time-stamp: the certificate of the authority is not in the token.');
        }
        $digest = Pkix::digestOf($digestAlgorithm);

        // The signed attributes: content type, message digest, signing certificate.
        $attributes = [];
        foreach (Der::readElements($signedAttrs['content']) as $attribute)
        {
            $parts = Pkix::sequenceOf($attribute, 'Attribute');
            $oid = Der::decodeOid($parts[0]);
            if (isset($attributes[$oid]) || !isset($parts[1]))
            {
                throw new Exception('Time-stamp: a signed attribute is repeated or malformed.');
            }
            $attributes[$oid] = Der::childrenOf($parts[1], Der::SET);
        }
        $single = function ($oid, $name) use ($attributes)
        {
            if (!isset($attributes[$oid]) || 1 !== count($attributes[$oid]))
            {
                throw new Exception('Time-stamp: the signed attribute ' . $name . ' is missing or not single.');
            }
            return $attributes[$oid][0];
        };
        if (self::OID_TST_INFO !== Der::decodeOid($single(self::OID_CONTENT_TYPE, 'contentType')))
        {
            throw new Exception('Time-stamp: the signed content type is not TSTInfo.');
        }
        $messageDigest = $single(self::OID_MESSAGE_DIGEST, 'messageDigest');
        if (Der::OCTET_STRING !== $messageDigest['tag'] || !hash_equals(hash($digest, $eContent['content'], true), $messageDigest['content']))
        {
            throw new Exception('Time-stamp: the TSTInfo has been altered (message digest mismatch).');
        }
        self::checkSigningCertificate($attributes, $certificate->getDer());

        // The signature, over the DER of the signed attributes as a SET.
        $publicKey = openssl_pkey_get_public($certificate->getPem());
        if (!Pkix::verifySignature($signatureAlgorithm, $digest, $publicKey, Der::encode(Der::SET, $signedAttrs['content']), $signature['content']))
        {
            throw new Exception('Time-stamp: the signature of the token is not valid.');
        }
        $chain = array_values(array_filter($certs, function ($cert) use ($certificate) { return $cert !== $certificate; }));
        if (!self::hasTimeStampingUsage($certificate))
        {
            throw new Exception('Time-stamp: the certificate of the authority does not have the extended key usage timeStamping alone, critical (RFC 3161, 2.3).');
        }

        return $tstInfo + ['certificate' => $certificate, 'chain' => $chain];
    }


    /**
     * TSTInfo (RFC 3161, 2.4.2): version 1, policy, messageImprint,
     * serialNumber, genTime, then optional fields.
     */
    private static function readTstInfo($content)
    {
        $fields = Pkix::sequenceOf(Der::readElement($content), 'TSTInfo');
        if (count($fields) < 5 || 1 !== Der::decodeSmallInteger($fields[0]))
        {
            throw new Exception('Time-stamp: malformed TSTInfo.');
        }
        list(, $policy, $messageImprint, $serialNumber, $genTime) = $fields;
        $imprint = Pkix::sequenceOf($messageImprint, 'MessageImprint');
        if (!isset($imprint[0], $imprint[1]) || Der::OCTET_STRING !== $imprint[1]['tag'])
        {
            throw new Exception('Time-stamp: malformed MessageImprint.');
        }

        return [
            'time' => Der::decodeGeneralizedTime($genTime),
            'imprintAlgorithm' => Pkix::digestOf($imprint[0]),
            'imprint' => $imprint[1]['content'],
            'policy' => Der::decodeOid($policy),
            'serialNumber' => Der::decodeUnsigned($serialNumber),
        ];
    }


    /**
     * The ESS signing-certificate attribute binds the certificate of the
     * authority to its signature: version 2 (a digest of the certificate
     * with the given algorithm, SHA-256 by default), or version 1 (SHA-1,
     * which identifies the certificate here, without signing anything).
     */
    private static function checkSigningCertificate(array $attributes, $certificate)
    {
        $v2 = isset($attributes[self::OID_SIGNING_CERTIFICATE_V2]) ? $attributes[self::OID_SIGNING_CERTIFICATE_V2] : null;
        $v1 = isset($attributes[self::OID_SIGNING_CERTIFICATE]) ? $attributes[self::OID_SIGNING_CERTIFICATE] : null;
        $values = null !== $v2 ? $v2 : $v1;
        if (null === $values || 1 !== count($values))
        {
            throw new Exception('Time-stamp: the signed attribute signingCertificate (ESS) is missing.');
        }
        // SigningCertificate(V2) ::= SEQUENCE { certs SEQUENCE OF ESSCertID(v2), policies OPTIONAL }
        $signingCertificate = Pkix::sequenceOf($values[0], 'SigningCertificate');
        $certs = isset($signingCertificate[0]) ? Der::childrenOf($signingCertificate[0], Der::SEQUENCE) : [];
        if (!isset($certs[0]))
        {
            throw new Exception('Time-stamp: the signed attribute signingCertificate names no certificate.');
        }
        $fields = Pkix::sequenceOf($certs[0], 'ESSCertID');
        $hash = 'sha1';
        $index = 0;
        if (null !== $v2)
        {
            $hash = 'sha256';
            if (isset($fields[0]) && Der::SEQUENCE === $fields[0]['tag'])
            {
                $hash = Pkix::digestOf($fields[0]);
                $index = 1;
            }
        }
        if (!isset($fields[$index]) || Der::OCTET_STRING !== $fields[$index]['tag'] || !hash_equals(hash($hash, $certificate, true), $fields[$index]['content']))
        {
            throw new Exception('Time-stamp: the signed attribute signingCertificate does not name the certificate of the signer.');
        }
    }


    /**
     * Whether a SignerIdentifier names a certificate: issuerAndSerialNumber,
     * or [0] subjectKeyIdentifier.
     */
    private static function identifies($sid, X509Cert $certificate)
    {
        if (Der::SEQUENCE === $sid['tag'])
        {
            $parts = Der::readElements($sid['content']);
            return 2 === count($parts)
                && Der::reencode($parts[0]) === $certificate->getRawIssuer()
                && Der::decodeUnsigned($parts[1]) === $certificate->getSerialNumber();
        }
        if (0x80 === $sid['tag'])
        {
            $extension = $certificate->getExtension('2.5.29.14');
            return null !== $extension && Der::readElement($extension['value'])['content'] === $sid['content'];
        }

        return false;
    }


    /**
     * RFC 3161, 2.3: the certificate of the authority has one extended key
     * usage, timeStamping, critical.
     */
    private static function hasTimeStampingUsage(X509Cert $certificate)
    {
        $extension = $certificate->getExtension(self::OID_EXTENDED_KEY_USAGE);
        if (null === $extension || !$extension['critical'])
        {
            return false;
        }
        $usages = array_map([Der::class, 'decodeOid'], Der::childrenOf(Der::readElement($extension['value']), Der::SEQUENCE));

        return 1 === count($usages) && self::OID_TIME_STAMPING === $usages[0];
    }
}
