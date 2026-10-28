<?php
/**
 * Ocsp.php
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
use webcoder31\ezxmldsig\core\X509Cert;

/**
 * OCSP (RFC 6960): the request of the status of a certificate, the reading
 * of a response, and the verification of its responder.
 *
 * The request identifies the certificate by SHA-1 hashes of the name and of
 * the key of its issuer, as the lightweight profile requires (RFC 5019,
 * 2.1.1) and as responders expect: an identifier, not a signature. It has
 * no nonce: the responses of the seals are kept, and the freshness rules of
 * Revocation, not a nonce, tell whether one is current.
 *
 * A response is signed by the CA that issued the certificate, or by a
 * responder that CA delegated (RFC 6960, 4.2.2.2): a certificate issued
 * directly by it, of extended key usage id-kp-OCSPSigning. The delegated
 * responder must carry id-pkix-ocsp-nocheck (4.2.2.2.1): this library does
 * not check the revocation of responders.
 *
 * @internal
 */
class Ocsp
{
    const BASIC_RESPONSE = '1.3.6.1.5.5.7.48.1.1';
    const NO_CHECK = '1.3.6.1.5.5.7.48.1.5';
    const ARCHIVE_CUTOFF = '1.3.6.1.5.5.7.48.1.6';
    const OCSP_SIGNING = '1.3.6.1.5.5.7.3.9';
    const EXTENDED_KEY_USAGE = '2.5.29.37';
    const REASON_CODE = '2.5.29.21';

    /** The digests a CertID may use, by OID; SHA-1 is an identifier there, not a signature. */
    const CERT_ID_DIGESTS = [
        Pkix::OID_SHA1 => 'sha1',
        Pkix::OID_SHA256 => 'sha256',
        Pkix::OID_SHA384 => 'sha384',
        Pkix::OID_SHA512 => 'sha512',
    ];

    const RESPONSE_STATUS = ['successful', 'malformedRequest', 'internalError', 'tryLater', '(4)', 'sigRequired', 'unauthorized'];


    /**
     * The OCSP request of the status of a certificate (OCSPRequest, DER), to
     * send by HTTP POST with the media type `application/ocsp-request`.
     */
    public static function buildRequest(X509Cert $certificate, X509Cert $issuer)
    {
        $certId = Der::encode(Der::SEQUENCE,
            Der::encode(Der::SEQUENCE, Der::encodeOid(Pkix::OID_SHA1), Der::encode(Der::NULL)),
            Der::encode(Der::OCTET_STRING, sha1($certificate->getRawIssuer(), true)),
            Der::encode(Der::OCTET_STRING, sha1(self::publicKeyBits($issuer), true)),
            Der::encodeInteger($certificate->getSerialNumber()));

        return Der::encode(Der::SEQUENCE, Der::encode(Der::SEQUENCE, Der::encode(Der::SEQUENCE, Der::encode(Der::SEQUENCE, $certId))));
    }


    /**
     * Read an OCSP response, in DER.
     *
     * @return array 'der', 'producedAt', 'responder' (['name' => DER] or
     *         ['keyHash' => bytes]), 'responses', 'certificates' (X509Cert),
     *         'tbs', 'signatureAlgorithm', 'signature'.
     *
     * @throws Exception If it is malformed, if the responder did not answer
     *         successfully, or if it is not a basic response.
     */
    public static function read($data)
    {
        try
        {
            return self::parse((string) $data);
        }
        catch (Exception $e)
        {
            throw new Exception('OCSP response: ' . $e->getMessage());
        }
    }


    private static function parse($der)
    {
        $response = Pkix::sequenceOf(Der::readElement($der), 'OCSPResponse');
        if (!isset($response[0]) || Der::ENUMERATED !== $response[0]['tag'] || 1 !== strlen($response[0]['content']) || count($response) > 2)
        {
            throw new Exception('malformed OCSPResponse.');
        }
        $status = ord($response[0]['content']);
        if (0 !== $status)
        {
            throw new Exception('the responder answered ' . (isset(self::RESPONSE_STATUS[$status]) ? self::RESPONSE_STATUS[$status] : $status) . '.');
        }
        if (!isset($response[1]) || 0xa0 !== $response[1]['tag'])
        {
            throw new Exception('malformed OCSPResponse: no response bytes.');
        }
        $bytes = Pkix::sequenceOf(Der::readElement($response[1]['content']), 'ResponseBytes');
        if (!isset($bytes[0], $bytes[1]) || self::BASIC_RESPONSE !== Der::decodeOid($bytes[0]) || Der::OCTET_STRING !== $bytes[1]['tag'])
        {
            throw new Exception('not a basic OCSP response.');
        }
        // BasicOCSPResponse: tbsResponseData, signatureAlgorithm, signature, [0] certs OPTIONAL.
        $basic = Pkix::sequenceOf(Der::readElement($bytes[1]['content']), 'BasicOCSPResponse');
        if (count($basic) < 3 || count($basic) > 4 || Der::BIT_STRING !== $basic[2]['tag'] || '' === $basic[2]['content'] || "\0" !== $basic[2]['content'][0]
            || (isset($basic[3]) && 0xa0 !== $basic[3]['tag']))
        {
            throw new Exception('malformed BasicOCSPResponse.');
        }
        list($tbs, $signatureAlgorithm, $signature) = $basic;
        $certificates = [];
        foreach (isset($basic[3]) ? Der::childrenOf(Der::readElement($basic[3]['content']), Der::SEQUENCE) : [] as $cert)
        {
            try
            {
                $certificates[] = new X509Cert(X509Cert::derToPem(Der::reencode($cert)));
            }
            catch (Exception $e)
            {
                throw new Exception('a certificate of the response cannot be read.');
            }
        }

        // ResponseData: [0] version DEFAULT v1, responderID, producedAt, responses, [1] responseExtensions.
        $fields = Pkix::sequenceOf($tbs, 'ResponseData');
        if (isset($fields[0]) && 0xa0 === $fields[0]['tag'])
        {
            if (0 !== Der::decodeSmallInteger(Der::readElement(array_shift($fields)['content'])))
            {
                throw new Exception('unsupported version.');
            }
        }
        if (count($fields) < 3 || count($fields) > 4 || Der::SEQUENCE !== $fields[2]['tag'] || (isset($fields[3]) && 0xa1 !== $fields[3]['tag']))
        {
            throw new Exception('malformed ResponseData.');
        }
        list($responderId, $producedAt, $list) = $fields;
        if (0xa1 === $responderId['tag'])
        {
            $responder = ['name' => Der::reencode(Der::readElement($responderId['content']))];
        }
        elseif (0xa2 === $responderId['tag'])
        {
            $responder = ['keyHash' => self::readOctets(Der::readElement($responderId['content']))];
        }
        else
        {
            throw new Exception('malformed ResponderID.');
        }
        if (isset($fields[3]))
        {
            self::checkExtensions(Der::readElement($fields[3]['content']), ['1.3.6.1.5.5.7.48.1.2']);
        }
        $responses = array_map([self::class, 'readSingleResponse'], Der::readElements($list['content']));
        if (empty($responses))
        {
            throw new Exception('no single response.');
        }

        return [
            'der' => $der,
            'producedAt' => Der::decodeGeneralizedTime($producedAt),
            'responder' => $responder,
            'responses' => $responses,
            'certificates' => $certificates,
            'tbs' => Der::reencode($tbs),
            'signatureAlgorithm' => $signatureAlgorithm,
            'signature' => (string) substr($signature['content'], 1),
        ];
    }


    private static function readSingleResponse($element)
    {
        // SingleResponse: certID, certStatus, thisUpdate, [0] nextUpdate, [1] singleExtensions.
        $fields = Pkix::sequenceOf($element, 'SingleResponse');
        if (count($fields) < 3)
        {
            throw new Exception('malformed SingleResponse.');
        }
        list($certId, $status, $thisUpdate) = $fields;
        $id = Pkix::sequenceOf($certId, 'CertID');
        $algorithm = isset($id[0]) ? Pkix::sequenceOf($id[0], 'AlgorithmIdentifier') : [];
        $hashOid = isset($algorithm[0]) ? Der::decodeOid($algorithm[0]) : '';
        if (!isset(self::CERT_ID_DIGESTS[$hashOid]) || (isset($algorithm[1]) && Der::NULL !== $algorithm[1]['tag']) || 4 !== count($id))
        {
            throw new Exception('malformed or unsupported CertID.');
        }

        $revocation = null;
        if (0x80 === $status['tag'] && '' === $status['content'])
        {
            $kind = 'good';
        }
        elseif (0xa1 === $status['tag'])
        {
            // RevokedInfo: revocationTime, [0] revocationReason OPTIONAL.
            $info = Der::readElements($status['content']);
            if (!isset($info[0]) || (isset($info[1]) && 0xa0 !== $info[1]['tag']))
            {
                throw new Exception('malformed RevokedInfo.');
            }
            $kind = 'revoked';
            $revocation = [
                'date' => Der::decodeGeneralizedTime($info[0]),
                'reason' => isset($info[1]) ? self::readReason(Der::readElement($info[1]['content'])) : null,
            ];
        }
        elseif (0x82 === $status['tag'] && '' === $status['content'])
        {
            $kind = 'unknown';
        }
        else
        {
            throw new Exception('malformed CertStatus.');
        }

        $nextUpdate = null;
        $archiveCutoff = null;
        foreach (array_slice($fields, 3) as $field)
        {
            if (0xa0 === $field['tag'] && null === $nextUpdate)
            {
                $nextUpdate = Der::decodeGeneralizedTime(Der::readElement($field['content']));
            }
            elseif (0xa1 === $field['tag'])
            {
                foreach (self::checkExtensions(Der::readElement($field['content']), [self::ARCHIVE_CUTOFF, self::REASON_CODE, '2.5.29.24']) as $extension)
                {
                    if (self::ARCHIVE_CUTOFF === $extension['oid'])
                    {
                        $archiveCutoff = Der::decodeGeneralizedTime(Der::readElement($extension['value']));
                    }
                }
            }
            else
            {
                throw new Exception('malformed SingleResponse.');
            }
        }

        return [
            'hash' => self::CERT_ID_DIGESTS[$hashOid],
            'issuerNameHash' => self::readOctets($id[1]),
            'issuerKeyHash' => self::readOctets($id[2]),
            'serial' => Der::decodeUnsigned($id[3]),
            'status' => $kind,
            'revocation' => $revocation,
            'thisUpdate' => Der::decodeGeneralizedTime($thisUpdate),
            'nextUpdate' => $nextUpdate,
            'archiveCutoff' => $archiveCutoff,
        ];
    }


    /**
     * The extensions of a sequence of them; a critical one not known makes
     * the response unusable.
     */
    private static function checkExtensions($element, array $known)
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
            $oid = Der::decodeOid($fields[0]);
            $critical = 3 === $count && Der::BOOLEAN === $fields[1]['tag'] && "\0" !== $fields[1]['content'] && '' !== $fields[1]['content'];
            if ($critical && !in_array($oid, $known, true))
            {
                throw new Exception('unsupported critical extension ' . $oid . '.');
            }
            $extensions[] = ['oid' => $oid, 'value' => $fields[$count - 1]['content']];
        }

        return $extensions;
    }


    private static function readReason($element)
    {
        if (Der::ENUMERATED !== $element['tag'] || 1 !== strlen($element['content']) || ord($element['content']) > 10)
        {
            throw new Exception('malformed reason code.');
        }

        return ord($element['content']);
    }


    private static function readOctets($element)
    {
        if (Der::OCTET_STRING !== $element['tag'])
        {
            throw new Exception('OCTET STRING expected.');
        }

        return $element['content'];
    }


    /**
     * The value of the BIT STRING of the public key of a certificate,
     * without its unused-bits octet (RFC 6960, 4.1.1).
     */
    public static function publicKeyBits(X509Cert $certificate)
    {
        $pem = openssl_pkey_get_details(openssl_pkey_get_public($certificate->getPem()))['key'];
        preg_match('/-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----/s', $pem, $match);
        $spki = Pkix::sequenceOf(Der::readElement(base64_decode($match[1])), 'SubjectPublicKeyInfo');

        return (string) substr($spki[1]['content'], 1);
    }


    /**
     * The certificate that signed a response for certificates the issuer
     * issued, if it may: the issuer itself, or a responder it delegated (see
     * the comment of the class).
     *
     * @return X509Cert|string The signer, or why there is none.
     */
    private static function responderOf(array $response, X509Cert $issuer)
    {
        $matches = function (X509Cert $cert) use ($response)
        {
            return isset($response['responder']['name'])
                ? $response['responder']['name'] === $cert->getRawSubject()
                : $response['responder']['keyHash'] === sha1(self::publicKeyBits($cert), true);
        };
        if ($matches($issuer))
        {
            return $issuer;
        }
        $delegated = null;
        foreach ($response['certificates'] as $cert)
        {
            if ($matches($cert))
            {
                $delegated = $cert;
                break;
            }
        }
        if (null === $delegated)
        {
            return 'its responder is neither the issuer nor a certificate of the response';
        }
        if ($delegated->getRawIssuer() !== $issuer->getRawSubject() || !self::verifiesWith($delegated, $issuer))
        {
            return 'its responder is not issued by the issuer of the certificate';
        }
        $usage = $delegated->getExtension(self::EXTENDED_KEY_USAGE);
        if (null === $usage || !in_array(self::OCSP_SIGNING, array_map([Der::class, 'decodeOid'], Der::childrenOf(Der::readElement($usage['value']), Der::SEQUENCE)), true))
        {
            return 'its responder has not the extended key usage OCSPSigning';
        }
        if (null === $delegated->getExtension(self::NO_CHECK))
        {
            return 'its responder has not the extension id-pkix-ocsp-nocheck, and this library does not check the revocation of responders';
        }
        if (!$delegated->canSign())
        {
            return 'the key usage of its responder does not allow signing';
        }
        if ($response['producedAt'] < (int) $delegated->getValidFrom('U') || $response['producedAt'] >= (int) $delegated->getValidTo('U'))
        {
            return 'its responder was not valid when it was produced';
        }

        return $delegated;
    }


    /**
     * Whether a certificate is signed by the key of another one.
     */
    private static function verifiesWith(X509Cert $certificate, X509Cert $issuer)
    {
        try
        {
            $parts = Pkix::sequenceOf(Der::readElement($certificate->getDer()), 'Certificate');
            return Pkix::verifySignature($parts[1], null, openssl_pkey_get_public($issuer->getPem()), Der::reencode($parts[0]), Der::decodeBitStringBytes($parts[2]));
        }
        catch (Exception $e)
        {
            return false;
        }
    }


    /**
     * The answers of a response as sources of revocation status: one for
     * each single response. Each tells the status of its certificate once
     * its signature is verified, by the issuer of the certificate or a
     * responder it delegated.
     *
     * @return array The sources (RevocationSource).
     */
    public static function sources(array $response)
    {
        $verified = [];
        $signedFor = function (X509Cert $issuer) use ($response, &$verified)
        {
            $key = $issuer->getDer();
            if (!array_key_exists($key, $verified))
            {
                $responder = self::responderOf($response, $issuer);
                if (is_string($responder))
                {
                    $result = $responder;
                }
                else
                {
                    try
                    {
                        $result = Pkix::verifySignature($response['signatureAlgorithm'], null, openssl_pkey_get_public($responder->getPem()), $response['tbs'], $response['signature'])
                            ? null : 'its signature is not valid';
                    }
                    catch (Exception $e)
                    {
                        $result = 'its signature cannot be verified: ' . $e->getMessage();
                    }
                }
                $verified[$key] = $result;
            }
            return $verified[$key];
        };
        $sources = [];
        foreach ($response['responses'] as $single)
        {
            $sources[] = new RevocationSource('ocsp', $response['der'], $single['thisUpdate'], $single['nextUpdate'], $single['archiveCutoff'],
                function (X509Cert $certificate, X509Cert $issuer) use ($single, $signedFor)
                {
                    if ($single['serial'] !== $certificate->getSerialNumber()
                        || $single['issuerNameHash'] !== hash($single['hash'], $certificate->getRawIssuer(), true)
                        || $single['issuerKeyHash'] !== hash($single['hash'], self::publicKeyBits($issuer), true))
                    {
                        return 'it is about another certificate';
                    }
                    if ('unknown' === $single['status'])
                    {
                        return 'its responder does not know the certificate';
                    }
                    return $signedFor($issuer);
                },
                function () use ($single) { return $single['revocation']; });
        }

        return $sources;
    }
}
