<?php
/**
 * Seal.php
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
use DOMDocument;
use DOMElement;
use Exception;
use webcoder31\ezxmldsig\core\Algorithms;
use webcoder31\ezxmldsig\core\Der;
use webcoder31\ezxmldsig\core\X509Cert;
use webcoder31\ezxmldsig\core\Xml;

/**
 * Seals of files: an ASiC-E container (ETSI EN 319 162-1) holding the files
 * and one detached XAdES baseline signature over them (ETSI EN 319 132-1),
 * at level B, T (a signature time-stamp, RFC 3161) or LT (the certificates,
 * CRLs and OCSP responses that validate it, embedded). The Node.js library
 * ezxmldsig-js creates and verifies the same seals; its design document,
 * design/seal.md, gives the structure and the rules followed.
 *
 * The seals are an experimental feature of the 2.x versions: their API may
 * change in a minor version.
 */
class Seal
{
    const XMLDSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';
    const ASIC_NS = 'http://uri.etsi.org/02918/v1.2.1#';
    const XADES_NS = 'http://uri.etsi.org/01903/v1.3.2#';
    /** The namespace of the properties XAdES 1.4.1 added, such as TimeStampValidationData. */
    const XADES141_NS = 'http://uri.etsi.org/01903/v1.4.1#';
    const MANIFEST_NS = 'urn:oasis:names:tc:opendocument:xmlns:manifest:1.0';
    const SIGNED_PROPERTIES_TYPE = 'http://uri.etsi.org/01903#SignedProperties';
    const ASICE_MIMETYPE = 'application/vnd.etsi.asic-e+zip';

    /** The path of the signature in the container. */
    const SIGNATURE_PATH = 'META-INF/signatures001.xml';
    const MANIFEST_PATH = 'META-INF/manifest.xml';

    /** The canonicalizations accepted for SignedInfo and the signed properties. */
    const CANONICALIZATIONS = [Algorithms::EXC_C14N, Algorithms::C14N];


    /**
     * Verify a seal.
     *
     * The structure is read strictly: every element of the signature is
     * where the baseline puts it, once, and anything this library does not
     * process (a signature policy, a manifest of references, a transform)
     * makes the seal invalid rather than ignored. A seal is valid only if
     * every file of the container outside META-INF is covered, so that a
     * file added to a sealed container cannot pass for a sealed one.
     *
     * The signing certificate is trusted at the time of the signature
     * time-stamp, if any, and at the current date otherwise: SigningTime is
     * claimed by the signer, and cannot date the check of its certificate.
     * The certificate of the time-stamping authority is checked at the
     * current date. The revocation of the certificates is checked, by CRLs
     * or OCSP responses, unless 'revocation' is FALSE: the library sends no
     * request, the data come from the seal (level LT) and from the options.
     *
     * @param string $container The ASiC-E container.
     *
     * @param array $options
     *        - 'caCertPath' (required): the trusted CA certificates, paths of
     *          PEM files or PEM contents: the root of the signer, and the
     *          intermediate CAs if the seal does not embed them;
     *        - 'tsaCertPath': the trusted certificates of the time-stamping
     *          authorities, required to verify a time-stamped seal;
     *        - 'expectedSubject': the subject the signing certificate must
     *          have, its DN as X509Cert::getDN() gives it, or fields that
     *          must all match (see XMLDSigToken's option of the same name);
     *        - 'revocation': whether the revocation is checked (default
     *          TRUE);
     *        - 'crls': CRLs, in DER or PEM, for the certificates of the
     *          signer and of the time-stamping authority, used besides those
     *          of a seal of level LT;
     *        - 'ocspResponses': OCSP responses (DER), likewise;
     *        - 'maxEntries', 'maxTotalSize': the limits of the reading of
     *          the container (default 1000 entries, 512 MiB uncompressed).
     *
     * @return SealVerification The result. An invalid seal does not throw:
     *         see its getError().
     *
     * @throws Exception On a misuse: the options are not valid, or a CA
     *         certificate cannot be read.
     */
    public static function verifySeal($container, array $options)
    {
        return self::inspectSeal($container, $options)['result'];
    }


    /**
     * verifySeal(), with what the extension of a seal needs: the chains, the
     * certificates the signature and its time-stamp hold, and the sources
     * that told the status of each chain.
     *
     * @internal
     */
    public static function inspectSeal($container, array $options, $forLevelLT = false)
    {
        if (!is_string($container))
        {
            throw new Exception('Seal verification: the container must be bytes (a string).');
        }
        $caCerts = self::readCertificates(isset($options['caCertPath']) ? $options['caCertPath'] : null, 'caCertPath');
        $tsaCerts = isset($options['tsaCertPath']) ? self::readCertificates($options['tsaCertPath'], 'tsaCertPath') : null;
        $expectedSubject = isset($options['expectedSubject']) ? $options['expectedSubject'] : null;
        if (array_key_exists('expectedSubject', $options) && ((!is_string($expectedSubject) && !is_array($expectedSubject)) || '' === $expectedSubject || [] === $expectedSubject))
        {
            throw new Exception("Seal verification: invalid option 'expectedSubject'.");
        }
        $revocation = array_key_exists('revocation', $options) ? $options['revocation'] : true;
        if (!is_bool($revocation))
        {
            throw new Exception("Seal verification: invalid option 'revocation'.");
        }
        foreach (['crls' => 'CRLs', 'ocspResponses' => 'OCSP responses'] as $name => $what)
        {
            if (isset($options[$name]) && (!is_array($options[$name]) || count(array_filter($options[$name], 'is_string')) !== count($options[$name])))
            {
                throw new Exception("Seal verification: invalid option '" . $name . "': an array of " . $what . ' (strings).');
            }
        }
        $given = [];
        foreach (isset($options['crls']) ? $options['crls'] : [] as $crl)
        {
            try
            {
                $given[] = Crl::source(Crl::read($crl));
            }
            catch (Exception $e)
            {
                throw new Exception('Seal verification: a CRL cannot be used. ' . $e->getMessage());
            }
        }
        foreach (isset($options['ocspResponses']) ? $options['ocspResponses'] : [] as $response)
        {
            try
            {
                $given = array_merge($given, Ocsp::sources(Ocsp::read($response)));
            }
            catch (Exception $e)
            {
                throw new Exception('Seal verification: an OCSP response cannot be used. ' . $e->getMessage());
            }
        }
        $maxEntries = isset($options['maxEntries']) ? $options['maxEntries'] : Zip::MAX_ENTRIES;
        $maxTotalSize = isset($options['maxTotalSize']) ? $options['maxTotalSize'] : Zip::MAX_TOTAL_SIZE;

        $signer = null;
        $signingTime = null;
        $found = ['chain' => null, 'tsaChain' => null, 'keyInfo' => [], 'tokenCertificates' => [], 'signerSources' => [], 'tsaSources' => [], 'hasValidationData' => false];
        try
        {
            list($files, $signatureFile) = self::readContainer($container, $maxEntries, $maxTotalSize);
            $signature = self::readSignature($signatureFile, $files);
            $signer = $signature['signer'];
            $signingTime = $signature['signingTime'];
            $validationData = null === $signature['validationData'] ? null : self::readValidationData($signature['validationData']);

            // The signature time-stamp proves that the signature existed at
            // its time: the certificates of the signer are checked at that
            // time. The certificate of the authority is checked at the
            // current date: only a time-stamp over the time-stamp (level LTA)
            // would check it at an earlier one.
            $timestampTime = null;
            $tsaChain = null;
            $tokenCertificates = [];
            if (null !== $signature['timestamp'])
            {
                if (null === $tsaCerts)
                {
                    self::invalid("The seal is time-stamped: the option 'tsaCertPath' is needed to trust its time-stamping authority.");
                }
                list($timestampTime, $tsaChain, $tokenCertificates) = self::checkTimestamp($signature['timestamp'], $tsaCerts, null === $validationData ? [] : $validationData['certificates']);
            }
            elseif (null !== $validationData)
            {
                self::invalid('The seal has validation data but no signature time-stamp: level LT is time-stamped.');
            }

            // Without time-stamp, the trust in the signer is checked at the
            // current date: SigningTime is claimed by the signer, and cannot
            // date the check of its certificate.
            $certificate = $signature['signer'];
            if (!$certificate->canSign())
            {
                self::invalid('The key usage of the signing certificate does not allow signing.');
            }
            $untrusted = array_merge($signature['chain'], null === $validationData ? [] : $validationData['certificates']);
            $chain = $certificate->getTrustedChain($caCerts, $untrusted, $timestampTime);
            if (null === $chain)
            {
                self::invalid('The signing certificate is not trusted: no valid chain up to a trusted CA certificate' . (null === $timestampTime ? '' : ' at the time of the time-stamp') . '.');
            }
            if (null !== $expectedSubject)
            {
                $matches = is_string($expectedSubject) ? $certificate->getDN() === $expectedSubject : X509Cert::matchesName($certificate->getSubject(), $expectedSubject);
                if (!$matches)
                {
                    self::invalid('The subject of the signing certificate is not the expected one.');
                }
            }
            $found = ['chain' => $chain, 'tsaChain' => $tsaChain, 'keyInfo' => $signature['keyInfo'], 'tokenCertificates' => $tokenCertificates, 'hasValidationData' => null !== $validationData] + $found;

            if ($revocation)
            {
                // The signer: from the time of the time-stamp, if any. The
                // time-stamping authority: at the current date, unless the
                // seal embeds its validation data, which are no longer
                // current when it is verified.
                $now = time();
                $signerCheck = ['now' => $now, 'issuedAfter' => $timestampTime, 'time' => $timestampTime];
                $tsaCheck = ['now' => $now, 'issuedAfter' => null === $validationData && !$forLevelLT ? null : $timestampTime, 'time' => $timestampTime, 'authority' => true];
                $run = function (array $pool) use ($chain, $tsaChain, $signerCheck, $tsaCheck)
                {
                    $ofSigner = Revocation::check($chain, $pool, $signerCheck);
                    $ofAuthority = null === $tsaChain ? null : Revocation::check($tsaChain, $pool, $tsaCheck);
                    $error = null !== $ofSigner['error'] ? $ofSigner['error'] : (null === $ofAuthority ? null : $ofAuthority['error']);
                    return ['error' => $error, 'signerSources' => $ofSigner['used'], 'tsaSources' => null === $ofAuthority ? [] : $ofAuthority['used']];
                };
                if (null !== $validationData)
                {
                    // Level LT: the embedded data must suffice by themselves.
                    $own = $run($validationData['sources']);
                    if (null !== $own['error'])
                    {
                        self::invalid('The validation data of the seal do not suffice. ' . $own['error']);
                    }
                    $found['signerSources'] = $own['signerSources'];
                    $found['tsaSources'] = $own['tsaSources'];
                }
                if (null === $validationData || !empty($given))
                {
                    $all = $run(array_merge(null === $validationData ? [] : $validationData['sources'], $given));
                    if (null !== $all['error'])
                    {
                        self::invalid($all['error'] . (null === $validationData ? " (the option 'revocation' => false verifies the seal without revocation.)" : ''));
                    }
                    if (null === $validationData)
                    {
                        $found['signerSources'] = $all['signerSources'];
                        $found['tsaSources'] = $all['tsaSources'];
                    }
                }
            }
            $level = null === $timestampTime ? 'B' : (null === $validationData ? 'T' : 'LT');

            return ['result' => new SealVerification([
                'error' => null,
                'files' => $signature['files'],
                'signingTime' => $signingTime,
                'signer' => $signer,
                'revocationChecked' => $revocation,
                'timestampTime' => $timestampTime,
                'level' => $level,
            ])] + $found;
        }
        catch (InvalidSeal $e)
        {
            return ['result' => new SealVerification(['error' => $e->getMessage(), 'signingTime' => $signingTime, 'signer' => $signer])] + $found;
        }
    }


    /**
     * @throws InvalidSeal Always.
     */
    private static function invalid($message)
    {
        throw new InvalidSeal($message);
    }


    /**
     * A value between double quotes, for the messages, as JSON writes it
     * but without escaping slashes and non-ASCII characters.
     */
    private static function quote($value)
    {
        return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }


    /**
     * Bytes read as ISO-8859-1 (each byte a character), in UTF-8, for a
     * message.
     */
    private static function latin1($bytes)
    {
        return preg_replace_callback('/[\x80-\xff]/', function ($m) { $c = ord($m[0]); return chr(0xc0 | ($c >> 6)) . chr(0x80 | ($c & 0x3f)); }, $bytes);
    }


    /**
     * The PEM contents of trusted certificates given as an option: paths of
     * PEM files or PEM contents.
     *
     * @throws Exception If the option is missing or a file cannot be read.
     */
    private static function readCertificates($source, $name)
    {
        $sources = is_array($source) ? $source : [$source];
        if (null === $source || empty($sources))
        {
            throw new Exception("Seal verification: the option '" . $name . "' is required.");
        }
        $pems = [];
        foreach ($sources as $item)
        {
            if (is_string($item) && false !== strpos($item, '-----BEGIN'))
            {
                $pems[] = $item;
                continue;
            }
            $pem = is_string($item) && is_file($item) && is_readable($item) ? file_get_contents($item) : false;
            if (false === $pem)
            {
                throw new Exception('Seal verification: cannot read the certificate file ' . (is_string($item) ? $item : gettype($item)) . " ('" . $name . "').");
            }
            $pems[] = $pem;
        }

        return $pems;
    }


    /**
     * The validation data the seal embeds, read.
     */
    private static function readValidationData(array $data)
    {
        $certificates = [];
        foreach ($data['certificates'] as $der)
        {
            try
            {
                $certificates[] = new X509Cert(X509Cert::derToPem($der));
            }
            catch (Exception $e)
            {
                self::invalid('A certificate of the validation data of the seal cannot be read.');
            }
        }
        $sources = [];
        foreach ($data['crls'] as $der)
        {
            try
            {
                $sources[] = Crl::source(Crl::read($der));
            }
            catch (Exception $e)
            {
                self::invalid('A CRL of the validation data of the seal cannot be used. ' . $e->getMessage());
            }
        }
        foreach ($data['ocspResponses'] as $der)
        {
            try
            {
                $sources = array_merge($sources, Ocsp::sources(Ocsp::read($der)));
            }
            catch (Exception $e)
            {
                self::invalid('An OCSP response of the validation data of the seal cannot be used. ' . $e->getMessage());
            }
        }

        return ['certificates' => $certificates, 'sources' => $sources];
    }


    /**
     * The signature time-stamp: a valid token, over this signature, of a
     * trusted authority. Returns its time, the chain of the authority, and
     * the DER of the certificates of the token.
     */
    private static function checkTimestamp(array $timestamp, array $tsaCerts, array $embedded)
    {
        try
        {
            $token = Timestamp::verifyToken($timestamp['token']);
        }
        catch (Exception $e)
        {
            self::invalid('The signature time-stamp is not valid. ' . $e->getMessage());
        }
        try
        {
            $imprint = self::imprintOf($timestamp['signatureValue'], $token['imprintAlgorithm'], $timestamp['canonicalization']);
        }
        catch (Exception $e)
        {
            self::invalid('The signature time-stamp cannot be checked. ' . $e->getMessage());
        }
        if (!hash_equals($token['imprint'], $imprint))
        {
            self::invalid('The signature time-stamp is not over the signature value of this seal.');
        }
        $chain = $token['certificate']->getTrustedChain($tsaCerts, array_merge($token['chain'], $embedded));
        if (null === $chain)
        {
            self::invalid('The time-stamping authority is not trusted.');
        }
        $certificates = array_map(function (X509Cert $cert) { return $cert->getDer(); }, array_merge([$token['certificate']], $token['chain']));

        return [$token['time'], $chain, $certificates];
    }


    /**
     * The imprint of the signature time-stamp: the digest of the canonical
     * ds:SignatureValue (EN 319 132-1, 5.3).
     *
     * @internal
     */
    public static function imprintOf(DOMElement $signatureValue, $digest, $canonicalization)
    {
        return hash($digest, self::canonicalize($signatureValue, $canonicalization, 'ds:SignatureValue'), true);
    }


    /**
     * Canonicalize an element in the context of its document. A
     * canonicalization that fails or yields an empty string throws, so that
     * a forged reference cannot be validated by the digest of an empty
     * string. This check must not be removed.
     *
     * @throws Exception If the canonicalization fails or is empty.
     */
    private static function canonicalize(DOMElement $element, $algorithm, $what)
    {
        $exclusive = Algorithms::EXC_C14N === $algorithm || Algorithms::EXC_C14N_COMMENTS === $algorithm;
        $withComments = Algorithms::C14N_COMMENTS === $algorithm || Algorithms::EXC_C14N_COMMENTS === $algorithm;
        $data = $element->C14N($exclusive, $withComments);
        if (!is_string($data) || '' === $data)
        {
            throw new Exception('Canonicalization of ' . $what . ' failed or is empty!');
        }

        return $data;
    }


    /**
     * The layout of the container (EN 319 162-1, 4.4.3.2, Table 5, A.1).
     *
     * @return array The files outside META-INF (name => content), and the
     *         signature file.
     */
    private static function readContainer($archive, $maxEntries, $maxTotalSize)
    {
        try
        {
            $entries = Zip::read($archive, $maxEntries, $maxTotalSize);
        }
        catch (Exception $e)
        {
            self::invalid('The container is not a valid ZIP archive. ' . $e->getMessage());
        }
        $files = [];
        $signatureFiles = [];
        $manifest = null;
        foreach ($entries as $index => $entry)
        {
            if ('mimetype' === $entry['name'])
            {
                if (0 !== $index || 0 !== $entry['method'] || '' !== $entry['extra'])
                {
                    self::invalid('The mimetype file must be the first entry, stored, without extra field.');
                }
                if (self::ASICE_MIMETYPE !== $entry['content'])
                {
                    self::invalid('The container is not an ASiC-E container (mimetype ' . self::quote(self::latin1(substr($entry['content'], 0, 100))) . ').');
                }
            }
            elseif (0 === strpos($entry['name'], 'META-INF/'))
            {
                $base = strtolower(substr($entry['name'], strlen('META-INF/')));
                if (self::MANIFEST_PATH === $entry['name'])
                {
                    $manifest = $entry;
                }
                elseif (false !== strpos($base, 'signatures') && '.xml' === substr($base, -4) && false === strpos($base, '/'))
                {
                    $signatureFiles[] = $entry;
                }
                elseif (preg_match('/signature|timestamp|manifest|evidencerecord/', $base))
                {
                    self::invalid('Unsupported file in META-INF: ' . self::quote($entry['name']) . ' (only XAdES signatures are supported).');
                }
            }
            else
            {
                $files[$entry['name']] = $entry['content'];
            }
        }
        if (null === $manifest)
        {
            self::invalid('The container has no META-INF/manifest.xml.');
        }
        self::checkManifest($manifest['content']);
        if (1 !== count($signatureFiles))
        {
            self::invalid(empty($signatureFiles) ? 'The container has no signature file.' : 'The container has several signature files: one seal per container is supported.');
        }
        if (empty($files))
        {
            self::invalid('The container has no file outside META-INF.');
        }

        return [$files, $signatureFiles[0]['content']];
    }


    /**
     * The manifest must be an ODF manifest. It is not signed: the media
     * types of the seal are those of its signature.
     */
    private static function checkManifest($content)
    {
        try
        {
            $doc = Xml::load($content, 'manifest');
        }
        catch (Exception $e)
        {
            self::invalid('The manifest is not valid: ' . $e->getMessage());
        }
        $root = $doc->documentElement;
        if (null === $root || self::MANIFEST_NS !== $root->namespaceURI || 'manifest' !== $root->localName)
        {
            self::invalid('The manifest is not an ODF manifest.');
        }
    }


    /**
     * The XAdES signature (EN 319 132-1, level B-B): its structure, its
     * references, its signed properties, its value.
     */
    private static function readSignature($content, array $files)
    {
        try
        {
            $doc = Xml::load($content, 'XAdES signature');
        }
        catch (Exception $e)
        {
            self::invalid('The signature file is not valid: ' . $e->getMessage());
        }
        $root = $doc->documentElement;
        if (!self::is($root, self::ASIC_NS, 'XAdESSignatures'))
        {
            self::invalid('The root of the signature file must be asic:XAdESSignatures.');
        }
        $signature = self::sequence($root, [[self::XMLDSIG_NS, 'Signature', 1, PHP_INT_MAX]])['Signature'][0];
        if (1 !== $root->getElementsByTagNameNS(self::XMLDSIG_NS, 'Signature')->length)
        {
            self::invalid('The signature file must hold one ds:Signature: one seal per container is supported.');
        }
        // With unique Ids, the reference to the signed properties has one
        // target: the element whose digest is checked below.
        self::uniqueIds($doc);
        $signatureId = self::attribute($signature, 'Id', 'ds:Signature');

        $parts = self::sequence($signature, [
            [self::XMLDSIG_NS, 'SignedInfo', 1, 1],
            [self::XMLDSIG_NS, 'SignatureValue', 1, 1],
            [self::XMLDSIG_NS, 'KeyInfo', 1, 1],
            [self::XMLDSIG_NS, 'Object', 1, 1],
        ]);
        $signedInfo = $parts['SignedInfo'][0];
        $info = self::sequence($signedInfo, [
            [self::XMLDSIG_NS, 'CanonicalizationMethod', 1, 1],
            [self::XMLDSIG_NS, 'SignatureMethod', 1, 1],
            [self::XMLDSIG_NS, 'Reference', 2, PHP_INT_MAX],
        ]);
        $canonicalization = self::algorithmOf($info['CanonicalizationMethod'][0]);
        if (!in_array($canonicalization, self::CANONICALIZATIONS, true))
        {
            self::invalid('Unsupported canonicalization of SignedInfo: ' . $canonicalization . '.');
        }
        $signatureAlgorithm = self::algorithmOf($info['SignatureMethod'][0]);
        if (!isset(Policy::SIGNATURE_SCHEMES[$signatureAlgorithm]))
        {
            self::invalid('Unsupported signature algorithm: ' . $signatureAlgorithm . '.');
        }
        $scheme = Policy::SIGNATURE_SCHEMES[$signatureAlgorithm];

        // The qualifying properties, in the one ds:Object.
        $qualifying = self::sequence($parts['Object'][0], [[self::XADES_NS, 'QualifyingProperties', 1, 1]])['QualifyingProperties'][0];
        if ($qualifying->getAttribute('Target') !== '#' . $signatureId)
        {
            self::invalid('The Target of QualifyingProperties must be the Id of the signature.');
        }
        $qualifyingParts = self::sequence($qualifying, [
            [self::XADES_NS, 'SignedProperties', 1, 1],
            [self::XADES_NS, 'UnsignedProperties', 0, 1],
        ]);
        $timestamp = null;
        $validationData = null;
        if (!empty($qualifyingParts['UnsignedProperties']))
        {
            $unsignedSignature = self::sequence($qualifyingParts['UnsignedProperties'][0], [[self::XADES_NS, 'UnsignedSignatureProperties', 1, 1]])['UnsignedSignatureProperties'][0];
            // Level LT: the validation data of the time-stamp right after it
            // (5.5.1.2), then those of the signer (5.4.2, 5.4.3).
            $timestamps = self::sequence($unsignedSignature, [
                [self::XADES_NS, 'SignatureTimeStamp', 1, 1],
                [self::XADES141_NS, 'TimeStampValidationData', 0, 1],
                [self::XADES_NS, 'CertificateValues', 0, 1],
                [self::XADES_NS, 'RevocationValues', 0, 1],
            ]);
            $holders = [];
            foreach ($timestamps['TimeStampValidationData'] as $element)
            {
                $holderParts = self::sequence($element, [[self::XADES_NS, 'CertificateValues', 0, 1], [self::XADES_NS, 'RevocationValues', 0, 1]]);
                $holders = array_merge($holders, $holderParts['CertificateValues'], $holderParts['RevocationValues']);
            }
            $holders = array_merge($holders, $timestamps['CertificateValues'], $timestamps['RevocationValues']);
            if (!empty($timestamps['TimeStampValidationData']) && empty($holders))
            {
                self::invalid('The xades141:TimeStampValidationData of the seal is empty.');
            }
            if (!empty($holders))
            {
                $validationData = ['certificates' => [], 'crls' => [], 'ocspResponses' => []];
                foreach ($holders as $holder)
                {
                    if ('CertificateValues' === $holder->localName)
                    {
                        foreach (self::sequence($holder, [[self::XADES_NS, 'EncapsulatedX509Certificate', 1, PHP_INT_MAX]])['EncapsulatedX509Certificate'] as $value)
                        {
                            $validationData['certificates'][] = self::encapsulated($value, 'an EncapsulatedX509Certificate');
                        }
                    }
                    else
                    {
                        $kinds = self::sequence($holder, [[self::XADES_NS, 'CRLValues', 0, 1], [self::XADES_NS, 'OCSPValues', 0, 1]]);
                        if (empty($kinds['CRLValues']) && empty($kinds['OCSPValues']))
                        {
                            self::invalid('Missing xades:CRLValues or xades:OCSPValues in xades:RevocationValues.');
                        }
                        foreach ($kinds['OCSPValues'] as $values)
                        {
                            foreach (self::sequence($values, [[self::XADES_NS, 'EncapsulatedOCSPValue', 1, PHP_INT_MAX]])['EncapsulatedOCSPValue'] as $value)
                            {
                                $validationData['ocspResponses'][] = self::encapsulated($value, 'an EncapsulatedOCSPValue');
                            }
                        }
                        foreach ($kinds['CRLValues'] as $values)
                        {
                            foreach (self::sequence($values, [[self::XADES_NS, 'EncapsulatedCRLValue', 1, PHP_INT_MAX]])['EncapsulatedCRLValue'] as $value)
                            {
                                $validationData['crls'][] = self::encapsulated($value, 'an EncapsulatedCRLValue');
                            }
                        }
                    }
                }
            }
            $timestampParts = self::sequence($timestamps['SignatureTimeStamp'][0], [
                // Required: EN 319 132-1, 4.5, sets no default for the new signatures.
                [self::XMLDSIG_NS, 'CanonicalizationMethod', 1, 1],
                [self::XADES_NS, 'EncapsulatedTimeStamp', 1, 1],
            ]);
            $timestampCanonicalization = self::algorithmOf($timestampParts['CanonicalizationMethod'][0]);
            if (!in_array($timestampCanonicalization, self::CANONICALIZATIONS, true))
            {
                self::invalid('Unsupported canonicalization of the signature time-stamp: ' . $timestampCanonicalization . '.');
            }
            $timestamp = ['token' => self::encapsulated($timestampParts['EncapsulatedTimeStamp'][0], 'the EncapsulatedTimeStamp'), 'canonicalization' => $timestampCanonicalization];
        }
        $signedProperties = $qualifyingParts['SignedProperties'][0];
        $signedPropertiesId = self::attribute($signedProperties, 'Id', 'xades:SignedProperties');
        $properties = self::sequence($signedProperties, [
            [self::XADES_NS, 'SignedSignatureProperties', 1, 1],
            [self::XADES_NS, 'SignedDataObjectProperties', 1, 1],
        ]);
        $signatureProperties = self::sequence($properties['SignedSignatureProperties'][0], [
            [self::XADES_NS, 'SigningTime', 1, 1],
            [self::XADES_NS, 'SigningCertificateV2', 1, 1],
            [self::XADES_NS, 'SignatureProductionPlaceV2', 0, 1],
            [self::XADES_NS, 'SignerRoleV2', 0, 1],
        ]);
        $signingTime = self::parseDateTime(self::text($signatureProperties['SigningTime'][0]));
        $cert = self::sequence($signatureProperties['SigningCertificateV2'][0], [[self::XADES_NS, 'Cert', 1, 1]])['Cert'][0];
        $certDigest = self::sequence($cert, [[self::XADES_NS, 'CertDigest', 1, 1], [self::XADES_NS, 'IssuerSerialV2', 0, 1]])['CertDigest'][0];
        $certDigestParts = self::sequence($certDigest, [[self::XMLDSIG_NS, 'DigestMethod', 1, 1], [self::XMLDSIG_NS, 'DigestValue', 1, 1]]);
        $certDigestAlgorithm = self::digestOf($certDigestParts['DigestMethod'][0]);
        $certDigestValue = self::base64(self::text($certDigestParts['DigestValue'][0]), 'the digest of the signing certificate');
        $formats = self::sequence($properties['SignedDataObjectProperties'][0], [
            [self::XADES_NS, 'DataObjectFormat', 1, PHP_INT_MAX],
            [self::XADES_NS, 'CommitmentTypeIndication', 0, PHP_INT_MAX],
        ])['DataObjectFormat'];
        $mimeTypes = [];
        foreach ($formats as $format)
        {
            $target = $format->getAttribute('ObjectReference');
            $formatParts = self::sequence($format, [
                [self::XADES_NS, 'Description', 0, 1],
                [self::XADES_NS, 'ObjectIdentifier', 0, 1],
                [self::XADES_NS, 'MimeType', 1, 1],
                [self::XADES_NS, 'Encoding', 0, 1],
            ]);
            if ('#' !== substr($target, 0, 1) || array_key_exists(substr($target, 1), $mimeTypes))
            {
                self::invalid('Each DataObjectFormat must point at a reference of its own.');
            }
            $mimeTypes[(string) substr($target, 1)] = self::text($formatParts['MimeType'][0]);
        }

        // The signing certificate, and the chain the seal embeds.
        $x509Data = self::sequence(self::sequence($parts['KeyInfo'][0], [[self::XMLDSIG_NS, 'X509Data', 1, 1]])['X509Data'][0], [
            [self::XMLDSIG_NS, 'X509Certificate', 1, PHP_INT_MAX],
        ])['X509Certificate'];
        $certificates = [];
        foreach ($x509Data as $element)
        {
            $certificates[] = self::base64(self::text($element), 'a certificate of KeyInfo');
        }
        $signerDer = null;
        foreach ($certificates as $der)
        {
            if (hash_equals($certDigestValue, hash($certDigestAlgorithm, $der, true)))
            {
                $signerDer = $der;
                break;
            }
        }
        if (null === $signerDer)
        {
            self::invalid('The signing certificate (SigningCertificateV2) is not in KeyInfo.');
        }
        try
        {
            $signer = new X509Cert(X509Cert::derToPem($signerDer));
            $publicKey = openssl_pkey_get_public($signer->getPem());
            $chain = [];
            foreach ($certificates as $der)
            {
                if ($der !== $signerDer)
                {
                    $chain[] = new X509Cert(X509Cert::derToPem($der));
                }
            }
        }
        catch (Exception $e)
        {
            self::invalid('A certificate of KeyInfo cannot be read.');
        }
        if (false === $publicKey)
        {
            self::invalid('A certificate of KeyInfo cannot be read.');
        }
        self::checkSigningKey($publicKey, $signatureAlgorithm, $scheme);

        // The references: the signed properties once, then each file of the
        // container once.
        $sealed = [];
        $covered = [];
        $propertiesReferences = 0;
        foreach ($info['Reference'] as $reference)
        {
            $referenceParts = self::sequence($reference, [
                [self::XMLDSIG_NS, 'Transforms', 0, 1],
                [self::XMLDSIG_NS, 'DigestMethod', 1, 1],
                [self::XMLDSIG_NS, 'DigestValue', 1, 1],
            ]);
            $digest = self::digestOf($referenceParts['DigestMethod'][0]);
            $expected = self::base64(self::text($referenceParts['DigestValue'][0]), 'a DigestValue');
            $transforms = $referenceParts['Transforms'];
            $uri = $reference->hasAttribute('URI') ? $reference->getAttribute('URI') : null;
            $type = $reference->hasAttribute('Type') ? $reference->getAttribute('Type') : null;
            if (self::SIGNED_PROPERTIES_TYPE === $type)
            {
                $propertiesReferences++;
                if ($uri !== '#' . $signedPropertiesId)
                {
                    self::invalid('The reference of type SignedProperties must point at the signed properties of the signature.');
                }
                if (1 !== count($transforms))
                {
                    self::invalid('The reference to the signed properties must canonicalize them (one Transform).');
                }
                $transform = self::sequence($transforms[0], [[self::XMLDSIG_NS, 'Transform', 1, 1]])['Transform'][0];
                $transformAlgorithm = self::algorithmOf($transform);
                if (!in_array($transformAlgorithm, self::CANONICALIZATIONS, true) || null !== $transform->firstChild)
                {
                    self::invalid('Unsupported transform of the signed properties: ' . $transformAlgorithm . '.');
                }
                try
                {
                    $computed = hash($digest, self::canonicalize($signedProperties, $transformAlgorithm, 'xades:SignedProperties'), true);
                }
                catch (Exception $e)
                {
                    self::invalid($e->getMessage());
                }
                if (!hash_equals($expected, $computed))
                {
                    self::invalid('The signed properties have been altered (digest mismatch).');
                }
                continue;
            }
            if (null !== $type && '' !== $type)
            {
                self::invalid('Unsupported reference type: ' . $type . '.');
            }
            if (!empty($transforms))
            {
                self::invalid('A reference to a file must have no transform.');
            }
            $name = self::fileName($uri);
            if (!array_key_exists($name, $files))
            {
                self::invalid('A reference points at no file of the container: ' . self::quote($uri) . '.');
            }
            if (isset($covered[$name]))
            {
                self::invalid('Two references point at the same file: ' . self::quote($name) . '.');
            }
            $covered[$name] = true;
            if (!hash_equals($expected, hash($digest, $files[$name], true)))
            {
                self::invalid('The file ' . self::quote($name) . ' has been altered (digest mismatch).');
            }
            $referenceId = $reference->getAttribute('Id');
            if ('' === $referenceId || !array_key_exists($referenceId, $mimeTypes))
            {
                self::invalid('The reference to ' . self::quote($name) . ' has no DataObjectFormat.');
            }
            $sealed[] = ['name' => (string) $name, 'mimeType' => $mimeTypes[$referenceId]];
            unset($mimeTypes[$referenceId]);
        }
        if (1 !== $propertiesReferences)
        {
            self::invalid('The signature must have one reference to its signed properties.');
        }
        if (!empty($mimeTypes))
        {
            self::invalid('A DataObjectFormat points at no reference to a file.');
        }
        foreach (array_keys($files) as $name)
        {
            if (!isset($covered[$name]))
            {
                self::invalid('The file ' . self::quote((string) $name) . ' is in the container but not sealed.');
            }
        }

        // The signature value, over SignedInfo as the document holds it.
        $signatureValueElement = $parts['SignatureValue'][0];
        $signatureValue = self::base64(self::text($signatureValueElement), 'the SignatureValue');
        try
        {
            $data = self::canonicalize($signedInfo, $canonicalization, 'ds:SignedInfo');
        }
        catch (Exception $e)
        {
            self::invalid($e->getMessage());
        }
        if (!Policy::verifyValue($scheme, $data, $signatureValue, $publicKey))
        {
            self::invalid('The signature value is not valid.');
        }

        return [
            'files' => $sealed,
            'signingTime' => $signingTime,
            'signer' => $signer,
            'chain' => $chain,
            'keyInfo' => $certificates,
            'validationData' => $validationData,
            'timestamp' => null === $timestamp ? null : $timestamp + ['signatureValue' => $signatureValueElement],
        ];
    }


    /**
     * The key of the signing certificate must suit the signature algorithm,
     * with the sizes the seals accept.
     */
    private static function checkSigningKey($key, $signatureAlgorithm, array $scheme)
    {
        $description = Policy::describeKey($key);
        if ($description['type'] !== $scheme['keyType'])
        {
            self::invalid('The signature algorithm ' . $signatureAlgorithm . ' does not suit the key of the signing certificate.');
        }
        if ('rsa' === $scheme['keyType'] && $description['bits'] < Policy::MIN_RSA_BITS)
        {
            self::invalid('The RSA key of the signing certificate has less than ' . Policy::MIN_RSA_BITS . ' bits.');
        }
        if ('ec' === $scheme['keyType'] && !isset(Policy::CURVES[$description['curve']]))
        {
            self::invalid('The EC key of the signing certificate is not on P-256, P-384 or P-521.');
        }
    }


    /**
     * The name of the file a reference points at: a relative URI, resolved
     * against the root of the container (EN 319 162-1, A.6), each segment
     * percent-decoded. An absolute URI, a query or a fragment points
     * outside.
     */
    private static function fileName($uri)
    {
        if (null === $uri || '' === $uri || '/' === $uri[0] || preg_match('/\A[A-Za-z][A-Za-z0-9+.-]*:/', $uri) || preg_match('/[?#]/', $uri))
        {
            self::invalid('A reference to a file must be a relative URI inside the container: ' . self::quote($uri) . '.');
        }
        $segments = [];
        foreach (explode('/', $uri) as $segment)
        {
            // decodeURIComponent() refuses a malformed escape and what does
            // not decode to UTF-8.
            if (preg_match('/%(?![0-9A-Fa-f]{2})/', $segment))
            {
                self::invalid('A reference to a file is not a valid URI: ' . self::quote($uri) . '.');
            }
            $decoded = rawurldecode($segment);
            if (!preg_match('//u', $decoded))
            {
                self::invalid('A reference to a file is not a valid URI: ' . self::quote($uri) . '.');
            }
            $segments[] = $decoded;
        }

        return implode('/', $segments);
    }


    /**
     * The element children of an element, checked against a sequence of
     * [namespace, name, min, max]; nothing else is allowed.
     *
     * @return array The elements found, by name.
     */
    private static function sequence(DOMElement $parent, array $spec)
    {
        $found = [];
        foreach ($spec as $entry)
        {
            $found[$entry[1]] = [];
        }
        $position = 0;
        for ($node = $parent->firstChild; null !== $node; $node = $node->nextSibling)
        {
            if (XML_TEXT_NODE === $node->nodeType)
            {
                if ('' !== trim($node->nodeValue))
                {
                    self::invalid('Unexpected text in ' . $parent->nodeName . '.');
                }
                continue;
            }
            if (XML_ELEMENT_NODE !== $node->nodeType)
            {
                self::invalid('Unexpected ' . $node->nodeName . ' in ' . $parent->nodeName . '.');
            }
            while ($position < count($spec) && !self::is($node, $spec[$position][0], $spec[$position][1]))
            {
                $position++;
            }
            if ($position >= count($spec))
            {
                self::invalid('Unexpected or misplaced element ' . $node->nodeName . ' in ' . $parent->nodeName . '.');
            }
            $entry = $spec[$position];
            $found[$entry[1]][] = $node;
            if (count($found[$entry[1]]) > $entry[3])
            {
                self::invalid('Too many ' . $node->nodeName . ' in ' . $parent->nodeName . '.');
            }
        }
        foreach ($spec as $entry)
        {
            if (count($found[$entry[1]]) < $entry[2])
            {
                self::invalid('Missing ' . (self::XMLDSIG_NS === $entry[0] ? 'ds' : 'xades') . ':' . $entry[1] . ' in ' . $parent->nodeName . '.');
            }
        }

        return $found;
    }


    private static function is($element, $namespace, $name)
    {
        return $element instanceof DOMElement && $element->namespaceURI === $namespace && $element->localName === $name;
    }


    private static function attribute(DOMElement $element, $name, $what)
    {
        $value = $element->getAttribute($name);
        if ('' === $value)
        {
            self::invalid($what . ' must have an ' . $name . '.');
        }

        return $value;
    }


    private static function algorithmOf(DOMElement $element)
    {
        if (null !== $element->firstChild && 'DigestMethod' !== $element->localName)
        {
            self::invalid('Unsupported parameters of ' . $element->nodeName . '.');
        }

        return self::attribute($element, 'Algorithm', $element->nodeName);
    }


    private static function digestOf(DOMElement $element)
    {
        $algorithm = self::attribute($element, 'Algorithm', $element->nodeName);
        if (!isset(Policy::DIGESTS[$algorithm]) || null !== $element->firstChild)
        {
            self::invalid('Unsupported digest algorithm: ' . $algorithm . '.');
        }

        return Policy::DIGESTS[$algorithm];
    }


    /**
     * The text of an element that holds text only.
     */
    private static function text(DOMElement $element)
    {
        for ($node = $element->firstChild; null !== $node; $node = $node->nextSibling)
        {
            if (XML_TEXT_NODE !== $node->nodeType)
            {
                self::invalid($element->nodeName . ' must hold text only.');
            }
        }

        return $element->textContent;
    }


    /**
     * Base64 content, white space allowed (XML Schema base64Binary).
     */
    private static function base64($value, $what)
    {
        $compact = preg_replace('/\s/', '', $value);
        if ('' === $compact || 0 !== strlen($compact) % 4 || !preg_match('#\A[A-Za-z0-9+/]*={0,2}\z#', $compact))
        {
            self::invalid($what . ' is not valid base64.');
        }

        return base64_decode($compact);
    }


    /**
     * The DER an EncapsulatedPKIData element holds (EN 319 132-1, 5.1.3):
     * base64, of the encoding DER, the default.
     */
    private static function encapsulated(DOMElement $element, $what)
    {
        $encoding = $element->getAttribute('Encoding');
        if ('' !== $encoding && 'http://uri.etsi.org/01903/v1.2.2#DER' !== $encoding)
        {
            self::invalid('Unsupported encoding of ' . $what . ': ' . $encoding . '.');
        }

        return self::base64(self::text($element), $what);
    }


    /**
     * An xsd:dateTime with a time zone, as SigningTime is written.
     *
     * @return float The UNIX time.
     */
    private static function parseDateTime($value)
    {
        if (!preg_match('/\A\s*(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|([+-])(\d{2}):(\d{2}))\s*\z/', $value, $m)
            || !checkdate((int) $m[2], (int) $m[3], (int) $m[1]) || (int) $m[4] > 23 || (int) $m[5] > 59 || (int) $m[6] > 59
            || (isset($m[10]) && ((int) $m[10] > 23 || (int) $m[11] > 59)))
        {
            self::invalid('SigningTime is not a date and time with a time zone: ' . self::quote($value) . '.');
        }
        $time = gmmktime((int) $m[4], (int) $m[5], (int) $m[6], (int) $m[2], (int) $m[3], (int) $m[1]);
        if (isset($m[9]))
        {
            $offset = ((int) $m[10] * 60 + (int) $m[11]) * 60;
            $time += '+' === $m[9] ? -$offset : $offset;
        }
        $fraction = '' !== $m[7] ? floor((float) ('0' . $m[7]) * 1000) / 1000 : 0;

        return $time + $fraction;
    }


    /**
     * The Id attributes of the document, which must be unique: a reference
     * by Id must not have two targets.
     */
    private static function uniqueIds(DOMDocument $doc)
    {
        $ids = [];
        $visit = function (DOMElement $element) use (&$visit, &$ids)
        {
            if ($element->hasAttribute('Id'))
            {
                $id = $element->getAttribute('Id');
                if (isset($ids[$id]))
                {
                    self::invalid('Two elements have the Id ' . self::quote($id) . '.');
                }
                $ids[$id] = true;
            }
            for ($node = $element->firstChild; null !== $node; $node = $node->nextSibling)
            {
                if ($node instanceof DOMElement)
                {
                    $visit($node);
                }
            }
        };
        $visit($doc->documentElement);
    }


    /** The media types written for the most common extensions; any other file is application/octet-stream. */
    const MEDIA_TYPES = [
        'pdf' => 'application/pdf',
        'txt' => 'text/plain',
        'md' => 'text/markdown',
        'html' => 'text/html',
        'htm' => 'text/html',
        'xml' => 'application/xml',
        'json' => 'application/json',
        'csv' => 'text/csv',
        'png' => 'image/png',
        'jpg' => 'image/jpeg',
        'jpeg' => 'image/jpeg',
        'svg' => 'image/svg+xml',
        'odt' => 'application/vnd.oasis.opendocument.text',
        'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xlsx' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    ];

    /** A media type: type/subtype, then parameters (RFC 6838, 4.2). */
    const MEDIA_TYPE = '/\A[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}(\s*;\s*[A-Za-z0-9!#$&^_.+-]+=("[^"\\\\\r\n]*"|[A-Za-z0-9!#$&^_.+-]+))*\z/';


    /**
     * Seal files: an ASiC-E container that holds them, its manifest, and a
     * XAdES-B-B signature over them.
     *
     * @param array $files The files to seal, in the order of the container:
     *        each an array with 'name' (its path in the container, `/`
     *        separated, outside `META-INF/`), 'content' (its bytes) and,
     *        optionally, 'mimeType' (by default, from the extension of its
     *        name, see MEDIA_TYPES).
     *
     * @param string $signKey The private key: the path of a PEM file, or its
     *        content.
     *
     * @param string $signCert The certificate of the key: the path of a PEM
     *        file, or its content; the certificates that follow the first
     *        one are embedded as its chain.
     *
     * @param string|null $signKeyPassword The password of the key, or NULL.
     *
     * @param array $options
     *        - 'chain': certificates of the path of the signing certificate,
     *          to embed for the verifier (the intermediate CAs): paths of
     *          PEM files or PEM contents;
     *        - 'signatureAlgorithm': by default, RSA-PSS for an RSA key,
     *          ECDSA for an EC key (its digest after the curve);
     *        - 'digestAlgorithm': the digest of the sealed files, the signed
     *          properties and the signing certificate (default SHA-256);
     *        - 'signingTime': the time the signer claims, a UNIX time
     *          (default: now), written to the second.
     *
     * @return string The container (`.asice`).
     *
     * @throws Exception On a misuse: no file, a name or a media type that
     *         cannot be sealed, a key that does not match the certificate,
     *         an algorithm that does not suit the key, a certificate that
     *         cannot sign at the signing time.
     */
    public static function createSeal(array $files, $signKey, $signCert, $signKeyPassword, array $options = [])
    {
        if (empty($files))
        {
            throw new Exception('Seal: no file to seal.');
        }
        $sealed = [];
        foreach (array_values($files) as $index => $file)
        {
            $sealed[] = self::checkFile($file, $index);
        }

        $certPem = self::readPem($signCert);
        if (null === $certPem)
        {
            throw new Exception('Seal: unable to read the signing certificate (' . self::describe($signCert) . ').');
        }
        $certificates = self::extractCertificates($certPem);
        foreach (isset($options['chain']) ? (array) $options['chain'] : [] as $source)
        {
            $pem = self::readPem($source);
            if (null === $pem)
            {
                throw new Exception('Seal: unable to read a chain certificate (' . self::describe($source) . ').');
            }
            $certificates = array_merge($certificates, self::extractCertificates($pem));
        }
        if (empty($certificates))
        {
            throw new Exception('Seal: the signing certificate holds no certificate.');
        }
        $certificateDer = base64_decode($certificates[0]);
        $certificate = new X509Cert(X509Cert::derToPem($certificateDer));

        $keyPem = self::readPem($signKey);
        if (null === $keyPem)
        {
            throw new Exception('Seal: unable to read the signing key (' . self::describe($signKey) . ').');
        }
        $privateKey = null === $signKeyPassword ? @openssl_pkey_get_private($keyPem) : @openssl_pkey_get_private($keyPem, $signKeyPassword);
        if (false === $privateKey)
        {
            throw new Exception('Seal: unable to load the signing key (wrong password?).');
        }
        if (!openssl_x509_check_private_key($certificate->getPem(), $privateKey))
        {
            throw new Exception('Seal: the signing key does not match the signing certificate.');
        }
        $signatureAlgorithm = isset($options['signatureAlgorithm']) ? $options['signatureAlgorithm'] : self::defaultSignatureAlgorithm($privateKey);
        self::checkKey($privateKey, $signatureAlgorithm);
        $scheme = Policy::SIGNATURE_SCHEMES[$signatureAlgorithm];

        $digestAlgorithm = isset($options['digestAlgorithm']) ? $options['digestAlgorithm'] : Algorithms::SHA256;
        if (!isset(Policy::DIGESTS[$digestAlgorithm]))
        {
            throw new Exception('Seal: unsupported digest algorithm ' . $digestAlgorithm . '.');
        }
        $digest = Policy::DIGESTS[$digestAlgorithm];

        $signingTime = isset($options['signingTime']) ? $options['signingTime'] : time();
        if (!is_int($signingTime) && !is_float($signingTime))
        {
            throw new Exception('Seal: invalid signing time.');
        }
        $signingTime = (int) floor($signingTime);
        if ($signingTime < (int) $certificate->getValidFrom('U') || $signingTime > (int) $certificate->getValidTo('U'))
        {
            throw new Exception('Seal: the signing certificate is not valid at the signing time.');
        }
        if (!$certificate->canSign())
        {
            throw new Exception('Seal: the key usage of the signing certificate does not allow signing.');
        }

        // Identifiers of the signature, of its references, of its signed properties.
        $id = 'S-' . bin2hex(random_bytes(16));
        $hash = function ($data) use ($digest) { return base64_encode(hash($digest, $data, true)); };
        $method = function ($name, $algorithm) { return '<ds:' . $name . ' Algorithm="' . self::escapeAttribute($algorithm) . '"/>'; };

        $fileReferences = '';
        $formats = '';
        foreach ($sealed as $index => $file)
        {
            $reference = $id . '-R' . ($index + 1);
            $fileReferences .= '<ds:Reference Id="' . $reference . '" URI="' . self::escapeAttribute(self::referenceUri($file['name'])) . '">'
                . $method('DigestMethod', $digestAlgorithm)
                . '<ds:DigestValue>' . $hash($file['content']) . '</ds:DigestValue></ds:Reference>';
            $formats .= '<xades:DataObjectFormat ObjectReference="#' . $reference . '">'
                . '<xades:MimeType>' . self::escapeText($file['mimeType']) . '</xades:MimeType></xades:DataObjectFormat>';
        }
        $signedProperties = '<xades:SignedProperties Id="' . $id . '-SP">'
            . '<xades:SignedSignatureProperties>'
            . '<xades:SigningTime>' . gmdate('Y-m-d\TH:i:s\Z', $signingTime) . '</xades:SigningTime>'
            . '<xades:SigningCertificateV2><xades:Cert><xades:CertDigest>'
            . $method('DigestMethod', $digestAlgorithm)
            . '<ds:DigestValue>' . $hash($certificateDer) . '</ds:DigestValue>'
            . '</xades:CertDigest></xades:Cert></xades:SigningCertificateV2>'
            . '</xades:SignedSignatureProperties>'
            . '<xades:SignedDataObjectProperties>' . $formats . '</xades:SignedDataObjectProperties>'
            . '</xades:SignedProperties>';
        $keyInfo = '';
        foreach ($certificates as $cert)
        {
            $keyInfo .= '<ds:X509Certificate>' . $cert . '</ds:X509Certificate>';
        }

        $document = function ($propertiesDigest, $signatureValue) use ($id, $method, $signatureAlgorithm, $fileReferences, $digestAlgorithm, $keyInfo, $signedProperties)
        {
            return '<?xml version="1.0" encoding="UTF-8"?>'
                . '<asic:XAdESSignatures xmlns:asic="' . self::ASIC_NS . '">'
                . '<ds:Signature xmlns:ds="' . self::XMLDSIG_NS . '" Id="' . $id . '">'
                . '<ds:SignedInfo>'
                . $method('CanonicalizationMethod', Algorithms::EXC_C14N)
                . $method('SignatureMethod', $signatureAlgorithm)
                . $fileReferences
                . '<ds:Reference Type="' . self::SIGNED_PROPERTIES_TYPE . '" URI="#' . $id . '-SP">'
                . '<ds:Transforms>' . $method('Transform', Algorithms::EXC_C14N) . '</ds:Transforms>'
                . $method('DigestMethod', $digestAlgorithm)
                . '<ds:DigestValue>' . $propertiesDigest . '</ds:DigestValue></ds:Reference>'
                . '</ds:SignedInfo>'
                . '<ds:SignatureValue Id="' . $id . '-SV">' . $signatureValue . '</ds:SignatureValue>'
                . '<ds:KeyInfo><ds:X509Data>' . $keyInfo . '</ds:X509Data></ds:KeyInfo>'
                . '<ds:Object><xades:QualifyingProperties xmlns:xades="' . self::XADES_NS . '" Target="#' . $id . '">' . $signedProperties . '</xades:QualifyingProperties></ds:Object>'
                . '</ds:Signature></asic:XAdESSignatures>';
        };

        // The digest of the signed properties, then the signature of
        // SignedInfo, each computed over the document as it will be read.
        $doc = Xml::load($document('', ''), 'XAdES signature');
        $propertiesDigest = $hash(self::canonicalize($doc->getElementsByTagNameNS(self::XADES_NS, 'SignedProperties')->item(0), Algorithms::EXC_C14N, 'xades:SignedProperties'));
        $doc = Xml::load($document($propertiesDigest, ''), 'XAdES signature');
        $data = self::canonicalize($doc->getElementsByTagNameNS(self::XMLDSIG_NS, 'SignedInfo')->item(0), Algorithms::EXC_C14N, 'ds:SignedInfo');
        $signatureValue = base64_encode(self::signValue($scheme, $data, $privateKey));

        $entries = [['name' => 'mimetype', 'content' => self::ASICE_MIMETYPE, 'stored' => true]];
        foreach ($sealed as $file)
        {
            $entries[] = ['name' => $file['name'], 'content' => $file['content']];
        }
        $entries[] = ['name' => self::MANIFEST_PATH, 'content' => self::manifest($sealed)];
        $entries[] = ['name' => self::SIGNATURE_PATH, 'content' => $document($propertiesDigest, $signatureValue)];

        return Zip::write($entries, $signingTime);
    }


    /**
     * Sign with a scheme of the seals: RSASSA-PSS (see RsaPss), RSA PKCS#1
     * v1.5, or ECDSA, its value written as r || s (RFC 4050).
     */
    private static function signValue(array $scheme, $data, $privateKey)
    {
        if ('pss' === $scheme['padding'])
        {
            return RsaPss::sign($data, $privateKey, $scheme['hash']);
        }
        $signature = '';
        if (!openssl_sign($data, $signature, $privateKey, $scheme['hash']))
        {
            throw new Exception('Seal: the signature failed.');
        }
        if ('ecdsa' === $scheme['padding'])
        {
            $signature = Policy::derToRaw($signature, Policy::describeKey($privateKey)['curve']);
        }

        return $signature;
    }


    /**
     * The reference to a file of the container: a relative URI, each
     * segment of its path percent-encoded as encodeURIComponent() does.
     *
     * @internal
     */
    public static function referenceUri($name)
    {
        $segments = [];
        foreach (explode('/', $name) as $segment)
        {
            $segments[] = strtr(rawurlencode($segment), ['%21' => '!', '%2A' => '*', '%27' => "'", '%28' => '(', '%29' => ')']);
        }

        return implode('/', $segments);
    }


    /**
     * The ODF manifest of the container (EN 319 162-1, A.4): the container
     * itself, then each sealed file.
     */
    private static function manifest(array $files)
    {
        $entries = '';
        foreach ($files as $file)
        {
            $entries .= '<manifest:file-entry manifest:full-path="' . self::escapeAttribute($file['name']) . '" manifest:media-type="' . self::escapeAttribute($file['mimeType']) . '"/>';
        }

        return '<?xml version="1.0" encoding="UTF-8"?>'
            . '<manifest:manifest xmlns:manifest="' . self::MANIFEST_NS . '" manifest:version="1.2">'
            . '<manifest:file-entry manifest:full-path="/" manifest:media-type="' . self::ASICE_MIMETYPE . '"/>'
            . $entries
            . '</manifest:manifest>';
    }


    private static function checkFile($file, $index)
    {
        if (!is_array($file) || !isset($file['name'], $file['content']) || !is_string($file['name']) || !is_string($file['content']))
        {
            throw new Exception('Seal: file ' . ($index + 1) . ' must have a name and a content (strings).');
        }
        $name = $file['name'];
        if ('mimetype' === $name || 0 === strpos($name, 'META-INF/') || 'META-INF' === $name)
        {
            throw new Exception('Seal: ' . self::quote($name) . ' is reserved by the container.');
        }
        if (class_exists('Normalizer') && \Normalizer::normalize($name, \Normalizer::FORM_C) !== $name)
        {
            throw new Exception('Seal: the name ' . self::quote($name) . ' is not in Unicode normalization form C.');
        }
        if (!preg_match('//u', $name))
        {
            throw new Exception('Seal: the name of file ' . ($index + 1) . ' is not UTF-8.');
        }
        $mimeType = isset($file['mimeType']) ? $file['mimeType'] : null;
        if (null === $mimeType)
        {
            $extension = preg_match('/\.([^.\/]+)\z/', $name, $match) ? strtolower($match[1]) : null;
            $mimeType = null !== $extension && isset(self::MEDIA_TYPES[$extension]) ? self::MEDIA_TYPES[$extension] : 'application/octet-stream';
        }
        if (!is_string($mimeType) || !preg_match(self::MEDIA_TYPE, $mimeType))
        {
            throw new Exception('Seal: invalid media type for ' . self::quote($name) . '.');
        }

        return ['name' => $name, 'content' => $file['content'], 'mimeType' => $mimeType];
    }


    private static function defaultSignatureAlgorithm($key)
    {
        $description = Policy::describeKey($key);
        if ('rsa' === $description['type'])
        {
            return Algorithms::RSA_PSS_SHA256;
        }
        if ('ec' === $description['type'] && isset(Policy::CURVES[$description['curve']]))
        {
            return Policy::CURVES[$description['curve']];
        }
        throw new Exception('Seal: the signing key must be an RSA key or an EC key on P-256, P-384 or P-521.');
    }


    private static function checkKey($key, $signatureAlgorithm)
    {
        if (!isset(Policy::SIGNATURE_SCHEMES[$signatureAlgorithm]))
        {
            throw new Exception('Seal: unsupported signature algorithm ' . $signatureAlgorithm . '.');
        }
        $scheme = Policy::SIGNATURE_SCHEMES[$signatureAlgorithm];
        $description = Policy::describeKey($key);
        if ($description['type'] !== $scheme['keyType'])
        {
            throw new Exception('Seal: the signature algorithm ' . $signatureAlgorithm . ' needs an ' . strtoupper($scheme['keyType']) . ' key.');
        }
        if ('rsa' === $scheme['keyType'] && $description['bits'] < Policy::MIN_RSA_BITS)
        {
            throw new Exception('Seal: RSA keys of less than ' . Policy::MIN_RSA_BITS . ' bits are refused.');
        }
        if ('ec' === $scheme['keyType'] && !isset(Policy::CURVES[$description['curve']]))
        {
            throw new Exception('Seal: the EC key must be on P-256, P-384 or P-521.');
        }
    }


    /**
     * The content of a PEM source: the path of a file, or PEM content; NULL
     * if it cannot be read.
     */
    private static function readPem($source)
    {
        if (!is_string($source))
        {
            return null;
        }
        if (false !== strpos($source, '-----BEGIN'))
        {
            return $source;
        }
        $content = is_file($source) && is_readable($source) ? file_get_contents($source) : false;

        return false === $content ? null : $content;
    }


    private static function describe($source)
    {
        return is_string($source) ? (false !== strpos($source, '-----BEGIN') ? 'PEM content' : $source) : gettype($source);
    }


    /**
     * The base64 of each certificate of a PEM content, its line breaks
     * removed.
     */
    private static function extractCertificates($pem)
    {
        $certificates = [];
        $data = null;
        foreach (explode("\n", $pem) as $line)
        {
            if (null === $data)
            {
                if (0 === strpos($line, '-----BEGIN CERTIFICATE'))
                {
                    $data = '';
                }
            }
            elseif (0 === strpos($line, '-----END CERTIFICATE'))
            {
                $certificates[] = $data;
                $data = null;
            }
            else
            {
                $data .= trim($line);
            }
        }

        return $certificates;
    }


    /**
     * Escape text content as libxml writes it.
     */
    private static function escapeText($text)
    {
        return strtr($text, ['&' => '&amp;', '<' => '&lt;', '>' => '&gt;', "\r" => '&#xD;']);
    }


    /**
     * Escape an attribute value (in double quotes) as libxml writes it.
     */
    private static function escapeAttribute($text)
    {
        return strtr($text, ['&' => '&amp;', '<' => '&lt;', '>' => '&gt;', '"' => '&quot;', "\r" => '&#13;', "\n" => '&#10;', "\t" => '&#9;']);
    }


    /** The canonicalization of ds:SignatureValue for its time-stamp. */
    const TIMESTAMP_CANONICALIZATION = Algorithms::EXC_C14N;

    const CRL_DISTRIBUTION_POINTS = '2.5.29.31';
    const AUTHORITY_INFO_ACCESS = '1.3.6.1.5.5.7.1.1';
    const ID_AD_OCSP = '1.3.6.1.5.5.7.48.1';


    /**
     * The time-stamp request of a seal (RFC 3161 TimeStampReq, DER), to send
     * to a time-stamping authority, with the media type
     * `application/timestamp-query`. The library sends no request: the
     * caller sends it to the authority of its choice, and gives the response
     * to addSignatureTimestamp().
     *
     * @param string $container The container.
     *
     * @param string $digestAlgorithm The digest of the imprint: SHA256
     *        (default), SHA384 or SHA512 of Algorithms.
     *
     * @return string The request.
     *
     * @throws Exception If the container does not hold one XAdES signature.
     */
    public static function timestampRequest($container, $digestAlgorithm = Algorithms::SHA256)
    {
        if (!isset(Policy::DIGESTS[$digestAlgorithm]))
        {
            throw new Exception('Time-stamp: unsupported digest algorithm ' . $digestAlgorithm . '.');
        }
        $digest = Policy::DIGESTS[$digestAlgorithm];
        $located = self::locate(Zip::read($container));

        return Timestamp::buildRequest(self::imprintOf($located['signatureValue'], $digest, self::TIMESTAMP_CANONICALIZATION), $digest);
    }


    /**
     * Add the signature time-stamp of a response to a seal: level B becomes
     * level T (EN 319 132-1, 5.3). The signed parts of the signature file
     * are left byte for byte as they are: the unsigned properties are
     * inserted after the signed ones.
     *
     * @param string $container The container.
     *
     * @param string $response The response of the authority (RFC 3161
     *        TimeStampResp, DER).
     *
     * @param array $options 'tsaCertPath' (required): the trusted
     *        certificates of the time-stamping authority, its root and its
     *        intermediate CAs if the token does not embed them.
     *
     * @return string The container, with the time-stamp in its signature.
     *
     * @throws Exception If the authority did not grant the time-stamp, if
     *         the token is not valid, is not over this seal, or its
     *         authority is not trusted, or if the seal is already
     *         time-stamped.
     */
    public static function addSignatureTimestamp($container, $response, array $options)
    {
        $tsaCerts = self::readTrusted(isset($options['tsaCertPath']) ? $options['tsaCertPath'] : null, 'tsaCertPath', 'Time-stamp');
        $entries = Zip::read($container);
        $located = self::locate($entries);
        if ($located['signedProperties']->parentNode->getElementsByTagNameNS(self::XADES_NS, 'UnsignedProperties')->length > 0)
        {
            throw new Exception('Time-stamp: the seal already has unsigned properties.');
        }

        $token = Timestamp::readResponse($response);
        $verified = Timestamp::verifyToken($token);
        if (!hash_equals($verified['imprint'], self::imprintOf($located['signatureValue'], $verified['imprintAlgorithm'], self::TIMESTAMP_CANONICALIZATION)))
        {
            throw new Exception('Time-stamp: the token is not over the signature of this seal.');
        }
        if (null === $verified['certificate']->getTrustedChain($tsaCerts, $verified['chain']))
        {
            throw new Exception('Time-stamp: the time-stamping authority is not trusted.');
        }

        // Inserted after the closing tag of SignedProperties, the namespaces
        // declared on the inserted elements themselves.
        $xml = $entries[$located['index']]['content'];
        $closing = '</' . $located['signedProperties']->nodeName . '>';
        $at = strpos($xml, $closing);
        if (false === $at || false !== strpos($xml, $closing, $at + 1))
        {
            throw new Exception('Time-stamp: the end of the signed properties cannot be told in the signature file.');
        }
        // An Id of its own, as DSS writes one, unless the signature has no Id to derive it from.
        $id = $located['signature']->getAttribute('Id') . '-TS';
        $idAttribute = '-TS' === $id || false !== strpos($xml, '"' . $id . '"') ? '' : ' Id="' . self::escapeAttribute($id) . '"';
        $unsigned = '<xades:UnsignedProperties xmlns:xades="' . self::XADES_NS . '"><xades:UnsignedSignatureProperties>'
            . '<xades:SignatureTimeStamp' . $idAttribute . '>'
            . '<ds:CanonicalizationMethod xmlns:ds="' . self::XMLDSIG_NS . '" Algorithm="' . self::TIMESTAMP_CANONICALIZATION . '"/>'
            . '<xades:EncapsulatedTimeStamp>' . base64_encode($token) . '</xades:EncapsulatedTimeStamp>'
            . '</xades:SignatureTimeStamp></xades:UnsignedSignatureProperties></xades:UnsignedProperties>';
        $extended = substr($xml, 0, $at + strlen($closing)) . $unsigned . substr($xml, $at + strlen($closing));
        Xml::load($extended, 'XAdES signature');

        return self::rewriteEntries($entries, $located['index'], $extended, (int) floor($verified['time']));
    }


    /**
     * The revocation data a seal needs: for each certificate of the chains
     * of the signer and of the time-stamping authority, their trust anchors
     * excepted, the CRL to fetch, and the OCSP request to send if the
     * certificate names a responder. One of the two suffices for a
     * certificate. Also useful at level B or T, to get the data
     * verifySeal() needs.
     *
     * @param string $container The container.
     *
     * @param array $options 'caCertPath' and 'tsaCertPath', as for
     *        verifySeal() (both required).
     *
     * @return array 'crls': the CRLs to fetch, one per certificate, each
     *         with 'certificate', 'issuer' (X509Cert) and 'urls' (the http
     *         and https URLs of its CRL distribution points, empty if it
     *         names none); 'ocsp': the OCSP requests to send, each with
     *         'certificate', 'issuer', 'urls' (of its responders) and
     *         'request' (the OCSPRequest, DER, to POST with the media type
     *         `application/ocsp-request`).
     *
     * @throws Exception If the seal is not valid, revocation aside.
     */
    public static function validationDataRequests($container, array $options)
    {
        $inspected = self::inspectForExtension($container, ['revocation' => false] + $options);
        $crls = [];
        $ocsp = [];
        foreach ([$inspected['chain'], $inspected['tsaChain']] as $chain)
        {
            for ($index = 0; null !== $chain && $index + 1 < count($chain); $index++)
            {
                $certificate = $chain[$index];
                $issuer = $chain[$index + 1];
                foreach ($crls as $request)
                {
                    if ($request['certificate']->getDer() === $certificate->getDer())
                    {
                        continue 2;
                    }
                }
                $crls[] = ['certificate' => $certificate, 'issuer' => $issuer, 'urls' => self::distributionPoints($certificate)];
                $responders = self::ocspResponders($certificate);
                if (!empty($responders))
                {
                    $ocsp[] = ['certificate' => $certificate, 'issuer' => $issuer, 'urls' => $responders, 'request' => Ocsp::buildRequest($certificate, $issuer)];
                }
            }
        }

        return ['crls' => $crls, 'ocsp' => $ocsp];
    }


    /**
     * Add to a seal of level T the certificates, CRLs and OCSP responses
     * that validate it: it becomes a seal of level LT (EN 319 132-1, 5.4,
     * 5.5.1, 6.3), which a third party can validate without reaching the
     * CAs. The answers are checked before they are embedded, only those that
     * told the status of a certificate; they must be issued after the
     * time-stamp. The signed parts of the signature file are left byte for
     * byte as they are.
     *
     * What goes where: xades141:TimeStampValidationData, right after the
     * time-stamp, the certificates of the chain of the time-stamping
     * authority the token does not hold, and their CRLs or OCSP responses;
     * xades:CertificateValues, the certificates of the chain of the signer
     * ds:KeyInfo does not hold, its trust anchor included;
     * xades:RevocationValues, a CRL or an OCSP response for each certificate
     * of that chain, its trust anchor excepted. Each one is embedded once.
     *
     * @param string $container The container.
     *
     * @param array $options 'caCertPath' and 'tsaCertPath', as for
     *        verifySeal(), and at least one of 'crls' (in DER or PEM) and
     *        'ocspResponses' (DER), fetched as validationDataRequests()
     *        lists.
     *
     * @return string The container, with the validation data in its
     *         signature.
     *
     * @throws Exception If the seal is not valid, is not of level T, or if
     *         the data do not tell the status of every certificate after the
     *         time-stamp.
     */
    public static function addValidationData($container, array $options)
    {
        if (!isset($options['crls']) && !isset($options['ocspResponses']))
        {
            throw new Exception("Validation data: the option 'crls' or 'ocspResponses' is required.");
        }
        $inspected = self::inspectForExtension($container, array_intersect_key($options, ['caCertPath' => 1, 'tsaCertPath' => 1, 'crls' => 1, 'ocspResponses' => 1]));
        $level = $inspected['result']->getLevel();
        if ('T' !== $level)
        {
            throw new Exception('B' === $level ? 'Validation data: the seal must be time-stamped first (level T).' : 'Validation data: the seal already has validation data.');
        }

        // Each certificate, CRL and OCSP response once: the signer's first,
        // then what the time-stamping authority needs besides.
        $ders = function (array $certificates) { return array_map(function (X509Cert $cert) { return $cert->getDer(); }, $certificates); };
        $held = array_merge($inspected['keyInfo'], $inspected['tokenCertificates']);
        $signerCertificates = self::unique($ders($inspected['chain']), $inspected['keyInfo']);
        $tsaCertificates = self::unique($ders($inspected['tsaChain']), array_merge($held, $signerCertificates));
        $sourcesOf = function (array $sources, $kind)
        {
            return array_map(function (RevocationSource $source) { return $source->der; },
                array_values(array_filter($sources, function (RevocationSource $source) use ($kind) { return $kind === $source->kind; })));
        };
        $signerCrls = self::unique($sourcesOf($inspected['signerSources'], 'crl'), []);
        $signerOcsp = self::unique($sourcesOf($inspected['signerSources'], 'ocsp'), []);
        $tsaCrls = self::unique($sourcesOf($inspected['tsaSources'], 'crl'), $signerCrls);
        $tsaOcsp = self::unique($sourcesOf($inspected['tsaSources'], 'ocsp'), $signerOcsp);

        $entries = Zip::read($container);
        $located = self::locate($entries, 'Validation data');
        $properties = $located['signature']->getElementsByTagNameNS(self::XADES_NS, 'UnsignedSignatureProperties');
        $xml = $entries[$located['index']]['content'];
        $closing = '</' . (1 === $properties->length ? $properties->item(0)->nodeName : '') . '>';
        $at = strpos($xml, $closing);
        if (1 !== $properties->length || false === $at || false !== strpos($xml, $closing, $at + 1))
        {
            throw new Exception('Validation data: the end of the unsigned signature properties cannot be told in the signature file.');
        }
        $timestampData = 0 === count($tsaCertificates) + count($tsaCrls) + count($tsaOcsp) ? ''
            : '<xades141:TimeStampValidationData xmlns:xades141="' . self::XADES141_NS . '">' . self::certificateValues($tsaCertificates) . self::revocationValues($tsaCrls, $tsaOcsp) . '</xades141:TimeStampValidationData>';
        $added = $timestampData . self::certificateValues($signerCertificates) . self::revocationValues($signerCrls, $signerOcsp);
        $extended = substr($xml, 0, $at) . $added . substr($xml, $at);
        Xml::load($extended, 'XAdES signature');
        $result = self::rewriteEntries($entries, $located['index'], $extended, time());

        // The seal must now validate with what it embeds alone.
        $check = self::inspectSeal($result, array_intersect_key($options, ['caCertPath' => 1, 'tsaCertPath' => 1]));
        if ('LT' !== $check['result']->getLevel())
        {
            throw new Exception('Validation data: the extended seal does not validate by itself. '
                . (null !== $check['result']->getError() ? $check['result']->getError() : 'Level ' . $check['result']->getLevel() . '.'));
        }

        return $result;
    }


    /**
     * inspectSeal(), an invalid seal turned into an exception.
     */
    private static function inspectForExtension($container, array $options)
    {
        if (!isset($options['tsaCertPath']))
        {
            throw new Exception("Validation data: the option 'tsaCertPath' is required.");
        }
        try
        {
            $inspected = self::inspectSeal($container, $options, true);
        }
        catch (Exception $e)
        {
            throw new Exception('Validation data: ' . $e->getMessage());
        }
        $error = $inspected['result']->getError();
        if (null !== $error)
        {
            // verifySeal() suggests 'revocation' => false, which the extension has not.
            throw new Exception('Validation data: the seal is not valid. ' . preg_replace("/ \\(the option 'revocation' => false [^)]*\\)\\z/", '', $error));
        }

        return $inspected;
    }


    /**
     * The signature file of a seal, and its elements the extensions need.
     *
     * @return array 'index' (of the entry), 'doc', 'signature',
     *         'signatureValue', 'signedProperties'.
     */
    private static function locate(array $entries, $what = 'Time-stamp')
    {
        $found = [];
        foreach ($entries as $index => $entry)
        {
            if (preg_match('/\AMETA-INF\/[^\/]*signatures[^\/]*\.xml\z/i', $entry['name']))
            {
                $found[] = $index;
            }
        }
        if (1 !== count($found))
        {
            throw new Exception($what . ': the container must hold one signature file.');
        }
        $doc = Xml::load($entries[$found[0]]['content'], 'XAdES signature');
        $signatures = $doc->getElementsByTagNameNS(self::XMLDSIG_NS, 'Signature');
        if (1 !== $signatures->length)
        {
            throw new Exception($what . ': the signature file must hold one ds:Signature.');
        }
        $signature = $signatures->item(0);
        $values = [];
        foreach ($signature->childNodes as $node)
        {
            if ($node instanceof DOMElement && 'SignatureValue' === $node->localName && self::XMLDSIG_NS === $node->namespaceURI)
            {
                $values[] = $node;
            }
        }
        $properties = $signature->getElementsByTagNameNS(self::XADES_NS, 'SignedProperties');
        if (1 !== count($values) || 1 !== $properties->length)
        {
            throw new Exception($what . ': the signature has no SignatureValue or no SignedProperties.');
        }

        return ['index' => $found[0], 'doc' => $doc, 'signature' => $signature, 'signatureValue' => $values[0], 'signedProperties' => $properties->item(0)];
    }


    /**
     * The entries of a container written again, one replaced.
     */
    private static function rewriteEntries(array $entries, $index, $content, $modified)
    {
        $inputs = [];
        foreach ($entries as $i => $entry)
        {
            $inputs[] = ['name' => $entry['name'], 'content' => $i === $index ? $content : $entry['content'], 'stored' => 0 === $entry['method']];
        }

        return Zip::write($inputs, $modified);
    }


    /**
     * The PEM contents of trusted certificates given to an extension.
     */
    private static function readTrusted($source, $name, $what)
    {
        $sources = is_array($source) ? $source : [$source];
        if (null === $source || empty($sources))
        {
            throw new Exception($what . ": the option '" . $name . "' is required.");
        }
        $pems = [];
        foreach ($sources as $item)
        {
            $pem = self::readPem($item);
            if (null === $pem)
            {
                throw new Exception($what . ': cannot read the certificate file ' . self::describe($item) . '.');
            }
            $pems[] = $pem;
        }

        return $pems;
    }


    /**
     * The DER encodings of a list, without duplicates nor those of $held.
     */
    private static function unique(array $list, array $held)
    {
        $kept = [];
        foreach ($list as $der)
        {
            if (!in_array($der, $held, true) && !in_array($der, $kept, true))
            {
                $kept[] = $der;
            }
        }

        return $kept;
    }


    private static function certificateValues(array $certificates)
    {
        if (empty($certificates))
        {
            return '';
        }
        $values = '';
        foreach ($certificates as $der)
        {
            $values .= '<xades:EncapsulatedX509Certificate>' . base64_encode($der) . '</xades:EncapsulatedX509Certificate>';
        }

        return '<xades:CertificateValues xmlns:xades="' . self::XADES_NS . '">' . $values . '</xades:CertificateValues>';
    }


    private static function revocationValues(array $crls, array $responses)
    {
        if (0 === count($crls) + count($responses))
        {
            return '';
        }
        $values = function ($name, array $list)
        {
            if (empty($list))
            {
                return '';
            }
            $encapsulated = '';
            foreach ($list as $der)
            {
                $encapsulated .= '<xades:Encapsulated' . $name . 'Value>' . base64_encode($der) . '</xades:Encapsulated' . $name . 'Value>';
            }
            return '<xades:' . $name . 'Values>' . $encapsulated . '</xades:' . $name . 'Values>';
        };

        return '<xades:RevocationValues xmlns:xades="' . self::XADES_NS . '">' . $values('CRL', $crls) . $values('OCSP', $responses) . '</xades:RevocationValues>';
    }


    /**
     * The http and https URLs of the OCSP responders of a certificate (RFC
     * 5280, 4.2.2.1).
     */
    private static function ocspResponders(X509Cert $certificate)
    {
        $extension = $certificate->getExtension(self::AUTHORITY_INFO_ACCESS);
        if (null === $extension)
        {
            return [];
        }
        $urls = [];
        try
        {
            foreach (Der::childrenOf(Der::readElement($extension['value']), Der::SEQUENCE) as $description)
            {
                $parts = Der::childrenOf($description, Der::SEQUENCE);
                if (isset($parts[0], $parts[1]) && self::ID_AD_OCSP === Der::decodeOid($parts[0]) && 0x86 === $parts[1]['tag'] && preg_match('#\Ahttps?://#i', $parts[1]['content']))
                {
                    $urls[] = $parts[1]['content'];
                }
            }
        }
        catch (Exception $e)
        {
            return [];
        }

        return $urls;
    }


    /**
     * The http and https URLs of the CRL distribution points of a
     * certificate (RFC 5280, 4.2.1.13). A distribution point restricted to
     * some reasons or with a CRL issuer of its own is left out: its CRLs are
     * partial or indirect, which this library does not use.
     */
    private static function distributionPoints(X509Cert $certificate)
    {
        $extension = $certificate->getExtension(self::CRL_DISTRIBUTION_POINTS);
        if (null === $extension)
        {
            return [];
        }
        $urls = [];
        try
        {
            foreach (Der::childrenOf(Der::readElement($extension['value']), Der::SEQUENCE) as $point)
            {
                $fields = Der::childrenOf($point, Der::SEQUENCE);
                // distributionPoint [0], reasons [1], cRLIssuer [2].
                foreach ($fields as $field)
                {
                    if (0xa0 !== $field['tag'])
                    {
                        continue 2;
                    }
                }
                foreach ($fields as $field)
                {
                    foreach (Der::readElements($field['content']) as $name)
                    {
                        // fullName [0] GeneralNames, of which uniformResourceIdentifier [6].
                        if (0xa0 !== $name['tag'])
                        {
                            continue;
                        }
                        foreach (Der::readElements($name['content']) as $general)
                        {
                            if (0x86 === $general['tag'] && preg_match('#\Ahttps?://#i', $general['content']))
                            {
                                $urls[] = $general['content'];
                            }
                        }
                    }
                }
            }
        }
        catch (Exception $e)
        {
            return [];
        }

        return $urls;
    }
}
