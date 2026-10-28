<?php
/**
 * X509Cert.php
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
namespace webcoder31\ezxmldsig\core;

// Use.
use DateTime;
use DateTimeZone;
use Exception;

/**
 * Analyze an X.509 certificate.
 *
 * The `X509Cert` class provides a set of convenient methods for extracting
 * essential information contained in an X.509 certificate and for performing
 * some useful checks. Every signature of a certificate is verified by
 * OpenSSL. isTrustedBy() leaves the whole chain of trust to OpenSSL, at the
 * current date; getTrustedChain(), which the seals use at the time of a
 * time-stamp, builds the chain and checks the dates and the constraints of
 * the CAs itself, from the DER of the certificates, with the rules of
 * OpenSSL. This class belongs to the core, shared by the tokens
 * (`XMLDSigToken`) and the seals.
 */
class X509Cert
{
    /** @var string The X.509 certificate in PEM format. */
    private $cert;

    /** @var array The X.509 information of the certificate. */
    private $x509Info;

    /** @var array|null The fields read from the DER of the certificate (see der()). */
    private $der = null;

    /** Extensions, by OID. */
    const OID_KEY_USAGE = '2.5.29.15';
    const OID_BASIC_CONSTRAINTS = '2.5.29.19';
    const OID_NAME_CONSTRAINTS = '2.5.29.30';
    const OID_SUBJECT_KEY_ID = '2.5.29.14';
    const OID_AUTHORITY_KEY_ID = '2.5.29.35';

    /** The key usages, by their bit in the extension. */
    const KEY_USAGE_DIGITAL_SIGNATURE = 0;
    const KEY_USAGE_NON_REPUDIATION = 1;
    const KEY_USAGE_KEY_CERT_SIGN = 5;
    const KEY_USAGE_CRL_SIGN = 6;

    /**
     * The extensions whose criticality the verification of a chain accepts.
     * They are those OpenSSL handles (`X509_supported_extension()`), but name
     * constraints, which it enforces and this library does not: a CA
     * certificate that has them is refused (see getTrustedChain()), and the
     * extensions of IP addresses and AS numbers (RFC 3779) and of proxy
     * certificates, which it does not handle either.
     */
    const HANDLED_CRITICAL_EXTENSIONS = [
        '2.16.840.1.113730.1.1', // Netscape certificate type
        self::OID_KEY_USAGE,
        '2.5.29.17', // subject alternative name
        self::OID_BASIC_CONSTRAINTS,
        '2.5.29.32', // certificate policies
        '2.5.29.31', // CRL distribution points
        '2.5.29.37', // extended key usage
        '1.3.6.1.5.5.7.48.1.5', // OCSP no check
        '2.5.29.36', // policy constraints
        '2.5.29.33', // policy mappings
        '2.5.29.54', // inhibit any policy
    ];

    /**
     * The key types that may sign with each signature algorithm. OpenSSL
     * takes a certificate whose signature algorithm does not suit the key of
     * a certificate as not issued by it.
     */
    const SIGNATURE_KEY_TYPES = [
        '1.2.840.113549.1.1.4' => ['rsa'], // md5WithRSAEncryption
        '1.2.840.113549.1.1.5' => ['rsa'], // sha1WithRSAEncryption
        '1.2.840.113549.1.1.11' => ['rsa'], // sha256WithRSAEncryption
        '1.2.840.113549.1.1.12' => ['rsa'], // sha384WithRSAEncryption
        '1.2.840.113549.1.1.13' => ['rsa'], // sha512WithRSAEncryption
        '1.2.840.113549.1.1.14' => ['rsa'], // sha224WithRSAEncryption
        '1.2.840.113549.1.1.10' => ['rsa'], // RSASSA-PSS
        '1.2.840.10045.4.1' => ['ec'], // ecdsa-with-SHA1
        '1.2.840.10045.4.3.1' => ['ec'], // ecdsa-with-SHA224
        '1.2.840.10045.4.3.2' => ['ec'], // ecdsa-with-SHA256
        '1.2.840.10045.4.3.3' => ['ec'], // ecdsa-with-SHA384
        '1.2.840.10045.4.3.4' => ['ec'], // ecdsa-with-SHA512
        '1.2.840.10040.4.3' => ['dsa'], // dsa-with-SHA1
        '2.16.840.1.101.3.4.3.1' => ['dsa'], // dsa-with-SHA224
        '2.16.840.1.101.3.4.3.2' => ['dsa'], // dsa-with-SHA256
    ];

    /** The string types OpenSSL compares names by in canonical form
    (`ASN1_MASK_CANON`): UTF8String, BMPString, UniversalString,
    PrintableString, T61String, IA5String, VisibleString. */
    const CANONICAL_STRING_TAGS = [0x0c, 0x1e, 0x1c, 0x13, 0x14, 0x16, 0x1a];

    /** The deepest chain OpenSSL builds by default. */
    const MAX_CHAIN_LENGTH = 100;


    /**
     * Create a new X509Cert object.
     *
     * @param string $cert An X.509 certificate (public key) in PEM format.
     *
     * @throws Exception
     */
    public function __construct($cert)
    {
        // Check that OpenSSL can read the certificate.
        if (!is_string($cert) || false === @openssl_x509_read($cert))
        {
            throw new Exception("Invalid certificate!");
        }

        // Get X.509 information.
        $x509Info = openssl_x509_parse($cert);
        if ($x509Info === false)
        {
            $msg = "Failed to extract X.509 information from certificate!";
            throw new Exception($msg);
        }

        // Store the PEM certificate.
        $this->cert = $cert;

        // Store X.509 information.
        $this->x509Info = $x509Info;
    }


    /**
     * Get the certificate (public key) in PEM format.
     *
     * @return String The certificate (public key) in PEM format.
     */
    public function getPem()
    {
        return $this->cert;
    }


    /**
     * Get the fingerprint of the certificate: the hash of its DER encoding.
     *
     * Two certificates are the same certificate if, and only if, their
     * fingerprints are equal.
     *
     * @param string $algorithm The hash algorithm. Default: 'sha256'.
     *
     * @return string The fingerprint, as a lowercase hexadecimal string.
     *
     * @throws Exception
     */
    public function getFingerprint($algorithm = 'sha256')
    {
        $fingerprint = openssl_x509_fingerprint($this->cert, $algorithm);
        if (false === $fingerprint)
        {
            throw new Exception("Failed to compute the fingerprint of the certificate!");
        }

        return $fingerprint;
    }


    /**
     * Get the issuer information of the certificate.
     *
     * @return array The issuer information of the certificate.
     */
    public function getIssuer()
    {
        return $this->x509Info['issuer'];
    }


    /**
     * Get the subject information of the certificate.
     *
     * @return array The subject information of the certificate.
     */
    public function getSubject()
    {
        return $this->x509Info['subject'];
    }


    /**
     * Get the Distinguished Name of the certificate.
     *
     * @return string The Distinguished Name of the certificate.
     */
    public function getDN()
    {
        return $this->x509Info['name'];
    }


    /**
     * Get the UTC date from which the certificate is valid.
     *
     * @param string $dateFormat The format of the returned date.
     *        Default: 'ymdHise'
     *
     * @return string|false The date from which the certificate is valid,
     *         FALSE if $dateFormat is invalid.
     */
    public function getValidFrom($dateFormat = 'ymdHise')
    {
        return $this->_date('validFrom_time_t')->format($dateFormat);
    }


    /**
     * Get the UTC date to which the certificate is valid.
     *
     * @param string $dateFormat The format of the returned date.
     *        Default: 'ymdHise'
     *
     * @return string|false The date to which the certificate is valid,
     *         FALSE if $dateFormat is invalid.
     */
    public function getValidTo($dateFormat = 'ymdHise')
    {
        return $this->_date('validTo_time_t')->format($dateFormat);
    }


    /**
     * Get a date of the certificate, from the UNIX timestamp OpenSSL gives
     * for it.
     *
     * openssl_x509_parse() also gives the dates as written in the
     * certificate, "validFrom" and "validTo", but X.509 writes a date before
     * 2050 as UTCTime (YYMMDDHHMMSSZ) and from 2050 on as GeneralizedTime
     * (YYYYMMDDHHMMSSZ): read with one format, the other gives no date. The
     * timestamps "validFrom_time_t" and "validTo_time_t" hold both.
     *
     * @param string $field "validFrom_time_t" or "validTo_time_t".
     *
     * @return DateTime The date, in UTC.
     */
    private function _date($field)
    {
        $date = new DateTime('@' . (int) $this->x509Info[$field]);
        $date->setTimezone(new DateTimeZone('UTC'));

        return $date;
    }


    /**
     * Indicates whether the certificate is out of date or not.
     *
     * @return boolean TRUE if embedded certificate is out of date,
     *         FALSE otherwise.
     */
    public function isOutOfDate()
    {
        // Compare UNIX timestamps (see _date()).
        $now = time();

        return $now < $this->_date('validFrom_time_t')->getTimestamp()
            || $now > $this->_date('validTo_time_t')->getTimestamp();
    }


    /**
     * Indicates whether the key usage of the certificate allows it to sign
     * data.
     *
     * The "keyUsage" extension, when the certificate has one, must allow
     * "digitalSignature" or "nonRepudiation". A certificate without this
     * extension is not restricted.
     *
     * @return boolean TRUE if the certificate may sign data, FALSE otherwise.
     */
    public function canSign()
    {
        if (!isset($this->x509Info['extensions']['keyUsage']))
        {
            return true;
        }

        $keyUsage = array_map('trim', explode(',', $this->x509Info['extensions']['keyUsage']));

        return in_array('Digital Signature', $keyUsage, true)
            || in_array('Non Repudiation', $keyUsage, true);
    }


    /**
     * Check that the certificate is trusted: OpenSSL builds and verifies its
     * chain up to a certificate of the given CA files.
     *
     * Every certificate of the given files is trusted, and the chain is built
     * from these certificates only. OpenSSL verifies the signature of each
     * link, the validity dates of every certificate of the chain at the
     * current date, that each issuer is a CA (basic constraints, key usage,
     * path length) and that the chain ends at a self-signed certificate of
     * the given files. A chain that stops at an intermediate CA is rejected:
     * to trust the certificates issued by an intermediate CA, give its
     * certificate and the certificates up to its root (in one file or in
     * several). A certificate issued by another intermediate CA of the same
     * root is then rejected, since the chain cannot be built without that
     * other intermediate certificate.
     *
     * @param string|array $caCertPaths The path, or the list of paths, of PEM
     *        files that hold the trusted CA certificates.
     *
     * @return boolean TRUE if the chain of the certificate has been verified,
     *         FALSE otherwise.
     *
     * @throws Exception
     */
    public function isTrustedBy($caCertPaths)
    {
        $caCertPaths = (array) $caCertPaths;
        if (empty($caCertPaths))
        {
            throw new Exception("No CA certificate file to verify the certificate chain!");
        }
        foreach ($caCertPaths as $caCertPath)
        {
            if (!is_string($caCertPath) || !is_file($caCertPath) || !is_readable($caCertPath))
            {
                throw new Exception("Cannot read CA certificate file! File: " . (is_string($caCertPath) ? $caCertPath : gettype($caCertPath)));
            }
        }

        // Only the given CA certificates may be trusted, not those of the
        // system. When the list given to openssl_x509_checkpurpose() holds no
        // directory, PHP adds the default CA directory of OpenSSL (that of
        // the system, or the one named by the environment variable
        // SSL_CERT_DIR) to the trusted certificates, and the default CA file
        // when the list holds no file: any public CA would then be a trust
        // anchor. An empty directory, created for this call, is therefore
        // always added to the list. This guard must not be removed.
        $emptyDir = self::createEmptyDirectory();
        try
        {
            // X509_PURPOSE_ANY: the chain is verified, but no purpose is
            // required from the certificate (see canSign() for its key
            // usage). openssl_x509_checkpurpose() returns -1 on error: only
            // TRUE is a success.
            $caInfo = array_merge(array_values($caCertPaths), [$emptyDir]);
            return true === openssl_x509_checkpurpose($this->cert, X509_PURPOSE_ANY, $caInfo);
        }
        finally
        {
            @rmdir($emptyDir);
        }
    }


    /**
     * Create an empty directory, readable by its owner only, in the
     * temporary directory of the system.
     *
     * @return string The path of the directory.
     *
     * @throws Exception If the directory cannot be created.
     */
    static private function createEmptyDirectory()
    {
        // mkdir() fails if the path exists (even as a link): the directory is
        // the one created here, hence empty.
        $path = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'ezxmldsig-ca-' . bin2hex(random_bytes(16));
        if (!@mkdir($path, 0700))
        {
            throw new Exception("Cannot create an empty directory to verify the certificate chain in " . sys_get_temp_dir() . "!");
        }

        return $path;
    }


    /**
     * Check the origin of the certificate.
     *
     * Verify that the X.509 certificate has been issued by the given CA
     * certificate: OpenSSL verifies the signature of the certificate with the
     * public key of the CA certificate, the issuer name of the certificate
     * must be the subject name of the CA certificate, and the CA certificate
     * must be a CA ("CA:TRUE" basic constraint and, if it has a "keyUsage"
     * extension, "keyCertSign").
     *
     * Only this link is checked: neither the validity dates nor the chain of
     * the CA certificate. Use `isTrustedBy()` to verify the whole chain.
     *
     * NOTE: More than one CA certificate can give a positive result,
     *        some CAs re-issue signing certificates after having only
     *        changed the expiration dates.
     *        Note that it also works with self-signed CA certificates. In this
     *        case, pass the X.509 certificate itself to the function.
     *
     * @param string $caCert The certificate (in PEM format) corresponding to
     *        the private key that is supposed to be used by the CA to sign the X.509
     *        certificate.
     *
     * @return boolean TRUE if origin of the X.509 certificate has been
     *         validated, FALSE otherwise.
     *
     * @throws Exception
     */
    public function isValidCA($caCert)
    {
        if (!is_string($caCert) || false === @openssl_x509_read($caCert))
        {
            throw new Exception("Invalid CA certificate!");
        }

        $caInfo = openssl_x509_parse($caCert);
        if ($caInfo === false)
        {
            throw new Exception("Failed to extract X.509 information from CA certificate!");
        }

        // The CA certificate must be allowed to issue certificates.
        $basicConstraints = isset($caInfo['extensions']['basicConstraints']) ? $caInfo['extensions']['basicConstraints'] : '';
        if (!in_array('CA:TRUE', array_map('trim', explode(',', $basicConstraints)), true))
        {
            return false;
        }
        if (isset($caInfo['extensions']['keyUsage']))
        {
            $keyUsage = array_map('trim', explode(',', $caInfo['extensions']['keyUsage']));
            if (!in_array('Certificate Sign', $keyUsage, true))
            {
                return false;
            }
        }

        // The certificate must name the CA as its issuer.
        if ($this->x509Info['issuer'] !== $caInfo['subject'])
        {
            return false;
        }

        // The signature of the certificate must verify with the public key of
        // the CA. openssl_x509_verify() returns 1 (valid), 0 (invalid) or -1
        // (error): only 1 is a success.
        return 1 === openssl_x509_verify($this->cert, $caCert);
    }


    /**
     * Convert PEM encoded X.509 certificate to DER encoding.
     *
     * @param string $pemCertificate PEM encoded X.509 certificate.
     *
     * @return string|false DER encoded X.509 certificate on success, 
     *         FALSE on failure.
     */
    static public function pemToDer($pemCertificate)
    {
        if (!is_string($pemCertificate))
        {
            // Invalid parameter.
            return false;
        }

        $pattern = '/(-----((BEGIN)|(END)) CERTIFICATE-----)/';
        $base64Content = preg_split($pattern, $pemCertificate);
        if (!isset($base64Content[1]))
        {
            // Invalid PEM certificate.
            return false;
        }

        // Returns the DER encoded certificate.
        return base64_decode($base64Content[1]);
    }


    /**
     * Convert DER encoded X.509 certificate to PEM encoding.
     *
     * The base64 is written in lines of 64 characters (RFC 7468): the PEM is
     * the one OpenSSL writes for the same certificate.
     *
     * @param string $derCertificate DER encoded X.509 certificate.
     *
     * @return string|false PEM encoded X.509 certificate on success, 
     *         FALSE on failure.
     */
    static public function derToPem($derCertificate)
    {
        if (!is_string($derCertificate))
        {
            // Invalid parameter.
            return false;
        }

        $b64DerCert = base64_encode($derCertificate);
        $pem  = "-----BEGIN CERTIFICATE-----\n";
        // Lines of 64 characters, as RFC 7468 (section 2) requires and
        // OpenSSL writes.
        $pem .= implode("\n", str_split($b64DerCert, 64)) . "\n";
        $pem .= "-----END CERTIFICATE-----\n";

        return $pem;
    }


    /**
     * Indicates whether a name (the subject or the issuer of a certificate,
     * as returned by `openssl_x509_parse()`) holds the expected fields.
     *
     * Each expected field must be present with the very same value: character
     * case is significant, and a field repeated in the name (e.g. two "OU")
     * is an array of its values.
     *
     * @param array $name The name to check.
     *
     * @param array $expected The expected fields.
     *
     * @return boolean TRUE if every expected field matches, FALSE otherwise.
     *
     * @internal
     */
    public static function matchesName($name, $expected)
    {
        foreach ($expected as $key => $value)
        {
            if (!isset($name[$key]) || $name[$key] !== $value)
            {
                return false;
            }
        }

        return true;
    }


    /**
     * The DER encoding of the certificate.
     *
     * @return string The DER.
     */
    public function getDer()
    {
        return self::pemToDer($this->cert);
    }


    /**
     * The serial number, as unsigned big-endian bytes.
     *
     * @return string The bytes.
     */
    public function getSerialNumber()
    {
        $serial = $this->der()['serial'];

        return strlen($serial) > 1 && "\0" === $serial[0] ? substr($serial, 1) : $serial;
    }


    /**
     * The DER encoding of the issuer name, as a CRL names its issuer.
     *
     * @return string The DER.
     */
    public function getRawIssuer()
    {
        return $this->der()['rawIssuer'];
    }


    /**
     * The DER encoding of the subject name.
     *
     * @return string The DER.
     */
    public function getRawSubject()
    {
        return $this->der()['rawSubject'];
    }


    /**
     * An extension, by its OID.
     *
     * @param string $oid The OID, in its dotted form.
     *
     * @return array|null 'critical' (boolean) and 'value' (the DER of its
     *         value, the content of its OCTET STRING), or NULL.
     */
    public function getExtension($oid)
    {
        $extensions = $this->der()['extensions'];

        return isset($extensions[$oid]) ? $extensions[$oid] : null;
    }


    /**
     * Indicates whether the key usage of the certificate, if it has one,
     * allows it to sign CRLs.
     *
     * @return boolean TRUE if it may sign CRLs.
     */
    public function canSignCrls()
    {
        $keyUsage = $this->der()['keyUsage'];

        return null === $keyUsage || !empty($keyUsage[self::KEY_USAGE_CRL_SIGN]);
    }


    /**
     * Indicates whether the certificate is a CA by its basic constraints.
     *
     * @return boolean TRUE if it is a CA.
     */
    public function isCA()
    {
        $basicConstraints = $this->der()['basicConstraints'];

        return null !== $basicConstraints && $basicConstraints['ca'];
    }


    /**
     * The chain of the certificate, from it to its root, built and verified
     * from the given CA certificates as OpenSSL does for `isTrustedBy()`, at
     * the current date or at another one; NULL if the certificate is not
     * trusted.
     *
     * Every given certificate is trusted, and the chain is built from these
     * certificates only (and the `$untrusted` ones), never from those of the
     * system. A certificate is taken as the issuer of another one when its
     * subject is the issuer of the other one (names compared in the canonical
     * form of OpenSSL), when the authority key identifier of the other one
     * matches it, and when its key suits the signature algorithm of the other
     * one. Then:
     *
     * - OpenSSL verifies the signature of each link (but the root's own);
     * - every certificate of the chain, the root included, is valid at the
     *   date of the verification;
     * - every issuer is a CA: basic constraints with "CA:TRUE" and, if it has
     *   a key usage, "keyCertSign"; the root may also be a CA by its key
     *   usage alone, or by being self-signed and of version 1;
     * - the path length of each CA is respected;
     * - no certificate has a critical extension the verification does not
     *   handle, nor a repeated or malformed extension.
     *
     * A chain that stops at an intermediate CA is rejected: the root must be
     * one of the CA certificates. Name constraints are not enforced: a CA
     * certificate that has them is rejected, where OpenSSL would enforce
     * them.
     *
     * @param string|array $caCerts The CA certificates: paths of PEM files,
     *        or PEM contents, each of which may hold several certificates.
     *
     * @param array $untrusted Certificates (X509Cert) the chain may be built
     *        with, after the CA certificates, without being trusted: the
     *        intermediate CAs a signature embeds.
     *
     * @param int|null $at The UNIX time the certificates must be valid at;
     *        NULL for the current time.
     *
     * @return array|null The chain (X509Cert), or NULL.
     *
     * @throws Exception If a CA certificate file cannot be read.
     */
    public function getTrustedChain($caCerts, array $untrusted = [], $at = null)
    {
        $sources = (array) $caCerts;
        if (empty($sources))
        {
            throw new Exception("No CA certificate file to verify the certificate chain!");
        }
        $trusted = [];
        foreach ($sources as $source)
        {
            $pem = self::readPemSource($source);
            if (null === $pem)
            {
                throw new Exception("Cannot read CA certificate file! File: " . (is_string($source) ? $source : gettype($source)));
            }
            // A file OpenSSL cannot load as a whole trusts nothing.
            if (!preg_match_all('/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s', $pem, $blocks))
            {
                return null;
            }
            foreach ($blocks[0] as $block)
            {
                try
                {
                    $trusted[] = new X509Cert($block);
                }
                catch (Exception $e)
                {
                    return null;
                }
            }
        }

        $time = null === $at ? time() : (int) floor($at);
        $chain = $this->buildChain($trusted, $untrusted, $time);

        return null !== $chain && self::verifyChain($chain, $time) ? $chain : null;
    }


    /**
     * The content of a PEM source: a path of a file, or PEM content.
     *
     * @return string|null The content, or NULL if the file cannot be read.
     */
    private static function readPemSource($source)
    {
        if (!is_string($source))
        {
            return null;
        }
        if (false !== strpos($source, '-----BEGIN'))
        {
            return $source;
        }
        if (!is_file($source) || !is_readable($source))
        {
            return null;
        }
        $content = file_get_contents($source);

        return false === $content ? null : $content;
    }


    /**
     * Build the chain of the certificate from the trusted certificates, as
     * OpenSSL does: from the certificate, take as issuer the first trusted
     * certificate, then the first untrusted one, that may have issued it and
     * is valid at the given time (or else the last one that may have issued
     * it), until a self-signed certificate, which must be a trusted one.
     *
     * @return array|null The chain, from this certificate to its root, or NULL.
     */
    private function buildChain(array $trusted, array $untrusted, $time)
    {
        $known = array_merge($trusted, $untrusted);
        $chain = [$this];
        for (;;)
        {
            $last = $chain[count($chain) - 1];
            if ($last->isSelfSigned())
            {
                foreach ($trusted as $cert)
                {
                    if ($cert->getDer() === $last->getDer())
                    {
                        return $chain;
                    }
                }
                return null;
            }
            if (count($chain) >= self::MAX_CHAIN_LENGTH)
            {
                return null;
            }
            $issuer = null;
            $lastCandidate = null;
            foreach ($known as $cert)
            {
                if ($last->mayBeIssuedBy($cert))
                {
                    $lastCandidate = $cert;
                    if (null === $issuer && $cert->isValidAt($time))
                    {
                        $issuer = $cert;
                    }
                }
            }
            $issuer = null !== $issuer ? $issuer : $lastCandidate;
            if (null === $issuer)
            {
                return null;
            }
            $chain[] = $issuer;
        }
    }


    /**
     * Verify a chain built by buildChain(), as OpenSSL does (see
     * getTrustedChain()).
     */
    private static function verifyChain(array $chain, $time)
    {
        $pathLength = 0;
        foreach ($chain as $i => $cert)
        {
            if (!$cert->isValidAt($time))
            {
                return false;
            }
            // openssl_x509_verify() returns 1 (valid), 0 (invalid) or -1
            // (error): only 1 is a success.
            if (isset($chain[$i + 1]) && 1 !== openssl_x509_verify($cert->cert, $chain[$i + 1]->cert))
            {
                return false;
            }

            $der = $cert->der();
            if ($der['invalidExtension'])
            {
                return false;
            }
            foreach ($der['extensions'] as $oid => $extension)
            {
                if ($extension['critical'] && !in_array($oid, self::HANDLED_CRITICAL_EXTENSIONS, true))
                {
                    return false;
                }
            }
            if (0 === $i)
            {
                continue;
            }

            if (isset($der['extensions'][self::OID_NAME_CONSTRAINTS]))
            {
                return false;
            }
            // An intermediate CA must be one by its basic constraints; the
            // root may be one otherwise.
            $kind = $cert->caKind();
            if (0 === $kind || (isset($chain[$i + 1]) && 1 !== $kind))
            {
                return false;
            }
            // The path length of a CA counts the CAs below it, but the
            // self-issued ones.
            $limit = null === $der['basicConstraints'] ? null : $der['basicConstraints']['pathLength'];
            if ($i > 1 && null !== $limit && $pathLength > $limit)
            {
                return false;
            }
            if (!$cert->isSelfIssued())
            {
                $pathLength++;
            }
        }

        return true;
    }


    /**
     * Indicates whether the certificate may have been issued by another one,
     * as OpenSSL tells it to build a chain (`ossl_x509_likely_issued()`): the
     * issuer of the certificate is the subject of the other one, its
     * authority key identifier, if any, matches the other one, and the key of
     * the other one suits its signature algorithm. Neither the signature nor
     * the key usage of the other one are checked here.
     */
    private function mayBeIssuedBy(X509Cert $issuer)
    {
        $der = $this->der();
        $issuerDer = $issuer->der();
        if ($der['invalidExtension'] || $issuerDer['invalidExtension'])
        {
            return false;
        }
        if (!self::sameName($der['issuer'], $issuerDer['subject']))
        {
            return false;
        }
        $akid = $der['authorityKeyId'];
        if (null !== $akid)
        {
            if (null !== $akid['keyId'] && null !== $issuerDer['subjectKeyId'] && $akid['keyId'] !== $issuerDer['subjectKeyId'])
            {
                return false;
            }
            if (null !== $akid['serial'] && $akid['serial'] !== $issuerDer['serial'])
            {
                return false;
            }
            if (null !== $akid['issuer'] && !self::sameName($akid['issuer'], $issuerDer['issuer']))
            {
                return false;
            }
        }
        $keyTypes = isset(self::SIGNATURE_KEY_TYPES[$der['signatureAlgorithm']]) ? self::SIGNATURE_KEY_TYPES[$der['signatureAlgorithm']] : [];

        return in_array($issuer->keyType(), $keyTypes, true);
    }


    /**
     * Indicates whether the certificate is self-signed, as OpenSSL tells it
     * (its signature is not verified).
     */
    private function isSelfSigned()
    {
        return $this->mayBeIssuedBy($this);
    }


    /**
     * Indicates whether the certificate is self-issued: its subject is its
     * issuer, whatever key signed it.
     */
    private function isSelfIssued()
    {
        $der = $this->der();

        return self::sameName($der['issuer'], $der['subject']);
    }


    /**
     * Indicates whether the certificate is valid at a UNIX time, as OpenSSL
     * tells it: it is no longer valid at its very date of expiry.
     */
    private function isValidAt($time)
    {
        return $time >= (int) $this->x509Info['validFrom_time_t'] && $time < (int) $this->x509Info['validTo_time_t'];
    }


    /**
     * Indicates how the certificate is a CA, as OpenSSL does
     * (`X509_check_ca()`): 0 if it is not, 1 by its basic constraints, 3 by
     * being self-signed and of version 1, 4 by its key usage alone.
     */
    private function caKind()
    {
        $der = $this->der();
        if (null !== $der['keyUsage'] && empty($der['keyUsage'][self::KEY_USAGE_KEY_CERT_SIGN]))
        {
            return 0;
        }
        if (null !== $der['basicConstraints'])
        {
            return $der['basicConstraints']['ca'] ? 1 : 0;
        }
        if (1 === $der['version'] && $this->isSelfSigned())
        {
            return 3;
        }

        return null !== $der['keyUsage'] ? 4 : 0;
    }


    /**
     * The type of the public key: "rsa", "ec", "dsa", or NULL for another
     * one.
     */
    private function keyType()
    {
        $key = @openssl_pkey_get_public($this->cert);
        $details = false === $key ? false : @openssl_pkey_get_details($key);
        if (false === $details)
        {
            return null;
        }
        switch ($details['type'])
        {
            case OPENSSL_KEYTYPE_RSA:
                return 'rsa';
            case OPENSSL_KEYTYPE_EC:
                return 'ec';
            case OPENSSL_KEYTYPE_DSA:
                return 'dsa';
            default:
                return null;
        }
    }


    /**
     * The fields of the certificate read from its DER, once: those the
     * OpenSSL extension of PHP does not give.
     *
     * TBSCertificate: [0] version (absent: v1), serialNumber, signature,
     * issuer, validity, subject, subjectPublicKeyInfo, [1] issuerUniqueID,
     * [2] subjectUniqueID, [3] extensions. An extension the verification of
     * a chain reads that cannot be decoded makes the certificate invalid, as
     * for OpenSSL.
     *
     * @throws Exception If the DER cannot be read.
     */
    private function der()
    {
        if (null !== $this->der)
        {
            return $this->der;
        }
        try
        {
            $tbs = Der::childrenOf(Der::childrenOf(Der::readElement($this->getDer()), Der::SEQUENCE)[0], Der::SEQUENCE);
            $version = 1;
            if (isset($tbs[0]) && 0xa0 === $tbs[0]['tag'])
            {
                $version = Der::decodeSmallInteger(Der::readElement(array_shift($tbs)['content'])) + 1;
            }
            if (count($tbs) < 6 || Der::INTEGER !== $tbs[0]['tag'])
            {
                throw new Exception('DER: malformed certificate.');
            }
            $info = [
                'version' => $version,
                'serial' => $tbs[0]['content'],
                'signatureAlgorithm' => Der::decodeOid(Der::childrenOf($tbs[1], Der::SEQUENCE)[0]),
                'rawIssuer' => Der::reencode($tbs[2]),
                'issuer' => self::readName($tbs[2]),
                'rawSubject' => Der::reencode($tbs[4]),
                'subject' => self::readName($tbs[4]),
            ];
            $extensionsElement = null;
            foreach (array_slice($tbs, 6) as $element)
            {
                if (0xa3 === $element['tag'])
                {
                    $extensionsElement = $element;
                }
            }
            list($info['extensions'], $info['invalidExtension']) = self::readExtensions($extensionsElement);
        }
        catch (Exception $e)
        {
            throw new Exception("Failed to extract X.509 information from certificate!");
        }

        $info += ['keyUsage' => null, 'basicConstraints' => null, 'subjectKeyId' => null, 'authorityKeyId' => null];
        $extensions = $info['extensions'];
        try
        {
            if (isset($extensions[self::OID_KEY_USAGE]))
            {
                $info['keyUsage'] = Der::decodeBits(Der::readElement($extensions[self::OID_KEY_USAGE]['value']));
            }
            if (isset($extensions[self::OID_BASIC_CONSTRAINTS]))
            {
                $info['basicConstraints'] = self::readBasicConstraints($extensions[self::OID_BASIC_CONSTRAINTS]['value']);
                // A path length without CA is invalid for OpenSSL.
                if (null !== $info['basicConstraints']['pathLength'] && !$info['basicConstraints']['ca'])
                {
                    $info['invalidExtension'] = true;
                }
            }
            if (isset($extensions[self::OID_SUBJECT_KEY_ID]))
            {
                $element = Der::readElement($extensions[self::OID_SUBJECT_KEY_ID]['value']);
                if (Der::OCTET_STRING !== $element['tag'])
                {
                    throw new Exception('DER: malformed subject key identifier.');
                }
                $info['subjectKeyId'] = $element['content'];
            }
            if (isset($extensions[self::OID_AUTHORITY_KEY_ID]))
            {
                $info['authorityKeyId'] = self::readAuthorityKeyId($extensions[self::OID_AUTHORITY_KEY_ID]['value']);
            }
        }
        catch (Exception $e)
        {
            $info['invalidExtension'] = true;
        }

        return $this->der = $info;
    }


    /**
     * Read the extensions: by OID, 'critical' and 'value'; and whether one
     * is repeated.
     */
    private static function readExtensions($element)
    {
        $extensions = [];
        $invalid = false;
        if (null === $element)
        {
            return [$extensions, $invalid];
        }
        foreach (Der::childrenOf(Der::readElement($element['content']), Der::SEQUENCE) as $extension)
        {
            $fields = Der::childrenOf($extension, Der::SEQUENCE);
            if (count($fields) < 2 || count($fields) > 3 || Der::OCTET_STRING !== $fields[count($fields) - 1]['tag'])
            {
                throw new Exception('DER: malformed extension.');
            }
            $oid = Der::decodeOid($fields[0]);
            if (isset($extensions[$oid]))
            {
                $invalid = true;
            }
            $extensions[$oid] = [
                'critical' => 3 === count($fields) ? Der::decodeBoolean($fields[1]) : false,
                'value' => $fields[count($fields) - 1]['content'],
            ];
        }

        return [$extensions, $invalid];
    }


    /**
     * Read the basic constraints: 'ca' and 'pathLength' (NULL if none).
     */
    private static function readBasicConstraints($value)
    {
        $ca = false;
        $pathLength = null;
        foreach (Der::childrenOf(Der::readElement($value), Der::SEQUENCE) as $field)
        {
            if (Der::BOOLEAN === $field['tag'] && null === $pathLength)
            {
                $ca = Der::decodeBoolean($field);
            }
            else
            {
                $pathLength = Der::decodeSmallInteger($field);
            }
        }

        return ['ca' => $ca, 'pathLength' => $pathLength];
    }


    /**
     * Read the authority key identifier: [0] key identifier, [1] issuer (the
     * first directory name of the general names, as OpenSSL takes it), [2]
     * serial number of the issuer.
     */
    private static function readAuthorityKeyId($value)
    {
        $akid = ['keyId' => null, 'issuer' => null, 'serial' => null];
        foreach (Der::childrenOf(Der::readElement($value), Der::SEQUENCE) as $field)
        {
            if (0x80 === $field['tag'])
            {
                $akid['keyId'] = $field['content'];
            }
            elseif (0xa1 === $field['tag'])
            {
                foreach (Der::readElements($field['content']) as $name)
                {
                    if (0xa4 === $name['tag'])
                    {
                        $akid['issuer'] = self::readName(Der::readElement($name['content']));
                        break;
                    }
                }
            }
            elseif (0x82 === $field['tag'])
            {
                $akid['serial'] = $field['content'];
            }
            else
            {
                throw new Exception('DER: malformed authority key identifier.');
            }
        }

        return $akid;
    }


    /**
     * Read a name (a sequence of sets of fields), in the canonical form
     * OpenSSL compares names by (`x509_name_canon()`): the values of the
     * string types converted to UTF-8, without leading and trailing white
     * space, each run of white space collapsed into one space, ASCII letters
     * in lowercase; the values of other types kept as they are, with their
     * type. The fields of an RDN are compared as a set. NULL if a value
     * cannot be converted: the name then matches none.
     */
    private static function readName($element)
    {
        $rdns = [];
        foreach (Der::childrenOf($element, Der::SEQUENCE) as $set => $rdn)
        {
            foreach (Der::childrenOf($rdn, Der::SET) as $attribute)
            {
                $parts = Der::childrenOf($attribute, Der::SEQUENCE);
                if (2 !== count($parts))
                {
                    throw new Exception('DER: malformed name.');
                }
                $oid = Der::decodeOid($parts[0]);
                $value = $parts[1];
                if (in_array($value['tag'], self::CANONICAL_STRING_TAGS, true))
                {
                    $utf8 = self::toUtf8($value);
                    if (null === $utf8)
                    {
                        return null;
                    }
                    $text = 's:' . bin2hex(self::canonicalString($utf8));
                }
                else
                {
                    $text = $value['tag'] . ':' . bin2hex($value['content']);
                }
                $rdns[$set][] = $oid . '=' . $text;
            }
        }
        $canonical = [];
        foreach ($rdns as $rdn)
        {
            sort($rdn, SORT_STRING);
            $canonical[] = implode('+', $rdn);
        }

        return implode('/', $canonical);
    }


    /**
     * Indicates whether two names are the same name, as OpenSSL compares
     * them (`X509_NAME_cmp()`).
     */
    private static function sameName($a, $b)
    {
        return null !== $a && $a === $b;
    }


    /**
     * Convert the value of a field to UTF-8, as OpenSSL does
     * (`ASN1_STRING_to_UTF8()`), or give NULL for a type it does not
     * convert.
     */
    private static function toUtf8($value)
    {
        $content = $value['content'];
        switch ($value['tag'])
        {
            case 0x0c: // UTF8String
                return preg_match('//u', $content) ? $content : null;
            case 0x12: // NumericString
            case 0x13: // PrintableString
            case 0x14: // T61String
            case 0x16: // IA5String
            case 0x1a: // VisibleString
                // Each byte is a character, as in ISO-8859-1.
                return self::codePointsToUtf8('' === $content ? [] : array_values(unpack('C*', $content)));
            case 0x1e: // BMPString
                if (0 !== strlen($content) % 2)
                {
                    return null;
                }
                // UTF-16BE, surrogate pairs included.
                $units = '' === $content ? [] : array_values(unpack('n*', $content));
                $codePoints = [];
                for ($i = 0, $n = count($units); $i < $n; $i++)
                {
                    $unit = $units[$i];
                    if ($unit >= 0xd800 && $unit <= 0xdbff && $i + 1 < $n && $units[$i + 1] >= 0xdc00 && $units[$i + 1] <= 0xdfff)
                    {
                        $codePoints[] = 0x10000 + (($unit - 0xd800) << 10) + ($units[++$i] - 0xdc00);
                    }
                    else
                    {
                        $codePoints[] = $unit;
                    }
                }
                return self::codePointsToUtf8($codePoints);
            case 0x1c: // UniversalString
                if (0 !== strlen($content) % 4)
                {
                    return null;
                }
                return self::codePointsToUtf8('' === $content ? [] : array_values(unpack('N*', $content)));
            default:
                return null;
        }
    }


    /**
     * The UTF-8 encoding of code points, or NULL if one is not a Unicode
     * scalar value (a surrogate, or beyond U+10FFFF).
     */
    private static function codePointsToUtf8(array $codePoints)
    {
        $utf8 = '';
        foreach ($codePoints as $codePoint)
        {
            if ($codePoint < 0 || $codePoint > 0x10ffff || ($codePoint >= 0xd800 && $codePoint <= 0xdfff))
            {
                return null;
            }
            if ($codePoint < 0x80)
            {
                $utf8 .= chr($codePoint);
            }
            elseif ($codePoint < 0x800)
            {
                $utf8 .= chr(0xc0 | ($codePoint >> 6)) . chr(0x80 | ($codePoint & 0x3f));
            }
            elseif ($codePoint < 0x10000)
            {
                $utf8 .= chr(0xe0 | ($codePoint >> 12)) . chr(0x80 | (($codePoint >> 6) & 0x3f)) . chr(0x80 | ($codePoint & 0x3f));
            }
            else
            {
                $utf8 .= chr(0xf0 | ($codePoint >> 18)) . chr(0x80 | (($codePoint >> 12) & 0x3f)) . chr(0x80 | (($codePoint >> 6) & 0x3f)) . chr(0x80 | ($codePoint & 0x3f));
            }
        }

        return $utf8;
    }


    /**
     * Trim, collapse the white space of, and lowercase a string, as
     * `asn1_string_canon()` does with the ASCII characters.
     */
    private static function canonicalString($value)
    {
        $value = preg_replace('/\A[ \t\n\v\f\r]+|[ \t\n\v\f\r]+\z/', '', $value);
        $value = preg_replace('/[ \t\n\v\f\r]+/', ' ', $value);

        return strtr($value, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz');
    }
}
