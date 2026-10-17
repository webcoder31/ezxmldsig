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
 * @version   1.0.0
 */

 
// Namespace.
namespace webcoder31\ezxmldsig;

// Use.
use DateTime;
use DateTimeZone;
use Exception;

/**
 * Analyze an X.509 certificate.
 *
 * The `X509Cert` class provides a set of convenient methods for extracting
 * essential information contained in an X.509 certificate and for performing
 * some useful checks. Every cryptographic check (signature of the
 * certificate, chain of trust, validity dates) is performed by OpenSSL. This
 * class is used internally by the `XMLDSigToken` class.
 */
class X509Cert
{
    /** @var string The X.509 certificate in PEM format. */
    private $cert;

    /** @var array The X.509 information of the certificate. */
    private $x509Info;


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
        $tz = new DateTimeZone('UTC');
        $validFrom = $this->x509Info['validFrom'];
        $dt = DateTime::createFromFormat('ymdHise', $validFrom, $tz);
        return $dt->format($dateFormat);
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
        $tz = new DateTimeZone('UTC');
        $validTo = $this->x509Info['validTo'];
        $dt = DateTime::createFromFormat('ymdHise', $validTo, $tz);
        return $dt->format($dateFormat);
    }


    /**
     * Indicates whether the certificate is out of date or not.
     *
     * @return boolean TRUE if embedded certificate is out of date,
     *         FALSE otherwise.
     */
    public function isOutOfDate()
    {
        // We will compare date in UTC.
        $tz = new DateTimeZone('UTC');

        // Compute the UTC UNIX timestamp for the current date/time.
        $curDate = new DateTime('now', $tz);
        $curTimestamp = $curDate->getTimestamp();

        // Compute the UTC UNIX timestamp certificate 'validFrom' date.
        $validFrom = $this->x509Info['validFrom'];
        $fromDate = DateTime::createFromFormat('ymdHise', $validFrom, $tz);
        $fromTimestamp = $fromDate->getTimestamp();

        // Compute the UTC UNIX timestamp certificate 'validTo' date.
        $validTo = $this->x509Info['validTo'];
        $toDate = DateTime::createFromFormat('ymdHise', $validTo, $tz);
        $toTimestamp = $toDate->getTimestamp();

        // Return timestamps comparison result.
        return $curTimestamp < $fromTimestamp || $curTimestamp > $toTimestamp;
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
        $pem .= implode("\n", str_split($b64DerCert, 65)) . "\n";
        $pem .= "-----END CERTIFICATE-----\n";

        return $pem;
    }
}
