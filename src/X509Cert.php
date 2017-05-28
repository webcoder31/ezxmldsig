<?php
/**
 * X509Cert.php
 *
 * Copyright © 2017 - Thierry Thiers <webcoder31@gmail.com>
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
 * @copyright 2017 - Thierry Thiers <webcoder31@gmail.com>
 * @license   http://www.cecill.info  CeCILL-C License
 * @version   1.0.0
 */

 
// Namespace.
namespace webcoder31\ezxmldsig;

// Use.
use DateTime;
use DateTimeZone;
use Exception;


class X509Cert
{
    /** @const int The category used for XMLDSigToken class exceptions */
    const X509CERT_CATEGORY_ERROR = 9998;

    /** @var string The X.509 certificate in PEM format. */
    private $cert;

     /** @var array The X.509 information of the certificatet. */
    private $x509Info;   

    /** @var string The signature that is encrypted in the certificate. */
    private $encryptedSignature;

    /** @var string The signature that is encrypted in the certificate. */
    private $originallyHashedContent;


    /**
     * Create a new X509Cert object.
     *
     * @param string $pemCert An X.509 certificate (public key) in PEM format.
     * @throws Exception
     */
    public function __construct($cert)
    {
        // DER encode the PEM certificate.
        $derCert = self::pemToDer($cert);
        if (!is_string($derCert))
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

        // Grab the encrypted signature from the DER encoded certificate.
        $encryptedSignature = self::extractEncryptedSignature($derCert);
        if (!is_string($encryptedSignature))
        {
            $msg = "Failed to extract encrypted signature from certificate!";
            throw new Exception($msg);
        }

        // Get what was originally hashed by the issuer of the certiicate. 
        // NOTE : This is the DER encoded certificate without the issuer 
        //        information and the signature.
        $originallyHashedContent = self::getHashedContent($derCert);
        if ($originallyHashedContent === false)
        {
            $msg = "Failed to extract hashed content from certificate!";
            throw new Exception($msg);
        }

        // Store the PEM certificate.
        $this->cert = $cert;

        // Store X.509 information.
        $this->x509Info = $x509Info;

        // Store the encrypted signature.
        $this->encryptedSignature = $encryptedSignature;

        // Store the content originally hashed by the issuer of the certiicate.
        $this->originallyHashedContent = $originallyHashedContent;
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
     * @param string The format of the returned date.
     *        Default: 'ymdHise'
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
     * @param string The format of the returned date.
     *        Default: 'ymdHise'
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
     * Verify that the X.509 certificate has been signed with the private key 
     * correcsponding to the given CA certificate to validate its origin.
     * NOTE : Note that more than one CA certificate can give a positive result, 
     *        some certificates re-issue signing certificates after having only 
     *        changed the expiration dates.
     *        Note that it also works with self-signed certificates. In this 
     *        case, passes the the X.509 certificate that is supposed been 
     *        included in the XML digital signature to the function.
     *
     * @param string $caCert The certificate (in PEM format) corresponding to 
     *        the private key that is supposed been used by CA to sign the X.509 
     *        certificate.
     * @return boolean TRUE if origin of the X.509 certificate has been 
     *         validated, FALSE otherwise.
     * @throws Exception
     */
    public function checkCA($caCert)
    {
        // Get the public key from the CA certificate, which is supposed been
        // used to encrypt the signature in the X.509 embedded certificate.
        $caPublicKey = openssl_pkey_get_public($caCert);
        if (false === $caPublicKey)
        {
            $msg = "Failed to get the public key from the CA certificate!";
            throw new Exception($msg);
        }

        // Try to decrypt the encrypted signature using the CA's public key.
        // The decrypted signature is a DER encoded ASN1 structure containing
        // the signature algorithm and the signature hash.
        // NOTE : The decrypted signature will be stored in $decryptedSignature.
        $result = openssl_public_decrypt(
                        $this->encryptedSignature, 
                        $decryptedSignature, 
                        $caPublicKey
                    );

        if (false === $result)
        {
            // Signature cannot be decrypted! This mean that the CA's public key
            // was not used to sign the embedded X.509 certificate.
            return false;
        }

        // Get the OID of the signature hash algorithm, which is required
        // to generate our own hash of the originally hashed content.
        // This hash will then be compared to the issuer's hash.
        $oid = self::getSignatureAlgorithmOid($decryptedSignature);
        if ($oid === false)
        {
            $msg = "Failed to determine algorithm used to sign certificate!";
            throw new Exception($msg);
        }
        switch ($oid)
        {
            case '1.2.840.113549.2.2': $algorithm = 'md2';
                break;
            case '1.2.840.113549.2.4': $algorithm = 'md4';
                break;
            case '1.2.840.113549.2.5': $algorithm = 'md5';
                break;
            case '1.3.14.3.2.18': $algorithm = 'sha';
                break;
            case '1.3.14.3.2.26': $algorithm = 'sha1';
                break;
            case '2.16.840.1.101.3.4.2.1': $algorithm = 'sha256';
                break;
            case '2.16.840.1.101.3.4.2.2': $algorithm = 'sha384';
                break;
            case '2.16.840.1.101.3.4.2.3': $algorithm = 'sha512';
                break;
            default:
                $msg = "Algorithm used to sign the certificate is unknown!";
                throw new Exception($msg);
                break;
        }

        // Get the hash generated by the issuer from the decrypted signature.
        $signatureHash = self::getSignatureHash($decryptedSignature);

        // Hash the originally hashed content with the same algorithm.
        $computedHash = hash($algorithm, $this->originallyHashedContent);

        // Compare hashes and returns the result.
        return ($signatureHash === $computedHash);
    }


    /**
     * Extract encrypted signature from a DER encoded certificate.
     * Expects X.509 DER encoded certificate consisting of a section container
     * containing 2 sequences and a bitstream. The bitstream contains the 
     * original signature encrypted with the public key of the issuing signer.
     * The DER encoded certificate has the following structure:
     *     SEQUENCE
     *         SEQUENCE  (Issuer and signature sections)
     *             ...
     *             ...
     *         SEQUENCE  (Signature encryption algorithm OID)
     *             ...
     *             NULL
     *         BITSTREAM (Encrypted signature)
     *
     * @param string $derCertificate DER encoded certificate.
     * @return string|false The encrypted signature on success, 
     *         FALSE on failure.
     */
    static private function extractEncryptedSignature($derCertificate)
    {
        if (strlen($derCertificate) < 5)
        {
            return false;
        }

        // Skip container sequence.
        $derData = substr($derCertificate, 4);

        // Now burns through two sequences and then return the final bitstream.
        while (strlen($derData) > 1)
        {
            // Get the class of the following data.
            $class = ord($derData[0]);

            switch ($class)
            {
                // Sequence class case.
                case 0x30:
                    // Compute the length of the sequence.
                    $length = ord($derData[1]);
                    $bytes = 0;
                    if ($length & 0x80)
                    {
                        $bytes = $length & 0x0f;
                        $length = 0;
                        for ($i = 0; $i < $bytes; $i++)
                        {
                            $length = ($length << 8) | ord($derData[$i + 2]);
                        }
                    }
                    // Get the content of the sequence.
                    $contents = substr($derData, 2 + $bytes, $length);

                    // Burns the sequence.
                    $derData = substr($derData, 2 + $bytes + $length);
                    break;

                // Bistream class case.
                case 0x03:
                    // Compute the length of the bitstream.
                    $length = ord($derData[1]);
                    $bytes = 0;
                    if ($length & 0x80)
                    {
                        $bytes = $length & 0x0f;
                        $length = 0;
                        for ($i = 0; $i < $bytes; $i++)
                        {
                            $length = ($length << 8) | ord($derData[$i + 2]);
                        }
                    }

                    // Returns the bitstream (the DER encoded signature).
                    return substr($derData, 3 + $bytes, $length);
                    break;

                // Unknown class case.
                default:
                    // Extraction failed.
                    return false;
                    break;
            }
        }

        // Extraction failed.
        return false;
    }


    /**
     * Get DER certificate with issuer and signature sections stripped.
     * The DER encoded certificate has the following structure:
     *     SEQUENCE
     *         SEQUENCE  (Issuer and signature sections)
     *             ...
     *             ...
     *         SEQUENCE  (Signature encryption algorithm OID)
     *             ...
     *             NULL
     *         BITSTREAM (Encrypted signature)
     *
     * @param string $derCertificate DER encoded certificate.
     * @return string|false DER certificate with issuer and signature sections 
     *         stripped on success, FALSE on failure.
     */
    static private function getHashedContent($derCertificate)
    {
        if (!is_string($derCertificate) or strlen($derCertificate) < 8)
        {
            // Invalid DER certificate.
            return false;
        }

        // Compute the length of data to strip.
        $bit = 4;
        $length = ord($derCertificate[($bit + 1)]);
        $bytes = 0;
        if ($length & 0x80)
        {
            $bytes = $length & 0x0f;
            $length = 0;
            for ($i = 0; $i < $bytes; $i++)
            {
                $length = ($length << 8) | ord($derCertificate[$bit + $i + 2]);
            }
        }

        // Returns DER certificate with issuer and signature sections stripped.
        return substr($derCertificate, 4, $length + 4);
    }


    /**
     * Get signature algorithm OID from DER encoded signature data.
     * This ASN1 data should contain the following structure:
     *     SEQUENCE
     *         SEQUENCE
     *             OID  (Signature hash algorithm)
     *             NULL
     *     OCTET STRING (Signature hash)
     *
     * @param string $derSignatureData DER encoded signature data.
     * @return string|false The signature algorithm OID, FALSE on failure.
     */
    static private function getSignatureAlgorithmOid($derSignatureData)
    {
        // Validate this is the DER encoded singature we need.
        if (!is_string($derSignatureData) or strlen($derSignatureData) < 5)
        {
            // Invalid DER data.
            return false;
        }

        $bit_seq1 = 0;
        $bit_seq2 = 2;
        $bit_oid  = 4;

        if (ord($derSignatureData[$bit_seq1]) !== 0x30)
        {
            // Invalid DER certificate.
            return false;
        }

        if (ord($derSignatureData[$bit_seq2]) !== 0x30)
        {
            // Invalid DER certificate.
            return false;
        }

        if (ord($derSignatureData[$bit_oid]) !== 0x06)
        {
            // Invalid DER certificate.
            return false;
        }

        // Strip out what we don't need.
        $derData = substr($derSignatureData, $bit_oid);

        // Get the algorithm OID.
        $length = ord($derData[1]);
        $bytes = 0;
        if ($length & 0x80)
        {
            $bytes = $length & 0x0f;
            $length = 0;
            for ($i = 0; $i < $bytes; $i++)
            {
                $length = ($length << 8) | ord($derData[$i + 2]);
            }
        }
        $oidData = substr($derData, 2 + $bytes, $length);

        // Unpack the algorithm OID.
        $oid = floor(ord($oidData[0])/40);
        $oid .= '.' . ord($oidData[0]) % 40;
        $value = 0;
        $i = 1;
        while ($i < strlen($oidData))
        {
            $value = $value << 7;
            $value = $value | (ord($oidData[$i]) & 0x7f);
            if (!(ord($oidData[$i]) & 0x80))
            {
                $oid .= '.' . $value;
                $value = 0;
            }
            $i++;
        }

        // Returns the algorithm OID.
        return $oid;
    }


    /**
     * Get signature hash from a DER encoded signature data.
     * This is ASN1 data that should contain the following structure:
     *     SEQUENCE
     *         SEQUENCE
     *             OID  (Signature hash algorithm)
     *             NULL
     *     OCTET STRING (Signature hash)
     *
     * @param string $derSignatureData Decrypted DER encoded signature data.
     * @return string|false The signature hash, FALSE on failure.
     */
    static private function getSignatureHash($derSignatureData)
    {
        // Validate this is the DER encoded singature we need.
        if (!is_string($derSignatureData) or strlen($derSignatureData) < 5)
        {
            // Invalid DER data.
            return false;
        }

        if (ord($derSignatureData[0]) !== 0x30)
        {
            // Invalid DER data.
            return false;
        }

        // Strip out the container sequence.
        $derData = substr($derSignatureData, 2);
        if (ord($derData[0]) !== 0x30)
        {
            // Invalid DER certificate.
            return false;
        }

        // Compute the length of the first sequence to strip out.
        $length = ord($derData[1]);
        $bytes = 0;
        if ($length & 0x80)
        {
            $bytes = $length & 0x0f;
            $length = 0;
            for ($i = 0; $i < $bytes; $i++)
            {
                $length = ($length << 8) | ord($derData[$i + 2]);
            }
        }

        // Strip out the first sequence.
        $derData = substr($derData, 2 + $bytes + $length);

        // Now we should have an octet string.
        if (ord($derData[0]) !== 0x04)
        {
            // Invalid DER data.
            return false;
        }

        // Compute the length of the octet string.
        $length = ord($derData[1]);
        $bytes = 0;
        if ($length & 0x80)
        {
            $bytes = $length & 0x0f;
            $length = 0;
            for ($i = 0; $i < $bytes; $i++)
            {
                $length = ($length << 8) | ord($derData[$i + 2]);
            }
        }

        // Returns the signature hash.
        return bin2hex(substr($derData, 2 + $bytes, $length));
    }


    /**
     * Convert PEM encoded X.509 certificate to DER encoding.
     *
     * @param string $pemCertificate PEM encoded X.509 certificate.
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
