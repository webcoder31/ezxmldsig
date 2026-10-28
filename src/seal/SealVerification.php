<?php
/**
 * SealVerification.php
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
use DateTimeImmutable;
use DateTimeZone;
use webcoder31\ezxmldsig\core\X509Cert;

/**
 * The result of the verification of a seal (see Seal::verifySeal()).
 *
 * The seals are an experimental feature of the 2.x versions: their API may
 * change in a minor version.
 */
class SealVerification
{
    /** @var string|null */
    private $error;

    /** @var array */
    private $files;

    /** @var int|float|null */
    private $signingTime;

    /** @var X509Cert|null */
    private $signer;

    /** @var boolean */
    private $revocationChecked;

    /** @var int|float|null */
    private $timestampTime;

    /** @var string|null */
    private $level;


    /**
     * @param array $result 'error', and, for a valid seal, 'files',
     *        'signingTime', 'signer', 'revocationChecked', 'timestampTime',
     *        'level'.
     *
     * @internal
     */
    public function __construct(array $result)
    {
        $result += ['files' => [], 'signingTime' => null, 'signer' => null, 'revocationChecked' => false, 'timestampTime' => null, 'level' => null];
        $valid = null === $result['error'];
        $this->error = $result['error'];
        $this->level = $valid ? $result['level'] : null;
        $this->timestampTime = $valid ? $result['timestampTime'] : null;
        $this->files = $valid ? $result['files'] : [];
        $this->signingTime = $result['signingTime'];
        $this->signer = $result['signer'];
        $this->revocationChecked = $result['revocationChecked'];
    }


    /**
     * Indicates whether the seal is valid: structure, algorithms, digests,
     * signature, trust, revocation.
     *
     * @return boolean
     */
    public function isValid()
    {
        return null === $this->error;
    }


    /**
     * Why the seal is not valid, or NULL.
     *
     * @return string|null
     */
    public function getError()
    {
        return $this->error;
    }


    /**
     * The level of the seal: "B"; "T" if it has a signature time-stamp;
     * "LT" if it also embeds the data that validate it (checked to suffice,
     * unless verified with 'revocation' => FALSE); NULL if it is not valid.
     *
     * @return string|null
     */
    public function getLevel()
    {
        return $this->level;
    }


    /**
     * The time the signer claims (SigningTime): not a proven one.
     *
     * @return DateTimeImmutable|null The time, in UTC.
     */
    public function getSigningTime()
    {
        return self::date($this->signingTime);
    }


    /**
     * The proven time of the seal: the time of its signature time-stamp
     * (level T), or NULL.
     *
     * @return DateTimeImmutable|null The time, in UTC.
     */
    public function getTimestampTime()
    {
        return self::date($this->timestampTime);
    }


    /**
     * The files the seal covers, in the order of its references; empty if
     * it is not valid.
     *
     * @return array Each file: 'name' (its path in the container) and
     *         'mimeType' (the media type the signature gives it).
     */
    public function getFiles()
    {
        return $this->files;
    }


    /**
     * The signing certificate, once it has been found.
     *
     * @return X509Cert|null
     */
    public function getSigningCertificate()
    {
        return $this->signer;
    }


    /**
     * Indicates whether the revocation of the certificates was checked.
     *
     * @return boolean
     */
    public function isRevocationChecked()
    {
        return $this->revocationChecked;
    }


    private static function date($time)
    {
        if (null === $time)
        {
            return null;
        }
        $date = DateTimeImmutable::createFromFormat('U.u', sprintf('%d.%06d', (int) floor($time), (int) round(($time - floor($time)) * 1000) * 1000), new DateTimeZone('UTC'));

        return $date->setTimezone(new DateTimeZone('UTC'));
    }
}
