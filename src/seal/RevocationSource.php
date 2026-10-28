<?php
/**
 * RevocationSource.php
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
use Closure;
use webcoder31\ezxmldsig\core\X509Cert;

/**
 * What tells the status of certificates: a CRL, or the answer of an OCSP
 * response for one certificate (see Crl::source() and Ocsp::sources()).
 * The times are UNIX times, in seconds.
 *
 * @internal
 */
class RevocationSource
{
    /** @var string "crl" or "ocsp". */
    public $kind;

    /** @var string The DER encoding of the CRL or of the whole OCSP response. */
    public $der;

    /** @var int|float */
    public $thisUpdate;

    /** @var int|float|null */
    public $nextUpdate;

    /** @var int|float|null The time from which it keeps the status of the expired certificates (ExpiredCertsOnCRL, archive cutoff). */
    public $keepsExpiredFrom;

    /** @var Closure (X509Cert $certificate, X509Cert $issuer): NULL if it tells the status of the certificate, or why it does not. */
    private $covers;

    /** @var Closure (X509Cert $certificate): the revocation ('date', 'reason'), or NULL. */
    private $revocationOf;


    public function __construct($kind, $der, $thisUpdate, $nextUpdate, $keepsExpiredFrom, Closure $covers, Closure $revocationOf)
    {
        $this->kind = $kind;
        $this->der = $der;
        $this->thisUpdate = $thisUpdate;
        $this->nextUpdate = $nextUpdate;
        $this->keepsExpiredFrom = $keepsExpiredFrom;
        $this->covers = $covers;
        $this->revocationOf = $revocationOf;
    }


    /**
     * NULL if the source tells the status of the certificate, which the
     * issuer issued, or why it does not.
     */
    public function covers(X509Cert $certificate, X509Cert $issuer)
    {
        return call_user_func($this->covers, $certificate, $issuer);
    }


    /**
     * The revocation of the certificate ('date', a UNIX time, and 'reason',
     * the reason code or NULL), or NULL if it is not revoked.
     */
    public function revocationOf(X509Cert $certificate)
    {
        return call_user_func($this->revocationOf, $certificate);
    }
}
