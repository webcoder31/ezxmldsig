<?php
/**
 * Revocation.php
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
use webcoder31\ezxmldsig\core\X509Cert;

/**
 * The revocation status of the certificates of a chain, from CRLs and OCSP
 * responses.
 *
 * Every certificate of the chain but its trust anchor needs a CRL of its
 * issuer, or an OCSP response of its issuer or of a responder it delegated,
 * that tells its status. Two questions are told apart:
 *
 * - which CRLs count: current ones, their next update not passed (a seal of
 *   level B, the time-stamping authority of a seal of level T), or ones
 *   issued after a time-stamp (the signer of a seal of level T or LT, and
 *   its time-stamping authority at level LT, whose CRLs are embedded and no
 *   longer current when the seal is verified);
 * - which revocation makes the certificate unusable: any one, or one at or
 *   before the time-stamp only, the time-stamp proving that the seal
 *   existed before.
 *
 * The certificates of a time-stamping authority follow RFC 3161, 4: a
 * revocation after the time-stamp leaves its tokens valid only if the CRL
 * gives a reason that is not a compromise of a key. Without a reason, or
 * for a key compromise, every token of the authority is distrusted.
 *
 * A CRL or a response issued after the certificate expired proves nothing
 * of it, since a CA may drop the expired certificates from its CRLs and a
 * responder forget them, unless they say they keep them (ExpiredCertsOnCRL,
 * archive cutoff).
 *
 * @internal
 */
class Revocation
{
    /** The reason codes (RFC 5280, 5.3.1) of a compromise: keyCompromise, cACompromise, aACompromise. */
    const COMPROMISE_REASONS = [1, 2, 10];


    /**
     * Check the revocation status of a chain.
     *
     * @param array $chain The chain (X509Cert), from the certificate to its
     *        trust anchor.
     *
     * @param array $sources The sources (RevocationSource).
     *
     * @param array $check 'now' (UNIX time); 'issuedAfter' (NULL: the
     *        sources must be current; a time: they must be issued after it);
     *        'time' (NULL: any revocation counts; a time: a revocation after
     *        it leaves the certificate usable); 'authority' (TRUE for the
     *        chain of a time-stamping authority: a revocation after 'time'
     *        must give a reason other than a compromise).
     *
     * @return array 'error' (why it fails, or NULL), 'used' (the source used
     *         for each certificate).
     */
    public static function check(array $chain, array $sources, array $check)
    {
        $check += ['issuedAfter' => null, 'time' => null, 'authority' => false];
        $used = [];
        for ($index = 0; $index + 1 < count($chain); $index++)
        {
            $certificate = $chain[$index];
            $issuer = $chain[$index + 1];
            $name = json_encode($certificate->getDN(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            $covering = array_values(array_filter($sources, function (RevocationSource $source) use ($certificate, $issuer)
            {
                return null === $source->covers($certificate, $issuer);
            }));
            if (empty($covering))
            {
                return ['error' => 'No revocation data for the certificate ' . $name . ': no CRL of its issuer, nor OCSP response.', 'used' => $used];
            }
            $validTo = (int) $certificate->getValidTo('U');
            $issuedAfter = $check['issuedAfter'];
            $usable = array_values(array_filter($covering, function (RevocationSource $source) use ($check, $validTo, $issuedAfter)
            {
                return $source->thisUpdate <= $check['now']
                    && ($source->thisUpdate <= $validTo || (null !== $source->keepsExpiredFrom && $source->keepsExpiredFrom <= $validTo))
                    && (null === $issuedAfter
                        ? null !== $source->nextUpdate && $check['now'] <= $source->nextUpdate
                        : $source->thisUpdate >= $issuedAfter);
            }));
            // The newest source tells the status. Of two issued at the same
            // second, the precision of their dates, the one that tells a
            // revocation.
            usort($usable, function ($a, $b) { return $b->thisUpdate <=> $a->thisUpdate; });
            $source = null;
            foreach ($usable as $other)
            {
                if ($other->thisUpdate == $usable[0]->thisUpdate && null !== $other->revocationOf($certificate))
                {
                    $source = $other;
                    break;
                }
            }
            $source = null !== $source ? $source : (isset($usable[0]) ? $usable[0] : null);
            if (null === $source)
            {
                return ['error' => null === $issuedAfter
                    ? 'No current revocation data for the certificate ' . $name . ': the CRLs and OCSP responses are past their next update, have none, or were issued after it expired.'
                    : 'No revocation data for the certificate ' . $name . ' issued after the time-stamp (' . self::iso($issuedAfter) . '), while it was valid.', 'used' => $used];
            }
            $used[] = $source;
            $revocation = $source->revocationOf($certificate);
            if (null !== $revocation && !self::tolerated($revocation, $check))
            {
                $since = 'The certificate ' . $name . ' is revoked since ' . self::iso($revocation['date']);
                if (null === $check['time'])
                {
                    return ['error' => $since . '.', 'used' => $used];
                }
                return ['error' => $revocation['date'] <= $check['time']
                    ? $since . ', before the time-stamp.'
                    : $since . ', after the time-stamp but ' . (null === $revocation['reason'] ? 'without a reason' : 'for a compromise of a key') . ': the tokens of the time-stamping authority are no longer trusted (RFC 3161, 4).', 'used' => $used];
            }
        }

        return ['error' => null, 'used' => $used];
    }


    /**
     * Whether a revocation leaves the certificate usable.
     */
    private static function tolerated(array $revocation, array $check)
    {
        if (null === $check['time'] || $revocation['date'] <= $check['time'])
        {
            return false;
        }

        return !$check['authority'] || (null !== $revocation['reason'] && !in_array($revocation['reason'], self::COMPROMISE_REASONS, true));
    }


    /**
     * A UNIX time in the ISO 8601 form JavaScript writes (milliseconds, Z).
     */
    public static function iso($time)
    {
        $seconds = (int) floor($time);
        $milliseconds = min(999, (int) round(($time - $seconds) * 1000));

        return gmdate('Y-m-d\TH:i:s', $seconds) . sprintf('.%03dZ', $milliseconds);
    }
}
