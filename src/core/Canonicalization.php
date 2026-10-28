<?php
/**
 * Canonicalization.php
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
use Exception;
use RobRichards\XMLSecLibs\XMLSecurityDSig;

/**
 * The guards of canonicalization, shared by the tokens and the seals.
 *
 * @internal
 */
class Canonicalization
{
    /**
     * Create the XMLSecurityDSig object that verifies a signature.
     *
     * Digests and signatures are computed over canonicalized XML. If the
     * canonicalization fails, `DOMNode::C14N()` returns FALSE (on PHP 8, some
     * XPath failures throw an Error instead), and an XPath transform that
     * selects nothing yields an empty string. Depending on its version,
     * xmlseclibs then hashes an empty string: a forged reference only has to
     * carry the digest of the empty string to validate, whatever the content
     * of the referenced node. The returned object therefore makes the
     * canonicalization of the node "ds:SignedInfo" and of each referenced node
     * throw an exception unless it produces a non-empty string.
     *
     * This check is deliberately independent of the xmlseclibs version and
     * must not be removed, even if xmlseclibs performs a similar check.
     *
     * @return XMLSecurityDSig The verifier.
     */
    public static function guardedVerifier()
    {
        return new class() extends XMLSecurityDSig
        {
            public function canonicalizeSignedInfo()
            {
                return $this->guard(function () {
                    return parent::canonicalizeSignedInfo();
                }, "ds:SignedInfo");
            }

            public function processTransforms($refNode, $objData, $includeCommentNodes = true)
            {
                return $this->guard(function () use ($refNode, $objData, $includeCommentNodes) {
                    return parent::processTransforms($refNode, $objData, $includeCommentNodes);
                }, "referenced node");
            }

            private function guard(callable $canonicalize, $what)
            {
                try
                {
                    $data = $canonicalize();
                }
                catch (\Throwable $e)
                {
                    throw new Exception("Canonicalization of " . $what . " failed! Reason: " . $e->getMessage());
                }

                if (!is_string($data) || '' === $data)
                {
                    throw new Exception("Canonicalization of " . $what . " failed or is empty!");
                }

                return $data;
            }
        };
    }
}
