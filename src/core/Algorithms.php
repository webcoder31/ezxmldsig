<?php
/**
 * Algorithms.php
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
namespace webcoder31\ezxmldsig\core;

// Use.
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/**
 * The algorithms of XML Signature, named by their URIs, as xmlseclibs names
 * them: canonicalization, digest and signature. The tokens and the seals
 * take their identifiers from here; which ones each accepts is its own
 * policy. `XMLDSigToken` has the same constants, with the algorithms of XML
 * Encryption. RSA-PSS and ECDSA, of the seals, are those of RFC 6931.
 */
class Algorithms
{
    /** Inclusive canonicalization. */
    const C14N = XMLSecurityDSig::C14N;
    /** Inclusive canonicalization, with comments. */
    const C14N_COMMENTS = XMLSecurityDSig::C14N_COMMENTS;
    /** Exclusive canonicalization. */
    const EXC_C14N = XMLSecurityDSig::EXC_C14N;
    /** Exclusive canonicalization, with comments. */
    const EXC_C14N_COMMENTS = XMLSecurityDSig::EXC_C14N_COMMENTS;

    /** SHA-1. */
    const SHA1 = XMLSecurityDSig::SHA1;
    /** SHA-256. */
    const SHA256 = XMLSecurityDSig::SHA256;
    /** SHA-384. */
    const SHA384 = XMLSecurityDSig::SHA384;
    /** SHA-512. */
    const SHA512 = XMLSecurityDSig::SHA512;
    /** RIPEMD-160. */
    const RIPEMD160 = XMLSecurityDSig::RIPEMD160;

    /** RSA-SHA1. */
    const RSA_SHA1 = XMLSecurityKey::RSA_SHA1;
    /** RSA-SHA256. */
    const RSA_SHA256 = XMLSecurityKey::RSA_SHA256;
    /** RSA-SHA384. */
    const RSA_SHA384 = XMLSecurityKey::RSA_SHA384;
    /** RSA-SHA512. */
    const RSA_SHA512 = XMLSecurityKey::RSA_SHA512;

    /** RSASSA-PSS with SHA-256, MGF1 with the same digest, salt as long as the digest (RFC 6931, 2.3.10). */
    const RSA_PSS_SHA256 = 'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1';
    /** RSASSA-PSS with SHA-384. */
    const RSA_PSS_SHA384 = 'http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1';
    /** RSASSA-PSS with SHA-512. */
    const RSA_PSS_SHA512 = 'http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1';

    /** ECDSA with SHA-256, the value written as r || s (RFC 6931, 2.3.6; RFC 4050). */
    const ECDSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256';
    /** ECDSA with SHA-384. */
    const ECDSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384';
    /** ECDSA with SHA-512. */
    const ECDSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512';
}
