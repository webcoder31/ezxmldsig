<?php
/**
 * Xml.php
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
use DOMDocument;
use Exception;

/**
 * The guarded parsing of XML documents, shared by the tokens and the seals.
 *
 * @internal
 */
class Xml
{
    /**
     * Load an XML document into a DOM document.
     *
     * A document type declaration (DOCTYPE) declares entities, which the
     * parser expands where the document references them: nested internal
     * entities make a small document expand into gigabytes ("billion
     * laughs"), and external entities read files or URLs. An XML token never
     * has one, so a document holding the bytes `<!DOCTYPE` is refused before
     * it is parsed, whatever it declares. This check reads the raw bytes: it
     * only holds for an encoding in which `<!DOCTYPE` can only be written as
     * these very bytes, which is why a document is also refused, before it is
     * parsed, when it is not in UTF-8, the encoding of the tokens: one that
     * holds a NUL byte (UTF-16, UTF-32), that declares another encoding, or
     * that does not start with `<` (EBCDIC, among others). The parsed document is refused too
     * if it has a document type node, should the check above miss one.
     *
     * The document is parsed with `LIBXML_NONET`: the parser never accesses
     * the network. Any libxml error refuses the document, and none is output.
     * Whitespace is preserved: digests are computed over the document as it
     * was signed.
     *
     * @param string $xml The XML document.
     *
     * @param string $what What the document is, for the error messages.
     *
     * @return DOMDocument The loaded document.
     *
     * @throws Exception If the document is refused.
     */
    public static function load($xml, $what)
    {
        if (!is_string($xml) || '' === $xml)
        {
            throw new Exception($what . " is not a valid XML document!");
        }

        $start = ltrim(preg_replace('/\A\xEF\xBB\xBF/', '', $xml), " \t\r\n");
        if (false !== strpos($xml, "\0")
            || (preg_match('/\A<\?xml\s[^>]*?\bencoding\s*=\s*(["\'])([^"\']*)\1/', $start, $matches)
                && 0 !== strcasecmp($matches[2], 'UTF-8')))
        {
            throw new Exception($what . " must be encoded in UTF-8!");
        }
        if ('<' !== substr($start, 0, 1))
        {
            throw new Exception($what . " is not a valid XML document!");
        }

        if (false !== strpos($xml, '<!DOCTYPE'))
        {
            throw new Exception($what . " must not have a document type declaration (DOCTYPE)!");
        }

        $xmlDoc = new DOMDocument('1.0', 'UTF-8');
        $xmlDoc->preserveWhiteSpace = true;

        $prevState = libxml_use_internal_errors(true);
        libxml_clear_errors();
        try
        {
            $loaded = $xmlDoc->loadXML($xml, LIBXML_NONET);
            $isValidXml = $loaded && 0 === count(libxml_get_errors());
        }
        finally
        {
            libxml_clear_errors();
            libxml_use_internal_errors($prevState);
        }

        if (!$isValidXml)
        {
            throw new Exception($what . " is not a valid XML document!");
        }

        foreach ($xmlDoc->childNodes as $node)
        {
            if (XML_DOCUMENT_TYPE_NODE === $node->nodeType)
            {
                throw new Exception($what . " must not have a document type declaration (DOCTYPE)!");
            }
        }

        return $xmlDoc;
    }
}
