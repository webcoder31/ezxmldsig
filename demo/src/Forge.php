<?php

namespace webcoder31\ezxmldsig\Demo;

use DOMDocument;
use DOMXPath;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use webcoder31\ezxmldsig\X509Cert;

/**
 * Alterations of a token for the attack lab: they edit the document in
 * place, so that the difference with the legitimate token stays readable,
 * and compute again the digest or the signature with xmlseclibs when the
 * attack calls for it. None of them goes through XMLDSigToken, whose
 * analysis is what the lab puts to the test.
 */
final class Forge
{
    /** @var DOMDocument */
    public $doc;

    /** @var DOMXPath */
    public $xpath;

    /**
     * Loads a token. The tokens of the lab come from the issuer of the demo,
     * or were accepted by its receiver: they have no document type
     * declaration.
     *
     * @param string $xml
     *
     * @throws \InvalidArgumentException If the document cannot be loaded.
     */
    public function __construct($xml)
    {
        if (false !== strpos($xml, '<!DOCTYPE'))
        {
            throw new \InvalidArgumentException('A token with a document type declaration cannot be altered.');
        }
        $this->doc = new DOMDocument();
        $this->doc->preserveWhiteSpace = true;
        $previous = libxml_use_internal_errors(true);
        $loaded = $this->doc->loadXML($xml, LIBXML_NONET);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);
        if (!$loaded)
        {
            throw new \InvalidArgumentException('The token is not a valid XML document.');
        }
        $this->xpath = new DOMXPath($this->doc);
        $this->xpath->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
        $this->xpath->registerNamespace('xenc', XMLSecEnc::XMLENCNS);
    }

    /**
     * Returns the altered token.
     *
     * @return string
     */
    public function xml()
    {
        return $this->doc->saveXML();
    }

    /**
     * Returns the single node an XPath query selects.
     *
     * @param string $query
     *
     * @return \DOMNode
     *
     * @throws \InvalidArgumentException If the query selects no node.
     */
    public function node($query)
    {
        $node = $this->xpath->query($query)->item(0);
        if (is_null($node))
        {
            throw new \InvalidArgumentException('The token has no node ' . $query . '.');
        }

        return $node;
    }

    /**
     * Changes a value of the user data: the leaf named "role" if there is
     * one, the first leaf otherwise.
     *
     * @param string $value The new value, base64-encoded if the leaf is.
     * @param string $objectQuery The ds:Object to alter.
     *
     * @return array ['path' => path of the leaf under TokenData, 'old' =>
     *     decoded old value, 'new' => new value]
     */
    public function changeDataValue($value, $objectQuery = '/ds:Signature/ds:Object')
    {
        $leaves = $this->xpath->query($objectQuery . '/Token/TokenData//*[not(*)]');
        if (0 === $leaves->length)
        {
            throw new \InvalidArgumentException('The token holds no data value.');
        }
        $leaf = $leaves->item(0);
        foreach ($leaves as $candidate)
        {
            if ('role' === $candidate->localName)
            {
                $leaf = $candidate;
                break;
            }
        }
        $encoded = 'base64' === $leaf->getAttribute('Algorithm');
        $old = $encoded ? base64_decode($leaf->textContent) : $leaf->textContent;
        $leaf->nodeValue = $encoded ? base64_encode($value) : $value;

        $path = [];
        for ($node = $leaf; 'TokenData' !== $node->localName; $node = $node->parentNode)
        {
            array_unshift($path, $node->localName);
        }

        return ['path' => 'TokenData/' . implode('/', $path), 'old' => $old, 'new' => $value];
    }

    /**
     * Computes again the digest of ds:Object, with the algorithms the token
     * declares.
     */
    public function redigest()
    {
        $object = $this->node('/ds:Signature/ds:Object');
        $transform = $this->xpath->evaluate('string(/ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform/@Algorithm)');
        $algorithm = $this->xpath->evaluate('string(/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm)');
        $this->node('/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue')->nodeValue =
            (new XMLSecurityDSig())->calculateDigest($algorithm, self::canonicalize($object, $transform));
    }

    /**
     * Signs ds:SignedInfo again, with the algorithms the token declares, and
     * replaces the certificate of ds:KeyInfo.
     *
     * @param string $keyPath PEM private key.
     * @param string|null $password Its password.
     * @param string $certPath PEM certificate written in ds:KeyInfo.
     */
    public function resign($keyPath, $password, $certPath)
    {
        $signedInfo = $this->node('/ds:Signature/ds:SignedInfo');
        $canonicalization = $this->xpath->evaluate('string(ds:CanonicalizationMethod/@Algorithm)', $signedInfo);
        $algorithm = $this->xpath->evaluate('string(ds:SignatureMethod/@Algorithm)', $signedInfo);

        $key = new XMLSecurityKey($algorithm, ['type' => 'private']);
        if (!is_null($password))
        {
            $key->passphrase = $password;
        }
        $key->loadKey($keyPath, true);
        $this->node('/ds:Signature/ds:SignatureValue')->nodeValue =
            base64_encode($key->signData(self::canonicalize($signedInfo, $canonicalization)));

        $this->replaceCertificate($certPath);
    }

    /**
     * Replaces the certificate of ds:KeyInfo.
     *
     * @param string $certPath PEM certificate.
     */
    public function replaceCertificate($certPath)
    {
        $this->node('/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate')->nodeValue =
            base64_encode(X509Cert::pemToDer(file_get_contents($certPath)));
    }

    /**
     * Canonicalizes a node as xmlseclibs does for the given algorithm.
     */
    private static function canonicalize(\DOMNode $node, $algorithm)
    {
        switch ($algorithm)
        {
            case XMLSecurityDSig::C14N_COMMENTS:
                return $node->C14N(false, true);
            case XMLSecurityDSig::EXC_C14N:
                return $node->C14N(true, false);
            case XMLSecurityDSig::EXC_C14N_COMMENTS:
                return $node->C14N(true, true);
            default:
                return $node->C14N(false, false);
        }
    }
}
