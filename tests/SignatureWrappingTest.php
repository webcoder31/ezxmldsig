<?php

namespace webcoder31\ezxmldsig\Tests;

use DateTime;
use DateTimeZone;
use DOMDocument;
use DOMXPath;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use webcoder31\ezxmldsig\token\XMLDSigToken;

/**
 * Signature wrapping: xmlseclibs computes the digest of the first element of
 * the document whose attribute "Id" is "Token". A copy of the signed
 * "ds:Object" placed elsewhere in the document must not let a modified
 * "ds:Signature/ds:Object" pass for the signed one.
 */
class SignatureWrappingTest extends TestCase
{
    /** Forged token data. */
    const FORGED_DATA = [
        'name' => 'Forged',
        'role' => 'Forged',
        'location' => 'Forged',
    ];

    /**
     * Loads a token into a DOM document and returns the document and an
     * XPath object with the prefixes "ds" and "xenc" registered.
     */
    private static function load($xml)
    {
        $doc = new DOMDocument();
        $doc->loadXML($xml);
        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
        $xpath->registerNamespace('xenc', 'http://www.w3.org/2001/04/xmlenc#');

        return [$doc, $xpath];
    }

    /**
     * Returns a timestamp that differs from the one of a token created now,
     * yet that keeps the token fresh for isOutOfDate().
     */
    private static function forgedTimestamp()
    {
        return (new DateTime('+20 seconds', new DateTimeZone('UTC')))
            ->format(XMLDSigToken::TOKEN_TIMESTAMP_FORMAT);
    }

    /**
     * Replaces the content of a "ds:Object" node with a plain token holding
     * the forged data and the given timestamp.
     */
    private static function forgeObjectContent($object, $timestamp)
    {
        $doc = $object->ownerDocument;
        while ($object->firstChild)
        {
            $object->removeChild($object->firstChild);
        }
        $token = $object->appendChild($doc->createElement('Token'));
        $token->appendChild($doc->createElement('TokenTimestamp', $timestamp));
        $tokenData = $token->appendChild($doc->createElement('TokenData'));
        foreach (self::FORGED_DATA as $name => $value)
        {
            $leaf = $tokenData->appendChild($doc->createElement($name, base64_encode($value)));
            $leaf->setAttribute('Algorithm', 'base64');
        }
    }

    /**
     * Copies the signed "ds:Object" into "ds:KeyInfo", which the signature
     * does not cover, then forges the data and the timestamp of the original
     * "ds:Object".
     */
    private static function wrapIntoKeyInfo($xml, $timestamp)
    {
        list($doc, $xpath) = self::load($xml);
        // The copy is inserted as text: cloning the node would let libxml
        // move the namespace declarations of an encrypted token, which
        // changes the canonical form of the copy.
        $copy = $doc->saveXML($xpath->query('/ds:Signature/ds:Object')->item(0));
        $xml = substr_replace($xml, $copy, strpos($xml, '</ds:KeyInfo>'), 0);

        list($doc, $xpath) = self::load($xml);
        self::forgeObjectContent($xpath->query('/ds:Signature/ds:Object')->item(0), $timestamp);

        return $doc->saveXML();
    }

    private function assertNotForged(XMLDSigToken $token, $timestamp)
    {
        $this->assertFalse($token->isSignatureValid());
        $this->assertNotNull($token->getError());
        $this->assertNotEquals(self::FORGED_DATA, $token->getData());
        $this->assertNotSame($timestamp, $token->getTimestamp());
    }

    public function testRejectsASignedObjectCopiedIntoKeyInfo()
    {
        $timestamp = self::forgedTimestamp();
        $xml = self::wrapIntoKeyInfo(self::createToken(self::sampleData())->getXML(), $timestamp);

        $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor());

        $this->assertNotForged($token, $timestamp);
        $this->assertNull($token->getData());
    }

    public function testRejectsAnEncryptedSignedObjectCopiedIntoKeyInfo()
    {
        $timestamp = self::forgedTimestamp();
        $xml = self::wrapIntoKeyInfo($this->createSecureToken(self::sampleData())->getXML(), $timestamp);

        $token = XMLDSigToken::analyzeSecureXMLToken($xml, self::cert('crypt.key.pem'), null, self::trustAnchor());

        $this->assertNotForged($token, $timestamp);
        $this->assertNull($token->getData());
    }

    /**
     * When "ds:Signature" is not the document element, xmlseclibs detaches it
     * from the document before computing the digest, and then looks for the
     * element "Id=Token" in what remains of the document: a copy of the signed
     * "ds:Object" placed outside "ds:Signature" is the one it digests.
     */
    public function testRejectsASignatureThatIsNotTheDocumentElement()
    {
        $timestamp = self::forgedTimestamp();
        list($doc, $xpath) = self::load(self::createToken(self::sampleData())->getXML());
        $signature = $doc->documentElement;
        $object = $xpath->query('/ds:Signature/ds:Object')->item(0);
        $envelope = $doc->createElement('Envelope');
        $doc->replaceChild($envelope, $signature);
        $envelope->appendChild($object->cloneNode(true));
        $envelope->appendChild($signature);
        self::forgeObjectContent($object, $timestamp);

        $token = XMLDSigToken::analyzeXMLToken($doc->saveXML(), self::trustAnchor());

        $this->assertNotForged($token, $timestamp);
        $this->assertNull($token->getData());
        // The digest was computed over the copy, not over the token: it must
        // not be reported as verified.
        $this->assertNotTrue($token->isDigestValueOk());
    }

    public function testRejectsALegitimateTokenWrappedInAnotherElement()
    {
        list($doc) = self::load(self::createToken(self::sampleData())->getXML());
        $signature = $doc->documentElement;
        $envelope = $doc->createElement('Envelope');
        $doc->replaceChild($envelope, $signature);
        $envelope->appendChild($signature);

        $token = XMLDSigToken::analyzeXMLToken($doc->saveXML(), self::trustAnchor());

        $this->assertFalse($token->isSignatureValid());
        $this->assertNull($token->getData());
        $this->assertStringContainsString('ds:Signature', $token->getError());
    }

    /**
     * A second element "Id=Token" makes the element digested by xmlseclibs
     * depend on the document order: the token is rejected wherever it is.
     */
    public function testRejectsADocumentWithTwoElementsIdToken()
    {
        list($doc, $xpath) = self::load(self::createToken(self::sampleData())->getXML());
        $extra = $doc->createElement('Extra', 'unsigned');
        $extra->setAttribute('Id', 'Token');
        $xpath->query('/ds:Signature')->item(0)->appendChild($extra);

        $token = XMLDSigToken::analyzeXMLToken($doc->saveXML(), self::trustAnchor());

        $this->assertFalse($token->isSignatureValid());
        $this->assertNull($token->getData());
        $this->assertStringContainsString('Id', $token->getError());
    }
}
