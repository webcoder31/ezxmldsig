<?php

namespace webcoder31\ezxmldsig\Tests;

use DOMDocument;
use DOMXPath;
use Exception;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use webcoder31\ezxmldsig\core\Canonicalization;

/**
 * The verifier used to analyze tokens must reject a canonicalization that
 * fails or yields an empty string, whatever the xmlseclibs version.
 */
class CanonicalizationGuardTest extends TestCase
{
    /**
     * Returns the verifier that XMLDSigToken uses to analyze a token.
     */
    private static function createVerifier()
    {
        return Canonicalization::guardedVerifier();
    }

    /**
     * Forges a signed token whose reference ends with an XPath transform that
     * selects nothing: the referenced node canonicalizes to an empty string.
     * The token data is altered, the digest is replaced by the digest of the
     * empty string and ds:SignedInfo is signed again with the signing key, so
     * that only the canonicalization check can reject the token.
     */
    private static function forgeEmptyCanonicalization()
    {
        $doc = new DOMDocument();
        $doc->loadXML(self::createToken(self::sampleData())->getXML());
        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);

        $reference = $xpath->query('//ds:Signature/ds:SignedInfo/ds:Reference')->item(0);
        $prefix = $reference->prefix ? $reference->prefix . ':' : '';
        $transform = $doc->createElementNS(XMLSecurityDSig::XMLDSIGNS, $prefix . 'Transform');
        $transform->setAttribute('Algorithm', 'http://www.w3.org/TR/1999/REC-xpath-19991116');
        $transform->appendChild($doc->createElementNS(XMLSecurityDSig::XMLDSIGNS, $prefix . 'XPath', 'false()'));
        $xpath->query('ds:Transforms', $reference)->item(0)->appendChild($transform);

        foreach ($xpath->query('//ds:Object//*[not(*)]') as $leaf)
        {
            $leaf->nodeValue = 'forged';
        }

        $digestAlgorithm = $xpath->evaluate('string(ds:DigestMethod/@Algorithm)', $reference);
        $xpath->query('ds:DigestValue', $reference)->item(0)->nodeValue =
            (new XMLSecurityDSig())->calculateDigest($digestAlgorithm, '');

        $signedInfo = $xpath->query('//ds:Signature/ds:SignedInfo')->item(0);
        $canonicalizationAlgorithm = $xpath->evaluate('string(ds:CanonicalizationMethod/@Algorithm)', $signedInfo);
        $key = new XMLSecurityKey($xpath->evaluate('string(ds:SignatureMethod/@Algorithm)', $signedInfo), ['type' => 'private']);
        $key->passphrase = self::SIGN_KEY_PASSWORD;
        $key->loadKey(self::cert('sign.key.pem'), true);
        $signature = $key->signData($signedInfo->C14N(
            strpos($canonicalizationAlgorithm, 'exc-c14n') !== false,
            strpos($canonicalizationAlgorithm, 'WithComments') !== false
        ));
        $xpath->query('//ds:Signature/ds:SignatureValue')->item(0)->nodeValue = base64_encode($signature);

        return $doc;
    }

    public function testForgedSignatureValueIsValid()
    {
        $verifier = self::createVerifier();
        $verifier->locateSignature(self::forgeEmptyCanonicalization());
        $verifier->canonicalizeSignedInfo();
        $key = $verifier->locateKey();
        XMLSecEnc::staticLocateKeyInfo($key, $verifier->sigNode);

        // The forged ds:SignedInfo is correctly signed: only the reference
        // check can reject the forged token.
        $this->assertSame(1, $verifier->verify($key));
    }

    public function testRejectsAReferenceCanonicalizedToAnEmptyString()
    {
        $verifier = self::createVerifier();
        $verifier->locateSignature(self::forgeEmptyCanonicalization());

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Canonicalization of referenced node failed or is empty!');
        $verifier->validateReference();
    }

    public function testRejectsAMissingSignedInfo()
    {
        $doc = new DOMDocument();
        $doc->loadXML(self::createToken(self::sampleData())->getXML());
        $verifier = self::createVerifier();
        $verifier->locateSignature($doc);
        $signedInfo = $doc->getElementsByTagNameNS(XMLSecurityDSig::XMLDSIGNS, 'SignedInfo')->item(0);
        $signedInfo->parentNode->removeChild($signedInfo);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Canonicalization of ds:SignedInfo failed or is empty!');
        $verifier->canonicalizeSignedInfo();
    }
}
