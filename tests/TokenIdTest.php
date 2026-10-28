<?php

namespace webcoder31\ezxmldsig\Tests;

use DOMDocument;
use DOMXPath;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use webcoder31\ezxmldsig\token\XMLDSigToken;

/**
 * Identifier of the token: random, unique, signed, and only given for a
 * valid token, so that the receiver can refuse a replayed token.
 */
class TokenIdTest extends TestCase
{
    const TOKEN_ID = '/ds:Signature/ds:Object/Token/TokenId';

    private static function xpath(DOMDocument $doc)
    {
        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);

        return $xpath;
    }

    /**
     * Signs again, with the trusted signing key, the token of a created one
     * after $alter changed it: the result is validly signed.
     */
    private static function signAgain(callable $alter)
    {
        $doc = new DOMDocument();
        $doc->loadXML(self::createToken(self::sampleData())->getXML());
        $tokenNode = self::xpath($doc)->query('/ds:Signature/ds:Object/Token')->item(0);
        $alter($tokenNode);

        $dsig = new XMLSecurityDSig('ds');
        $dsig->setCanonicalMethod(XMLSecurityDSig::C14N);
        $object = $dsig->addObject($tokenNode);
        $object->setAttribute('Id', 'Token');
        $dsig->addReference($object, XMLSecurityDSig::SHA256, null, ['overwrite' => false, 'force_uri' => true]);
        $signKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'private']);
        $signKey->passphrase = self::SIGN_KEY_PASSWORD;
        $signKey->loadKey(self::cert('sign.key.pem'), true);
        $dsig->add509Cert(file_get_contents(self::cert('sign.cert.pem')));
        $dsig->sign($signKey);

        return $dsig->sigNode->ownerDocument->saveXML();
    }

    private static function tokenIdOf($xml)
    {
        $doc = new DOMDocument();
        $doc->loadXML($xml);
        $nodes = self::xpath($doc)->query(self::TOKEN_ID);

        return 1 === $nodes->length ? $nodes->item(0)->nodeValue : null;
    }

    public function testCreatedTokenHasARandomIdentifier()
    {
        $token = self::createToken(self::sampleData());

        $this->assertTrue($token->isSignatureValid(), (string) $token->getError());
        $this->assertMatchesRegularExpression('/\A[0-9a-f]{32}\z/', $token->getTokenId());
        $this->assertSame($token->getTokenId(), self::tokenIdOf($token->getXML()));
    }

    public function testAnalysisGivesTheIdentifier()
    {
        $xml = self::createToken(self::sampleData())->getXML();

        $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor());

        $this->assertTrue($token->isSignatureValid(), (string) $token->getError());
        $this->assertSame(self::tokenIdOf($xml), $token->getTokenId());
    }

    public function testEncryptedTokenHasAnIdentifier()
    {
        $created = $this->createSecureToken(self::sampleData());
        $this->assertNull(self::tokenIdOf($created->getXML()), 'The identifier is encrypted with the data.');

        $token = XMLDSigToken::analyzeSecureXMLToken($created->getXML(), self::cert('crypt.key.pem'), null, self::trustAnchor());

        $this->assertTrue($token->isSignatureValid(), (string) $token->getError());
        $this->assertMatchesRegularExpression('/\A[0-9a-f]{32}\z/', $token->getTokenId());
        $this->assertSame($created->getTokenId(), $token->getTokenId());
    }

    public function testIdentifiersAreUnique()
    {
        $ids = [];
        for ($i = 0; $i < 20; $i++)
        {
            $ids[] = self::createToken(self::sampleData())->getTokenId();
        }

        $this->assertCount(20, array_unique(array_filter($ids)));
    }

    public function testAlteredIdentifierInvalidatesTheToken()
    {
        $xml = self::createToken(self::sampleData())->getXML();
        $original = XMLDSigToken::alterXML($xml, self::TOKEN_ID, null, str_repeat('0', 32));
        $this->assertMatchesRegularExpression('/\A[0-9a-f]{32}\z/', $original);

        $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor());

        $this->assertFalse($token->isSignatureValid());
        $this->assertFalse($token->isDigestValueOk());
        $this->assertStringContainsString('Token hash verification failed!', $token->getError());
        $this->assertNull($token->getTokenId());
    }

    public function testTokenWithoutIdentifierIsRejected()
    {
        $xml = self::signAgain(function ($tokenNode) {
            $tokenNode->removeChild($tokenNode->getElementsByTagName('TokenId')->item(0));
        });

        $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor());

        $this->assertTrue($token->isSignatureValueOk());
        $this->assertTrue($token->isCertTrusted());
        $this->assertFalse($token->isSignatureValid());
        $this->assertSame('1 anomaly detected: Token identifier is missing!', $token->getError());
        $this->assertNull($token->getTokenId());
    }

    public function provideMalformedIdentifiers()
    {
        return [
            'too short' => [function ($node) { $node->nodeValue = str_repeat('a', 31); }],
            'too long' => [function ($node) { $node->nodeValue = str_repeat('a', 33); }],
            'upper case' => [function ($node) { $node->nodeValue = str_repeat('A', 32); }],
            'not hexadecimal' => [function ($node) { $node->nodeValue = str_repeat('g', 32); }],
            'empty' => [function ($node) { $node->nodeValue = ''; }],
            'element' => [function ($node) { $node->nodeValue = ''; $node->appendChild($node->ownerDocument->createElement('x', str_repeat('a', 32))); }],
            'twice' => [function ($node) { $node->parentNode->appendChild($node->cloneNode(true)); }],
        ];
    }

    /**
     * @dataProvider provideMalformedIdentifiers
     */
    public function testMalformedIdentifierIsRejected(callable $alter)
    {
        $xml = self::signAgain(function ($tokenNode) use ($alter) {
            $alter($tokenNode->getElementsByTagName('TokenId')->item(0));
        });

        $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor());

        $this->assertTrue($token->isSignatureValueOk());
        $this->assertTrue($token->isCertTrusted());
        $this->assertFalse($token->isSignatureValid());
        $this->assertSame('1 anomaly detected: Token identifier is malformed!', $token->getError());
        $this->assertNull($token->getTokenId());
    }

    public function testTokenWithAnotherAnomalyGivesNoIdentifier()
    {
        // The identifier is read, but the timestamp is not valid.
        $xml = self::signAgain(function ($tokenNode) {
            $tokenNode->getElementsByTagName('TokenTimestamp')->item(0)->nodeValue = 'yesterday';
        });

        $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor());

        $this->assertTrue($token->isCertTrusted());
        $this->assertSame('1 anomaly detected: Token timestamp format is invalid!', $token->getError());
        $this->assertNull($token->getTokenId());
    }

    public function testUntrustedTokenGivesNoIdentifier()
    {
        // Signed by a certificate the analysis does not trust.
        $xml = self::createToken(self::sampleData())->getXML();

        $token = XMLDSigToken::analyzeXMLToken($xml, ['signerCertPath' => self::cert('crypt.cert.pem')]);

        $this->assertFalse($token->isSignatureValid());
        $this->assertTrue($token->isDigestValueOk());
        $this->assertNull($token->getTokenId());
    }
}
