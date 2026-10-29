<?php

namespace webcoder31\ezxmldsig\Tests;

use DOMDocument;
use DOMXPath;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use webcoder31\ezxmldsig\Tests\helpers\Js;
use webcoder31\ezxmldsig\token\XMLDSigToken;

/**
 * Tokens with xml-crypto and xml-encryption, third-party libraries for
 * Node.js, as the interoperability page of the documentation site shows
 * them, both ways: the tokens they create, signed and encrypted, are valid
 * here, and refused once altered; they read the tokens created here, and
 * refuse one altered; the digest xml-crypto computes is the one written
 * here. They run in the service of the Node.js library (the commands
 * xmlCryptoCreate and xmlCryptoRead of tests/js/ezxmldsig.ts), in the
 * versions it installs. The cases are those of test/token/interop.test.ts
 * of the Node.js library.
 */
class TokenXmlCryptoTest extends TestCase
{
    const DATA = TokenJsTest::DATA;

    protected function setUp(): void
    {
        parent::setUp();
        $reason = Js::skipReason();
        if (!is_null($reason))
        {
            $this->markTestSkipped($reason);
        }
    }

    public function kinds()
    {
        return ['signed' => [false], 'encrypted' => [true]];
    }

    /** A token xml-crypto creates, encrypted by xml-encryption if asked. */
    private static function createWithXmlCrypto($encrypted)
    {
        $result = Js::run([[
            'command' => 'xmlCryptoCreate',
            'encrypted' => $encrypted,
            'signKey' => self::cert('sign.key.pem'),
            'signKeyPassword' => self::SIGN_KEY_PASSWORD,
            'signCert' => self::cert('sign.cert.pem'),
            'cryptCert' => self::cert('crypt.cert.pem'),
        ]])[0];
        self::assertArrayHasKey('xml', $result, isset($result['exception']) ? $result['exception'] : '');
        return $result['xml'];
    }

    /** What xml-crypto, and xml-encryption, read of a token: see xmlCryptoRead in tests/js/ezxmldsig.ts. */
    private static function readWithXmlCrypto($xml)
    {
        $result = Js::run([['command' => 'xmlCryptoRead', 'xml' => $xml, 'signCert' => self::cert('sign.cert.pem'), 'cryptKey' => self::cert('crypt.key.pem')]])[0];
        self::assertArrayHasKey('valid', $result, isset($result['exception']) ? $result['exception'] : '');
        return $result;
    }

    private static function analyze($xml, $encrypted, array $options)
    {
        return $encrypted
            ? XMLDSigToken::analyzeSecureXMLToken($xml, self::cert('crypt.key.pem'), null, self::trustAnchor($options))
            : XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor($options));
    }

    private function create($encrypted)
    {
        if ($encrypted)
        {
            $this->requireSymmetricEncryption();
            return XMLDSigToken::createSecureXMLToken(self::DATA, self::cert('sign.key.pem'), self::cert('sign.cert.pem'), null, self::cert('crypt.cert.pem'), self::SIGN_KEY_PASSWORD);
        }
        return XMLDSigToken::createXMLToken(self::DATA, self::cert('sign.key.pem'), self::cert('sign.cert.pem'), self::SIGN_KEY_PASSWORD);
    }

    /** The token with the text of the node the XPath expression finds replaced; the change must apply. */
    private function alter($xml, $expression, $text)
    {
        $doc = new DOMDocument();
        $doc->loadXML($xml);
        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
        $xpath->registerNamespace('xenc', XMLSecEnc::XMLENCNS);
        $nodes = $xpath->query($expression);
        $this->assertSame(1, $nodes->length, $expression);
        $nodes->item(0)->nodeValue = $text;
        $altered = $doc->saveXML();
        $this->assertNotSame($xml, $altered);
        return $altered;
    }

    /**
     * @dataProvider kinds
     */
    public function testATokenTheyCreateIsValidHere($encrypted)
    {
        if ($encrypted)
        {
            $this->requireSymmetricEncryption();
        }
        $token = self::analyze(self::createWithXmlCrypto($encrypted), $encrypted, ['expectedAudience' => 'receiver', 'expectedSubject' => ['O' => 'Lothbrok Ltd', 'OU' => 'Signature Dept']]);
        $this->assertNull($token->getError());
        $this->assertTrue($token->isSignatureValid());
        $this->assertSame($encrypted, $token->isDataEncrypted());
        $this->assertSame(['name' => 'Ragnar Lothbrok', 'city' => 'Kattegat & Hedeby'], $token->getData());
        $this->assertSame(['receiver'], $token->getAudience());
        $this->assertFalse($token->isOutOfDate(120));
    }

    /**
     * @dataProvider kinds
     */
    public function testATokenTheyCreateAndThatIsAlteredIsRefusedHere($encrypted)
    {
        if ($encrypted)
        {
            $this->requireSymmetricEncryption();
        }
        $xml = $encrypted
            ? $this->alter(self::createWithXmlCrypto(true), '/ds:Signature/ds:Object/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue', base64_encode(random_bytes(64)))
            : $this->alter(self::createWithXmlCrypto(false), '/ds:Signature/ds:Object/Token/TokenData/name', base64_encode('Forged'));
        $token = self::analyze($xml, $encrypted, ['expectedAudience' => 'receiver']);
        $this->assertFalse($token->isSignatureValid());
        $this->assertFalse($token->isDigestValueOk(), (string) $token->getError());
    }

    /**
     * @dataProvider kinds
     */
    public function testTheyReadATokenCreatedHere($encrypted)
    {
        $result = self::readWithXmlCrypto($this->create($encrypted)->getXML());
        $this->assertTrue($result['valid'], isset($result['error']) ? $result['error'] : '');
        $this->assertSame(self::DATA, $result['data']);
    }

    public function testXmlCryptoRefusesATokenCreatedHereAndAltered()
    {
        $xml = $this->alter($this->create(false)->getXML(), '/ds:Signature/ds:Object/Token/TokenData/role', base64_encode('Thrall'));
        $result = self::readWithXmlCrypto($xml);
        $this->assertFalse($result['valid']);
        $this->assertMatchesRegularExpression('/invalid signature|digest/i', $result['error']);
    }

    public function testTheDigestXmlCryptoComputesIsTheOneWrittenHere()
    {
        // A control of the canonicalization, apart from the verification of
        // this library: the digest of the canonical ds:Object, by xml-crypto.
        $xml = $this->create(false)->getXML();
        $result = self::readWithXmlCrypto($xml);
        $this->assertTrue($result['valid'], isset($result['error']) ? $result['error'] : '');
        $this->assertStringContainsString('<ds:DigestValue>' . $result['digest'] . '</ds:DigestValue>', $xml);
    }
}
