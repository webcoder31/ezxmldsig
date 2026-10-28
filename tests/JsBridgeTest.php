<?php

namespace webcoder31\ezxmldsig\Tests;

use webcoder31\ezxmldsig\Tests\helpers\Js;
use webcoder31\ezxmldsig\token\XMLDSigToken;

/**
 * The bridge to the Node.js library (tests/helpers/Js.php): a token goes
 * from one library to the other, both ways, and a token altered after its
 * signature is refused there, so that a bridge that answered "valid" to
 * anything would fail.
 */
class JsBridgeTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $reason = Js::skipReason();
        if (!is_null($reason))
        {
            $this->markTestSkipped($reason);
        }
    }

    private static function analyzeInJs($xml, array $request = [])
    {
        return Js::run([['command' => 'analyze', 'xml' => $xml, 'options' => self::trustAnchor()] + $request])[0];
    }

    public function testASignedTokenCreatedHereIsValidForTheNodeJsLibrary()
    {
        $token = self::createToken(self::sampleData());
        $result = self::analyzeInJs($token->getXML());
        $this->assertTrue($result['isSignatureValid'], (string) $result['error']);
        $this->assertTrue($result['isCertTrusted']);
        $this->assertSame(self::sampleData(), $result['data']);
        $this->assertSame($token->getCertDN(), $result['certDN']);
    }

    public function testAnEncryptedTokenCreatedHereIsDecryptedByTheNodeJsLibrary()
    {
        $token = $this->createSecureToken(self::sampleData());
        $result = self::analyzeInJs($token->getXML(), ['cryptKey' => self::cert('crypt.key.pem')]);
        $this->assertTrue($result['isDataEncrypted']);
        $this->assertTrue($result['isSignatureValid'], (string) $result['error']);
        $this->assertSame(self::sampleData(), $result['data']);
    }

    public function testATokenAlteredAfterItsSignatureIsRefusedByTheNodeJsLibrary()
    {
        $xml = self::createToken(self::sampleData())->getXML();
        $altered = str_replace(base64_encode('Jarl'), base64_encode('King'), $xml);
        $this->assertNotSame($xml, $altered);
        $result = self::analyzeInJs($altered);
        $this->assertFalse($result['isSignatureValid']);
        $this->assertFalse($result['isDigestValueOk'], (string) $result['error']);
    }

    public function testATokenCreatedByTheNodeJsLibraryIsValidHere()
    {
        $result = Js::run([[
            'command' => 'create',
            'data' => self::sampleData(),
            'signKey' => self::cert('sign.key.pem'),
            'signCert' => self::cert('sign.cert.pem'),
            'signKeyPassword' => self::SIGN_KEY_PASSWORD,
        ]])[0];
        $this->assertArrayHasKey('xml', $result, isset($result['exception']) ? $result['exception'] : '');
        $token = XMLDSigToken::analyzeXMLToken($result['xml'], self::trustAnchor());
        $this->assertTrue($token->isSignatureValid(), (string) $token->getError());
        $this->assertSame(self::sampleData(), $token->getData());
    }
}
