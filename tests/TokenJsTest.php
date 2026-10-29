<?php

namespace webcoder31\ezxmldsig\Tests;

use webcoder31\ezxmldsig\Tests\helpers\Js;
use webcoder31\ezxmldsig\token\XMLDSigToken;

/**
 * Tokens made here, analyzed by the Node.js library (tests/helpers/Js.php):
 * signed and encrypted, with and without audience and expiry, with several
 * algorithms, valid there with the values this library reads; a token
 * altered after its signature, refused there. A token of the Node.js
 * library is also analyzed here, so that the bridge is checked both ways.
 * The variants are those of test/token/interop.test.ts of the Node.js
 * library. The error messages are not compared.
 */
class TokenJsTest extends TestCase
{
    /** Values that the XML escapes, characters outside ASCII, nested values. */
    const DATA = [
        'name' => 'Ragnar Lothbrok',
        'role' => 'Jarl',
        'city' => 'Kattegat & Hedeby <north> "fjord"',
        'nested' => ['a' => '1', 'b' => "\u{c6}sir \u{20ac} \u{65e5}\u{672c}"],
    ];

    protected function setUp(): void
    {
        parent::setUp();
        $reason = Js::skipReason();
        if (!is_null($reason))
        {
            $this->markTestSkipped($reason);
        }
    }

    /** Each variant: whether it is encrypted, the options of its creation, and those of its analysis besides the trust anchor. */
    private static function variants()
    {
        return [
            'signed' => [false, [], []],
            'signed, audience and expiry' => [false, ['audience' => ['crm', 'mail'], 'validity' => 300], ['expectedAudience' => 'mail']],
            'signed, RSA-SHA512, SHA-512, exclusive C14N, no prefix' => [false,
                ['signatureAlgorithm' => XMLDSigToken::RSA_SHA512, 'digestAlgorithm' => XMLDSigToken::SHA512, 'canonicalizationAlgorithm' => XMLDSigToken::EXC_C14N, 'xmldsigNsPrefix' => ''],
                ['signatureAlgorithm' => XMLDSigToken::RSA_SHA512, 'digestAlgorithm' => XMLDSigToken::SHA512, 'canonicalizationAlgorithm' => XMLDSigToken::EXC_C14N]],
            'signed, RIPEMD-160, C14N with comments, prefix sig' => [false,
                ['digestAlgorithm' => XMLDSigToken::RIPEMD160, 'canonicalizationAlgorithm' => XMLDSigToken::C14N_COMMENTS, 'xmldsigNsPrefix' => 'sig'],
                ['digestAlgorithm' => XMLDSigToken::RIPEMD160, 'canonicalizationAlgorithm' => XMLDSigToken::C14N_COMMENTS]],
            'signed, values not in base64' => [false, ['base64Encode' => false], []],
            'encrypted' => [true, [], []],
            'encrypted, audience and expiry' => [true, ['audience' => 'crm', 'validity' => 60], ['expectedAudience' => 'crm']],
            'encrypted, AES-128-CBC' => [true, ['sessionKeyCipheringAlgorithm' => XMLDSigToken::AES128_CBC], ['sessionKeyCipheringAlgorithm' => XMLDSigToken::AES128_CBC]],
            'encrypted, Triple DES, no prefix' => [true, ['sessionKeyCipheringAlgorithm' => XMLDSigToken::TRIPLEDES_CBC, 'xmldsigNsPrefix' => ''], ['sessionKeyCipheringAlgorithm' => XMLDSigToken::TRIPLEDES_CBC]],
        ];
    }

    /**
     * The variants, and the encrypted ones again, encrypted by a sender
     * without the private key of the recipient: this library cannot read
     * those.
     */
    public function tokens()
    {
        $cases = [];
        foreach (self::variants() as $name => $variant)
        {
            $cases[$name] = array_merge($variant, [true]);
            if ($variant[0])
            {
                $cases[$name . ', by a sender without the key of the recipient'] = array_merge($variant, [false]);
            }
        }
        return $cases;
    }

    private static function analyzeInJs($xml, array $request = [])
    {
        return Js::run([$request + ['command' => 'analyze', 'xml' => $xml, 'options' => self::trustAnchor()]])[0];
    }

    /**
     * @dataProvider tokens
     */
    public function testATokenCreatedHereIsValidForTheNodeJsLibrary($encrypted, array $options, array $analysis, $withRecipientKey)
    {
        if ($encrypted)
        {
            $this->requireSymmetricEncryption();
        }
        $token = $encrypted
            ? XMLDSigToken::createSecureXMLToken(self::DATA, self::cert('sign.key.pem'), self::cert('sign.cert.pem'), $withRecipientKey ? self::cert('crypt.key.pem') : null,
                self::cert('crypt.cert.pem'), self::SIGN_KEY_PASSWORD, null, $options)
            : XMLDSigToken::createXMLToken(self::DATA, self::cert('sign.key.pem'), self::cert('sign.cert.pem'), self::SIGN_KEY_PASSWORD, $options);
        $js = self::analyzeInJs($token->getXML(), ['options' => self::trustAnchor($analysis)] + ($encrypted ? ['cryptKey' => self::cert('crypt.key.pem')] : []));
        $this->assertArrayHasKey('error', $js, isset($js['exception']) ? $js['exception'] : '');
        $this->assertNull($js['error']);
        $this->assertTrue($js['isSignatureValid']);
        $this->assertSame($encrypted, $js['isDataEncrypted']);
        $this->assertSame(self::DATA, $js['data']);
        $this->assertFalse($js['isOutOfDate']);
        $this->assertSame($token->getCertDN(), $js['certDN']);
        if ($withRecipientKey)
        {
            // This library read its own token: the Node.js library reads the same values.
            $this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $token->getTokenId());
            $this->assertSame($token->getTokenId(), $js['tokenId']);
            $this->assertSame($token->getTimestamp(), $js['timestamp']);
            $this->assertSame($token->getAudience(), $js['audience']);
            $this->assertSame($token->getExpiry(), $js['expiry']);
            // Without a prefix, the readable form of the Node.js library splits no value; that of this library does.
            if ('' !== (isset($options['xmldsigNsPrefix']) ? $options['xmldsigNsPrefix'] : 'ds'))
            {
                $this->assertSame($token->getPrettyXML(), $js['prettyXml']);
            }
        }
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
