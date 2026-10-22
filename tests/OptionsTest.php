<?php

namespace webcoder31\ezxmldsig\Tests;

use DOMDocument;
use DOMXPath;
use Exception;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use webcoder31\ezxmldsig\XMLDSigToken;

/**
 * Options of the four factories, algorithm lists and default algorithms.
 */
class OptionsTest extends TestCase
{
    const DSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';
    const XENC_NS = 'http://www.w3.org/2001/04/xmlenc#';

    /**
     * Returns the algorithms an XML token declares, read with DOMXPath.
     */
    private static function algorithmsOf($xml)
    {
        $doc = new DOMDocument();
        $doc->loadXML($xml);
        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('ds', self::DSIG_NS);
        $xpath->registerNamespace('xenc', self::XENC_NS);

        $read = function ($query) use ($xpath) {
            return $xpath->evaluate('string(' . $query . ')');
        };

        return [
            'canonicalization' => $read('/ds:Signature/ds:SignedInfo/ds:CanonicalizationMethod/@Algorithm'),
            'signature'        => $read('/ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm'),
            'digest'           => $read('/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm'),
            'sessionKey'       => $read('/ds:Signature/ds:Object/xenc:EncryptedData/xenc:EncryptionMethod/@Algorithm'),
            'keyTransport'     => $read('/ds:Signature/ds:Object/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/@Algorithm'),
        ];
    }

    /**
     * Sets the attribute Algorithm of the element an XPath query selects.
     */
    private static function withAlgorithm($xml, $query, $algorithm)
    {
        $doc = new DOMDocument();
        $doc->loadXML($xml);
        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('ds', self::DSIG_NS);
        $xpath->registerNamespace('xenc', self::XENC_NS);
        $xpath->query($query)->item(0)->setAttribute('Algorithm', $algorithm);

        return $doc->saveXML();
    }

    private static function createTokenWithOptions(array $options)
    {
        return XMLDSigToken::createXMLToken(
            self::sampleData(),
            self::cert('sign.key.pem'),
            self::cert('sign.cert.pem'),
            self::SIGN_KEY_PASSWORD,
            $options
        );
    }

    private static function createSecureTokenWithOptions(array $options)
    {
        return XMLDSigToken::createSecureXMLToken(
            self::sampleData(),
            self::cert('sign.key.pem'),
            self::cert('sign.cert.pem'),
            self::cert('crypt.key.pem'),
            self::cert('crypt.cert.pem'),
            self::SIGN_KEY_PASSWORD,
            null,
            $options
        );
    }

    /**
     * Calls one of the four factories with the given options.
     */
    private static function callFactory($factory, array $options)
    {
        switch ($factory)
        {
            case 'createXMLToken':
                return self::createTokenWithOptions($options);
            case 'createSecureXMLToken':
                return self::createSecureTokenWithOptions($options);
            case 'analyzeXMLToken':
                return XMLDSigToken::analyzeXMLToken('not an XML token', self::trustAnchor($options));
            case 'analyzeSecureXMLToken':
                return XMLDSigToken::analyzeSecureXMLToken('not an XML token', self::cert('crypt.key.pem'), null, self::trustAnchor($options));
        }
    }

    public function testCreateXMLTokenAppliesTheRequestedSignatureAndDigestAlgorithms()
    {
        $token = self::createTokenWithOptions([
            'signatureAlgorithm' => XMLDSigToken::RSA_SHA256,
            'digestAlgorithm' => XMLDSigToken::SHA256,
        ]);

        $this->assertNull($token->getError());
        $algorithms = self::algorithmsOf($token->getXML());
        $this->assertSame('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', $algorithms['signature']);
        $this->assertSame('http://www.w3.org/2001/04/xmlenc#sha256', $algorithms['digest']);
    }

    public function testCreateXMLTokenAppliesItsOptions()
    {
        $token = self::createTokenWithOptions([
            'signatureAlgorithm' => XMLDSigToken::RSA_SHA512,
            'digestAlgorithm' => XMLDSigToken::SHA512,
            'canonicalizationAlgorithm' => XMLDSigToken::EXC_C14N,
            'base64Encode' => false,
            'xmldsigNsPrefix' => 'sig',
        ]);

        $this->assertNull($token->getError());
        $xml = $token->getXML();
        $algorithms = self::algorithmsOf($xml);
        $this->assertSame('http://www.w3.org/2001/04/xmldsig-more#rsa-sha512', $algorithms['signature']);
        $this->assertSame('http://www.w3.org/2001/04/xmlenc#sha512', $algorithms['digest']);
        $this->assertSame('http://www.w3.org/2001/10/xml-exc-c14n#', $algorithms['canonicalization']);
        $this->assertStringContainsString('<sig:Signature', $xml);
        $this->assertStringContainsString('<name>Ragnar Lothbrok</name>', $xml);
    }

    /**
     * Without base64, each value is written as text: the characters that
     * XML escapes are read back as given, and none is taken for the start of
     * an entity reference.
     */
    public function testWithoutBase64TheValuesAreReadBackAsGiven()
    {
        $data = [
            'ampersand' => 'a & b',
            'entity' => 'a&amp;b',
            'reference' => '&#65;&lt;',
            'lessThan' => 'a<b',
            'greaterThan' => 'a>b',
            'quotes' => 'a"b\'c',
            'cdataEnd' => 'a]]>b',
            'carriageReturn' => "a\rb\r\nc",
            'nested' => ['ampersand' => 'x & y'],
        ];

        $messages = [];
        set_error_handler(function ($level, $message) use (&$messages) {
            if (error_reporting() & $level)
            {
                $messages[] = $message;
            }
            return true;
        });
        try
        {
            $created = XMLDSigToken::createXMLToken($data, self::cert('sign.key.pem'), self::cert('sign.cert.pem'), self::SIGN_KEY_PASSWORD, ['base64Encode' => false]);
        }
        finally
        {
            restore_error_handler();
        }

        $this->assertSame([], $messages);
        $this->assertNull($created->getError());
        $this->assertSame($data, $created->getData());

        $token = XMLDSigToken::analyzeXMLToken($created->getXML(), self::trustAnchor());

        $this->assertTrue($token->isSignatureValid());
        $this->assertSame($data, $token->getData());
    }

    public function testATokenCreatedWithoutOptionIsSignedWithRsaSha256AndSha256()
    {
        $algorithms = self::algorithmsOf(self::createToken(self::sampleData())->getXML());

        $this->assertSame('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', $algorithms['signature']);
        $this->assertSame('http://www.w3.org/2001/04/xmlenc#sha256', $algorithms['digest']);
    }

    public function testTheDefaultEncryptionAlgorithmsAreAes256GcmAndRsaOaep()
    {
        $algorithms = self::algorithmsOf($this->createSecureToken(self::sampleData())->getXML());

        $this->assertSame('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', $algorithms['signature']);
        $this->assertSame('http://www.w3.org/2009/xmlenc11#aes256-gcm', $algorithms['sessionKey']);
        $this->assertSame('http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p', $algorithms['keyTransport']);
    }

    public function testAnRsaSha1TokenIsRejectedByDefault()
    {
        $xml = self::createTokenWithOptions([
            'signatureAlgorithm' => XMLDSigToken::RSA_SHA1,
            'digestAlgorithm' => XMLDSigToken::SHA1,
        ])->getXML();
        $this->assertSame('http://www.w3.org/2000/09/xmldsig#rsa-sha1', self::algorithmsOf($xml)['signature']);

        $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor());

        $this->assertFalse($token->isSignatureValid());
        $this->assertStringContainsString('Unauthorized Signature algorithm!', (string) $token->getError());
        $this->assertStringContainsString('Unauthorized Digest algorithm!', (string) $token->getError());
    }

    public function testAnRsaSha1TokenIsAcceptedWhenTheCallerExpectsIt()
    {
        $data = self::sampleData();
        $xml = self::createTokenWithOptions([
            'signatureAlgorithm' => XMLDSigToken::RSA_SHA1,
            'digestAlgorithm' => XMLDSigToken::SHA1,
        ])->getXML();

        $expected = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor([
            'signatureAlgorithm' => XMLDSigToken::RSA_SHA1,
            'digestAlgorithm' => XMLDSigToken::SHA1,
        ]));
        $unchecked = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor([
            'checkSigningAlgorithms' => false,
        ]));

        $this->assertNull($expected->getError());
        $this->assertTrue($expected->isSignatureValid());
        $this->assertSame($data, $expected->getData());
        $this->assertTrue($unchecked->isSignatureValid());
    }

    public function factories()
    {
        return [
            'createXMLToken' => ['createXMLToken'],
            'createSecureXMLToken' => ['createSecureXMLToken'],
            'analyzeXMLToken' => ['analyzeXMLToken'],
            'analyzeSecureXMLToken' => ['analyzeSecureXMLToken'],
        ];
    }

    /**
     * @dataProvider factories
     */
    public function testAnUnknownOptionIsRefused($factory)
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Unknown option 'digestAlgoritm'!");

        self::callFactory($factory, ['digestAlgoritm' => XMLDSigToken::SHA512]);
    }

    public function optionsOutOfContext()
    {
        $cases = [
            'createXMLToken' => [
                'sessionKeyCipheringAlgorithm' => XMLDSigToken::AES256_CBC,
                'cryptAlgorithm' => XMLDSigToken::RSA_OAEP_MGF1P,
                'checkCryptingAlgorithms' => false,
                'checkSigningAlgorithms' => false,
                'caCertPath' => self::cert('root.cert.pem'),
                'signerCertPath' => self::cert('sign.cert.pem'),
                'expectedSubject' => ['O' => 'Lothbrok Ltd'],
            ],
            'createSecureXMLToken' => [
                'checkCryptingAlgorithms' => false,
                'checkSigningAlgorithms' => false,
                'caCertPath' => self::cert('root.cert.pem'),
                'signerCertPath' => self::cert('sign.cert.pem'),
                'expectedSubject' => ['O' => 'Lothbrok Ltd'],
            ],
            'analyzeXMLToken' => [
                'base64Encode' => false,
                'xmldsigNsPrefix' => '',
                'sessionKeyCipheringAlgorithm' => XMLDSigToken::AES256_CBC,
                'cryptAlgorithm' => XMLDSigToken::RSA_OAEP_MGF1P,
                'checkCryptingAlgorithms' => false,
            ],
            'analyzeSecureXMLToken' => [
                'base64Encode' => false,
                'xmldsigNsPrefix' => '',
            ],
        ];

        $data = [];
        foreach ($cases as $factory => $options)
        {
            foreach ($options as $name => $value)
            {
                $data[$factory . ': ' . $name] = [$factory, $name, $value];
            }
        }

        return $data;
    }

    /**
     * @dataProvider optionsOutOfContext
     */
    public function testAnOptionOutOfItsContextIsRefused($factory, $name, $value)
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Option '" . $name . "' only applies to");

        self::callFactory($factory, [$name => $value]);
    }

    public function invalidOptionValues()
    {
        return [
            'base64Encode not a boolean' => ['base64Encode', 'no', 'It must be a boolean.'],
            'xmldsigNsPrefix not a string' => ['xmldsigNsPrefix', false, 'It must be a string.'],
            'signatureAlgorithm NULL' => ['signatureAlgorithm', null, 'Its value must not be NULL.'],
            'signatureAlgorithm TRUE' => ['signatureAlgorithm', true, "Invalid parameter 'signatureAlgorithm'!"],
        ];
    }

    /**
     * @dataProvider invalidOptionValues
     */
    public function testAnInvalidOptionValueIsRefused($name, $value, $message)
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage($message);

        self::createTokenWithOptions([$name => $value]);
    }

    public function testCreateSecureXMLTokenRequiresAnEncryptionCertificate()
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Missing parameter 'cryptCertPath'!");

        XMLDSigToken::createSecureXMLToken(
            self::sampleData(),
            self::cert('sign.key.pem'),
            self::cert('sign.cert.pem'),
            self::cert('crypt.key.pem'),
            null,
            self::SIGN_KEY_PASSWORD
        );
    }

    public function testASymmetricSessionKeyCipheringAlgorithmIsAccepted()
    {
        $this->requireSymmetricEncryption();

        $data = self::sampleData();
        $options = ['sessionKeyCipheringAlgorithm' => XMLDSigToken::AES256_CBC];
        $created = self::createSecureTokenWithOptions($options);

        $this->assertNull($created->getError());
        $this->assertSame('http://www.w3.org/2001/04/xmlenc#aes256-cbc', self::algorithmsOf($created->getXML())['sessionKey']);

        $token = XMLDSigToken::analyzeSecureXMLToken($created->getXML(), self::cert('crypt.key.pem'), null, self::trustAnchor($options));

        $this->assertNull($token->getError());
        $this->assertTrue($token->isSignatureValid());
        $this->assertSame($data, $token->getData());
    }

    public function testADigestAlgorithmIsRefusedAsSessionKeyCipheringAlgorithm()
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Invalid parameter 'sessionKeyCipheringAlgorithm'!");

        self::createSecureTokenWithOptions(['sessionKeyCipheringAlgorithm' => XMLDSigToken::SHA256]);
    }

    public function keyTransportAlgorithms()
    {
        return [
            'RSA_1_5' => [XMLSecurityKey::RSA_1_5],
            'RSA_OAEP_MGF1P' => [XMLDSigToken::RSA_OAEP_MGF1P],
        ];
    }

    /**
     * @dataProvider keyTransportAlgorithms
     */
    public function testAKeyTransportAlgorithmIsRefusedAsSignatureAlgorithmAtCreation($algorithm)
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Invalid parameter 'signatureAlgorithm'!");

        self::createTokenWithOptions(['signatureAlgorithm' => $algorithm]);
    }

    /**
     * @dataProvider keyTransportAlgorithms
     */
    public function testAKeyTransportAlgorithmIsRefusedAsSignatureAlgorithmAtAnalysis($algorithm)
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Invalid parameter 'signatureAlgorithm'!");

        XMLDSigToken::analyzeXMLToken('not an XML token', self::trustAnchor(['signatureAlgorithm' => $algorithm]));
    }

    /**
     * @dataProvider keyTransportAlgorithms
     */
    public function testATokenSignedWithAKeyTransportAlgorithmIsRejected($algorithm)
    {
        $xml = self::withAlgorithm(
            self::createToken(self::sampleData())->getXML(),
            '/ds:Signature/ds:SignedInfo/ds:SignatureMethod',
            $algorithm
        );

        $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor(['checkSigningAlgorithms' => false]));

        $this->assertFalse($token->isSignatureValid());
        $this->assertSame('Signature algorithm is invalid!', $token->getError());
    }

    public function testASignatureAlgorithmIsRefusedAsKeyTransportAlgorithmAtCreation()
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Invalid parameter 'cryptAlgorithm'!");

        self::createSecureTokenWithOptions(['cryptAlgorithm' => XMLDSigToken::RSA_SHA256]);
    }

    public function testASignatureAlgorithmIsRefusedAsKeyTransportAlgorithmAtAnalysis()
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Invalid parameter 'cryptAlgorithm'!");

        XMLDSigToken::analyzeSecureXMLToken(
            'not an XML token',
            self::cert('crypt.key.pem'),
            null,
            self::trustAnchor(['cryptAlgorithm' => XMLDSigToken::RSA_SHA256])
        );
    }

    public function testATokenWhoseSessionKeyIsEncryptedWithASignatureAlgorithmIsRejected()
    {
        $xml = self::withAlgorithm(
            $this->createSecureToken(self::sampleData())->getXML(),
            '/ds:Signature/ds:Object/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod',
            XMLDSigToken::RSA_SHA256
        );

        $token = XMLDSigToken::analyzeSecureXMLToken(
            $xml,
            self::cert('crypt.key.pem'),
            null,
            self::trustAnchor(['checkCryptingAlgorithms' => false])
        );

        $this->assertFalse($token->isSignatureValid());
        $this->assertSame('Crypt algorithm is invalid!', $token->getError());
    }
}
