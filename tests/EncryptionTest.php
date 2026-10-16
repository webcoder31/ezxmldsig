<?php

namespace webcoder31\ezxmldsig\Tests;

use DOMDocument;
use DOMXPath;
use Exception;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use webcoder31\ezxmldsig\XMLDSigToken;

/**
 * Encryption of the token data: default algorithms, refused algorithms, and
 * the failures of the decryption, which must neither be told apart nor
 * happen before the token is verified.
 */
class EncryptionTest extends TestCase
{
    const DECRYPTION_FAILED = 'Token decryption failed!';

    const ENCRYPTED_KEY = '/ds:Signature/ds:Object/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue';
    const ENCRYPTED_DATA = '/ds:Signature/ds:Object/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue';

    private static function xpath(DOMDocument $doc)
    {
        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
        $xpath->registerNamespace('xenc', XMLSecEnc::XMLENCNS);

        return $xpath;
    }

    /**
     * Builds an encrypted token with xmlseclibs, whatever the algorithms
     * XMLDSigToken accepts: the plain token comes from createXMLToken(), is
     * encrypted for crypt.cert.pem, optionally altered, then digested and
     * signed.
     *
     * @param string $keyTransport Key transport algorithm.
     * @param string $cipher Symmetric algorithm of the token data.
     * @param callable|null $alter Receives the DOMXPath of the encrypted
     *     token, before it is digested and signed.
     * @param string $signer 'sign' (trusted) or 'attacker' (not trusted).
     */
    private static function buildEncryptedToken($keyTransport, $cipher, ?callable $alter = null, $signer = 'sign')
    {
        $plain = new DOMDocument();
        $plain->loadXML(self::createToken(self::sampleData())->getXML());
        $tokenNode = self::xpath($plain)->query('/ds:Signature/ds:Object/Token')->item(0);

        $dsig = new XMLSecurityDSig('ds');
        $dsig->setCanonicalMethod(XMLSecurityDSig::C14N);
        $object = $dsig->addObject($tokenNode);
        $object->setAttribute('Id', 'Token');

        $sessionKey = new XMLSecurityKey($cipher);
        $sessionKey->generateSessionKey();
        $publicKey = new XMLSecurityKey($keyTransport, ['type' => 'public']);
        $publicKey->loadKey(self::cert('crypt.cert.pem'), true, true);
        $enc = new XMLSecEnc();
        $enc->encryptKey($publicKey, $sessionKey);
        $enc->setNode($object);
        $enc->type = XMLSecEnc::Content;
        $enc->encryptNode($sessionKey);

        if (!is_null($alter))
        {
            $alter(self::xpath($object->ownerDocument));
        }

        $dsig->addReference($object, XMLSecurityDSig::SHA256, null, ['overwrite' => false, 'force_uri' => true]);
        $signKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'private']);
        if ('sign' === $signer)
        {
            $signKey->passphrase = self::SIGN_KEY_PASSWORD;
        }
        $signKey->loadKey(self::cert($signer . '.key.pem'), true);
        $dsig->add509Cert(file_get_contents(self::cert($signer . '.cert.pem')));
        $dsig->sign($signKey);

        return $dsig->sigNode->ownerDocument->saveXML();
    }

    /**
     * Returns an alteration that replaces the content of a CipherValue
     * (base64 decoded) with what $replace returns for it.
     */
    private static function replaceCipherValue($query, callable $replace)
    {
        return function (DOMXPath $xpath) use ($query, $replace) {
            $node = $xpath->query($query)->item(0);
            $node->nodeValue = base64_encode($replace(base64_decode($node->nodeValue)));
        };
    }

    /**
     * Returns the session key encrypted with RSA-OAEP for crypt.cert.pem.
     */
    private static function oaepEncrypt($sessionKey)
    {
        $publicKey = openssl_pkey_get_public(file_get_contents(self::cert('crypt.cert.pem')));
        openssl_public_encrypt($sessionKey, $encrypted, $publicKey, OPENSSL_PKCS1_OAEP_PADDING);

        return $encrypted;
    }

    /**
     * Returns a file holding a decryption key that cannot be loaded: it is
     * only loaded to decrypt, so that the error it gives tells that a
     * decryption was attempted.
     */
    private function unloadableKey()
    {
        return $this->tempFile('unloadable.key.pem', "not a key\n");
    }

    private static function analyze($xml, $cryptKeyPath, array $options = [])
    {
        return XMLDSigToken::analyzeSecureXMLToken($xml, $cryptKeyPath, null, self::trustAnchor($options));
    }

    private static function assertNotDecrypted(XMLDSigToken $token, $reason)
    {
        self::assertStringContainsString($reason, (string) $token->getError());
        self::assertStringNotContainsString('private key', (string) $token->getError());
        self::assertFalse($token->isSignatureValid());
        self::assertNull($token->getData());
    }

    public function testATokenEncryptedWithoutOptionUsesAesGcmAndRsaOaepAndIsDecrypted()
    {
        $data = self::sampleData();
        $created = $this->createSecureToken($data);
        $this->assertNull($created->getError());

        $doc = new DOMDocument();
        $doc->loadXML($created->getXML());
        $xpath = self::xpath($doc);
        $this->assertSame(
            'http://www.w3.org/2009/xmlenc11#aes256-gcm',
            $xpath->evaluate('string(/ds:Signature/ds:Object/xenc:EncryptedData/xenc:EncryptionMethod/@Algorithm)')
        );
        $this->assertSame(
            'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
            $xpath->evaluate('string(/ds:Signature/ds:Object/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/@Algorithm)')
        );

        $token = self::analyze($created->getXML(), self::cert('crypt.key.pem'));

        $this->assertNull($token->getError());
        $this->assertTrue($token->isSignatureValid());
        $this->assertTrue($token->isDataEncrypted());
        $this->assertSame($data, $token->getData());
    }

    public function testRsa15IsRefusedAtCreation()
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Invalid parameter 'cryptAlgorithm'!");

        XMLDSigToken::createSecureXMLToken(
            self::sampleData(),
            self::cert('sign.key.pem'),
            self::cert('sign.cert.pem'),
            self::cert('crypt.key.pem'),
            self::cert('crypt.cert.pem'),
            self::SIGN_KEY_PASSWORD,
            null,
            ['cryptAlgorithm' => XMLSecurityKey::RSA_1_5]
        );
    }

    public function testRsa15CannotBeDeclaredAtAnalysis()
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Invalid parameter 'cryptAlgorithm'!");

        self::analyze('not an XML token', self::cert('crypt.key.pem'), ['cryptAlgorithm' => XMLSecurityKey::RSA_1_5]);
    }

    public function provideRsa15Analyses()
    {
        return [
            'algorithms checked' => [[]],
            'algorithms not checked' => [['checkCryptingAlgorithms' => false]],
        ];
    }

    /**
     * @dataProvider provideRsa15Analyses
     */
    public function testATokenWhoseSessionKeyIsEncryptedWithRsa15IsRefusedWithoutDecryption(array $options)
    {
        // The data are encrypted with AES-128-CBC, declared, so that only
        // the key transport algorithm is at stake.
        $xml = self::buildEncryptedToken(XMLSecurityKey::RSA_1_5, XMLSecurityKey::AES128_CBC);
        $options += ['sessionKeyCipheringAlgorithm' => XMLDSigToken::AES128_CBC];

        self::assertNotDecrypted(self::analyze($xml, $this->unloadableKey(), $options), 'Crypt algorithm is invalid!');
        self::assertNotDecrypted(self::analyze($xml, self::cert('crypt.key.pem'), $options), 'Crypt algorithm is invalid!');
    }

    public function provideUndeclaredCbcAnalyses()
    {
        return [
            'algorithms checked' => [[]],
            'algorithms not checked' => [['checkCryptingAlgorithms' => false]],
        ];
    }

    /**
     * @dataProvider provideUndeclaredCbcAnalyses
     */
    public function testATokenEncryptedWithCbcIsRefusedWithoutDecryptionUnlessDeclared(array $options)
    {
        $xml = self::buildEncryptedToken(XMLSecurityKey::RSA_OAEP_MGF1P, XMLSecurityKey::AES128_CBC);

        self::assertNotDecrypted(self::analyze($xml, $this->unloadableKey(), $options), 'Unauthorized Session Key Ciphering algorithm!');
        self::assertNotDecrypted(self::analyze($xml, self::cert('crypt.key.pem'), $options), 'Unauthorized Session Key Ciphering algorithm!');
    }

    public function testATokenEncryptedWithCbcIsDecryptedWhenDeclared()
    {
        $xml = self::buildEncryptedToken(XMLSecurityKey::RSA_OAEP_MGF1P, XMLSecurityKey::AES128_CBC);

        $token = self::analyze($xml, self::cert('crypt.key.pem'), ['sessionKeyCipheringAlgorithm' => XMLDSigToken::AES128_CBC]);

        $this->assertNull($token->getError());
        $this->assertTrue($token->isSignatureValid());
        $this->assertSame(self::sampleData(), $token->getData());
    }

    public function testTheDeclaredCbcAndAesGcmAreBothAcceptedWhenTheAlgorithmsAreNotChecked()
    {
        $options = [
            'sessionKeyCipheringAlgorithm' => XMLDSigToken::AES128_CBC,
            'checkCryptingAlgorithms' => false,
        ];
        $declared = self::buildEncryptedToken(XMLSecurityKey::RSA_OAEP_MGF1P, XMLSecurityKey::AES128_CBC);
        $gcm = $this->createSecureToken(self::sampleData())->getXML();
        $undeclared = self::buildEncryptedToken(XMLSecurityKey::RSA_OAEP_MGF1P, XMLSecurityKey::AES256_CBC);

        foreach ([$declared, $gcm] as $xml)
        {
            $token = self::analyze($xml, self::cert('crypt.key.pem'), $options);
            $this->assertNull($token->getError());
            $this->assertSame(self::sampleData(), $token->getData());
        }
        self::assertNotDecrypted(self::analyze($undeclared, $this->unloadableKey(), $options), 'Unauthorized Session Key Ciphering algorithm!');
    }

    public function provideAlteredCiphertexts()
    {
        $alterations = [
            'session key: random bytes' => [self::ENCRYPTED_KEY, function ($c) { return "\x00" . random_bytes(strlen($c) - 1); }],
            'session key: 5-byte key' => [self::ENCRYPTED_KEY, function () { return self::oaepEncrypt('12345'); }],
            'session key: another key' => [self::ENCRYPTED_KEY, function () { return self::oaepEncrypt(random_bytes(32)); }],
            'data: altered byte' => [self::ENCRYPTED_DATA, function ($c) { $c[20] = chr(ord($c[20]) ^ 0xff); return $c; }],
            'data: altered last block' => [self::ENCRYPTED_DATA, function ($c) { $c[strlen($c) - 17] = chr(ord($c[strlen($c) - 17]) ^ 0x01); return $c; }],
            'data: truncated' => [self::ENCRYPTED_DATA, function ($c) { return substr($c, 0, -1); }],
            'data: too short' => [self::ENCRYPTED_DATA, function ($c) { return substr($c, 0, 8); }],
        ];
        $ciphers = [
            'AES-256-GCM' => [XMLSecurityKey::AES256_GCM, []],
            'AES-128-CBC declared' => [XMLSecurityKey::AES128_CBC, ['sessionKeyCipheringAlgorithm' => XMLDSigToken::AES128_CBC]],
        ];

        $cases = [];
        foreach ($ciphers as $cipherName => list($cipher, $options))
        {
            foreach ($alterations as $alterationName => list($query, $replace))
            {
                $cases[$cipherName . ', ' . $alterationName] = [$cipher, $options, $query, $replace];
            }
        }

        return $cases;
    }

    /**
     * The altered ciphertext is signed by the trusted signer, so that the
     * token reaches the decryption.
     *
     * @dataProvider provideAlteredCiphertexts
     */
    public function testEveryDecryptionFailureGivesTheSameError($cipher, array $options, $query, callable $replace)
    {
        $xml = self::buildEncryptedToken(XMLSecurityKey::RSA_OAEP_MGF1P, $cipher, self::replaceCipherValue($query, $replace));

        $token = self::analyze($xml, self::cert('crypt.key.pem'), $options);

        $this->assertTrue($token->isSignatureValueOk());
        $this->assertTrue($token->isCertTrusted());
        $this->assertSame(self::DECRYPTION_FAILED, $token->getError());
        $this->assertSame([], $token->getAnomalies());
        $this->assertNull($token->getData());
        // No detail in what the object shows either. getHTMLDump() shows
        // getError() and getAnomalies(); under PHP 8 it fails beforehand, in
        // getPrettyXML(), which passes its arguments to implode() in an order
        // PHP 8 no longer accepts.
        $outputs = [print_r($token, true)];
        if (PHP_MAJOR_VERSION < 8)
        {
            $outputs[] = $token->getHTMLDump();
        }
        foreach ($outputs as $output)
        {
            foreach (['Reason', 'openssl', 'Key must', 'appendXML', 'parser error', 'Session key', 'Token data'] as $detail)
            {
                $this->assertStringNotContainsString($detail, $output);
            }
        }
    }

    public function provideUnverifiedTokens()
    {
        return [
            'untrusted signer' => [
                function () {
                    return self::buildEncryptedToken(XMLSecurityKey::RSA_OAEP_MGF1P, XMLSecurityKey::AES256_GCM, null, 'attacker');
                },
                'not issued by a trusted CA',
            ],
            'altered data, not signed again' => [
                function () {
                    $doc = new DOMDocument();
                    $doc->loadXML(self::buildEncryptedToken(XMLSecurityKey::RSA_OAEP_MGF1P, XMLSecurityKey::AES256_GCM));
                    $alter = self::replaceCipherValue(self::ENCRYPTED_DATA, function ($c) { $c[20] = chr(ord($c[20]) ^ 0xff); return $c; });
                    $alter(self::xpath($doc));
                    return $doc->saveXML();
                },
                'Token hash verification failed!',
            ],
            'altered signature value' => [
                function () {
                    $doc = new DOMDocument();
                    $doc->loadXML(self::buildEncryptedToken(XMLSecurityKey::RSA_OAEP_MGF1P, XMLSecurityKey::AES256_GCM));
                    $node = self::xpath($doc)->query('/ds:Signature/ds:SignatureValue')->item(0);
                    $value = base64_decode($node->nodeValue);
                    $value[10] = chr(ord($value[10]) ^ 0xff);
                    $node->nodeValue = base64_encode($value);
                    return $doc->saveXML();
                },
                'Token hash signature verification failed!',
            ],
        ];
    }

    /**
     * @dataProvider provideUnverifiedTokens
     */
    public function testATokenThatFailsVerificationIsNotDecrypted(callable $build, $reason)
    {
        $token = self::analyze($build(), $this->unloadableKey());

        self::assertNotDecrypted($token, $reason);
        $this->assertNull($token->isDataEncrypted());
    }
}
