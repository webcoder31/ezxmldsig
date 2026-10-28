<?php

namespace webcoder31\ezxmldsig\Tests;

use DOMDocument;
use DOMXPath;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use webcoder31\ezxmldsig\Demo\Forge;
use webcoder31\ezxmldsig\token\XMLDSigToken;

/**
 * The verification of "ds:SignatureValue" returns the value of
 * openssl_verify(): 1 (valid), 0 (invalid) or -1 (error). Only 1 makes the
 * signature valid: -1, which is TRUE in a boolean context, is returned when
 * an RSA signature is verified with an EC or DSA key, whatever the signature
 * value. An ECDSA signature verified with the EC key gives 1: the signature
 * algorithms being RSA ones, a key of another type is refused.
 */
class SignatureVerificationResultTest extends TestCase
{
    /** Forged token data. */
    const FORGED_DATA = ['name' => 'Forged'];

    /**
     * Returns a self-signed certificate (base64 DER, as in
     * "ds:X509Certificate") for a new key of the given configuration.
     */
    private static function selfSignedCertificate(array $keyConfig)
    {
        $key = openssl_pkey_new($keyConfig);
        $csr = openssl_csr_new(['CN' => 'forger'], $key, ['digest_alg' => 'sha256']);
        $cert = openssl_csr_sign($csr, null, $key, 1, ['digest_alg' => 'sha256']);
        openssl_x509_export($cert, $pem);

        return preg_replace('/-----[^-]+-----|\s/', '', $pem);
    }

    /**
     * Forges a token without any private key: the token data is altered, the
     * digest is computed again and the certificate is replaced. The signature
     * value is the one of the legitimate token, unless one is given.
     */
    private static function forge($certificate, $signatureValue = null)
    {
        $doc = new DOMDocument();
        $doc->loadXML(self::createToken(self::sampleData())->getXML());
        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);

        $tokenData = $xpath->query('/ds:Signature/ds:Object/Token/TokenData')->item(0);
        while ($tokenData->firstChild)
        {
            $tokenData->removeChild($tokenData->firstChild);
        }
        foreach (self::FORGED_DATA as $name => $value)
        {
            $tokenData->appendChild($doc->createElement($name, $value));
        }

        $object = $xpath->query('/ds:Signature/ds:Object')->item(0);
        $reference = $xpath->query('/ds:Signature/ds:SignedInfo/ds:Reference')->item(0);
        $digestAlgorithm = $xpath->evaluate('string(ds:DigestMethod/@Algorithm)', $reference);
        $xpath->query('ds:DigestValue', $reference)->item(0)->nodeValue =
            (new XMLSecurityDSig())->calculateDigest($digestAlgorithm, $object->C14N());

        if (!is_null($certificate))
        {
            $xpath->query('/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate')->item(0)->nodeValue = $certificate;
        }
        if (!is_null($signatureValue))
        {
            $xpath->query('/ds:Signature/ds:SignatureValue')->item(0)->nodeValue = $signatureValue;
        }

        return $doc;
    }

    /**
     * Returns what xmlseclibs' verification of "ds:SignatureValue" returns
     * for the given document, after checking that its digest is valid.
     */
    private function verificationResult(DOMDocument $doc)
    {
        $doc = clone $doc;
        $verifier = new XMLSecurityDSig();
        $verifier->locateSignature($doc);
        $this->assertTrue($verifier->validateReference());
        $verifier->canonicalizeSignedInfo();
        $key = $verifier->locateKey();
        XMLSecEnc::staticLocateKeyInfo($key, $verifier->sigNode);

        return $verifier->verify($key);
    }

    public function provideForgedTokens()
    {
        return [
            'EC certificate' => [
                function () {
                    return self::forge(self::selfSignedCertificate([
                        'private_key_type' => OPENSSL_KEYTYPE_EC,
                        'curve_name' => 'prime256v1',
                    ]));
                },
                -1,
            ],
            'EC certificate, empty signature value' => [
                function () {
                    return self::forge(self::selfSignedCertificate([
                        'private_key_type' => OPENSSL_KEYTYPE_EC,
                        'curve_name' => 'prime256v1',
                    ]), '=');
                },
                -1,
            ],
            'DSA certificate' => [
                function () {
                    return self::forge(self::selfSignedCertificate([
                        'private_key_type' => OPENSSL_KEYTYPE_DSA,
                        'private_key_bits' => 2048,
                    ]));
                },
                -1,
            ],
            'signing certificate, random signature value' => [
                function () {
                    return self::forge(null, base64_encode(random_bytes(256)));
                },
                0,
            ],
        ];
    }

    /**
     * @dataProvider provideForgedTokens
     */
    public function testOnlyAVerificationResultOfOneMakesTheSignatureValid(callable $forge, $expectedResult)
    {
        $doc = $forge();
        $this->assertSame($expectedResult, $this->verificationResult($doc));

        $token = XMLDSigToken::analyzeXMLToken($doc->saveXML(), self::trustAnchor());

        $this->assertTrue($token->isDigestValueOk());
        $this->assertFalse($token->isSignatureValueOk());
        $this->assertFalse($token->isSignatureValid());
        $this->assertNotEquals(self::FORGED_DATA, $token->getData());
    }

    /**
     * Returns a signing certificate with an EC key (P-256), issued by the
     * trusted intermediate: refused for its key, not for its trust.
     */
    private function ecSigner()
    {
        return $this->issueCertificate('ec-signer', 'sign', 'intermediate', 30, null, [], [
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
    }

    public function testAnEcdsaSignatureUnderAnRsaAlgorithmIsRefused()
    {
        // Signed again with the EC key: xmlseclibs signs with OpenSSL, which
        // signs in ECDSA with an EC key, under the declared rsa-sha256.
        $ec = $this->ecSigner();
        $forge = new Forge(self::createToken(self::sampleData())->getXML());
        $forge->resign($ec['key'], null, $ec['cert']);
        $doc = new DOMDocument();
        $doc->loadXML($forge->xml());
        $this->assertSame(XMLDSigToken::RSA_SHA256, (new DOMXPath($doc))->evaluate('string(//*[local-name()="SignatureMethod"]/@Algorithm)'));
        // openssl_verify() accepts it.
        $this->assertSame(1, $this->verificationResult($doc));

        $token = XMLDSigToken::analyzeXMLToken($forge->xml(), self::trustAnchor());

        $this->assertTrue($token->isDigestValueOk());
        $this->assertFalse($token->isSignatureValueOk());
        $this->assertFalse($token->isSignatureValid());
        $this->assertStringContainsString('Token hash signature verification failed!', (string) $token->getError());
        $this->assertNull($token->getData());
    }

    public function testAnEcKeyCannotSignAToken()
    {
        $ec = $this->ecSigner();

        $token = self::createTokenWith($ec, self::sampleData());

        $this->assertSame('The signing key is not an RSA key: the signature algorithms are RSA ones!', $token->getError());
        $this->assertFalse($token->isSignatureValid());
    }
}
