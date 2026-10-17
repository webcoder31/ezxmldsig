<?php

namespace webcoder31\ezxmldsig\Tests;

use DOMDocument;
use DOMXPath;
use webcoder31\ezxmldsig\XMLDSigToken;

/**
 * getHTMLDump() and getPrettyXML(): what a token carries comes from its
 * sender and must come out escaped, the HTML must load nothing from
 * elsewhere, and both must work under PHP 8.
 */
class HTMLDumpTest extends TestCase
{
    const PAYLOAD = '<script>alert(1)</script>';
    const ESCAPED_PAYLOAD = '&lt;script&gt;alert(1)&lt;/script&gt;';

    /** OpenSSL writes "/" as "\/" in a Distinguished Name: the payload of
    the certificate fields has none. */
    const CERT_PAYLOAD = '<svg onload=alert(1)>';
    const ESCAPED_CERT_PAYLOAD = '&lt;svg onload=alert(1)&gt;';

    /**
     * Asserts that the payload only appears escaped in the HTML, and that
     * the HTML has neither a script element nor an attribute that loads a
     * resource.
     */
    private function assertEscaped($html, $payload = self::PAYLOAD, $escapedPayload = self::ESCAPED_PAYLOAD)
    {
        $this->assertStringNotContainsString($payload, $html);
        $this->assertStringContainsString($escapedPayload, $html);
        $this->assertNoExternalResource($html);
    }

    private function assertNoExternalResource($html)
    {
        $this->assertStringNotContainsStringIgnoringCase('<script', $html);
        $this->assertStringNotContainsStringIgnoringCase('<svg', $html);
        $this->assertDoesNotMatchRegularExpression('/\b(src|href|srcset|action|background)\s*=/i', $html);

        $doc = new DOMDocument();
        $this->assertTrue(@$doc->loadHTML('<html><body>' . $html . '</body></html>'));
        $xpath = new DOMXPath($doc);
        $this->assertSame(0, $xpath->query('//script | //link | //img | //iframe | //object | //embed | //style | //svg')->length);
        $this->assertSame(0, $xpath->query('//@src | //@href | //@srcset | //@action | //@background')->length);
    }

    public function testDataAreEscaped()
    {
        $token = self::createToken(['name' => self::PAYLOAD, 'quote' => '"\'']);

        $this->assertTrue($token->isSignatureValid(), (string) $token->getError());
        $html = $token->getHTMLDump();
        $this->assertEscaped($html);
        $this->assertStringContainsString('&quot;&#039;', $html);
    }

    public function testCertificateFieldsAreEscaped()
    {
        $issued = $this->issueCertificate('xss', 'sign', 'intermediate', 30, null, ['OU' => self::CERT_PAYLOAD]);
        $token = self::createTokenWith($issued, self::sampleData());

        $this->assertTrue($token->isSignatureValid(), (string) $token->getError());
        $this->assertSame(self::CERT_PAYLOAD, $token->getCertSubject()['OU']);
        $this->assertStringContainsString(self::CERT_PAYLOAD, $token->getCertDN());
        $html = $token->getHTMLDump();
        $this->assertEscaped($html, self::CERT_PAYLOAD, self::ESCAPED_CERT_PAYLOAD);
        // The DN and the subject both hold the payload.
        $this->assertSame(2, substr_count($html, self::ESCAPED_CERT_PAYLOAD));
    }

    public function testErrorIsEscaped()
    {
        // The error names the subject of a certificate the sender chose.
        $issued = $this->issueCertificate('xss', 'sign', 'intermediate', 30, null, ['OU' => self::CERT_PAYLOAD]);
        $xml = self::createTokenWith($issued, self::sampleData())->getXML();
        $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor([
            'expectedSubject' => ['OU' => 'Signature Dept'],
        ]));

        $this->assertFalse($token->isSignatureValid());
        $this->assertStringContainsString(self::CERT_PAYLOAD, $token->getError());
        $html = $token->getHTMLDump();
        $this->assertEscaped($html, self::CERT_PAYLOAD, self::ESCAPED_CERT_PAYLOAD);
        // The error, the DN and the subject hold the payload.
        $this->assertSame(3, substr_count($html, self::ESCAPED_CERT_PAYLOAD));
    }

    public function testRejectedDocumentIsEscaped()
    {
        // A document that is not a token at all is shown as is.
        $token = XMLDSigToken::analyzeXMLToken('<a>' . self::ESCAPED_PAYLOAD . '</a><b>' . self::PAYLOAD, self::trustAnchor());

        $this->assertFalse($token->isSignatureValid());
        $html = $token->getHTMLDump();
        $this->assertStringNotContainsString(self::PAYLOAD, $html);
        $this->assertNoExternalResource($html);
    }

    public function testHTMLDumpLoadsNoExternalResource()
    {
        $this->assertNoExternalResource(self::createToken(self::sampleData())->getHTMLDump());
        $this->assertNoExternalResource($this->createSecureToken(self::sampleData())->getHTMLDump());
    }

    public function provideTokens()
    {
        return [
            'signed' => [false],
            'signed and encrypted' => [true],
        ];
    }

    /**
     * getPrettyXML() splits the long values into lines of 64 characters;
     * it used to pass its arguments to implode() in an order PHP 8 refuses.
     *
     * @dataProvider provideTokens
     */
    public function testPrettyXMLAndHTMLDumpWork($encrypted)
    {
        $token = $encrypted ? $this->createSecureToken(self::sampleData()) : self::createToken(self::sampleData());
        $this->assertTrue($token->isSignatureValid(), (string) $token->getError());

        $pretty = $token->getPrettyXML();
        $doc = new DOMDocument();
        $doc->loadXML($token->getXML());
        $signatureValue = $doc->getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'SignatureValue')->item(0)->nodeValue;
        $this->assertGreaterThan(64, strlen($signatureValue));
        $this->assertMatchesRegularExpression('/^ *' . preg_quote(substr($signatureValue, 0, 64), '/') . '$/m', $pretty);
        $this->assertStringContainsString('<ds:Object Id="Token">', $pretty);

        $html = $token->getHTMLDump();
        $this->assertStringContainsString(htmlspecialchars(substr($signatureValue, 0, 64)), $html);
        $this->assertStringContainsString('Ragnar Lothbrok', $html);
    }

    public function testPrettyXMLOfARejectedDocumentRaisesNoWarning()
    {
        // PHPUnit turns warnings into errors.
        $token = XMLDSigToken::analyzeXMLToken('not an XML document', self::trustAnchor());

        $this->assertSame("not an XML document\n", $token->getPrettyXML());
        $this->assertStringContainsString('not an XML document', $token->getHTMLDump());
    }
}
