<?php

namespace webcoder31\ezxmldsig\Tests;

use webcoder31\ezxmldsig\XMLDSigToken;

/**
 * Loading of XML documents (token analysis and alterXML()): a document type
 * declaration is refused before any entity is expanded or loaded, and so is
 * a document whose encoding would hide one from that check.
 */
class XMLParsingTest extends TestCase
{
    const DOCTYPE_ERROR = 'XML Digital Signature must not have a document type declaration (DOCTYPE)!';
    const ENCODING_ERROR = 'XML Digital Signature must be encoded in UTF-8!';
    const INVALID_ERROR = 'XML Digital Signature is not a valid XML document!';

    /** Stream wrapper protocol whose opening the tests watch for. */
    const PROBE = 'ezxmldsigprobe';

    protected function setUp(): void
    {
        parent::setUp();
        EntityProbe::$opened = [];
        stream_wrapper_register(self::PROBE, EntityProbe::class);
    }

    protected function tearDown(): void
    {
        stream_wrapper_unregister(self::PROBE);
        parent::tearDown();
    }

    /**
     * Inserts a document type declaration after the XML declaration of a
     * valid signed token: the signature does not cover it.
     */
    private static function withDoctype($internalSubset)
    {
        $xml = self::createToken(self::sampleData())->getXML();

        return preg_replace('/\A(<\?xml[^>]*\?>\s*)/', '$1<!DOCTYPE ds:Signature [' . $internalSubset . ']>' . "\n", $xml, 1);
    }

    private function assertRefused(XMLDSigToken $token, $error)
    {
        $this->assertFalse($token->isSignatureValid());
        $this->assertSame($error, $token->getError());
        $this->assertNull($token->getData());
        $this->assertNull($token->getTimestamp());
        $this->assertNull($token->getTokenId());
        $this->assertNull($token->getCertificate());
        $this->assertSame([], EntityProbe::$opened);
    }

    public function testProbeSeesTheLoadOfAnExternalEntity()
    {
        // The probe works: libxml opens it when asked to load external
        // entities, which the analysis never asks.
        $doc = new \DOMDocument();
        @$doc->loadXML('<!DOCTYPE r [<!ENTITY e SYSTEM "' . self::PROBE . '://entity">]><r>&e;</r>', LIBXML_NOENT);

        $this->assertNotSame([], EntityProbe::$opened);
    }

    public function testDoctypeIsTheOnlyChange()
    {
        // The tokens below are valid but for their document type
        // declaration: their refusal is due to it.
        $xml = self::withDoctype('');
        $this->assertStringContainsString('<!DOCTYPE ds:Signature []>', $xml);
        $valid = XMLDSigToken::analyzeXMLToken(str_replace("<!DOCTYPE ds:Signature []>\n", '', $xml), self::trustAnchor());
        $this->assertTrue($valid->isSignatureValid(), (string) $valid->getError());
    }

    public function provideDoctypes()
    {
        return [
            'empty' => [''],
            'internal entity' => ['<!ENTITY e "expanded">'],
            'nested internal entities' => ['<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'],
            'external entity' => ['<!ENTITY e SYSTEM "' . self::PROBE . '://entity">'],
            'external parameter entity' => ['<!ENTITY % p SYSTEM "' . self::PROBE . '://parameter"> %p;'],
        ];
    }

    /**
     * @dataProvider provideDoctypes
     */
    public function testAnalysisRefusesADoctype($internalSubset)
    {
        $token = XMLDSigToken::analyzeXMLToken(self::withDoctype($internalSubset), self::trustAnchor());

        $this->assertRefused($token, self::DOCTYPE_ERROR);
    }

    public function testAnalysisRefusesAnEntityReferencedInTheToken()
    {
        $xml = str_replace('<TokenData>', '<TokenData><e>&e;</e>', self::withDoctype('<!ENTITY e SYSTEM "' . self::PROBE . '://entity">'));

        $this->assertRefused(XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor()), self::DOCTYPE_ERROR);
    }

    public function provideHiddenDoctypes()
    {
        $doctype = self::withDoctype('<!ENTITY e SYSTEM "' . self::PROBE . '://entity">');
        $declared = function ($encoding) use ($doctype) {
            return preg_replace('/\A<\?xml[^>]*\?>/', '<?xml version="1.0" encoding="' . $encoding . '"?>', $doctype);
        };

        return [
            'UTF-16 with BOM' => ["\xFF\xFE" . mb_convert_encoding($declared('UTF-16'), 'UTF-16LE', 'UTF-8'), self::ENCODING_ERROR],
            'UTF-16 without BOM' => [mb_convert_encoding($declared('UTF-16'), 'UTF-16BE', 'UTF-8'), self::ENCODING_ERROR],
            'declared ISO-8859-1' => [$declared('ISO-8859-1'), self::ENCODING_ERROR],
            // libxml detects EBCDIC from these first bytes ("<?xm").
            'EBCDIC' => ["\x4C\x6F\xA7\x94" . substr($doctype, 4), self::INVALID_ERROR],
        ];
    }

    /**
     * A document in another encoding than UTF-8 could write "<!DOCTYPE" with
     * other bytes: it is refused before it is parsed.
     *
     * @dataProvider provideHiddenDoctypes
     */
    public function testAnalysisRefusesAnotherEncodingThanUTF8($xml, $error)
    {
        $this->assertRefused(XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor()), $error);
    }

    public function testAnalysisAcceptsADeclaredUTF8Encoding()
    {
        $xml = self::createToken(self::sampleData())->getXML();
        $xml = preg_replace('/\A<\?xml[^>]*\?>/', "\xEF\xBB\xBF" . '<?xml version="1.0" encoding="utf-8"?>', $xml);

        $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor());

        $this->assertTrue($token->isSignatureValid(), (string) $token->getError());
    }

    public function testAlterXMLRefusesAnInternalEntity()
    {
        $xml = '<!DOCTYPE r [<!ENTITY e "expanded">]><r><a>&e;</a></r>';
        $original = $xml;

        $this->assertFalse(XMLDSigToken::alterXML($xml, '//a', null, 'altered'));
        $this->assertSame($original, $xml);
    }

    public function testAlterXMLRefusesAnExternalEntity()
    {
        $xml = '<!DOCTYPE r [<!ENTITY e SYSTEM "' . self::PROBE . '://entity">]><r><a>&e;</a></r>';
        $original = $xml;

        $this->assertFalse(XMLDSigToken::alterXML($xml, '//a', null, 'altered'));
        $this->assertSame($original, $xml);
        $this->assertSame([], EntityProbe::$opened);
    }

    public function testAlterXMLStillAltersADocumentWithoutDoctype()
    {
        $xml = '<r><a>value</a></r>';

        $this->assertSame('value', XMLDSigToken::alterXML($xml, '//a', null, 'altered'));
        $this->assertStringContainsString('<a>altered</a>', $xml);
    }

    public function testAnInvalidDocumentIsRefusedWithoutWarning()
    {
        // PHPUnit turns warnings into errors.
        foreach (['', 'not XML', '<a>', '<a/><b/>'] as $xml)
        {
            $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor());
            $this->assertSame(self::INVALID_ERROR, $token->getError(), $xml);

            $this->assertFalse(XMLDSigToken::alterXML($xml, '//a', null, 'altered'));
        }
    }

    /**
     * Runs $run and returns the deprecations it raised.
     */
    private static function deprecationsOf(callable $run)
    {
        $deprecations = [];
        set_error_handler(function ($errno, $errstr, $errfile, $errline) use (&$deprecations) {
            $deprecations[] = $errstr . ' (' . $errfile . ':' . $errline . ')';
            return true;
        }, E_DEPRECATED | E_USER_DEPRECATED);
        try
        {
            $run();
        }
        finally
        {
            restore_error_handler();
        }

        return $deprecations;
    }

    /**
     * The analysis used to set DOMDocument::$preserveWhiteSpaces, which
     * does not exist: PHP 8.2 and later deprecate the creation of such a
     * property.
     */
    public function testAnalysisRaisesNoDeprecation()
    {
        $deprecations = self::deprecationsOf(function () use (&$analyzed) {
            $token = self::createToken(self::sampleData());
            $analyzed = XMLDSigToken::analyzeXMLToken($token->getXML(), self::trustAnchor());
            $xml = $token->getXML();
            XMLDSigToken::alterXML($xml, '//ds:SignatureValue', null, 'altered');
        });

        $this->assertTrue($analyzed->isSignatureValid(), (string) $analyzed->getError());
        $this->assertSame([], $deprecations);
    }

    /**
     * getPrettyXML() used to pass its arguments to implode() in an order
     * PHP 7.4 deprecates and PHP 8 refuses.
     */
    public function testDisplayRaisesNoDeprecation()
    {
        $token = self::createToken(self::sampleData());

        $deprecations = self::deprecationsOf(function () use ($token) {
            $token->getPrettyXML();
            $token->getHTMLDump();
        });

        $this->assertSame([], $deprecations);
    }

    /**
     * Whitespace is preserved: the digest covers the token as it was
     * signed, whitespace text nodes included.
     */
    public function testWhitespaceIsPreserved()
    {
        $data = ['indented' => "\n  ", 'name' => 'Ragnar'];
        $token = XMLDSigToken::createXMLToken($data, self::cert('sign.key.pem'), self::cert('sign.cert.pem'), self::SIGN_KEY_PASSWORD, [
            'base64Encode' => false,
        ]);
        $this->assertTrue($token->isSignatureValid(), (string) $token->getError());

        $analyzed = XMLDSigToken::analyzeXMLToken($token->getXML(), self::trustAnchor());

        $this->assertTrue($analyzed->isSignatureValid(), (string) $analyzed->getError());
        $this->assertSame($data, $analyzed->getData());
    }
    /**
     * @return array Case => [content of ds:X509Certificate]
     */
    public function unreadableCertificates()
    {
        return [
            'base64 of nothing' => ['AAAA'],
            'empty' => [''],
            'not base64' => ['not a certificate'],
            'a truncated certificate' => [substr(preg_replace('/-----[^-]+-----|\s/', '', file_get_contents(self::cert('sign.cert.pem'))), 0, 200)],
        ];
    }

    /**
     * The content of ds:X509Certificate comes from the sender, and is read
     * before the signature is verified: a token whose certificate cannot be
     * read is refused without any PHP message (warning, deprecation), which
     * would reach the response or the logs of the receiver.
     *
     * @dataProvider unreadableCertificates
     */
    public function testAnUnreadableCertificateIsRefusedWithoutPhpMessage($content)
    {
        $doc = new \DOMDocument();
        $doc->loadXML(self::createToken(self::sampleData())->getXML());
        $doc->getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'X509Certificate')->item(0)->nodeValue = $content;
        $xml = $doc->saveXML();

        $messages = [];
        // The messages PHP would display or log: not those silenced with @.
        set_error_handler(function ($level, $message, $file, $line) use (&$messages) {
            if (error_reporting() & $level)
            {
                $messages[] = $message . ' (' . basename($file) . ':' . $line . ')';
            }
            return true;
        });
        try
        {
            $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor());
        }
        finally
        {
            restore_error_handler();
        }

        $this->assertSame([], $messages, implode(" | ", $messages));
        $this->assertFalse($token->isSignatureValid());
        $this->assertStringContainsString('Unable to extract public key', (string) $token->getError());
    }

}

/**
 * Stream wrapper that records every attempt to open it: libxml reads
 * external entities through PHP streams.
 */
class EntityProbe
{
    /** @var array The URIs libxml tried to open. */
    public static $opened = [];

    /** @var resource|null Set by PHP. */
    public $context;

    public function stream_open($path, $mode, $options, &$openedPath)
    {
        self::$opened[] = $path;

        return false;
    }

    public function url_stat($path, $flags)
    {
        self::$opened[] = $path;

        return false;
    }
}
