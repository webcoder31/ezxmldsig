<?php

namespace webcoder31\ezxmldsig\Tests;

use DateTime;
use DateTimeZone;
use DOMDocument;
use DOMElement;
use DOMXPath;
use Exception;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use webcoder31\ezxmldsig\token\XMLDSigToken;

/**
 * Audience and expiry of the token: who it is addressed to, checked by
 * isSignatureValid() against the option "expectedAudience", and the date
 * after which isOutOfDate() rejects it, set by the issuer.
 */
class AudienceAndExpiryTest extends TestCase
{
    const TOKEN = '/ds:Signature/ds:Object/Token';

    private static function xpath(DOMDocument $doc)
    {
        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);

        return $xpath;
    }

    /**
     * Creates a signed token with the given creation options.
     */
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

    /**
     * Signs again, with the trusted signing key, the token of $xml after
     * $alter changed it: the result is validly signed, as a token the
     * trusted issuer would have created.
     */
    private static function signAgain($xml, callable $alter)
    {
        $doc = new DOMDocument();
        $doc->loadXML($xml);
        $tokenNode = self::xpath($doc)->query(self::TOKEN)->item(0);
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

    /**
     * Replaces the text of the child $name of the token node, or adds it.
     */
    private static function setChild(DOMElement $tokenNode, $name, $value)
    {
        $nodes = $tokenNode->getElementsByTagName($name);
        $node = $nodes->length > 0 ? $nodes->item(0) : $tokenNode->appendChild($tokenNode->ownerDocument->createElement($name));
        $node->nodeValue = '';
        $node->appendChild($tokenNode->ownerDocument->createTextNode($value));
    }

    private static function utc($modifier)
    {
        return (new DateTime($modifier, new DateTimeZone('UTC')))->format(XMLDSigToken::TOKEN_TIMESTAMP_FORMAT);
    }

    // ---- Audience ---------------------------------------------------------

    public function testCreatedTokenNamesItsAudiencesInTheSignedToken()
    {
        $token = self::createTokenWithOptions(['audience' => ['mail', 'crm']]);

        $this->assertTrue($token->isSignatureValid(), (string) $token->getError());
        $this->assertSame(['mail', 'crm'], $token->getAudience());

        $doc = new DOMDocument();
        $doc->loadXML($token->getXML());
        $values = [];
        foreach (self::xpath($doc)->query(self::TOKEN . '/TokenAudience') as $node)
        {
            $values[] = $node->nodeValue;
        }
        $this->assertSame(['mail', 'crm'], $values);
    }

    public function testATokenIsAcceptedByTheAudienceItNames()
    {
        $xml = self::createTokenWithOptions(['audience' => ['mail', 'crm']])->getXML();

        foreach (['mail', 'crm'] as $audience)
        {
            $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor(['expectedAudience' => $audience]));

            $this->assertTrue($token->isSignatureValid(), (string) $token->getError());
            $this->assertSame(['mail', 'crm'], $token->getAudience());
            $this->assertSame(self::sampleData(), $token->getData());
        }
    }

    public function testATokenIsRejectedByAnotherAudience()
    {
        $xml = self::createTokenWithOptions(['audience' => 'mail'])->getXML();

        $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor(['expectedAudience' => 'crm']));

        $this->assertFalse($token->isSignatureValid());
        $this->assertSame("Token is not addressed to the expected audience! Expected: 'crm'. Token audience: 'mail'.", $token->getError());
        $this->assertNull($token->getData());
        $this->assertNull($token->getAudience());
        $this->assertNull($token->getTokenId());
        $this->assertNull($token->getTimestamp());
    }

    public function testTheAudienceIsComparedAsIs()
    {
        $xml = self::createTokenWithOptions(['audience' => 'Mail'])->getXML();

        $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor(['expectedAudience' => 'mail']));

        $this->assertFalse($token->isSignatureValid());
    }

    public function testATokenNamingAnAudienceIsRejectedWithoutExpectedAudience()
    {
        $xml = self::createTokenWithOptions(['audience' => 'mail'])->getXML();

        $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor());

        $this->assertFalse($token->isSignatureValid());
        $this->assertSame("Token is addressed to an audience ('mail'), but the option 'expectedAudience' is not given: pass the audience of this receiver to accept it!", $token->getError());
        $this->assertNull($token->getData());
    }

    public function testATokenWithoutAudienceIsRejectedWhenAnAudienceIsExpected()
    {
        $xml = self::createToken(self::sampleData())->getXML();

        $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor(['expectedAudience' => 'mail']));

        $this->assertFalse($token->isSignatureValid());
        $this->assertSame("Token is not addressed to any audience, but the audience 'mail' is expected!", $token->getError());
        $this->assertNull($token->getData());
    }

    public function testATokenWithoutAudienceIsAcceptedWithoutExpectedAudience()
    {
        $xml = self::createToken(self::sampleData())->getXML();

        $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor());

        $this->assertTrue($token->isSignatureValid(), (string) $token->getError());
        $this->assertNull($token->getAudience());
        $this->assertSame(self::sampleData(), $token->getData());
    }

    public function testAnAudienceKeepsItsCharacters()
    {
        $audience = 'https://crm.example.com/sso?a=1&b=<2> "é€"';
        $xml = self::createTokenWithOptions(['audience' => $audience])->getXML();

        $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor(['expectedAudience' => $audience]));

        $this->assertTrue($token->isSignatureValid(), (string) $token->getError());
        $this->assertSame([$audience], $token->getAudience());
    }

    public function testAMalformedAudienceIsRejectedBeforeTheDataAreRead()
    {
        $xml = self::createTokenWithOptions(['audience' => 'mail'])->getXML();
        $forged = self::signAgain($xml, function (DOMElement $tokenNode) {
            $node = $tokenNode->getElementsByTagName('TokenAudience')->item(0);
            $node->appendChild($tokenNode->ownerDocument->createElement('Extra', 'crm'));
        });

        $token = XMLDSigToken::analyzeXMLToken($forged, self::trustAnchor(['expectedAudience' => 'mail']));

        $this->assertFalse($token->isSignatureValid());
        $this->assertStringContainsString('Token audience is malformed!', (string) $token->getError());
        $this->assertNull($token->getData());
    }

    public function testTheAudienceIsCoveredByTheDigest()
    {
        // Changing the audience without signing again breaks the digest.
        $xml = self::createTokenWithOptions(['audience' => 'mail'])->getXML();
        $doc = new DOMDocument();
        $doc->loadXML($xml);
        self::xpath($doc)->query(self::TOKEN . '/TokenAudience')->item(0)->nodeValue = 'crm';

        $token = XMLDSigToken::analyzeXMLToken($doc->saveXML(), self::trustAnchor(['expectedAudience' => 'crm']));

        $this->assertFalse($token->isSignatureValid());
        $this->assertFalse($token->isDigestValueOk());
    }

    /**
     * @dataProvider malformedAudiences
     */
    public function testAMalformedAudienceNodeIsRejected(callable $alter)
    {
        $xml = self::signAgain(self::createTokenWithOptions(['audience' => 'mail'])->getXML(), $alter);

        $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor(['expectedAudience' => 'mail']));

        $this->assertFalse($token->isSignatureValid());
        $this->assertStringContainsString('Token audience is malformed!', (string) $token->getError());
        $this->assertNull($token->getData());
    }

    public function malformedAudiences()
    {
        return [
            'empty' => [function (DOMElement $tokenNode) {
                $tokenNode->getElementsByTagName('TokenAudience')->item(0)->nodeValue = '';
            }],
            'CDATA' => [function (DOMElement $tokenNode) {
                $node = $tokenNode->getElementsByTagName('TokenAudience')->item(0);
                $node->nodeValue = '';
                $node->appendChild($tokenNode->ownerDocument->createCDATASection('mail'));
            }],
            'surrounding space' => [function (DOMElement $tokenNode) {
                $tokenNode->getElementsByTagName('TokenAudience')->item(0)->nodeValue = ' mail';
            }],
        ];
    }

    public function testAnAudienceNodeInANamespaceIsNotAnAudience()
    {
        // Only the children "TokenAudience" of the token, in no namespace,
        // name its audiences: this signed token names none.
        $xml = self::signAgain(self::createToken(self::sampleData())->getXML(), function (DOMElement $tokenNode) {
            $tokenNode->appendChild($tokenNode->ownerDocument->createElementNS('urn:other', 'o:TokenAudience', 'mail'));
        });

        $expected = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor(['expectedAudience' => 'mail']));
        $this->assertFalse($expected->isSignatureValid());
        $this->assertSame("Token is not addressed to any audience, but the audience 'mail' is expected!", $expected->getError());

        $none = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor());
        $this->assertTrue($none->isSignatureValid(), (string) $none->getError());
        $this->assertNull($none->getAudience());
    }

    public function testEarlierAnomaliesAreReportedBeforeTheAudience()
    {
        $xml = self::signAgain(self::createTokenWithOptions(['audience' => 'mail'])->getXML(), function (DOMElement $tokenNode) {
            self::setChild($tokenNode, 'TokenId', 'not-hexadecimal');
        });

        $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor(['expectedAudience' => 'crm']));

        $this->assertFalse($token->isSignatureValid());
        $this->assertSame('1 anomaly detected: Token identifier is malformed!', $token->getError());
        $this->assertNull($token->getData());
    }

    public function testAnEncryptedTokenCarriesItsAudience()
    {
        $this->requireSymmetricEncryption();
        $created = XMLDSigToken::createSecureXMLToken(
            self::sampleData(),
            self::cert('sign.key.pem'),
            self::cert('sign.cert.pem'),
            self::cert('crypt.key.pem'),
            self::cert('crypt.cert.pem'),
            self::SIGN_KEY_PASSWORD,
            null,
            ['audience' => 'mail']
        );
        $this->assertTrue($created->isSignatureValid(), (string) $created->getError());
        $this->assertStringNotContainsString('TokenAudience', $created->getXML());

        $ok = XMLDSigToken::analyzeSecureXMLToken($created->getXML(), self::cert('crypt.key.pem'), null, self::trustAnchor(['expectedAudience' => 'mail']));
        $this->assertTrue($ok->isSignatureValid(), (string) $ok->getError());
        $this->assertSame(['mail'], $ok->getAudience());

        $other = XMLDSigToken::analyzeSecureXMLToken($created->getXML(), self::cert('crypt.key.pem'), null, self::trustAnchor(['expectedAudience' => 'crm']));
        $this->assertFalse($other->isSignatureValid());
        $this->assertNull($other->getData());
    }

    public function testAnEncryptedTokenCreatedWithoutTheRecipientKeyLeavesItsAudienceUnread()
    {
        $this->requireSymmetricEncryption();
        $created = XMLDSigToken::createSecureXMLToken(
            self::sampleData(),
            self::cert('sign.key.pem'),
            self::cert('sign.cert.pem'),
            null,
            self::cert('crypt.cert.pem'),
            self::SIGN_KEY_PASSWORD,
            null,
            ['audience' => 'mail', 'validity' => 60]
        );

        $this->assertTrue($created->isSignatureValid(), (string) $created->getError());
        $this->assertNull($created->getAudience());
        $this->assertNull($created->getExpiry());
    }

    /**
     * @dataProvider invalidAudienceOptions
     */
    public function testAnInvalidAudienceOptionThrows(array $options, $message)
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage($message);

        self::createTokenWithOptions($options);
    }

    public function invalidAudienceOptions()
    {
        $message = "Invalid option 'audience'!";

        return [
            'empty string'      => [['audience' => ''], $message],
            'empty list'        => [['audience' => []], $message],
            'surrounding space' => [['audience' => ' mail'], $message],
            'line feed'         => [['audience' => "mail\ncrm"], $message],
            'not a string'      => [['audience' => 42], $message],
            'list with a hole'  => [['audience' => ['mail', '']], $message],
            'associative array' => [['audience' => ['a' => 'mail']], $message],
            'invalid UTF-8'     => [['audience' => "\xC3\x28"], $message],
            'U+FFFE'            => [['audience' => "mail\u{FFFE}"], $message],
            'given twice'       => [['audience' => ['mail', 'crm', 'mail']], "Invalid option 'audience'! An audience is given twice."],
            'analysis option'   => [['expectedAudience' => 'mail'], "Option 'expectedAudience' only applies to token analysis!"],
        ];
    }

    /**
     * @dataProvider invalidExpectedAudienceOptions
     */
    public function testAnInvalidExpectedAudienceOptionThrows($value)
    {
        $xml = self::createToken(self::sampleData())->getXML();

        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Invalid option 'expectedAudience'!");

        XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor(['expectedAudience' => $value]));
    }

    public function invalidExpectedAudienceOptions()
    {
        return [
            'empty string' => [''],
            'list'         => [['mail']],
            'control char' => ["mail\t"],
        ];
    }

    public function testCreationOptionsAreRefusedAtAnalysis()
    {
        $xml = self::createToken(self::sampleData())->getXML();

        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Option 'audience' only applies to token creation!");

        XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor(['audience' => 'mail']));
    }

    // ---- Expiry -----------------------------------------------------------

    public function testCreatedTokenHoldsItsExpiry()
    {
        $token = self::createTokenWithOptions(['validity' => 300]);

        $this->assertTrue($token->isSignatureValid(), (string) $token->getError());
        $timezone = new DateTimeZone('UTC');
        $timestamp = DateTime::createFromFormat(XMLDSigToken::TOKEN_TIMESTAMP_FORMAT, $token->getTimestamp(), $timezone);
        $expiry = DateTime::createFromFormat(XMLDSigToken::TOKEN_TIMESTAMP_FORMAT, $token->getExpiry(), $timezone);
        $this->assertSame(300, $expiry->getTimestamp() - $timestamp->getTimestamp());

        $analyzed = XMLDSigToken::analyzeXMLToken($token->getXML(), self::trustAnchor());
        $this->assertTrue($analyzed->isSignatureValid(), (string) $analyzed->getError());
        $this->assertSame($token->getExpiry(), $analyzed->getExpiry());
        $this->assertFalse($analyzed->isOutOfDate(600));
    }

    public function testATokenWithoutValidityHasNoExpiry()
    {
        $token = XMLDSigToken::analyzeXMLToken(self::createToken(self::sampleData())->getXML(), self::trustAnchor());

        $this->assertTrue($token->isSignatureValid(), (string) $token->getError());
        $this->assertNull($token->getExpiry());
        $this->assertStringNotContainsString('TokenExpiry', $token->getXML());
    }

    public function testAnExpiredTokenIsOutOfDateWhateverTheTimeToLive()
    {
        // A recent token whose expiry, set by the issuer, is passed.
        $xml = self::signAgain(self::createToken(self::sampleData())->getXML(), function (DOMElement $tokenNode) {
            self::setChild($tokenNode, 'TokenTimestamp', self::utc('-20 seconds'));
            self::setChild($tokenNode, 'TokenExpiry', self::utc('-10 seconds'));
        });

        $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor());

        $this->assertTrue($token->isSignatureValid(), (string) $token->getError());
        $this->assertTrue($token->isOutOfDate(3600));
    }

    public function testTheTimeToLiveOfTheReceiverStillApplies()
    {
        // The issuer allows a day; the receiver allows 60 seconds.
        $xml = self::signAgain(self::createToken(self::sampleData())->getXML(), function (DOMElement $tokenNode) {
            self::setChild($tokenNode, 'TokenTimestamp', self::utc('-120 seconds'));
            self::setChild($tokenNode, 'TokenExpiry', self::utc('+1 day'));
        });

        $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor());

        $this->assertTrue($token->isSignatureValid(), (string) $token->getError());
        $this->assertTrue($token->isOutOfDate(60));
        $this->assertFalse($token->isOutOfDate(600));
    }

    /**
     * @dataProvider malformedExpiries
     */
    public function testAMalformedExpiryMakesTheTokenInvalid(callable $alter, $anomaly)
    {
        $xml = self::signAgain(self::createToken(self::sampleData())->getXML(), $alter);

        $token = XMLDSigToken::analyzeXMLToken($xml, self::trustAnchor());

        $this->assertFalse($token->isSignatureValid());
        $this->assertStringContainsString($anomaly, (string) $token->getError());
        // Neither the data nor a freshness are given for it.
        $this->assertNull($token->getData());
        $this->assertNull($token->getExpiry());
        $this->assertTrue($token->isOutOfDate(3600));
    }

    public function malformedExpiries()
    {
        return [
            'not a date' => [function (DOMElement $tokenNode) {
                self::setChild($tokenNode, 'TokenExpiry', 'tomorrow');
            }, 'Token expiry is malformed!'],
            'out of range date' => [function (DOMElement $tokenNode) {
                self::setChild($tokenNode, 'TokenExpiry', '2030-02-30T00:00:00Z');
            }, 'Token expiry is malformed!'],
            'two expiries' => [function (DOMElement $tokenNode) {
                self::setChild($tokenNode, 'TokenExpiry', self::utc('+1 hour'));
                $tokenNode->appendChild($tokenNode->ownerDocument->createElement('TokenExpiry', self::utc('+2 hours')));
            }, 'Token expiry is malformed!'],
            'time zone suffix' => [function (DOMElement $tokenNode) {
                self::setChild($tokenNode, 'TokenExpiry', (new DateTime('+1 hour'))->format('Y-m-d\TH:i:sP'));
            }, 'Token expiry is malformed!'],
            'child element' => [function (DOMElement $tokenNode) {
                self::setChild($tokenNode, 'TokenExpiry', '');
                $tokenNode->getElementsByTagName('TokenExpiry')->item(0)->appendChild($tokenNode->ownerDocument->createElement('Date', self::utc('+1 hour')));
            }, 'Token expiry is malformed!'],
            'before the timestamp' => [function (DOMElement $tokenNode) {
                self::setChild($tokenNode, 'TokenTimestamp', self::utc('now'));
                self::setChild($tokenNode, 'TokenExpiry', self::utc('-1 hour'));
            }, 'Token expiry is not after its timestamp!'],
            'equal to the timestamp' => [function (DOMElement $tokenNode) {
                $now = self::utc('now');
                self::setChild($tokenNode, 'TokenTimestamp', $now);
                self::setChild($tokenNode, 'TokenExpiry', $now);
            }, 'Token expiry is not after its timestamp!'],
        ];
    }

    /**
     * @dataProvider invalidValidityOptions
     */
    public function testAnInvalidValidityOptionThrows($value)
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Invalid option 'validity'!");

        self::createTokenWithOptions(['validity' => $value]);
    }

    public function invalidValidityOptions()
    {
        return [
            'zero'     => [0],
            'negative' => [-60],
            'string'   => ['60'],
            'float'    => [60.0],
            'past the year 9999' => [PHP_INT_MAX],
        ];
    }
}
