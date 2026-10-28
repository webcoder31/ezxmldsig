<?php

namespace webcoder31\ezxmldsig\Tests;

use Exception;
use webcoder31\ezxmldsig\core\Der;

/**
 * The DER reader and writer of the core. The structures read come from
 * OpenSSL (the certificates of the seal tests), and what is read is
 * compared with what openssl_x509_parse() gives for them.
 */
class DerTest extends TestCase
{
    private static function certificateDer($name)
    {
        $pem = file_get_contents(__DIR__ . '/fixtures/seal/certs/' . $name . '.cert.pem');
        preg_match('/-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/s', $pem, $match);
        return [base64_decode($match[1]), openssl_x509_parse($pem)];
    }

    public function testReadsACertificateAsOpenSslDoes()
    {
        list($der, $parsed) = self::certificateDer('rsa3072');
        $certificate = Der::childrenOf(Der::readElement($der), Der::SEQUENCE);
        $this->assertCount(3, $certificate);
        $tbs = Der::childrenOf($certificate[0], Der::SEQUENCE);

        // version [0] v3, serialNumber, signature, issuer, validity, ...
        $this->assertSame(0xa0, $tbs[0]['tag']);
        $this->assertSame(2, Der::decodeSmallInteger(Der::readElement($tbs[0]['content'])));
        $this->assertSame(strtoupper($parsed['serialNumberHex']), strtoupper(bin2hex(Der::decodeUnsigned($tbs[1]))));
        $this->assertSame('1.2.840.113549.1.1.11', Der::decodeOid(Der::childrenOf($tbs[2], Der::SEQUENCE)[0]));
        $validity = Der::childrenOf($tbs[4], Der::SEQUENCE);
        $this->assertSame($parsed['validFrom_time_t'], Der::decodeTime($validity[0]));
        $this->assertSame($parsed['validTo_time_t'], Der::decodeTime($validity[1]));

        // The DER is written back as it was read.
        $this->assertSame($der, Der::reencode(Der::readElement($der)));
        $this->assertSame($der, Der::encode(Der::SEQUENCE, ...array_map([Der::class, 'reencode'], $certificate)));
    }

    public function testReadsTheKeyUsageBits()
    {
        list($der, $parsed) = self::certificateDer('rsa3072');
        $tbs = Der::childrenOf(Der::childrenOf(Der::readElement($der), Der::SEQUENCE)[0], Der::SEQUENCE);
        $extensions = Der::childrenOf(Der::readElement(end($tbs)['content']), Der::SEQUENCE);
        $keyUsage = null;
        foreach ($extensions as $extension)
        {
            $fields = Der::childrenOf($extension, Der::SEQUENCE);
            if ('2.5.29.15' === Der::decodeOid($fields[0]))
            {
                $this->assertTrue(Der::decodeBoolean($fields[1]));
                $keyUsage = Der::decodeBits(Der::readElement($fields[2]['content']));
            }
        }
        // digitalSignature (0) and nonRepudiation (1), as OpenSSL reads them.
        $this->assertSame('Digital Signature, Non Repudiation', $parsed['extensions']['keyUsage']);
        $this->assertSame([true, true], $keyUsage);
    }

    public function testEncodesKnownValues()
    {
        $this->assertSame('06092a864886f70d01010b', bin2hex(Der::encodeOid('1.2.840.113549.1.1.11')));
        $this->assertSame('0603550409', bin2hex(Der::encodeOid('2.5.4.9')));
        $this->assertSame('1.2.840.113549.1.1.11', Der::decodeOid(Der::readElement(hex2bin('06092a864886f70d01010b'))));
        $this->assertSame('2.999.3', Der::decodeOid(Der::readElement(Der::encodeOid('2.999.3'))));
        $this->assertSame('020100', bin2hex(Der::encodeInteger(0)));
        $this->assertSame('02020080', bin2hex(Der::encodeInteger(128)));
        $this->assertSame('020200ff', bin2hex(Der::encodeInteger("\xff")));
        $this->assertSame('020101', bin2hex(Der::encodeInteger("\0\0\x01")));
        $long = str_repeat('a', 300);
        $this->assertSame('04820' . '12c', bin2hex(substr(Der::encode(Der::OCTET_STRING, $long), 0, 4)));
        $this->assertSame($long, Der::readElement(Der::encode(Der::OCTET_STRING, $long))['content']);
    }

    public function testDecodesTimes()
    {
        $this->assertSame(gmmktime(12, 0, 0, 10, 28, 2026), Der::decodeTime(['tag' => Der::UTC_TIME, 'content' => '261028120000Z']));
        $this->assertSame(gmmktime(12, 0, 0, 10, 28, 1999), Der::decodeTime(['tag' => Der::UTC_TIME, 'content' => '991028120000Z']));
        $this->assertSame(gmmktime(0, 0, 0, 1, 1, 2050), Der::decodeTime(['tag' => Der::GENERALIZED_TIME, 'content' => '20500101000000Z']));
        $this->assertEquals(gmmktime(12, 0, 0, 10, 28, 2026) + 0.25, Der::decodeGeneralizedTime(['tag' => Der::GENERALIZED_TIME, 'content' => '20261028120000.25Z']));
        foreach (['20261028120000', '20261028120000+0100', '20261028120000.0Z', '20260230120000Z', '20261028250000Z'] as $text)
        {
            try
            {
                Der::decodeGeneralizedTime(['tag' => Der::GENERALIZED_TIME, 'content' => $text]);
                $this->fail('Accepted: ' . $text);
            }
            catch (Exception $e)
            {
                $this->assertStringStartsWith('DER: ', $e->getMessage());
            }
        }
    }

    /**
     * @dataProvider malformations
     */
    public function testRefusesMalformedDer($hex, $message)
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage($message);
        Der::readElement(hex2bin($hex));
    }

    public function malformations()
    {
        return [
            'truncated length' => ['04', 'DER: truncated length.'],
            'truncated content' => ['0403aabb', 'DER: truncated content.'],
            'indefinite length' => ['3080020100' . '0000', 'DER: invalid length.'],
            'length of 5 bytes' => ['04850000000001aa', 'DER: invalid length.'],
            'multi-byte tag' => ['1f8101' . '00', 'DER: multi-byte tags are not supported.'],
            'two elements' => ['050005' . '00', 'DER: one element expected.'],
        ];
    }

    public function testRefusesValuesOfAnotherType()
    {
        foreach ([
            function () { Der::childrenOf(['tag' => Der::SET, 'content' => ''], Der::SEQUENCE); },
            function () { Der::decodeOid(['tag' => Der::OID, 'content' => "\x2a\x86"]); },
            function () { Der::decodeBoolean(['tag' => Der::BOOLEAN, 'content' => "\x01\x01"]); },
            function () { Der::decodeSmallInteger(['tag' => Der::INTEGER, 'content' => "\x80"]); },
            function () { Der::decodeUnsigned(['tag' => Der::INTEGER, 'content' => "\xff"]); },
            function () { Der::decodeBits(['tag' => Der::BIT_STRING, 'content' => "\x08\x00"]); },
            function () { Der::decodeBitStringBytes(['tag' => Der::BIT_STRING, 'content' => "\x01\x00"]); },
            function () { Der::encodeOid('1.2.x'); },
        ] as $index => $call)
        {
            try
            {
                $call();
                $this->fail('Accepted: case ' . $index);
            }
            catch (Exception $e)
            {
                $this->assertStringStartsWith('DER: ', $e->getMessage());
            }
        }
    }
}
