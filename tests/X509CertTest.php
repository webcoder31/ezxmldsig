<?php

namespace webcoder31\ezxmldsig\Tests;

use webcoder31\ezxmldsig\X509Cert;

/**
 * X509Cert on the test certificate chain.
 */
class X509CertTest extends TestCase
{
    private static function load($name)
    {
        return new X509Cert(file_get_contents(self::cert($name)));
    }

    public function testReadsSubjectAndIssuer()
    {
        $cert = self::load('sign.cert.pem');

        $this->assertSame('Signature Dept', $cert->getSubject()['OU']);
        $this->assertSame(self::INTERMEDIATE_DN, $cert->getIssuer());
        $this->assertFalse($cert->isOutOfDate());
    }

    /**
     * From 2050 on, X.509 writes a date as GeneralizedTime (YYYYMMDDHHMMSSZ)
     * instead of UTCTime (YYMMDDHHMMSSZ): long.cert.pem ends in 2060,
     * future.cert.pem is valid in 2099 only.
     */
    public function testReadsDatesFrom2050On()
    {
        $long = self::load('long.cert.pem');
        $this->assertSame('2026-01-01 00:00:00', $long->getValidFrom('Y-m-d H:i:s'));
        $this->assertSame('2060-01-01 00:00:00', $long->getValidTo('Y-m-d H:i:s'));
        $this->assertFalse($long->isOutOfDate());

        $future = self::load('future.cert.pem');
        $this->assertSame('2099-01-01 00:00:00', $future->getValidFrom('Y-m-d H:i:s'));
        $this->assertSame('2099-12-31 23:59:59', $future->getValidTo('Y-m-d H:i:s'));
        $this->assertTrue($future->isOutOfDate());
    }

    public function testValidatesEachLinkOfTheChain()
    {
        $root = file_get_contents(self::cert('root.cert.pem'));
        $intermediate = file_get_contents(self::cert('intermediate.cert.pem'));

        $this->assertTrue(self::load('intermediate.cert.pem')->isValidCA($root));
        $this->assertTrue(self::load('sign.cert.pem')->isValidCA($intermediate));
        $this->assertTrue(self::load('crypt.cert.pem')->isValidCA($intermediate));
        $this->assertTrue(self::load('root.cert.pem')->isValidCA($root));
    }
}
