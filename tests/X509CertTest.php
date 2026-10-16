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
