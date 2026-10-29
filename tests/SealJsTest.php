<?php

namespace webcoder31\ezxmldsig\Tests;

use webcoder31\ezxmldsig\Tests\helpers\Js;
use webcoder31\ezxmldsig\Tests\helpers\SealPki;
use webcoder31\ezxmldsig\core\X509Cert;
use webcoder31\ezxmldsig\seal\Seal;

/**
 * Seals made here, verified by the Node.js library (tests/helpers/Js.php):
 * the sample seals of SealTestCase, valid at their level, with the verdict
 * of this library, and a seal whose file was changed, refused by both. The
 * error messages are not compared, only whether there is one.
 */
class SealJsTest extends SealTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $reason = Js::skipReason();
        if (!is_null($reason))
        {
            $this->markTestSkipped($reason);
        }
    }

    /** The verdict of the Node.js library: see "verifySeal" in tests/js/ezxmldsig.ts. */
    private static function verifyInJs($container, array $crls)
    {
        $bytes = function ($der) { return ['bytes' => base64_encode($der)]; };
        $result = Js::run([['command' => 'verifySeal', 'container' => $bytes($container), 'options' => self::trust(['crls' => array_map($bytes, $crls)])]])[0];
        self::assertArrayHasKey('valid', $result, isset($result['exception']) ? $result['exception'] : '');
        return $result;
    }

    /** The verdict of this library, in the form of verifyInJs(). */
    private static function verifyHere($container, array $crls)
    {
        $result = Seal::verifySeal($container, self::trust(['crls' => $crls]));
        $iso = function ($date) { return null === $date ? null : $date->format('Y-m-d\TH:i:s.v\Z'); };
        return [
            'valid' => $result->isValid(),
            'error' => $result->getError(),
            'level' => $result->getLevel(),
            'files' => $result->getFiles(),
            'signingTime' => $iso($result->getSigningTime()),
            'timestampTime' => $iso($result->getTimestampTime()),
            'signer' => null === $result->getSigningCertificate() ? null : $result->getSigningCertificate()->getDN(),
            'revocationChecked' => $result->isRevocationChecked(),
        ];
    }

    /**
     * @dataProvider sampleSeals
     */
    public function testASealMadeHereIsValidForTheNodeJsLibraryAtItsLevel($name)
    {
        $seal = self::sampleSeal($name);
        $verdict = self::verifyInJs($seal['container'], $seal['crls']);
        $this->assertNull($verdict['error']);
        $this->assertTrue($verdict['valid']);
        $this->assertSame($seal['level'], $verdict['level']);
        $this->assertTrue($verdict['revocationChecked']);
        $this->assertSame(array_column(self::sampleFiles(), 'name'), array_column($verdict['files'], 'name'));
        $this->assertSame(self::sampleFiles()[3]['mimeType'], $verdict['files'][3]['mimeType']);
        $this->assertSame((new X509Cert(file_get_contents(SealPki::cert($seal['key']))))->getDN(), $verdict['signer']);
        $this->assertSame(self::verifyHere($seal['container'], $seal['crls']), $verdict);
    }

    public function testASealMadeHereWhoseFileWasChangedIsRefusedByBoth()
    {
        $seal = self::sampleSeal('B, RSA 3072, RSA-PSS');
        $container = self::rebuild($seal['container'], function ($entries) {
            return array_map(function ($e) { if ('contrat final.pdf' === $e['name']) { $e['content'] = "%PDF-1.5\n"; } return $e; }, $entries);
        });
        $verdict = self::verifyInJs($container, $seal['crls']);
        $this->assertFalse($verdict['valid']);
        $this->assertNotNull($verdict['error']);
        $this->assertFalse(self::verifyHere($container, $seal['crls'])['valid']);
    }
}
