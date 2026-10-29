<?php

namespace webcoder31\ezxmldsig\Tests;

use webcoder31\ezxmldsig\Tests\helpers\Dss;

/**
 * Seals made here, validated by DSS (tests/helpers/Dss.php), a validator
 * apart from this library: the sample seals of SealTestCase, of the profile
 * XAdES-BASELINE of their level, and a seal whose file was changed, refused.
 * A seal of level LT is validated by the revocation data it embeds; DSS
 * fetches the CRLs of the others at pki.ezxmlseal.test, where they are
 * published once for the class.
 *
 * @group dss
 */
class SealDssTest extends SealTestCase
{
    /** @var bool Whether the CRLs DSS fetches are published. */
    private static $published = false;

    protected function setUp(): void
    {
        parent::setUp();
        $reason = Dss::skipReason();
        if (!is_null($reason))
        {
            $this->markTestSkipped($reason);
        }
        if (!self::$published)
        {
            Dss::publishTestCrls();
            self::$published = true;
        }
    }

    /**
     * @dataProvider sampleSeals
     */
    public function testASealMadeHereIsValidForDssAtTheProfileOfItsLevel($name)
    {
        $seal = self::sampleSeal($name);
        $report = Dss::validate($seal['container']);
        $this->assertSame('ASiC-E', $report['containerType']);
        $this->assertCount(1, $report['signatures']);
        $signature = $report['signatures'][0];
        $this->assertSame('XAdES-BASELINE-' . $seal['level'], $signature['format']);
        $this->assertSame(array_column(self::sampleFiles(), 'name'), $signature['scope']);
        $this->assertTrue($signature['signatureIntact']);
        $this->assertCount(count(self::sampleFiles()) + 1, $signature['references']);
        foreach ($signature['references'] as $reference)
        {
            $this->assertTrue($reference['found'] && $reference['intact'], json_encode($reference));
        }
        $this->assertContains('CN=Lothbrok Seal Test,OU=Seal Root CA,O=Lothbrok Ltd,C=DK', $signature['trusted']);
        if ('B' !== $seal['level'])
        {
            $this->assertContains('CN=Lothbrok Seal Test,OU=TSA Root CA,O=Lothbrok Ltd,C=DK', $signature['trusted']);
        }
        $this->assertSame('TOTAL_PASSED', $signature['indication'], json_encode($signature['errors']));
        $this->assertSame([], $signature['errors']);
        if ('LT' === $seal['level'])
        {
            // The signer, the intermediate and the authority, by what the seal embeds.
            $this->assertCount(3, array_keys($report['revocationOrigins'], 'INPUT_DOCUMENT'), json_encode($report['revocationOrigins']));
        }
    }

    public function testASealWhoseFileWasChangedIsRefusedByDss()
    {
        $container = self::rebuild(self::sampleSeal('B, RSA 3072, RSA-PSS')['container'], function ($entries) {
            return array_map(function ($e) { if ('contrat final.pdf' === $e['name']) { $e['content'] = "%PDF-1.5\n"; } return $e; }, $entries);
        });
        $signature = Dss::validate($container)['signatures'][0];
        $this->assertSame('TOTAL_FAILED', $signature['indication']);
        $this->assertSame('HASH_FAILURE', $signature['subIndication']);
    }
}
