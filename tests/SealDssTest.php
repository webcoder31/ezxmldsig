<?php

namespace webcoder31\ezxmldsig\Tests;

use webcoder31\ezxmldsig\Tests\helpers\Dss;

/**
 * Seals made here, validated by DSS (tests/helpers/Dss.php), a validator
 * apart from this library. The files are those of the validation by DSS in
 * test/seal/seal.test.ts of the Node.js library.
 *
 * @group dss
 */
class SealDssTest extends SealTestCase
{
    private static function files()
    {
        return [
            ['name' => 'contrat final.pdf', 'content' => "%PDF-1.4\n"],
            ['name' => "notes d'\u{e9}t\u{e9}.md", 'content' => "# Notes d'\u{e9}t\u{e9}\n"],
            ['name' => 'docs/a#b%c.txt', 'content' => "odd name\n"],
            ['name' => 'data.bin', 'content' => "\x00\x01\x02\xff", 'mimeType' => 'application/x-test; charset="none"'],
        ];
    }

    protected function setUp(): void
    {
        parent::setUp();
        $reason = Dss::skipReason();
        if (!is_null($reason))
        {
            $this->markTestSkipped($reason);
        }
        Dss::publishTestCrls();
    }

    public function testASealOfLevelBIsValidForDss()
    {
        $report = Dss::validate(self::seal('rsa3072', [], self::files()));
        $this->assertSame('ASiC-E', $report['containerType']);
        $this->assertCount(1, $report['signatures']);
        $signature = $report['signatures'][0];
        $this->assertSame('XAdES-BASELINE-B', $signature['format']);
        $this->assertSame(array_column(self::files(), 'name'), $signature['scope']);
        $this->assertTrue($signature['signatureIntact']);
        $this->assertCount(count(self::files()) + 1, $signature['references']);
        foreach ($signature['references'] as $reference)
        {
            $this->assertTrue($reference['found'] && $reference['intact'], json_encode($reference));
        }
        $this->assertSame(['CN=Lothbrok Seal Test,OU=Seal Root CA,O=Lothbrok Ltd,C=DK'], $signature['trusted']);
        $this->assertSame('TOTAL_PASSED', $signature['indication'], json_encode($signature['errors']));
        $this->assertSame([], $signature['errors']);
    }

    public function testASealWhoseFileWasChangedIsRefusedByDss()
    {
        $container = self::rebuild(self::seal('rsa3072', [], self::files()), function ($entries) {
            return array_map(function ($e) { if ('contrat final.pdf' === $e['name']) { $e['content'] = "%PDF-1.5\n"; } return $e; }, $entries);
        });
        $signature = Dss::validate($container)['signatures'][0];
        $this->assertSame('TOTAL_FAILED', $signature['indication']);
        $this->assertSame('HASH_FAILURE', $signature['subIndication']);
    }
}
