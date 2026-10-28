<?php

namespace webcoder31\ezxmldsig\Tests;

use webcoder31\ezxmldsig\Tests\helpers\TestZip;
use webcoder31\ezxmldsig\seal\Zip;

/**
 * The ZIP archives of ASiC containers: the writer, the reading of a
 * container built by DSS, and the refusal of each archive that two readers
 * could see differently. The malformed archives are built by
 * tests/helpers/TestZip.php, not by the writer under test. A port of
 * test/seal/zip.test.ts of the Node.js library; ZipTest reads the archives
 * of the zipfile module of Python.
 */
class ZipRawTest extends TestCase
{
    const MIMETYPE = 'application/vnd.etsi.asic-e+zip';

    private static function entry($name, $text, array $more = [])
    {
        return ['name' => $name, 'content' => $text] + $more;
    }

    private function refused($archive, $pattern)
    {
        try
        {
            Zip::read($archive);
        }
        catch (\Exception $e)
        {
            $this->assertMatchesRegularExpression($pattern, $e->getMessage());
            return;
        }
        $this->fail('Accepted; expected a refusal matching ' . $pattern);
    }

    private static function written()
    {
        return Zip::write([
            ['name' => 'mimetype', 'content' => self::MIMETYPE, 'stored' => true],
            ['name' => "notes d'\u{e9}t\u{e9}.md", 'content' => "# Notes\n"],
            ['name' => 'META-INF/manifest.xml', 'content' => '<manifest/>'],
        ], gmmktime(12, 0, 0, 1, 1, 2026));
    }

    // The writer.

    public function testTheEntriesAreReadBackInTheirOrder()
    {
        $this->assertSame([
            ['mimetype', self::MIMETYPE, 0, ''],
            ["notes d'\u{e9}t\u{e9}.md", "# Notes\n", 8, ''],
            ['META-INF/manifest.xml', '<manifest/>', 8, ''],
        ], array_map(function ($e) { return [$e['name'], $e['content'], $e['method'], $e['extra']]; }, Zip::read(self::written())));
    }

    public function testTheMimetypeCanBeReadAtTheOffsetsOfEn319162()
    {
        $archive = self::written();
        $this->assertSame("PK\x03\x04", substr($archive, 0, 4));
        $this->assertSame('mimetype', substr($archive, 30, 8));
        $this->assertSame(strlen(self::MIMETYPE), unpack('V', substr($archive, 18, 4))[1]);
        $this->assertSame(self::MIMETYPE, substr($archive, 38, strlen(self::MIMETYPE)));
    }

    public function testTheArchiveDependsOnItsEntriesAndItsDateOnly()
    {
        $this->assertSame(self::written(), self::written());
    }

    public function testNamesTheReaderWouldRefuseAreRefused()
    {
        foreach (['', '/abs', '../up', 'a/../b', 'a//b', 'a\\b', 'dir/', "nul\x00"] as $name)
        {
            try
            {
                Zip::write([['name' => $name, 'content' => '']], gmmktime(12, 0, 0, 1, 1, 2026));
                $this->fail('Accepted: ' . json_encode($name));
            }
            catch (\Exception $e)
            {
                $this->assertMatchesRegularExpression('/invalid entry name/', $e->getMessage(), json_encode($name));
            }
        }
    }

    /**
     * Two names that only differ by their Unicode normalization are refused
     * with the intl extension (class Normalizer); without it, the names are
     * compared byte by byte, and both are written.
     */
    public function testTwoNamesThatOnlyDifferByTheirUnicodeNormalization()
    {
        $entries = [['name' => "\u{e9}t\u{e9}", 'content' => ''], ['name' => "e\u{301}te\u{301}", 'content' => '']];
        if (class_exists('Normalizer'))
        {
            $this->assertThrowsMatchingZip('/duplicate entry/', function () use ($entries) { Zip::write($entries, gmmktime(12, 0, 0, 1, 1, 2026)); });
            return;
        }
        $this->assertCount(2, Zip::read(Zip::write($entries, gmmktime(12, 0, 0, 1, 1, 2026))));
    }

    public function testADateOutsideTheMsDosRangeIsRefused()
    {
        $this->assertThrowsMatchingZip('/between 1980 and 2107/', function () { Zip::write([], gmmktime(0, 0, 0, 12, 31, 1979)); });
    }

    public function testAContainerBuiltByDssIsRead()
    {
        $entries = Zip::read(file_get_contents(__DIR__ . '/fixtures/seal/dss/dss-xades-b.asice'));
        $this->assertSame(['mimetype', 'contrat final.pdf', "notes d'\u{e9}t\u{e9}.md", 'META-INF/signatures001.xml', 'META-INF/manifest.xml'], array_column($entries, 'name'));
        $this->assertSame(self::MIMETYPE, $entries[0]['content']);
        $this->assertSame(0, $entries[0]['method']);
        $this->assertSame("# Notes d'\u{e9}t\u{e9}\n", $entries[2]['content']);
    }

    // The builder of the tests makes archives the reader accepts.

    public function testWithDataDescriptorsSignedOrNot()
    {
        $archive = TestZip::raw([self::entry('a.txt', 'A'), self::entry('b.txt', 'B', ['descriptorSignature' => false])]);
        $this->assertSame(['A', 'B'], array_column(Zip::read($archive), 'content'));
    }

    public function testWithoutDataDescriptorWithAnAsciiNameNotFlaggedUtf8()
    {
        $this->assertSame('A', Zip::read(TestZip::raw([self::entry('a.txt', 'A', ['flags' => 0, 'method' => 0])]))[0]['content']);
    }

    public function testWithACommentAndADirectoryEntryLeftOut()
    {
        $archive = TestZip::raw([self::entry('META-INF/', ''), self::entry('META-INF/a.xml', '<a/>')], ['comment' => 'mimetype=application/vnd.etsi.asic-e+zip']);
        $this->assertSame(['META-INF/a.xml'], array_column(Zip::read($archive), 'name'));
    }

    // Refused archives.

    public function refusedArchives()
    {
        $descriptor = function ()
        {
            // The CRC of the descriptor follows its signature.
            $archive = TestZip::raw([self::entry('a.txt', 'A')]);
            $at = strpos($archive, "PK\x07\x08") + 4;
            $archive[$at] = chr(ord($archive[$at]) ^ 1);
            return $archive;
        };
        $deflated = gzdeflate('some content to compress');
        $bomb = str_repeat("\x00", 100000);
        $cases = [
            // An ambiguous archive.
            'bytes before the first entry' => [TestZip::raw([self::entry('a.txt', 'A')], ['prefix' => 'xx']), '/not where the previous entry ends/'],
            'bytes between two entries' => [TestZip::raw([self::entry('a.txt', 'A'), self::entry('b.txt', 'B')], ['gapAfter' => ['index' => 0, 'bytes' => 'xx']]), '/not where the previous entry ends/'],
            'an entry absent from the central directory' => [TestZip::raw([self::entry('a.txt', 'A'), self::entry('hidden.txt', 'H', ['hidden' => true])]), '/bytes outside the entries/'],
            'bytes after the end record' => [TestZip::raw([self::entry('a.txt', 'A')], ['suffix' => 'xx']), '/not a ZIP archive/'],
            'a local name that differs from the central one' => [TestZip::raw([self::entry('a.txt', 'A', ['local' => ['name' => 'b.txt']])]), '/local header of "a.txt" differs/'],
            'a local method that differs from the central one' => [TestZip::raw([self::entry('a.txt', 'A', ['method' => 0, 'local' => ['method' => 8]])]), '/local header of "a.txt" differs/'],
            'a data descriptor that differs from the central directory' => [$descriptor(), '/data descriptor of "a.txt" differs/'],
            'two entries of the same name' => [TestZip::raw([self::entry('a.txt', 'A'), self::entry('a.txt', 'B')]), '/duplicate entry "a.txt"/'],
            'a second name in an Info-ZIP Unicode path field' => [TestZip::raw([self::entry('a.txt', 'A', ['extra' => TestZip::extraField(0x7075, "\x01xxxxb.txt")])]), '/unsupported extra field 0x7075/'],
            'a ZIP64 field' => [TestZip::raw([self::entry('a.txt', 'A', ['extra' => TestZip::extraField(0x0001, str_repeat("\x00", 16))])]), '/unsupported extra field 0x0001/'],
            'a malformed extra field' => [TestZip::raw([self::entry('a.txt', 'A', ['extra' => "\x99\x99\x10\x00"])]), '/malformed extra field/'],
            'a stored entry with two sizes' => [TestZip::raw([self::entry('a.txt', 'AAAA', ['method' => 0, 'flags' => TestZip::UTF8, 'size' => 3])]), '/stored entry "a.txt" with two sizes/'],
            'a declared count different from the central directory' => [TestZip::raw([self::entry('a.txt', 'A'), self::entry('b.txt', 'B')], ['count' => 1]), '/bytes outside the entries/'],
            // A name that is not valid, or not UTF-8.
            'a name that is not valid UTF-8' => [TestZip::raw([self::entry("a\xffb", 'A')]), '/name is not valid UTF-8/'],
            'a name not in ASCII without the UTF-8 flag (legacy code page)' => [TestZip::raw([self::entry("\x82\x74\x82", 'A', ['flags' => TestZip::DESCRIPTOR])]), '/name neither in UTF-8 nor in ASCII/'],
            // An unsupported entry.
            'encrypted' => [TestZip::raw([self::entry('a.txt', 'A', ['flags' => TestZip::UTF8 | TestZip::DESCRIPTOR | 0x0001])]), '/encrypted or unsupported/'],
            'compressed with another method (bzip2)' => [TestZip::raw([self::entry('a.txt', 'A', ['method' => 12, 'data' => 'BZh'])]), '/compression method 12/'],
            // Content that does not match its headers.
            'a CRC mismatch' => [TestZip::raw([self::entry('a.txt', 'A', ['crc' => 0x12345678])]), '/CRC mismatch for "a.txt"/'],
            'a deflate stream followed by other bytes' => [TestZip::raw([self::entry('a.txt', 'A', ['data' => gzdeflate('A') . 'hidden'])]), '/does not inflate to its size/'],
            'a deflate stream longer than its declared size' => [TestZip::raw([['name' => 'bomb', 'content' => $bomb, 'data' => gzdeflate($bomb), 'size' => 10]]), '/does not inflate to its size/'],
            'a truncated deflate stream' => [TestZip::raw([self::entry('a.txt', 'some content to compress', ['data' => substr($deflated, 0, -2)])]), '/does not inflate to its size/'],
        ];
        foreach (['/etc/passwd', '../up.txt', 'a/../../b', 'a\\..\\b', 'a//b', './a', "tab\there"] as $name)
        {
            $cases['the name ' . json_encode($name)] = [TestZip::raw([self::entry($name, 'A')]), '/invalid entry name/'];
        }
        return $cases;
    }

    /**
     * @dataProvider refusedArchives
     */
    public function testARefusedArchive($archive, $pattern)
    {
        $this->refused($archive, $pattern);
    }

    // Limits.

    public function testTheNumberOfEntries()
    {
        $archive = TestZip::raw([self::entry('a', 'A'), self::entry('b', 'B'), self::entry('c', 'C')]);
        $this->assertThrowsMatchingZip('/more than 2 entries/', function () use ($archive) { Zip::read($archive, 2, 1000); });
    }

    public function testTheTotalUncompressedSizeCheckedBeforeInflating()
    {
        $archive = TestZip::raw([self::entry('a', str_repeat('A', 600)), self::entry('b', str_repeat('B', 600))]);
        $this->assertThrowsMatchingZip('/more than 1000 bytes/', function () use ($archive) { Zip::read($archive, 10, 1000); });
    }

    private function assertThrowsMatchingZip($pattern, callable $run)
    {
        try
        {
            $run();
        }
        catch (\Exception $e)
        {
            $this->assertMatchesRegularExpression($pattern, $e->getMessage());
            return;
        }
        $this->fail('No exception; expected one matching ' . $pattern);
    }
}
