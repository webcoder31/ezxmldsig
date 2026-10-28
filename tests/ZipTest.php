<?php

namespace webcoder31\ezxmldsig\Tests;

use Exception;
use webcoder31\ezxmldsig\seal\Zip;

/**
 * The ZIP reader and writer of the seals. The archives of
 * tests/fixtures/seal/zip/ are written by the zipfile module of Python (see
 * generate.py there); the malformed ones are altered here, byte by byte.
 */
class ZipTest extends TestCase
{
    private static function fixture($name)
    {
        return file_get_contents(__DIR__ . '/fixtures/seal/zip/' . $name);
    }

    private static function names(array $entries)
    {
        return array_map(function ($entry) { return $entry['name']; }, $entries);
    }

    public function testReadsTheArchivesOfAnotherWriter()
    {
        $entries = Zip::read(self::fixture('plain.zip'));
        $this->assertSame(['mimetype', "docs/r\u{e9}sum\u{e9}.txt", 'empty.bin'], self::names($entries));
        $this->assertSame('application/vnd.etsi.asic-e+zip', $entries[0]['content']);
        $this->assertSame(0, $entries[0]['method']);
        $this->assertSame('', $entries[0]['extra']);
        $this->assertSame(str_repeat("Un r\u{e9}sum\u{e9}.\n", 50), $entries[1]['content']);
        $this->assertSame(8, $entries[1]['method']);
        $this->assertSame('', $entries[2]['content']);

        $entries = Zip::read(self::fixture('descriptor.zip'));
        $this->assertSame(['streamed.txt', 'streamed-stored.txt'], self::names($entries));
        $this->assertSame(str_repeat('Written to a stream. ', 100), $entries[0]['content']);
        $this->assertSame('Stored to a stream.', $entries[1]['content']);
    }

    public function testReadsWhatItWrites()
    {
        $inputs = [
            ['name' => 'mimetype', 'content' => 'application/vnd.etsi.asic-e+zip', 'stored' => true],
            ['name' => 'a/b/c.bin', 'content' => random_bytes(70000)],
            ['name' => "\u{65e5}\u{672c}.txt", 'content' => str_repeat('x', 100000)],
        ];
        $archive = Zip::write($inputs, gmmktime(12, 0, 0, 10, 28, 2026));
        $entries = Zip::read($archive);
        $this->assertSame(array_column($inputs, 'name'), self::names($entries));
        $this->assertSame(array_column($inputs, 'content'), array_column($entries, 'content'));
        $this->assertSame([0, 8, 8], array_column($entries, 'method'));
        // The first entry is stored, at offset 0, its content right after its name.
        $this->assertSame('mimetypeapplication/vnd.etsi.asic-e+zip', substr($archive, 30, 39));
        // A fixed date gives the same archive.
        $this->assertSame(Zip::write($inputs, gmmktime(12, 0, 0, 10, 28, 2026)), Zip::write($inputs, gmmktime(12, 0, 0, 10, 28, 2026)));
    }

    public function testRefusesNamesThatLeaveTheContainerOrCollide()
    {
        foreach (['/abs', '../up', 'a/../b', 'a//b', './a', "a\\b", "a\x01b", ''] as $name)
        {
            try
            {
                Zip::write([['name' => $name, 'content' => 'x']], time());
                $this->fail('Accepted: ' . json_encode($name));
            }
            catch (Exception $e)
            {
                $this->assertStringStartsWith('ZIP: invalid entry name', $e->getMessage());
            }
        }
        $this->expectExceptionMessage('ZIP: duplicate entry "a".');
        Zip::write([['name' => 'a', 'content' => '1'], ['name' => 'a', 'content' => '2']], time());
    }

    /**
     * Replaces bytes of an archive, at the offset of the first occurrence of
     * a marker (plus a shift).
     */
    private static function patch($archive, $marker, $shift, $bytes)
    {
        $offset = strpos($archive, $marker);
        return substr_replace($archive, $bytes, $offset + $shift, strlen($bytes));
    }

    private static function sample()
    {
        return Zip::write([
            ['name' => 'mimetype', 'content' => 'application/vnd.etsi.asic-e+zip', 'stored' => true],
            ['name' => 'file.txt', 'content' => str_repeat('content ', 20)],
        ], gmmktime(12, 0, 0, 10, 28, 2026));
    }

    public function malformations()
    {
        $local = pack('V', Zip::LOCAL_SIGNATURE);
        $central = pack('V', Zip::CENTRAL_SIGNATURE);
        $end = pack('V', Zip::END_SIGNATURE);
        return [
            'not an archive' => [function ($a) { return 'not a zip archive at all'; }, 'ZIP: not a ZIP archive.'],
            'truncated' => [function ($a) { return substr($a, 0, -1); }, 'ZIP: not a ZIP archive.'],
            'bytes after the end' => [function ($a) { return $a . 'x'; }, 'ZIP: not a ZIP archive.'],
            'bytes before the first entry' => [function ($a) { return 'x' . $a; }, 'ZIP: the central directory does not end where the archive ends.'],
            'several disks' => [function ($a) use ($end) { return self::patch($a, $end, 4, "\x01\x00"); }, 'ZIP: archives on several disks are not supported.'],
            'ZIP64 count' => [function ($a) use ($end) { return self::patch($a, $end, 8, "\xff\xff\xff\xff"); }, 'ZIP: ZIP64 is not supported.'],
            'encrypted entry' => [function ($a) use ($central, $local) { return self::patch(self::patch($a, $central, 8, "\x01\x08"), $local, 6, "\x01\x08"); }, 'ZIP: encrypted or unsupported entry.'],
            'method 12' => [function ($a) use ($central) { return self::patch($a, $central, 10, "\x0c\x00"); }, 'ZIP: unsupported compression method 12.'],
            'local method differs' => [function ($a) use ($local) { return self::patch($a, $local, 8, "\x08\x00"); }, 'ZIP: local header of "mimetype" differs from the central directory.'],
            'local name differs' => [function ($a) { return self::patch($a, 'file.txt', 0, 'File'); }, 'ZIP: local header of "file.txt" differs from the central directory.'],
            'local CRC differs' => [function ($a) use ($local) { return self::patch($a, $local, 14, "\0\0\0\0"); }, 'ZIP: local header of "mimetype" differs from the central directory.'],
            'altered content' => [function ($a) { return self::patch($a, 'application/vnd', 0, 'A'); }, 'ZIP: CRC mismatch for "mimetype".'],
        ];
    }

    /**
     * @dataProvider malformations
     */
    public function testRefusesMalformedArchives($alter, $message)
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage($message);
        Zip::read($alter(self::sample()));
    }

    public function testRefusesEntriesThatDoNotInflateToTheirSize()
    {
        $archive = self::sample();
        // The central directory and the local header both claim one byte more.
        $offset = strpos($archive, pack('V', Zip::CENTRAL_SIGNATURE), strpos($archive, pack('V', Zip::CENTRAL_SIGNATURE)) + 1);
        $size = unpack('V', $archive, $offset + 24)[1];
        $archive = substr_replace($archive, pack('V', $size + 1), $offset + 24, 4);
        $localOffset = unpack('V', $archive, $offset + 42)[1];
        $archive = substr_replace($archive, pack('V', $size + 1), $localOffset + 22, 4);
        $this->expectExceptionMessage('ZIP: entry "file.txt" does not inflate to its size.');
        Zip::read($archive);
    }

    public function testRefusesADuplicateName()
    {
        $archive = Zip::write([['name' => 'a.txt', 'content' => '1'], ['name' => 'b.txt', 'content' => '2']], time());
        $archive = str_replace('b.txt', 'a.txt', $archive);
        $this->expectExceptionMessage('ZIP: duplicate entry "a.txt".');
        Zip::read($archive);
    }

    public function testRefusesAnEntryThatIsNotWhereThePreviousOneEnds()
    {
        $plain = self::fixture('plain.zip');
        // A second copy of the central directory entry of the first file in
        // place of the second: two entries over the same bytes.
        $first = strpos($plain, pack('V', Zip::CENTRAL_SIGNATURE));
        $second = strpos($plain, pack('V', Zip::CENTRAL_SIGNATURE), $first + 1);
        $patched = substr_replace($plain, pack('V', 0), $second + 42, 4);
        $this->expectExceptionMessage('ZIP: entry "docs/" is not where the previous entry ends.');
        Zip::read($patched);
    }

    public function testAppliesItsLimits()
    {
        $archive = self::sample();
        try
        {
            Zip::read($archive, 1);
            $this->fail('More entries than the limit');
        }
        catch (Exception $e)
        {
            $this->assertSame('ZIP: more than 1 entries.', $e->getMessage());
        }
        $this->expectExceptionMessage('ZIP: more than 100 bytes once uncompressed.');
        Zip::read($archive, 1000, 100);
    }
}
