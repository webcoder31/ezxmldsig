<?php

namespace webcoder31\ezxmldsig\Tests\helpers;

/**
 * A ZIP builder for the tests, written apart from src/seal/Zip.php so that
 * the archives the reader is tested on do not come from the code under
 * test. Every field can be set, so that each test builds one malformation;
 * by default, an entry is written as the archives of DSS are: UTF-8 name,
 * deflate, sizes in a data descriptor. A port of test/helpers/zip.ts of the
 * Node.js library.
 */
class TestZip
{
    const UTF8 = 0x0800;
    const DESCRIPTOR = 0x0008;

    /**
     * An archive. Each entry: 'name', 'content', and optionally 'method'
     * (default 8), 'flags' (the same in both headers, default UTF-8 and data
     * descriptor), 'data' (the compressed bytes), 'crc', 'size' (the
     * uncompressed size written), 'extra', 'descriptorSignature' (default
     * TRUE), 'local' (overrides of the local header: 'name', 'method',
     * 'flags', 'extra'), 'hidden' (left out of the central directory).
     * Options: 'prefix', 'gapAfter' (['index', 'bytes']), 'comment',
     * 'suffix', 'count' (the number of entries the end record declares).
     */
    public static function raw(array $entries, array $options = [])
    {
        $parts = '';
        $centrals = '';
        if (isset($options['prefix']))
        {
            $parts .= $options['prefix'];
        }
        foreach ($entries as $index => $entry)
        {
            $get = function ($name, $default) use ($entry) { return array_key_exists($name, $entry) ? $entry[$name] : $default; };
            $local = $get('local', []);
            $method = $get('method', 8);
            $flags = $get('flags', self::UTF8 | self::DESCRIPTOR);
            $name = $entry['name'];
            $data = $get('data', 8 === $method ? gzdeflate($entry['content']) : $entry['content']);
            $crc = $get('crc', crc32($entry['content']));
            $size = $get('size', strlen($entry['content']));
            $extra = $get('extra', '');
            $localName = isset($local['name']) ? $local['name'] : $name;
            $localExtra = isset($local['extra']) ? $local['extra'] : $extra;
            $localFlags = isset($local['flags']) ? $local['flags'] : $flags;
            $withDescriptor = 0 !== ($localFlags & self::DESCRIPTOR);
            $offset = strlen($parts);

            $parts .= pack('VvvvvvVVVvv', 0x04034b50, 20, $localFlags, isset($local['method']) ? $local['method'] : $method, 0, 0,
                $withDescriptor ? 0 : $crc, $withDescriptor ? 0 : strlen($data), $withDescriptor ? 0 : $size, strlen($localName), strlen($localExtra))
                . $localName . $localExtra . $data;
            if ($withDescriptor)
            {
                $parts .= ($get('descriptorSignature', true) ? "PK\x07\x08" : '') . pack('VVV', $crc, strlen($data), $size);
            }
            if (!$get('hidden', false))
            {
                $centrals .= pack('VvvvvvvVVVvvvvvVV', 0x02014b50, 20, 20, $flags, $method, 0, 0, $crc, strlen($data), $size, strlen($name), strlen($extra), 0, 0, 0, 0, $offset)
                    . $name . $extra;
            }
            if (isset($options['gapAfter']) && $options['gapAfter']['index'] === $index)
            {
                $parts .= $options['gapAfter']['bytes'];
            }
        }
        $count = isset($options['count']) ? $options['count'] : count(array_filter($entries, function ($e) { return empty($e['hidden']); }));
        $comment = isset($options['comment']) ? $options['comment'] : '';
        return $parts . $centrals . pack('VvvvvVVv', 0x06054b50, 0, 0, $count, $count, strlen($centrals), strlen($parts), strlen($comment))
            . $comment . (isset($options['suffix']) ? $options['suffix'] : '');
    }

    /** An extra field of one record. */
    public static function extraField($id, $data = '')
    {
        return pack('vv', $id, strlen($data)) . $data;
    }
}
