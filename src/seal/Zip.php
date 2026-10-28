<?php
/**
 * Zip.php
 *
 * Copyright © 2017-2026 - Thierry Thiers <webcoder31@gmail.com>
 * 
 * This  software  is governed  by  the CeCILL-C  license under French  law  and
 * abiding  by the rules of distribution of free  software. You can  use, modify
 * and/or redistribute the software under the terms  of the  CeCILL-C license as
 * circulated by CEA, CNRS and INRIA at the following URL:
 * 
 * http://www.cecill.info
 * 
 * As a counterpart to the access to the source code  and rights to copy, modify
 * and redistribute  granted by  the  license, users are  provided  only with  a
 * limited  warranty and  the software's author,  the  holder  of  the  economic
 * rights, and the successive licensors have only limited liability.
 * 
 * In this respect, the user's  attention is drawn to the risks  associated with
 * loading, using, modifying and/or  developing or reproducing  the software  by
 * the user in light of its specific status of free software, that may mean that
 * it is complicated to manipulate,  and that also  therefore means  that it  is
 * reserved  for  developers   and  experienced  professionals  having  in-depth
 * computer  knowledge. Users  are  therefore  encouraged to load  and  test the
 * software's suitability as  regards  their requirements in conditions enabling
 * the security of their systems and/or data to be  ensured and, more generally,
 * to use and operate it in the same conditions as regards security.
 * 
 * The  fact  that you are  presently  reading  this  means  that you  have  had
 * knowledge of the CeCILL-C license and that you accept its terms.
 *
 * @author    Thierry Thiers <webcoder31@gmail.com>
 * @copyright 2017-2026 - Thierry Thiers <webcoder31@gmail.com>
 * @license   http://www.cecill.info  CeCILL-C License
 * @version   2.0.0
 */


// Namespace.
namespace webcoder31\ezxmldsig\seal;

// Use.
use Exception;

/**
 * The ZIP archives of ASiC containers (ETSI EN 319 162-1, 4.2): a writer of
 * what a container needs, and a strict reader. The ZIP extension of PHP is
 * not used: it is often missing, and it resolves what this reader refuses.
 *
 * A seal covers the files of its container: the reader refuses whatever lets
 * two tools see different files in the same archive, which general ZIP
 * readers accept. A local header that differs from its central directory
 * entry, bytes between entries, two names that look the same, a path that
 * leaves the container: each is refused, not resolved one way or the other.
 * Two names are the same when they are the same in Unicode normalization
 * form C, if the intl extension of PHP is loaded (class Normalizer), and
 * when they are the same bytes otherwise.
 *
 * Neither ZIP64 nor encryption is supported, nor any method but stored (0)
 * and deflate (8).
 *
 * An entry read is an array: 'name' (its path, `/` separated), 'content'
 * (the uncompressed bytes), 'method' (0 or 8) and 'extra' (the extra field
 * of its local header).
 *
 * @internal
 */
class Zip
{
    /** The default limits of the reader: entries, and uncompressed bytes in all. */
    const MAX_ENTRIES = 1000;
    const MAX_TOTAL_SIZE = 536870912;

    const LOCAL_SIGNATURE = 0x04034b50;
    const CENTRAL_SIGNATURE = 0x02014b50;
    const END_SIGNATURE = 0x06054b50;
    const DESCRIPTOR_SIGNATURE = 0x08074b50;

    const LOCAL_SIZE = 30;
    const CENTRAL_SIZE = 46;
    const END_SIZE = 22;

    /** General purpose flags: data descriptor and UTF-8 names. */
    const FLAG_DESCRIPTOR = 0x0008;
    const FLAG_UTF8 = 0x0800;
    /** Flags a reader may meet: bits 1 and 2 only tell how deflate was tuned. */
    const ALLOWED_FLAGS = 0x0006 | 0x0008 | 0x0800;

    /** Extra fields that change the meaning of the header: ZIP64, and a second name (Info-ZIP Unicode path). */
    const REFUSED_EXTRA_IDS = [0x0001, 0x7075];

    const MAX_16 = 0xffff;
    const MAX_32 = 0xffffffff;


    /**
     * Write an archive: names in UTF-8, sizes and CRC in the local headers
     * (no data descriptor), deflate unless 'stored', no comment.
     *
     * @param array $inputs The entries, each an array with 'name', 'content'
     *        and, optionally, 'stored' (TRUE to store the content
     *        uncompressed: the `mimetype` entry of a container).
     *
     * @param int $modified The date of every entry, a UNIX time, in UTC. A
     *        fixed date makes the archive depend on its entries only.
     *
     * @return string The archive.
     *
     * @throws Exception If a name is not acceptable to the reader, if two
     *         names collide, or if the archive would need ZIP64.
     */
    public static function write(array $inputs, $modified)
    {
        if (count($inputs) > self::MAX_16)
        {
            throw new Exception('ZIP: too many entries for an archive without ZIP64.');
        }
        list($time, $date) = self::dosDateTime($modified);
        $names = [];
        $locals = '';
        $centrals = '';
        $offset = 0;
        foreach ($inputs as $input)
        {
            $name = $input['name'];
            self::checkName($name);
            $key = self::key($name);
            if (isset($names[$key]))
            {
                throw new Exception('ZIP: duplicate entry ' . self::quote($name) . '.');
            }
            $names[$key] = true;
            $method = empty($input['stored']) ? 8 : 0;
            $data = 0 === $method ? $input['content'] : gzdeflate($input['content'], 6, ZLIB_ENCODING_RAW);
            $crc = crc32($input['content']);
            if (strlen($input['content']) > self::MAX_32 - 1 || strlen($data) > self::MAX_32 - 1 || $offset > self::MAX_32 - 1)
            {
                throw new Exception('ZIP: entry too large for an archive without ZIP64.');
            }
            $version = 0 === $method ? 10 : 20;
            $locals .= pack('VvvvvvVVVvv', self::LOCAL_SIGNATURE, $version, self::FLAG_UTF8, $method, $time, $date,
                $crc, strlen($data), strlen($input['content']), strlen($name), 0) . $name . $data;
            $centrals .= pack('VvvvvvvVVVvvvvvVV', self::CENTRAL_SIGNATURE, 20, $version, self::FLAG_UTF8, $method, $time, $date,
                $crc, strlen($data), strlen($input['content']), strlen($name), 0, 0, 0, 0, 0, $offset) . $name;
            $offset += self::LOCAL_SIZE + strlen($name) + strlen($data);
        }
        if ($offset + strlen($centrals) > self::MAX_32 - 1)
        {
            throw new Exception('ZIP: archive too large without ZIP64.');
        }

        return $locals . $centrals . pack('VvvvvVVv', self::END_SIGNATURE, 0, 0, count($inputs), count($inputs), strlen($centrals), $offset, 0);
    }


    /**
     * Read an archive, entries in their order. Directory entries (a name
     * ending with `/`, empty) are checked and left out.
     *
     * @param string $archive The archive.
     *
     * @param int $maxEntries The largest number of entries.
     *
     * @param int $maxTotalSize The largest uncompressed size of the entries
     *        together, in bytes.
     *
     * @return array The entries.
     *
     * @throws Exception If the archive is malformed, ambiguous, or beyond the
     *         limits.
     */
    public static function read($archive, $maxEntries = self::MAX_ENTRIES, $maxTotalSize = self::MAX_TOTAL_SIZE)
    {
        $endOffset = self::findEnd($archive);
        $end = unpack('Vsignature/vdisk/vdirectoryDisk/vdiskCount/vcount/VdirectorySize/VdirectoryOffset/vcommentLength', $archive, $endOffset);
        $count = $end['count'];
        if (0 !== $end['disk'] || 0 !== $end['directoryDisk'] || $end['diskCount'] !== $count)
        {
            throw new Exception('ZIP: archives on several disks are not supported.');
        }
        if (self::MAX_16 === $count || self::MAX_32 === $end['directorySize'] || self::MAX_32 === $end['directoryOffset'])
        {
            throw new Exception('ZIP: ZIP64 is not supported.');
        }
        if ($count > $maxEntries)
        {
            throw new Exception('ZIP: more than ' . $maxEntries . ' entries.');
        }
        $directoryOffset = $end['directoryOffset'];
        if ($directoryOffset + $end['directorySize'] !== $endOffset)
        {
            throw new Exception('ZIP: the central directory does not end where the archive ends.');
        }
        $directory = (string) substr($archive, $directoryOffset, $end['directorySize']);
        $directoryLength = strlen($directory);

        $entries = [];
        $names = [];
        $position = 0;
        $expectedOffset = 0;
        $totalSize = 0;
        for ($index = 0; $index < $count; $index++)
        {
            if ($position + self::CENTRAL_SIZE > $directoryLength
                || self::CENTRAL_SIGNATURE !== unpack('V', $directory, $position)[1])
            {
                throw new Exception('ZIP: malformed central directory.');
            }
            $central = unpack('Vsignature/vmadeBy/vneeded/vflags/vmethod/vtime/vdate/Vcrc/VcompressedSize/Vsize/vnameLength/vextraLength/vcommentLength/vdisk/vinternal/Vexternal/VlocalOffset', $directory, $position);
            $flags = $central['flags'];
            $method = $central['method'];
            $fieldsEnd = $position + self::CENTRAL_SIZE + $central['nameLength'] + $central['extraLength'] + $central['commentLength'];
            if ($fieldsEnd > $directoryLength)
            {
                throw new Exception('ZIP: malformed central directory.');
            }
            $nameBytes = (string) substr($directory, $position + self::CENTRAL_SIZE, $central['nameLength']);
            self::checkExtra((string) substr($directory, $position + self::CENTRAL_SIZE + $central['nameLength'], $central['extraLength']));
            self::decodeText((string) substr($directory, $position + self::CENTRAL_SIZE + $central['nameLength'] + $central['extraLength'], $central['commentLength']), $flags, 'comment');
            $position = $fieldsEnd;

            if ($flags & ~self::ALLOWED_FLAGS)
            {
                throw new Exception('ZIP: encrypted or unsupported entry.');
            }
            if (0 !== $method && 8 !== $method)
            {
                throw new Exception('ZIP: unsupported compression method ' . $method . '.');
            }
            if (0 !== $central['disk'])
            {
                throw new Exception('ZIP: archives on several disks are not supported.');
            }
            $crc = $central['crc'];
            $compressedSize = $central['compressedSize'];
            $size = $central['size'];
            $localOffset = $central['localOffset'];
            if (self::MAX_32 === $compressedSize || self::MAX_32 === $size || self::MAX_32 === $localOffset)
            {
                throw new Exception('ZIP: ZIP64 is not supported.');
            }
            $name = self::decodeText($nameBytes, $flags, 'name');
            $isDirectory = '/' === substr($name, -1);
            self::checkName($isDirectory ? substr($name, 0, -1) : $name);
            $key = self::key($name);
            if (isset($names[$key]))
            {
                throw new Exception('ZIP: duplicate entry ' . self::quote($name) . '.');
            }
            $names[$key] = true;
            if (0 === $method && $compressedSize !== $size)
            {
                throw new Exception('ZIP: stored entry ' . self::quote($name) . ' with two sizes.');
            }
            if ($isDirectory && 0 !== $size)
            {
                throw new Exception('ZIP: directory entry ' . self::quote($name) . ' with content.');
            }
            $totalSize += $size;
            if ($totalSize > $maxTotalSize)
            {
                throw new Exception('ZIP: more than ' . $maxTotalSize . ' bytes once uncompressed.');
            }

            // The local header, where the previous entry ended.
            if ($localOffset !== $expectedOffset)
            {
                throw new Exception('ZIP: entry ' . self::quote($name) . ' is not where the previous entry ends.');
            }
            if ($localOffset + self::LOCAL_SIZE > $directoryOffset || self::LOCAL_SIGNATURE !== unpack('V', $archive, $localOffset)[1])
            {
                throw new Exception('ZIP: missing local header for ' . self::quote($name) . '.');
            }
            $local = unpack('Vsignature/vneeded/vflags/vmethod/vtime/vdate/Vcrc/VcompressedSize/Vsize/vnameLength/vextraLength', $archive, $localOffset);
            $dataOffset = $localOffset + self::LOCAL_SIZE + $local['nameLength'] + $local['extraLength'];
            if ($dataOffset + $compressedSize > $directoryOffset)
            {
                throw new Exception('ZIP: entry ' . self::quote($name) . ' overlaps the central directory.');
            }
            $localName = (string) substr($archive, $localOffset + self::LOCAL_SIZE, $local['nameLength']);
            $extra = (string) substr($archive, $localOffset + self::LOCAL_SIZE + $local['nameLength'], $local['extraLength']);
            self::checkExtra($extra);
            $sameSizes = $local['crc'] === $crc && $local['compressedSize'] === $compressedSize && $local['size'] === $size;
            $zeroSizes = 0 === $local['crc'] && 0 === $local['compressedSize'] && 0 === $local['size'];
            if ($local['flags'] !== $flags || $local['method'] !== $method || $localName !== $nameBytes
                || !($sameSizes || (($flags & self::FLAG_DESCRIPTOR) && $zeroSizes)))
            {
                throw new Exception('ZIP: local header of ' . self::quote($name) . ' differs from the central directory.');
            }
            $expectedOffset = $dataOffset + $compressedSize;
            if ($flags & self::FLAG_DESCRIPTOR)
            {
                $expectedOffset = self::readDescriptor($archive, $expectedOffset, $directoryOffset, $crc, $compressedSize, $size, $name);
            }

            $data = (string) substr($archive, $dataOffset, $compressedSize);
            $content = 0 === $method ? $data : self::inflate($data, $size, $name);
            if (crc32($content) !== $crc)
            {
                throw new Exception('ZIP: CRC mismatch for ' . self::quote($name) . '.');
            }
            if (!$isDirectory)
            {
                $entries[] = ['name' => $name, 'content' => $content, 'method' => $method, 'extra' => $extra];
            }
        }
        if ($position !== $directoryLength || $expectedOffset !== $directoryOffset)
        {
            throw new Exception('ZIP: bytes outside the entries of the archive.');
        }

        return $entries;
    }


    /**
     * Find the end of central directory record, which the archive must end
     * with (its comment included), and return its offset.
     */
    private static function findEnd($archive)
    {
        $length = is_string($archive) ? strlen($archive) : 0;
        for ($offset = $length - self::END_SIZE; $offset >= max(0, $length - self::END_SIZE - self::MAX_16); $offset--)
        {
            if (self::END_SIGNATURE === unpack('V', $archive, $offset)[1]
                && $offset + self::END_SIZE + unpack('v', $archive, $offset + 20)[1] === $length)
            {
                self::decodeText((string) substr($archive, $offset + self::END_SIZE), self::FLAG_UTF8, 'comment');
                return $offset;
            }
        }
        throw new Exception('ZIP: not a ZIP archive.');
    }


    /**
     * Read a data descriptor, with or without its signature, and return
     * where it ends.
     */
    private static function readDescriptor($archive, $offset, $limit, $crc, $compressedSize, $size, $name)
    {
        $signed = $offset + 4 <= $limit && self::DESCRIPTOR_SIGNATURE === unpack('V', $archive, $offset)[1];
        $start = $signed ? $offset + 4 : $offset;
        if ($start + 12 > $limit)
        {
            throw new Exception('ZIP: missing data descriptor for ' . self::quote($name) . '.');
        }
        $descriptor = unpack('Vcrc/VcompressedSize/Vsize', $archive, $start);
        if ($descriptor['crc'] !== $crc || $descriptor['compressedSize'] !== $compressedSize || $descriptor['size'] !== $size)
        {
            throw new Exception('ZIP: data descriptor of ' . self::quote($name) . ' differs from the central directory.');
        }

        return $start + 12;
    }


    /**
     * Inflate exactly `$size` bytes from all of `$data`: the stream must end
     * where the data end, and inflate to the size.
     */
    private static function inflate($data, $size, $name)
    {
        $context = inflate_init(ZLIB_ENCODING_RAW);
        $content = '';
        $failed = false;
        // Chunks of input, so that a stream that inflates beyond its size
        // stops early instead of filling the memory.
        for ($offset = 0, $length = strlen($data); $offset < $length || 0 === $length; $offset += 4096)
        {
            $chunk = @inflate_add($context, (string) substr($data, $offset, 4096), ZLIB_SYNC_FLUSH);
            if (false === $chunk)
            {
                $failed = true;
                break;
            }
            $content .= $chunk;
            if (strlen($content) > $size || ZLIB_STREAM_END === inflate_get_status($context) || 0 === $length)
            {
                break;
            }
        }
        if ($failed || strlen($content) !== $size || ZLIB_STREAM_END !== inflate_get_status($context)
            || inflate_get_read_len($context) !== strlen($data))
        {
            throw new Exception('ZIP: entry ' . self::quote($name) . ' does not inflate to its size.');
        }

        return $content;
    }


    /**
     * Check that an extra field is a well-formed list, without a field that
     * changes the header.
     */
    private static function checkExtra($extra)
    {
        $offset = 0;
        $length = strlen($extra);
        while ($offset < $length)
        {
            if ($offset + 4 > $length)
            {
                throw new Exception('ZIP: malformed extra field.');
            }
            $field = unpack('vid/vlength', $extra, $offset);
            if (in_array($field['id'], self::REFUSED_EXTRA_IDS, true))
            {
                throw new Exception(sprintf('ZIP: unsupported extra field 0x%04x.', $field['id']));
            }
            $offset += 4 + $field['length'];
        }
        if ($offset !== $length)
        {
            throw new Exception('ZIP: malformed extra field.');
        }
    }


    /**
     * Decode a name or a comment: UTF-8 when flagged, ASCII otherwise (the
     * legacy code page is refused).
     */
    private static function decodeText($bytes, $flags, $what)
    {
        if (!($flags & self::FLAG_UTF8) && preg_match('/[\x80-\xff]/', $bytes))
        {
            throw new Exception('ZIP: ' . $what . ' neither in UTF-8 nor in ASCII.');
        }
        if (!preg_match('//u', $bytes))
        {
            throw new Exception('ZIP: ' . $what . ' is not valid UTF-8.');
        }
        // A byte order mark is a character of the name, as in Node.js.
        return $bytes;
    }


    /**
     * Check a path: relative, `/` separated, without empty, `.` or `..`
     * segment, nor control character or backslash.
     */
    private static function checkName($name)
    {
        if ('' === $name || preg_match('/[\x00-\x1f\x7f\\\\]/', $name) || '/' === $name[0])
        {
            throw new Exception('ZIP: invalid entry name ' . self::quote($name) . '.');
        }
        foreach (explode('/', $name) as $segment)
        {
            if ('' === $segment || '.' === $segment || '..' === $segment)
            {
                throw new Exception('ZIP: invalid entry name ' . self::quote($name) . '.');
            }
        }
    }


    /**
     * The key two names are compared by: their normalization form C, or
     * their bytes without the intl extension.
     */
    private static function key($name)
    {
        if (class_exists('Normalizer'))
        {
            $normalized = \Normalizer::normalize($name, \Normalizer::FORM_C);
            if (false !== $normalized)
            {
                return $normalized;
            }
        }

        return $name;
    }


    /**
     * A name between double quotes, for the messages, as JSON writes it but
     * without escaping slashes and non-ASCII characters.
     */
    private static function quote($text)
    {
        return json_encode($text, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }


    /**
     * The MS-DOS time and date of a moment, from its UTC fields (1980 to
     * 2107).
     */
    private static function dosDateTime($moment)
    {
        $year = (int) gmdate('Y', $moment);
        if ($year < 1980 || $year > 2107)
        {
            throw new Exception('ZIP: the date of the entries must be between 1980 and 2107.');
        }

        return [
            ((int) gmdate('G', $moment) << 11) | ((int) gmdate('i', $moment) << 5) | ((int) gmdate('s', $moment) >> 1),
            (($year - 1980) << 9) | ((int) gmdate('n', $moment) << 5) | (int) gmdate('j', $moment),
        ];
    }
}
