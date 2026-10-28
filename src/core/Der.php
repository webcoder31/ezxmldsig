<?php
/**
 * Der.php
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
namespace webcoder31\ezxmldsig\core;

// Use.
use Exception;

/**
 * A minimal reader and writer of DER, the binary encoding of X.509
 * certificates, CRLs, OCSP responses and time-stamp tokens (RFC 3161), for
 * what the OpenSSL extension of PHP does not expose: the fields of names,
 * the extensions and their criticality, the structures of the seals. Every
 * malformation throws, and what is read is then refused. Only DER is read:
 * an indefinite length is a malformation.
 *
 * An element is an array with two keys: 'tag', its identifier octet (class,
 * constructed bit and tag number), and 'content', its content octets (a
 * binary string).
 *
 * @internal
 */
class Der
{
    /** Universal tags. */
    const BOOLEAN = 0x01;
    const INTEGER = 0x02;
    const BIT_STRING = 0x03;
    const OCTET_STRING = 0x04;
    const NULL = 0x05;
    const OID = 0x06;
    const ENUMERATED = 0x0a;
    const UTF8_STRING = 0x0c;
    const PRINTABLE_STRING = 0x13;
    const IA5_STRING = 0x16;
    const UTC_TIME = 0x17;
    const GENERALIZED_TIME = 0x18;
    const SEQUENCE = 0x30;
    const SET = 0x31;


    /**
     * Read the elements that follow each other in a binary string.
     *
     * @param string $buffer The DER.
     *
     * @return array The elements.
     *
     * @throws Exception If the string is not a sequence of DER elements.
     */
    public static function readElements($buffer)
    {
        if (!is_string($buffer))
        {
            throw new Exception('DER: bytes expected.');
        }
        $elements = [];
        $offset = 0;
        $size = strlen($buffer);
        while ($offset < $size)
        {
            $tag = ord($buffer[$offset++]);
            if (0x1f === ($tag & 0x1f))
            {
                throw new Exception('DER: multi-byte tags are not supported.');
            }
            if ($offset >= $size)
            {
                throw new Exception('DER: truncated length.');
            }
            $length = ord($buffer[$offset++]);
            if ($length & 0x80)
            {
                $count = $length & 0x7f;
                if (0 === $count || $count > 4 || $offset + $count > $size)
                {
                    throw new Exception('DER: invalid length.');
                }
                $length = 0;
                for ($i = 0; $i < $count; $i++)
                {
                    $length = $length * 256 + ord($buffer[$offset++]);
                }
            }
            if ($offset + $length > $size)
            {
                throw new Exception('DER: truncated content.');
            }
            $elements[] = ['tag' => $tag, 'content' => (string) substr($buffer, $offset, $length)];
            $offset += $length;
        }

        return $elements;
    }


    /**
     * Read the single element a binary string holds.
     *
     * @param string $buffer The DER.
     *
     * @return array The element.
     *
     * @throws Exception If the string does not hold exactly one element.
     */
    public static function readElement($buffer)
    {
        $elements = self::readElements($buffer);
        if (1 !== count($elements))
        {
            throw new Exception('DER: one element expected.');
        }

        return $elements[0];
    }


    /**
     * Read the elements of a constructed element of the given tag.
     *
     * @param array $element The element.
     *
     * @param int $tag The tag it must have.
     *
     * @return array The elements it holds.
     *
     * @throws Exception If the element has another tag.
     */
    public static function childrenOf($element, $tag)
    {
        if ($element['tag'] !== $tag)
        {
            throw new Exception(sprintf('DER: tag %x expected, %x found.', $tag, $element['tag']));
        }

        return self::readElements($element['content']);
    }


    /**
     * Decode an object identifier into its dotted form.
     *
     * @param array $element The element.
     *
     * @return string The dotted form, such as "1.2.840.113549.1.1.11".
     *
     * @throws Exception If the element is not an object identifier.
     */
    public static function decodeOid($element)
    {
        if (self::OID !== $element['tag'] || '' === $element['content'])
        {
            throw new Exception('DER: object identifier expected.');
        }
        $content = $element['content'];
        $arcs = [];
        $value = 0;
        for ($i = 0, $n = strlen($content); $i < $n; $i++)
        {
            $byte = ord($content[$i]);
            if ($value > (PHP_INT_MAX >> 7))
            {
                throw new Exception('DER: object identifier arc too large.');
            }
            $value = $value * 128 + ($byte & 0x7f);
            if (!($byte & 0x80))
            {
                $arcs[] = $value;
                $value = 0;
            }
        }
        if (ord($content[strlen($content) - 1]) & 0x80)
        {
            throw new Exception('DER: truncated object identifier.');
        }
        $first = array_shift($arcs);
        $head = $first < 40 ? [0, $first] : ($first < 80 ? [1, $first - 40] : [2, $first - 80]);

        return implode('.', array_merge($head, $arcs));
    }


    /**
     * Decode a boolean.
     *
     * @param array $element The element.
     *
     * @return boolean The value.
     *
     * @throws Exception If the element is not a boolean.
     */
    public static function decodeBoolean($element)
    {
        if (self::BOOLEAN !== $element['tag'] || 1 !== strlen($element['content']))
        {
            throw new Exception('DER: boolean expected.');
        }

        return "\0" !== $element['content'];
    }


    /**
     * Decode a non-negative integer that fits in a PHP integer (6 bytes at
     * most).
     *
     * @param array $element The element.
     *
     * @return int The value.
     *
     * @throws Exception If the element is not such an integer.
     */
    public static function decodeSmallInteger($element)
    {
        $content = $element['content'];
        if (self::INTEGER !== $element['tag'] || '' === $content || strlen($content) > 6)
        {
            throw new Exception('DER: small integer expected.');
        }
        if (ord($content[0]) & 0x80)
        {
            throw new Exception('DER: negative integer.');
        }

        return hexdec(bin2hex($content));
    }


    /**
     * Decode a bit string into its bits, the first one (bit 0) first.
     *
     * @param array $element The element.
     *
     * @return array The bits, as booleans.
     *
     * @throws Exception If the element is not a bit string.
     */
    public static function decodeBits($element)
    {
        $content = $element['content'];
        if (self::BIT_STRING !== $element['tag'] || '' === $content)
        {
            throw new Exception('DER: bit string expected.');
        }
        $unused = ord($content[0]);
        if ($unused > 7 || (1 === strlen($content) && 0 !== $unused))
        {
            throw new Exception('DER: invalid bit string.');
        }
        $bits = [];
        $count = (strlen($content) - 1) * 8 - $unused;
        for ($i = 0; $i < $count; $i++)
        {
            $bits[] = 1 === ((ord($content[1 + ($i >> 3)]) >> (7 - ($i & 7))) & 1);
        }

        return $bits;
    }


    /**
     * The bytes of a bit string with no unused bit, such as a signature or a
     * public key.
     *
     * @param array $element The element.
     *
     * @return string The bytes.
     *
     * @throws Exception If the element is not such a bit string.
     */
    public static function decodeBitStringBytes($element)
    {
        if (self::BIT_STRING !== $element['tag'] || '' === $element['content'] || "\0" !== $element['content'][0])
        {
            throw new Exception('DER: bit string of whole bytes expected.');
        }

        return (string) substr($element['content'], 1);
    }


    /**
     * Decode a GeneralizedTime in UTC (`YYYYMMDDhhmmss[.f]Z`, RFC 5280
     * 4.1.2.5.2, RFC 3161 2.4.2).
     *
     * @param array $element The element.
     *
     * @return float The time, in seconds since the UNIX epoch, the fraction
     *         of a second kept to the millisecond.
     *
     * @throws Exception If the element is not such a time.
     */
    public static function decodeGeneralizedTime($element)
    {
        $text = self::GENERALIZED_TIME === $element['tag'] ? $element['content'] : '';
        if (!preg_match('/\A(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d*[1-9])?Z\z/', $text, $match))
        {
            throw new Exception('DER: GeneralizedTime in UTC expected.');
        }

        return self::utc($match[1], $match[2], $match[3], $match[4], $match[5], $match[6])
            + (isset($match[7]) ? floor((float) ('0' . $match[7]) * 1000) / 1000 : 0);
    }


    /**
     * Decode a Time (RFC 5280, 4.1.2.5): UTCTime (years 1950 to 2049) or
     * GeneralizedTime, in UTC.
     *
     * @param array $element The element.
     *
     * @return float The time, in seconds since the UNIX epoch.
     *
     * @throws Exception If the element is not such a time.
     */
    public static function decodeTime($element)
    {
        if (self::GENERALIZED_TIME === $element['tag'])
        {
            return self::decodeGeneralizedTime($element);
        }
        if (self::UTC_TIME !== $element['tag']
            || !preg_match('/\A(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z\z/', $element['content'], $match))
        {
            throw new Exception('DER: malformed time.');
        }
        $year = (int) $match[1] < 50 ? 2000 + (int) $match[1] : 1900 + (int) $match[1];

        return self::utc($year, $match[2], $match[3], $match[4], $match[5], $match[6]);
    }


    /**
     * The UNIX time of a date and time in UTC, its fields checked.
     *
     * @return int The time, in seconds.
     *
     * @throws Exception If a field is out of its range.
     */
    private static function utc($year, $month, $day, $hour, $minute, $second)
    {
        $time = gmmktime((int) $hour, (int) $minute, (int) $second, (int) $month, (int) $day, (int) $year);
        if (false === $time || (int) gmdate('j', $time) !== (int) $day || (int) gmdate('n', $time) !== (int) $month
            || (int) gmdate('G', $time) !== (int) $hour || (int) $minute > 59 || (int) $second > 59)
        {
            throw new Exception('DER: invalid time.');
        }

        return $time;
    }


    /**
     * Decode an integer into its unsigned big-endian bytes (a serial number,
     * a nonce).
     *
     * @param array $element The element.
     *
     * @return string The bytes, without leading zero byte.
     *
     * @throws Exception If the element is not a non-negative integer.
     */
    public static function decodeUnsigned($element)
    {
        $content = $element['content'];
        if (self::INTEGER !== $element['tag'] || '' === $content || (ord($content[0]) & 0x80))
        {
            throw new Exception('DER: non-negative integer expected.');
        }

        return "\0" === $content[0] && strlen($content) > 1 ? (string) substr($content, 1) : $content;
    }


    /**
     * Encode an element: its identifier octet, its length (definite,
     * minimal), its content.
     *
     * @param int $tag The identifier octet.
     *
     * @param string ...$content The content, in parts.
     *
     * @return string The DER.
     */
    public static function encode($tag, ...$content)
    {
        $body = implode('', $content);
        $size = strlen($body);
        if ($size < 0x80)
        {
            $length = chr($size);
        }
        else
        {
            $bytes = '';
            for ($rest = $size; $rest > 0; $rest = intdiv($rest, 256))
            {
                $bytes = chr($rest % 256) . $bytes;
            }
            $length = chr(0x80 | strlen($bytes)) . $bytes;
        }

        return chr($tag) . $length . $body;
    }


    /**
     * Encode an element read by readElements() again: DER has a single
     * encoding.
     *
     * @param array $element The element.
     *
     * @return string The DER.
     */
    public static function reencode($element)
    {
        return self::encode($element['tag'], $element['content']);
    }


    /**
     * Encode an object identifier given in its dotted form.
     *
     * @param string $oid The dotted form.
     *
     * @return string The DER.
     *
     * @throws Exception If the identifier is not valid.
     */
    public static function encodeOid($oid)
    {
        $arcs = explode('.', (string) $oid);
        foreach ($arcs as $arc)
        {
            if (!ctype_digit($arc) || strlen($arc) > 15)
            {
                throw new Exception('DER: invalid object identifier ' . $oid . '.');
            }
        }
        if (count($arcs) < 2)
        {
            throw new Exception('DER: invalid object identifier ' . $oid . '.');
        }
        $values = array_merge([(int) $arcs[0] * 40 + (int) $arcs[1]], array_map('intval', array_slice($arcs, 2)));
        $bytes = '';
        foreach ($values as $arc)
        {
            $group = chr($arc & 0x7f);
            for ($rest = $arc >> 7; $rest > 0; $rest >>= 7)
            {
                $group = chr(($rest & 0x7f) | 0x80) . $group;
            }
            $bytes .= $group;
        }

        return self::encode(self::OID, $bytes);
    }


    /**
     * Encode a non-negative integer given as unsigned big-endian bytes, or as
     * a PHP integer.
     *
     * @param string|int $value The value.
     *
     * @return string The DER.
     */
    public static function encodeInteger($value)
    {
        if (is_int($value))
        {
            $hex = dechex($value);
            $bytes = hex2bin(0 === strlen($hex) % 2 ? $hex : '0' . $hex);
        }
        else
        {
            $bytes = '' === $value ? "\0" : $value;
        }
        while (strlen($bytes) > 1 && "\0" === $bytes[0] && !(ord($bytes[1]) & 0x80))
        {
            $bytes = substr($bytes, 1);
        }

        return self::encode(self::INTEGER, (ord($bytes[0]) & 0x80 ? "\0" : '') . $bytes);
    }
}
