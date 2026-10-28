<?php

namespace webcoder31\ezxmldsig\Tests\helpers;

/**
 * A DER writer and reader for the test helpers, written apart from
 * src/core/Der.php so that the structures the library is tested on do not
 * come from the code under test. A port of test/helpers/der.ts of the
 * Node.js library.
 */
class TestDer
{
    public static function der($tag, ...$content)
    {
        $body = implode('', $content);
        $length = strlen($body);
        $header = $length < 128 ? chr($length) : ($length < 256 ? "\x81" . chr($length) : "\x82" . chr($length >> 8) . chr($length & 0xff));
        return chr($tag) . $header . $body;
    }

    public static function seq(...$content)
    {
        return self::der(0x30, ...$content);
    }

    public static function set(...$content)
    {
        return self::der(0x31, ...$content);
    }

    public static function octets($bytes)
    {
        return self::der(0x04, $bytes);
    }

    /** An INTEGER, from a small number or from its big-endian bytes. */
    public static function int($value)
    {
        $bytes = is_int($value) ? chr($value) : $value;
        return self::der(0x02, (ord($bytes[0]) & 0x80 ? "\x00" : '') . $bytes);
    }

    public static function oid($dotted)
    {
        $arcs = array_map('intval', explode('.', $dotted));
        $bytes = chr($arcs[0] * 40 + $arcs[1]);
        foreach (array_slice($arcs, 2) as $arc)
        {
            $group = chr($arc & 0x7f);
            for ($v = $arc >> 7; $v > 0; $v >>= 7)
            {
                $group = chr(($v & 0x7f) | 0x80) . $group;
            }
            $bytes .= $group;
        }
        return self::der(0x06, $bytes);
    }

    /** The elements of a DER string: each ['tag' => int, 'content' => string]. */
    public static function children($bytes)
    {
        $out = [];
        for ($i = 0; $i < strlen($bytes);)
        {
            $tag = ord($bytes[$i++]);
            $length = ord($bytes[$i++]);
            if ($length & 0x80)
            {
                $n = $length & 0x7f;
                $length = 0;
                for ($k = 0; $k < $n; $k++)
                {
                    $length = $length * 256 + ord($bytes[$i++]);
                }
            }
            $out[] = ['tag' => $tag, 'content' => substr($bytes, $i, $length)];
            $i += $length;
        }
        return $out;
    }

    /** A Time: UTCTime up to 2049, GeneralizedTime after (RFC 5280, 4.1.2.5); the fraction of a second is dropped. */
    public static function time($time)
    {
        $seconds = (int) floor($time);
        return (int) gmdate('Y', $seconds) < 2050 ? self::der(0x17, gmdate('ymdHis', $seconds) . 'Z') : self::generalized($time);
    }

    /** A GeneralizedTime, to the second. */
    public static function generalized($time)
    {
        return self::der(0x18, gmdate('YmdHis', (int) floor($time)) . 'Z');
    }

    /** The DER of a certificate, from its PEM. */
    public static function certificateDer($pem)
    {
        preg_match('/-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/s', $pem, $match);
        return base64_decode($match[1]);
    }

    /** The fields of the TBSCertificate of a certificate (serial 0, signature 1, issuer 2, validity 3, subject 4, key 5), without the version, in DER. */
    public static function tbsFields($pem)
    {
        $certificate = self::children(self::certificateDer($pem));
        $fields = self::children(self::children($certificate[0]['content'])[0]['content']);
        if (0xa0 === $fields[0]['tag'])
        {
            array_shift($fields);
        }
        return array_map(function ($field) { return self::der($field['tag'], $field['content']); }, $fields);
    }
}
