<?php

namespace webcoder31\ezxmldsig\Demo;

use webcoder31\ezxmldsig\XMLDSigToken;

/**
 * The algorithms the demo lets choose: those each option of XMLDSigToken
 * accepts (see the README, section "Options"), named by their constant.
 */
final class Algorithms
{
    /** Option => [constant name => label]. The first one is the default of
    the library. */
    const CHOICES = [
        'signatureAlgorithm' => [
            'RSA_SHA256' => 'RSA-SHA256',
            'RSA_SHA384' => 'RSA-SHA384',
            'RSA_SHA512' => 'RSA-SHA512',
            'RSA_SHA1' => 'RSA-SHA1 (legacy)',
        ],
        'digestAlgorithm' => [
            'SHA256' => 'SHA-256',
            'SHA384' => 'SHA-384',
            'SHA512' => 'SHA-512',
            'SHA1' => 'SHA-1 (legacy)',
            'RIPEMD160' => 'RIPEMD-160',
        ],
        'sessionKeyCipheringAlgorithm' => [
            'AES256_GCM' => 'AES-256-GCM',
            'AES192_GCM' => 'AES-192-GCM',
            'AES128_GCM' => 'AES-128-GCM',
            'AES256_CBC' => 'AES-256-CBC (no integrity)',
            'AES192_CBC' => 'AES-192-CBC (no integrity)',
            'AES128_CBC' => 'AES-128-CBC (no integrity)',
            'TRIPLEDES_CBC' => '3DES-CBC (no integrity)',
        ],
    ];

    /**
     * Turns a choice of algorithms (option => constant name) into options of
     * XMLDSigToken (option => URI). Only the options that differ from the
     * defaults of the library are kept, as a caller would write them.
     *
     * @param array $choice Option => constant name, e.g.
     *     ['signatureAlgorithm' => 'RSA_SHA512'].
     * @param bool $encryption Whether the encryption option applies.
     *
     * @return array Options of XMLDSigToken.
     *
     * @throws \InvalidArgumentException For an unknown option or algorithm.
     */
    public static function toOptions(array $choice, $encryption)
    {
        $options = [];
        foreach ($choice as $option => $name)
        {
            if (!isset(self::CHOICES[$option]))
            {
                throw new \InvalidArgumentException('Unknown algorithm option.');
            }
            if (!is_string($name) || !isset(self::CHOICES[$option][$name]))
            {
                throw new \InvalidArgumentException('Unknown algorithm for ' . $option . '.');
            }
            if ('sessionKeyCipheringAlgorithm' === $option && !$encryption)
            {
                continue;
            }
            if ($name !== array_key_first(self::CHOICES[$option]))
            {
                $options[$option] = constant(XMLDSigToken::class . '::' . $name);
            }
        }

        return $options;
    }

    /**
     * Returns the URI of each algorithm a token may name: those of CHOICES,
     * the canonicalization algorithms and the key transport algorithm.
     *
     * @return array URI => label.
     */
    public static function uris()
    {
        $uris = [
            XMLDSigToken::C14N => 'C14N 1.0',
            XMLDSigToken::C14N_COMMENTS => 'C14N 1.0 with comments',
            XMLDSigToken::EXC_C14N => 'Exclusive C14N',
            XMLDSigToken::EXC_C14N_COMMENTS => 'Exclusive C14N with comments',
            XMLDSigToken::RSA_OAEP_MGF1P => 'RSA-OAEP (MGF1)',
        ];
        foreach (self::CHOICES as $names)
        {
            foreach ($names as $name => $label)
            {
                $uris[constant(XMLDSigToken::class . '::' . $name)] = $label;
            }
        }

        return $uris;
    }

    /**
     * Returns the constant name of an algorithm URI, or NULL.
     *
     * @param string $uri
     *
     * @return string|null
     */
    public static function nameOf($uri)
    {
        foreach (self::CHOICES as $names)
        {
            foreach ($names as $name => $label)
            {
                if (constant(XMLDSigToken::class . '::' . $name) === $uri)
                {
                    return $name;
                }
            }
        }

        return null;
    }
}
