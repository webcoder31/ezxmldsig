<?php

namespace webcoder31\ezxmldsig\Demo;

use webcoder31\ezxmldsig\XMLDSigToken;

/**
 * The sender of the demo: creates signed, possibly encrypted, tokens with
 * the signing key of demo/certs/.
 */
final class Issuer
{
    /** Maximum depth of the user data. */
    const MAX_DEPTH = 4;

    /** Maximum number of values of the user data. */
    const MAX_VALUES = 64;

    /** Maximum length of a value, in bytes. */
    const MAX_VALUE_LENGTH = 4096;

    /** The user data the demo starts with. */
    const DEFAULT_DATA = [
        'name' => 'Ragnar Lothbrok',
        'role' => 'Jarl',
        'location' => 'Kattegat',
        'permissions' => [
            'fleet' => 'command',
            'treasury' => 'read',
        ],
    ];

    /**
     * Creates a token.
     *
     * An encrypted token is created for the encryption certificate of the
     * receiver, without its private key, as a sender does (see the README,
     * section "Encryption").
     *
     * @param array $data User data (an associative array, possibly nested).
     * @param bool $encrypt Whether to encrypt the data.
     * @param array $algorithms Option => constant name (see Algorithms).
     *
     * @return XMLDSigToken
     *
     * @throws \InvalidArgumentException For invalid data or algorithms.
     */
    public static function create(array $data, $encrypt, array $algorithms = [])
    {
        self::checkData($data);
        $options = Algorithms::toOptions($algorithms, $encrypt);

        if ($encrypt)
        {
            return XMLDSigToken::createSecureXMLToken(
                $data,
                Certs::path('sign.key.pem'),
                Certs::path('sign.cert.pem'),
                null,
                Certs::path('crypt.cert.pem'),
                Certs::SIGN_KEY_PASSWORD,
                null,
                $options
            );
        }

        return XMLDSigToken::createXMLToken(
            $data,
            Certs::path('sign.key.pem'),
            Certs::path('sign.cert.pem'),
            Certs::SIGN_KEY_PASSWORD,
            $options
        );
    }

    /**
     * Checks that user data can be written as the elements of a token: each
     * key is an XML name, each value a string or a non-empty array, within
     * the limits of the demo.
     *
     * @param array $data
     *
     * @throws \InvalidArgumentException
     */
    public static function checkData(array $data)
    {
        $count = 0;
        $check = function (array $data, $depth) use (&$check, &$count) {
            if (empty($data))
            {
                throw new \InvalidArgumentException('A group of values must not be empty.');
            }
            if ($depth > self::MAX_DEPTH)
            {
                throw new \InvalidArgumentException('User data must not be nested more than ' . self::MAX_DEPTH . ' levels deep.');
            }
            foreach ($data as $key => $value)
            {
                // A name starting with "xml" is reserved by XML.
                if (!is_string($key) || !preg_match('/\A[A-Za-z_][A-Za-z0-9_.-]{0,63}\z/', $key) || 0 === stripos($key, 'xml'))
                {
                    throw new \InvalidArgumentException('Invalid key "' . $key . '": use letters, digits, "_", "-" and ".", starting with a letter or "_" (and not with "xml").');
                }
                if (is_array($value))
                {
                    $check($value, $depth + 1);
                    continue;
                }
                // An empty value would be written as an empty element, which
                // the analysis does not read back.
                if (!is_string($value) || '' === $value || strlen($value) > self::MAX_VALUE_LENGTH || !preg_match('//u', $value))
                {
                    throw new \InvalidArgumentException('The value of "' . $key . '" must be a non-empty UTF-8 string of at most ' . self::MAX_VALUE_LENGTH . ' bytes.');
                }
                if (++$count > self::MAX_VALUES)
                {
                    throw new \InvalidArgumentException('User data must hold at most ' . self::MAX_VALUES . ' values.');
                }
            }
        };
        $check($data, 1);
    }

    /**
     * Returns the PHP code that creates a token as create() does, as an
     * application would write it with the library installed by Composer.
     *
     * @param array $data
     * @param bool $encrypt
     * @param array $algorithms
     *
     * @return string
     */
    public static function phpCode(array $data, $encrypt, array $algorithms = [])
    {
        $options = [];
        foreach (Algorithms::toOptions($algorithms, $encrypt) as $option => $uri)
        {
            $options[] = "    '" . $option . "' => XMLDSigToken::" . Algorithms::nameOf($uri) . ",";
        }

        $lines = [
            '<?php',
            "require 'vendor/autoload.php';",
            '',
            'use webcoder31\ezxmldsig\XMLDSigToken;',
            '',
            '$data = ' . self::exportArray($data, '') . ';',
            '',
        ];
        if (!empty($options))
        {
            $lines[] = "\$options = [\n" . implode("\n", $options) . "\n];";
            $lines[] = '';
        }
        if ($encrypt)
        {
            $lines[] = "// Encrypted for the recipient's certificate. Its private key stays with";
            $lines[] = '// the recipient: null.';
            $lines[] = '$token = XMLDSigToken::createSecureXMLToken(';
            $lines[] = "    \$data, 'certs/sign.key.pem', 'certs/sign.cert.pem',";
            $lines[] = "    null, 'certs/crypt.cert.pem', 'signKeyPassword'" . (empty($options) ? '' : ', null, $options');
            $lines[] = ');';
        }
        else
        {
            $lines[] = "\$token = XMLDSigToken::createXMLToken(\$data, 'certs/sign.key.pem', 'certs/sign.cert.pem', 'signKeyPassword'"
                . (empty($options) ? '' : ', $options') . ');';
        }
        $lines[] = '';
        $lines[] = 'if (!is_null($token->getError())) {';
        $lines[] = '    throw new RuntimeException($token->getError());';
        $lines[] = '}';
        $lines[] = '$xml = $token->getXML();';

        return implode("\n", $lines) . "\n";
    }

    /**
     * Writes an array as a PHP short array literal.
     */
    private static function exportArray(array $array, $indent)
    {
        $lines = [];
        foreach ($array as $key => $value)
        {
            $lines[] = $indent . '    ' . var_export($key, true) . ' => '
                . (is_array($value) ? self::exportArray($value, $indent . '    ') : var_export($value, true)) . ',';
        }

        return "[\n" . implode("\n", $lines) . "\n" . $indent . ']';
    }
}
