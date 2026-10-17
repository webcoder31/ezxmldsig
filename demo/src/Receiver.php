<?php

namespace webcoder31\ezxmldsig\Demo;

use webcoder31\ezxmldsig\XMLDSigToken;

/**
 * The receiver of the demo: analyzes a token with the library, then makes
 * the two checks the library leaves to its caller, freshness and replay
 * (see the README, section "Checking an XML token").
 *
 * The result is presented as a pipeline of checks. The library makes its
 * checks in one call: the state of each step is read from what the token
 * object reports (`isDigestValueOk()`, `isSignatureValueOk()`,
 * `isCertTrusted()`, `isDataEncrypted()`, `getAnomalies()`, `getError()`).
 * A step the analysis did not reach is "skip".
 */
final class Receiver
{
    /** The single error of every decryption failure. */
    const DECRYPTION_FAILED = 'Token decryption failed!';

    /** The errors of the caller's checks, as the README writes them. */
    const OUT_OF_DATE = 'Token is out of date!';
    const ALREADY_USED = 'Token already used!';

    /** Bounds of the time to live, in seconds. */
    const MIN_TTL = 5;
    const MAX_TTL = 86400;

    /** @var array The configuration (see fromArray()). */
    private $config;

    /**
     * @param array $config See fromArray().
     */
    private function __construct(array $config)
    {
        $this->config = $config;
    }

    /**
     * Returns the default configuration: the trust anchor of the README
     * (intermediate CA, root and expected subject), the decryption key, a
     * time to live of 120 seconds, replay protection, and the default
     * algorithms of the library.
     *
     * @return array
     */
    public static function defaults()
    {
        $algorithms = [];
        foreach (Algorithms::CHOICES as $option => $names)
        {
            $algorithms[$option] = array_key_first($names);
        }

        return [
            'ca' => true,
            'pin' => false,
            'subject' => true,
            'subjectO' => Certs::EXPECTED_SUBJECT['O'],
            'subjectOU' => Certs::EXPECTED_SUBJECT['OU'],
            'decrypt' => true,
            'ttl' => 120,
            'replay' => true,
            'algorithms' => $algorithms,
        ];
    }

    /**
     * Builds a receiver from a configuration, the missing entries taken from
     * the defaults.
     *
     * @param array $config
     *     - ca (bool): trust the intermediate CA and its root (`caCertPath`);
     *     - pin (bool): pin the signing certificate (`signerCertPath`);
     *     - subject (bool), subjectO, subjectOU (string): expect these
     *       subject fields (`expectedSubject`);
     *     - decrypt (bool): give the decryption key
     *       (`analyzeSecureXMLToken()`);
     *     - ttl (int): time to live of `isOutOfDate()`, in seconds;
     *     - replay (bool): refuse a token identifier already accepted;
     *     - algorithms (array): expected algorithms, option => constant name.
     *
     * @return Receiver
     *
     * @throws \InvalidArgumentException For an invalid configuration.
     */
    public static function fromArray(array $config)
    {
        $defaults = self::defaults();
        $unknown = array_diff(array_keys($config), array_keys($defaults));
        if (!empty($unknown))
        {
            throw new \InvalidArgumentException('Unknown receiver setting: ' . implode(', ', $unknown) . '.');
        }
        $config += $defaults;
        foreach (['ca', 'pin', 'subject', 'decrypt', 'replay'] as $name)
        {
            if (!is_bool($config[$name]))
            {
                throw new \InvalidArgumentException('Receiver setting "' . $name . '" must be a boolean.');
            }
        }
        foreach (['subjectO', 'subjectOU'] as $name)
        {
            if (!is_string($config[$name]) || strlen($config[$name]) > 256 || !preg_match('//u', $config[$name]))
            {
                throw new \InvalidArgumentException('Receiver setting "' . $name . '" must be a string.');
            }
        }
        if (!is_int($config['ttl']) || $config['ttl'] < self::MIN_TTL || $config['ttl'] > self::MAX_TTL)
        {
            throw new \InvalidArgumentException('The time to live must be an integer from ' . self::MIN_TTL . ' to ' . self::MAX_TTL . ' seconds.');
        }
        if (!is_array($config['algorithms']))
        {
            throw new \InvalidArgumentException('Receiver setting "algorithms" must be an object.');
        }
        $config['algorithms'] += $defaults['algorithms'];
        // Checks the names.
        Algorithms::toOptions($config['algorithms'], true);

        return new self($config);
    }

    /**
     * Returns the configuration.
     *
     * @return array
     */
    public function config()
    {
        return $this->config;
    }

    /**
     * Returns the expected subject, as given to the option
     * `expectedSubject`, or NULL.
     *
     * @return array|null
     */
    private function expectedSubject()
    {
        if (!$this->config['subject'])
        {
            return null;
        }
        $subject = array_filter([
            'O' => $this->config['subjectO'],
            'OU' => $this->config['subjectOU'],
        ], 'strlen');

        return empty($subject) ? null : $subject;
    }

    /**
     * Returns the options of the analysis.
     *
     * @return array
     */
    public function options()
    {
        $options = [];
        if ($this->config['ca'])
        {
            $options['caCertPath'] = Certs::trustedCAs();
        }
        if ($this->config['pin'])
        {
            $options['signerCertPath'] = Certs::path('sign.cert.pem');
        }
        if (!is_null($this->expectedSubject()))
        {
            $options['expectedSubject'] = $this->expectedSubject();
        }

        return $options + Algorithms::toOptions($this->config['algorithms'], $this->config['decrypt']);
    }

    /**
     * Analyzes a token with the library.
     *
     * @param string $xml
     *
     * @return XMLDSigToken
     */
    public function analyze($xml)
    {
        if ($this->config['decrypt'])
        {
            return XMLDSigToken::analyzeSecureXMLToken($xml, Certs::path('crypt.key.pem'), Certs::CRYPT_KEY_PASSWORD, $this->options());
        }

        return XMLDSigToken::analyzeXMLToken($xml, $this->options());
    }

    /**
     * Analyzes a token and makes the checks of the caller.
     *
     * @param string $xml The token.
     * @param ReplayStore $store The identifiers already accepted.
     *
     * @return array
     *     - accepted (bool): every check passed, the data can be trusted;
     *     - signatureValid (bool): what `isSignatureValid()` returned;
     *     - error (string|null): what `getError()` returned;
     *     - anomalies (string[]): what `getAnomalies()` returned;
     *     - steps (array[]): the checks, each ['id', 'label', 'by'
     *       ('library' or 'caller'), 'status' ('pass', 'fail', 'skip' or
     *       'off'), 'detail', 'message' (the error that stopped the token,
     *       or NULL)];
     *     - token (array): what the token tells of itself;
     *     - data (array|null): the data, only when the token is accepted.
     */
    public function verify($xml, ReplayStore $store)
    {
        $token = $this->analyze($xml);
        $steps = $this->librarySteps($token, $xml);
        $signatureValid = $token->isSignatureValid();

        // Freshness, then replay: the caller's checks, made only on a token
        // the library accepted.
        $ttl = $this->config['ttl'];
        $age = is_null($token->getTimestamp()) ? null
            : time() - \DateTime::createFromFormat(XMLDSigToken::TOKEN_TIMESTAMP_FORMAT, $token->getTimestamp(), new \DateTimeZone('UTC'))->getTimestamp();
        $fresh = $signatureValid && !$token->isOutOfDate($ttl);
        $steps[] = self::step(
            'freshness',
            'Freshness',
            'caller',
            !$signatureValid ? 'skip' : ($fresh ? 'pass' : 'fail'),
            'isOutOfDate(' . $ttl . ') — ' . (!$signatureValid || is_null($age)
                ? 'checked once the library has accepted the token.'
                : self::describeAge($age, $ttl)),
            $signatureValid && !$fresh ? self::OUT_OF_DATE : null
        );

        $replayOk = true;
        if (!$this->config['replay'])
        {
            $steps[] = self::step('replay', 'Replay', 'caller', 'off',
                'Not checked: a captured token can be submitted again until it is out of date.', null);
        }
        elseif (!$fresh)
        {
            $steps[] = self::step('replay', 'Replay', 'caller', 'skip',
                'getTokenId() is stored only once every other check has passed.', null);
        }
        else
        {
            $retention = $ttl + XMLDSigToken::DESYNC_TOLERANCE;
            $stored = $store->add($token->getTokenId(), $retention);
            $replayOk = $stored['added'];
            $steps[] = self::step('replay', 'Replay', 'caller', $replayOk ? 'pass' : 'fail',
                $replayOk
                    ? 'getTokenId() ' . $token->getTokenId() . ' was not seen before: stored for ' . $retention . ' s (TTL + DESYNC_TOLERANCE).'
                    : 'getTokenId() ' . $token->getTokenId() . ' was accepted ' . self::describeSeconds(time() - $stored['storedAt']) . ' ago.',
                $replayOk ? null : self::ALREADY_USED);
        }

        $accepted = $signatureValid && $fresh && $replayOk;

        return [
            'accepted' => $accepted,
            'signatureValid' => $signatureValid,
            'error' => $token->getError(),
            'anomalies' => $token->getAnomalies(),
            'steps' => $steps,
            'token' => [
                'encrypted' => $token->isDataEncrypted(),
                'timestamp' => $token->getTimestamp(),
                'tokenId' => $token->getTokenId(),
                'certSubject' => $token->getCertDN(),
                'certIssuer' => self::formatName($token->getCertIssuer()),
                'certValidTo' => $token->getCertValidTo() ?: null,
            ],
            'data' => $accepted ? $token->getData() : null,
        ];
    }

    /**
     * Returns the steps the library made, read from the analyzed token.
     *
     * @param XMLDSigToken $token
     * @param string $xml The analyzed token.
     *
     * @return array[]
     */
    private function librarySteps(XMLDSigToken $token, $xml)
    {
        $error = $token->getError();
        $anomalies = $token->getAnomalies();
        $digest = $token->isDigestValueOk();
        $signature = $token->isSignatureValueOk();
        $trusted = $token->isCertTrusted();
        // isDataEncrypted() is only set once the certificate is trusted: before,
        // the document tells whether a decryption step is to come.
        $encrypted = $token->isDataEncrypted();
        if (is_null($encrypted))
        {
            $encrypted = false !== strpos($xml, 'EncryptedData');
        }

        $algorithmAnomalies = array_values(array_filter($anomalies, function ($anomaly) {
            return 0 === strpos($anomaly, 'Unauthorized ');
        }));
        $contentAnomalies = array_values(array_filter($anomalies, function ($anomaly) {
            return 1 === preg_match('/\AToken (timestamp|identifier|data) /', $anomaly);
        }));

        // The analysis stops at the first error (an exception); anomalies
        // are collected and reported together. Before the digest is computed,
        // an error is either about the algorithms or about the document.
        $earlyStop = null;
        if (is_null($digest) && !is_null($error))
        {
            $earlyStop = preg_match('/ algorithm is (missing|invalid)!\z/', $error) ? 'algorithms' : 'structure';
        }

        $steps = [];

        $steps[] = self::step('structure', 'Parsing & structure', 'library',
            'structure' === $earlyStop ? 'fail' : 'pass',
            'UTF-8, no DOCTYPE, ds:Signature as document element, a single Id="Token", the fixed elements of a token.',
            'structure' === $earlyStop ? $error : null);

        if ('structure' === $earlyStop)
        {
            $status = 'skip';
        }
        else
        {
            $status = ('algorithms' === $earlyStop || !empty($algorithmAnomalies)) ? 'fail' : 'pass';
        }
        $steps[] = self::step('algorithms', 'Algorithms', 'library', $status,
            'Signature, digest and canonicalization algorithms' . ($encrypted ? ', and encryption ones,' : '') . ' are the expected ones.',
            'algorithms' === $earlyStop ? $error : (empty($algorithmAnomalies) ? null : implode(' ', $algorithmAnomalies)));

        $reached = !is_null($digest);
        $steps[] = self::step('digest', 'Digest', 'library',
            !$reached ? 'skip' : ($digest ? 'pass' : 'fail'),
            'The hash of the canonicalized ds:Object matches ds:DigestValue.',
            $reached && !$digest ? 'Token hash verification failed!' : null);

        $reached = $reached && !is_null($signature);
        $steps[] = self::step('signature', 'Signature', 'library',
            !$reached ? (is_null($digest) ? 'skip' : 'fail') : ($signature ? 'pass' : 'fail'),
            'ds:SignatureValue verifies over ds:SignedInfo with the key of the certificate the token carries (OpenSSL result exactly 1).',
            !is_null($digest) && !$signature ? ($reached ? 'Token hash signature verification failed!' : $error) : null);

        $reached = $reached && $digest && $signature;
        $steps[] = self::step('trust', 'Certificate trust', 'library',
            !$reached || is_null($trusted) ? 'skip' : ($trusted ? 'pass' : 'fail'),
            $this->describeTrust(),
            $reached && false === $trusted ? $error : null);

        $reached = $reached && true === $trusted;
        if (true === $encrypted)
        {
            if (!$reached)
            {
                $status = 'skip';
            }
            elseif (!empty($algorithmAnomalies))
            {
                // A token whose algorithms are refused is not decrypted.
                $status = 'skip';
            }
            elseif (!is_null($error) && empty($contentAnomalies) && 'Malformed token!' !== $error)
            {
                $status = 'fail';
            }
            else
            {
                $status = 'pass';
            }
            $steps[] = self::step('decryption', 'Decryption', 'library', $status,
                'The session key (RSA-OAEP) and then the content are decrypted, only once the checks above have passed.',
                'fail' === $status ? $error : null);
            $reached = 'pass' === $status;
        }

        $contentFailed = !empty($contentAnomalies) || 'Malformed token!' === $error;
        $steps[] = self::step('content', 'Token content', 'library',
            !$reached ? 'skip' : ($contentFailed ? 'fail' : 'pass'),
            'TokenTimestamp, TokenId (32 hexadecimal characters) and TokenData are well formed.',
            $reached && $contentFailed ? ('Malformed token!' === $error ? $error : implode(' ', $contentAnomalies)) : null);

        return $steps;
    }

    /**
     * Describes the trust anchor of the analysis.
     *
     * @return string
     */
    private function describeTrust()
    {
        $parts = [];
        if ($this->config['ca'])
        {
            $parts[] = 'chain verified by OpenSSL up to the intermediate CA and its root (caCertPath)';
        }
        if ($this->config['pin'])
        {
            $parts[] = 'same certificate as the pinned one (signerCertPath)';
        }
        if (!is_null($this->expectedSubject()))
        {
            $parts[] = 'subject ' . self::formatName($this->expectedSubject()) . ' (expectedSubject)';
        }
        if (!$this->config['ca'] && !$this->config['pin'])
        {
            return 'No trust anchor: without caCertPath or signerCertPath, no certificate is trusted.';
        }

        return 'Valid now, allowed to sign, ' . implode(', ', $parts) . '.';
    }

    /**
     * Builds a step.
     */
    private static function step($id, $label, $by, $status, $detail, $message)
    {
        return [
            'id' => $id,
            'label' => $label,
            'by' => $by,
            'status' => $status,
            'detail' => $detail,
            'message' => $message,
        ];
    }

    /**
     * Describes the age of a token against its time to live.
     */
    private static function describeAge($age, $ttl)
    {
        if ($age < 0)
        {
            return 'issued ' . self::describeSeconds(-$age) . ' in the future (' . XMLDSigToken::DESYNC_TOLERANCE . ' s of clock drift allowed).';
        }

        return 'issued ' . self::describeSeconds($age) . ' ago, time to live ' . self::describeSeconds($ttl) . '.';
    }

    /**
     * Writes a duration in seconds, minutes or hours.
     */
    private static function describeSeconds($seconds)
    {
        if ($seconds < 120)
        {
            return $seconds . ' s';
        }
        if ($seconds < 7200)
        {
            return intdiv($seconds, 60) . ' min';
        }

        return intdiv($seconds, 3600) . ' h';
    }

    /**
     * Writes a name (subject or issuer fields) as "O=..., OU=...".
     *
     * @param array|null $name
     *
     * @return string|null
     */
    public static function formatName($name)
    {
        if (!is_array($name))
        {
            return null;
        }
        $parts = [];
        foreach ($name as $key => $value)
        {
            foreach ((array) $value as $item)
            {
                $parts[] = $key . '=' . $item;
            }
        }

        return implode(', ', $parts);
    }

    /**
     * Returns the PHP code of this receiver, as an application would write
     * it with the library installed by Composer.
     *
     * @return string
     */
    public function phpCode()
    {
        $options = [];
        if ($this->config['ca'])
        {
            $options[] = "    'caCertPath' => ['certs/intermediate.cert.pem', 'certs/root.cert.pem'],";
        }
        if ($this->config['pin'])
        {
            $options[] = "    'signerCertPath' => 'certs/sign.cert.pem',";
        }
        if (!is_null($this->expectedSubject()))
        {
            $fields = [];
            foreach ($this->expectedSubject() as $key => $value)
            {
                $fields[] = var_export($key, true) . ' => ' . var_export($value, true);
            }
            $options[] = "    'expectedSubject' => [" . implode(', ', $fields) . "],";
        }
        foreach (Algorithms::toOptions($this->config['algorithms'], $this->config['decrypt']) as $option => $uri)
        {
            $options[] = "    '" . $option . "' => XMLDSigToken::" . Algorithms::nameOf($uri) . ",";
        }

        $lines = [
            '<?php',
            "require 'vendor/autoload.php';",
            '',
            'use webcoder31\ezxmldsig\XMLDSigToken;',
            '',
        ];
        if (!$this->config['ca'] && !$this->config['pin'])
        {
            $lines[] = '// No trust anchor: isSignatureValid() returns FALSE for every token.';
        }
        $lines[] = empty($options) ? '$options = [];' : "\$options = [\n" . implode("\n", $options) . "\n];";
        $lines[] = '';
        if ($this->config['decrypt'])
        {
            $lines[] = "\$token = XMLDSigToken::analyzeSecureXMLToken(\$xml, 'certs/crypt.key.pem', 'cryptKeyPassword', \$options);";
        }
        else
        {
            $lines[] = '$token = XMLDSigToken::analyzeXMLToken($xml, $options);';
        }
        $lines[] = '';
        $lines[] = '// 1. Structure, algorithms, digest, signature, trust (and decryption).';
        $lines[] = 'if (!$token->isSignatureValid()) {';
        $lines[] = '    reject($token->getError());';
        $lines[] = '}';
        $lines[] = '';
        $lines[] = '// 2. Freshness: up to you.';
        $lines[] = 'if ($token->isOutOfDate(' . $this->config['ttl'] . ')) {';
        $lines[] = "    reject('" . self::OUT_OF_DATE . "');";
        $lines[] = '}';
        $lines[] = '';
        if ($this->config['replay'])
        {
            $lines[] = '// 3. Replay: up to you. Store the identifier atomically, for as long';
            $lines[] = '// as the token could be accepted.';
            $lines[] = "if (!apcu_add('xmltoken-' . \$token->getTokenId(), true, " . $this->config['ttl'] . ' + XMLDSigToken::DESYNC_TOLERANCE)) {';
            $lines[] = "    reject('" . self::ALREADY_USED . "');";
            $lines[] = '}';
        }
        else
        {
            $lines[] = '// 3. Replay: NOT checked. A captured token can be submitted again';
            $lines[] = '// until it is out of date.';
        }
        $lines[] = '';
        $lines[] = '$data = $token->getData();';

        return implode("\n", $lines) . "\n";
    }
}
