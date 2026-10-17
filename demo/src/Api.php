<?php

namespace webcoder31\ezxmldsig\Demo;

use webcoder31\ezxmldsig\XMLDSigToken;

/**
 * The JSON API of the demo.
 *
 * Every endpoint but GET /api/config takes a POST request whose body is a
 * JSON object, and every response is a JSON object, an error being
 * {"error": "..."}. The JSON is written with `<`, `>`, `&`, `'` and `"`
 * escaped as \u sequences, so that a value of a token never reads as markup,
 * whatever reads the response.
 */
final class Api
{
    /** Maximum size of a request body, in bytes. */
    const MAX_BODY = 262144;

    /** Options of json_encode(). */
    const JSON_FLAGS = JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
        | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE;

    /** @var ReplayStore */
    private $replayStore;

    /**
     * @param ReplayStore $replayStore The memory of the receiver.
     */
    public function __construct(ReplayStore $replayStore)
    {
        $this->replayStore = $replayStore;
    }

    /**
     * Handles a request.
     *
     * @param string $method HTTP method.
     * @param string $path Path of the request, e.g. "/api/issue".
     * @param string $body Body of the request.
     *
     * @return array [HTTP status, response object]
     */
    public function handle($method, $path, $body)
    {
        try
        {
            $routes = [
                'GET /api/config' => 'config',
                'POST /api/issue' => 'issue',
                'POST /api/issuer-code' => 'issuerCode',
                'POST /api/verify' => 'verify',
                'POST /api/receiver-code' => 'receiverCode',
                'POST /api/replay/clear' => 'clearReplay',
                'POST /api/attack' => 'attack',
            ];
            $route = $method . ' ' . $path;
            if (!isset($routes[$route]))
            {
                return [404, ['error' => 'Unknown endpoint.']];
            }
            $input = 'POST' === $method ? self::decode($body) : [];

            return [200, $this->{$routes[$route]}($input)];
        }
        catch (\InvalidArgumentException $e)
        {
            return [400, ['error' => $e->getMessage()]];
        }
    }

    /**
     * Encodes a response.
     *
     * @param array $response
     *
     * @return string
     */
    public static function encode(array $response)
    {
        return json_encode($response, self::JSON_FLAGS);
    }

    /**
     * Decodes the body of a request.
     */
    private static function decode($body)
    {
        if (!is_string($body) || strlen($body) > self::MAX_BODY)
        {
            throw new \InvalidArgumentException('The request is too large.');
        }
        $input = json_decode($body, true);
        if (!is_array($input))
        {
            throw new \InvalidArgumentException('The request must be a JSON object.');
        }

        return $input;
    }

    /**
     * Returns an entry of the request, checked against a type.
     */
    private static function field(array $input, $name, $type, $default = null)
    {
        if (!array_key_exists($name, $input) || is_null($input[$name]))
        {
            return $default;
        }
        $value = $input[$name];
        $valid = [
            'array' => is_array($value),
            'bool' => is_bool($value),
            'string' => is_string($value),
        ][$type];
        if (!$valid)
        {
            throw new \InvalidArgumentException('Invalid request field "' . $name . '".');
        }

        return $value;
    }

    /**
     * Returns the receiver a request configures.
     */
    private static function receiver(array $input)
    {
        return Receiver::fromArray(self::field($input, 'receiver', 'array', []));
    }

    /**
     * GET /api/config: what the interface needs to start.
     */
    private function config()
    {
        $signCert = openssl_x509_parse(file_get_contents(Certs::path('sign.cert.pem')));
        // The version of the library, as its source file declares it.
        $source = file_get_contents((new \ReflectionClass(XMLDSigToken::class))->getFileName());
        $version = preg_match('/@version\s+(\S+)/', $source, $matches) ? $matches[1] : null;

        return [
            'version' => $version,
            'algorithms' => Algorithms::CHOICES,
            'uris' => Algorithms::uris(),
            'data' => Issuer::DEFAULT_DATA,
            'receiver' => Receiver::defaults(),
            'ttlBounds' => [Receiver::MIN_TTL, Receiver::MAX_TTL],
            'desyncTolerance' => XMLDSigToken::DESYNC_TOLERANCE,
            'attacks' => AttackLab::catalog(),
            'signer' => [
                'subject' => Receiver::formatName($signCert['subject']),
                'issuer' => Receiver::formatName($signCert['issuer']),
                'validTo' => gmdate('Y-m-d', $signCert['validTo_time_t']),
            ],
            'replayMemory' => $this->replayStore->size(),
        ];
    }

    /**
     * POST /api/issue {data, encrypt, algorithms}: creates a token.
     */
    private function issue(array $input)
    {
        $data = self::field($input, 'data', 'array', Issuer::DEFAULT_DATA);
        $encrypt = self::field($input, 'encrypt', 'bool', false);
        $algorithms = self::field($input, 'algorithms', 'array', []);

        $token = Issuer::create($data, $encrypt, $algorithms);

        return [
            'xml' => $token->getXML(),
            'error' => $token->getError(),
            'encrypted' => $encrypt,
            'code' => Issuer::phpCode($data, $encrypt, $algorithms),
        ];
    }

    /**
     * POST /api/issuer-code {data, encrypt, algorithms}: the PHP code of the
     * issuer.
     */
    private function issuerCode(array $input)
    {
        $data = self::field($input, 'data', 'array', Issuer::DEFAULT_DATA);
        Issuer::checkData($data);

        return ['code' => Issuer::phpCode(
            $data,
            self::field($input, 'encrypt', 'bool', false),
            self::field($input, 'algorithms', 'array', [])
        )];
    }

    /**
     * POST /api/verify {xml, receiver}: analyzes a token.
     */
    private function verify(array $input)
    {
        $xml = self::field($input, 'xml', 'string', '');
        $receiver = self::receiver($input);

        return $receiver->verify($xml, $this->replayStore) + [
            'code' => $receiver->phpCode(),
            'replayMemory' => $this->replayStore->size(),
        ];
    }

    /**
     * POST /api/receiver-code {receiver}: the PHP code of a receiver.
     */
    private function receiverCode(array $input)
    {
        return ['code' => self::receiver($input)->phpCode()];
    }

    /**
     * POST /api/replay/clear: forgets the identifiers accepted.
     */
    private function clearReplay()
    {
        $this->replayStore->clear();

        return ['replayMemory' => 0];
    }

    /**
     * POST /api/attack {id, lastXml, data, algorithms, receiver}: runs an
     * attack of the lab.
     */
    private function attack(array $input)
    {
        $data = self::field($input, 'data', 'array', Issuer::DEFAULT_DATA);
        Issuer::checkData($data);
        $lab = new AttackLab(
            self::receiver($input),
            $data,
            self::field($input, 'algorithms', 'array', [])
        );

        return $lab->run(self::field($input, 'id', 'string', ''), self::field($input, 'lastXml', 'string'));
    }
}
