<?php

namespace webcoder31\ezxmldsig\DemoSso;

/**
 * The protections of the SSO demo, which the home page lets turn off to see
 * what each one stops (demo-sso/var/settings.json).
 *
 * Each protection belongs to the code of idp or of the applications, never
 * to the library:
 *
 * - audience: idp addresses each token to its application (option
 *   "audience"), and each application expects its own name (option
 *   "expectedAudience"). Off, as with version 1.0, a token issued for one
 *   application is accepted by the other.
 * - returnUrl: idp only posts a token to the address registered for the
 *   application. Off, it posts it wherever the request says.
 * - freshness: each application refuses a token that is out of date
 *   (isOutOfDate()).
 * - replay: each application refuses a token whose identifier it has
 *   already accepted (getTokenId()).
 *
 * And one option: encrypt, idp encrypts each token for its application,
 * with the encryption certificate of that application (demo-sso/certs/).
 */
final class Settings
{
    /** The settings and their default values. */
    const DEFAULTS = [
        'audience' => true,
        'returnUrl' => true,
        'freshness' => true,
        'replay' => true,
        'encrypt' => false,
    ];

    /** @var array */
    private $values;

    /**
     * @param array $values Setting => boolean; the missing ones take their
     *     default value.
     *
     * @throws \InvalidArgumentException For an unknown or non-boolean
     *     setting.
     */
    public function __construct(array $values = [])
    {
        foreach ($values as $name => $value)
        {
            if (!array_key_exists($name, self::DEFAULTS) || !is_bool($value))
            {
                throw new \InvalidArgumentException('Invalid setting: ' . $name . '.');
            }
        }
        $this->values = $values + self::DEFAULTS;
    }

    /**
     * Reads the settings of a file, the default ones if it does not exist.
     *
     * @param string $path
     *
     * @return Settings
     */
    public static function load($path)
    {
        $values = is_file($path) ? json_decode((string) file_get_contents($path), true) : null;
        try
        {
            return new self(is_array($values) ? $values : []);
        }
        catch (\InvalidArgumentException $e)
        {
            return new self();
        }
    }

    /**
     * Writes the settings to a file.
     *
     * @param string $path
     */
    public function save($path)
    {
        if (!is_dir(dirname($path)))
        {
            mkdir(dirname($path), 0700, true);
        }
        file_put_contents($path, json_encode($this->values), LOCK_EX);
    }

    /**
     * @param string $name
     *
     * @return bool
     */
    public function on($name)
    {
        return $this->values[$name];
    }

    /**
     * @return array Setting => boolean.
     */
    public function all()
    {
        return $this->values;
    }

    /**
     * Returns the path of the encryption certificate or key of an
     * application.
     *
     * @param string $app
     * @param string $kind 'cert' or 'key'.
     *
     * @return string
     */
    public static function cryptFile($app, $kind)
    {
        return dirname(__DIR__) . '/certs/' . $app . '.crypt.' . $kind . '.pem';
    }
}
