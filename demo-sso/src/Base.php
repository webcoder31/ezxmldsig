<?php

namespace webcoder31\ezxmldsig\DemoSso;

/**
 * Where the sites of the demo live: the scheme, the domain under which each
 * site has its host name, and the port.
 *
 * On this machine: http, localhost, the port of bin/demo-sso
 * (http://mail.localhost:8090). Online: https, the public domain, no port
 * (https://mail.sso.example.org), the home page on the domain itself.
 */
final class Base
{
    /** The domain of the demo on this machine. */
    const LOCAL_DOMAIN = 'localhost';

    /** @var string */
    private $scheme;

    /** @var string */
    private $domain;

    /** @var int|null */
    private $port;

    /**
     * @param string $scheme 'http' or 'https'.
     * @param string $domain e.g. 'localhost' or 'sso.example.org'.
     * @param int|null $port NULL for the default port of the scheme.
     */
    public function __construct($scheme, $domain, $port = null)
    {
        $this->scheme = $scheme;
        $this->domain = $domain;
        $this->port = $port;
    }

    /**
     * Returns the base of the demo on this machine.
     *
     * @param int|null $port
     *
     * @return self
     */
    public static function local($port = null)
    {
        return new self('http', self::LOCAL_DOMAIN, $port);
    }

    /**
     * Returns the base of the demo online, served over HTTPS.
     *
     * @param string $domain
     *
     * @return self
     */
    public static function online($domain)
    {
        return new self('https', $domain, null);
    }

    /**
     * Tells whether the demo is served online: its cookies are then Secure.
     *
     * @return bool
     */
    public function isOnline()
    {
        return self::LOCAL_DOMAIN !== $this->domain;
    }

    /**
     * Returns the domain, e.g. 'sso.example.org'.
     *
     * @return string
     */
    public function domain()
    {
        return $this->domain;
    }

    /**
     * Returns the host name of a site, e.g. 'mail.localhost'; the home page
     * is on the domain itself.
     *
     * @param string $site
     *
     * @return string
     */
    public function host($site)
    {
        return Sites::HOME === $site ? $this->domain : $site . '.' . $this->domain;
    }

    /**
     * Returns the origin of a site, e.g. 'http://mail.localhost:8090'.
     *
     * @param string $site A site, or any other name under the domain (the
     *     attack lab uses 'evil').
     *
     * @return string
     */
    public function origin($site)
    {
        return $this->scheme . '://' . $this->host($site) . (is_null($this->port) ? '' : ':' . $this->port);
    }
}
