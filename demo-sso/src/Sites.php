<?php

namespace webcoder31\ezxmldsig\DemoSso;

/**
 * The three sites of the SSO demo, each on its own host name, all served by
 * one PHP server on one port:
 *
 * - idp.localhost: the identity provider, the only site that knows the
 *   users and their passwords; it signs tokens;
 * - mail.localhost and crm.localhost: two applications without passwords,
 *   which trust the tokens of idp.
 *
 * Plain localhost serves the home page of the demo. Browsers send a cookie
 * to the host that set it, whatever the port: three host names, not three
 * ports, give each site cookies of its own. Online, the sites are the
 * subdomains of a public domain instead (see Base).
 */
final class Sites
{
    /** The identity provider. */
    const IDP = 'idp';

    /** The home page of the demo (plain localhost). */
    const HOME = 'home';

    /** The applications: name => what the demo shows of them. */
    const APPS = [
        'mail' => ['title' => 'MAIL', 'tagline' => 'Your messages'],
        'crm' => ['title' => 'CRM', 'tagline' => 'Your customers'],
    ];

    /**
     * The accounts of the identity provider (demo only). Two kinds of rights
     * come from them:
     *
     * - apps: the applications the user may enter. idp decides: it signs no
     *   token for another application. The token does not carry this list.
     * - role: an attribute idp writes in the token. Each application decides
     *   what it allows from it (see CRM_DELETE_ROLES).
     */
    const USERS = [
        'ragnar' => [
            'password' => 'kattegat',
            'name' => 'Ragnar Lothbrok',
            'role' => 'Jarl',
            'email' => 'ragnar@lothbrok.dk',
            'apps' => ['mail', 'crm'],
        ],
        'lagertha' => [
            'password' => 'shieldmaiden',
            'name' => 'Lagertha',
            'role' => 'Shieldmaiden',
            'email' => 'lagertha@lothbrok.dk',
            'apps' => ['mail', 'crm'],
        ],
        'bjorn' => [
            'password' => 'ironside',
            'name' => 'Björn Ironside',
            'role' => 'Warrior',
            'email' => 'bjorn@lothbrok.dk',
            'apps' => ['mail'],
        ],
    ];

    /** The customers crm shows. */
    const CRM_CUSTOMERS = [
        'c1' => ['name' => 'Earl Haraldson', 'place' => 'Kattegat'],
        'c2' => ['name' => 'King Ecbert', 'place' => 'Wessex'],
        'c3' => ['name' => 'Count Odo', 'place' => 'Paris'],
    ];

    /** The roles crm lets delete a customer: crm decides, from the role the
    token carries. */
    const CRM_DELETE_ROLES = ['Jarl'];

    /** How long a token is valid, in seconds (option "validity"). */
    const TOKEN_VALIDITY = 60;

    /** The time to live the applications accept, in seconds. */
    const APP_TTL = 60;

    /**
     * Returns the site a Host header names, or NULL if it is none of them.
     *
     * On this machine, only *.localhost host names are answered, whatever
     * the port. Online, $publicDomain and its subdomains are answered too,
     * without a port (a proxy serves them over HTTPS). Another name that
     * resolves to the server (DNS rebinding) is refused.
     *
     * @param string $host The Host header, e.g. "mail.localhost:8090".
     * @param string|null $publicDomain The domain of the demo online, e.g.
     *     "sso.example.org", or NULL.
     *
     * @return array|null ['site' => 'idp', 'mail', 'crm' or 'home',
     *     'base' => Base]
     */
    public static function parseHost($host, $publicDomain = null)
    {
        if (!is_string($host))
        {
            return null;
        }
        if (preg_match('/\A(?:([a-z]+)\.)?localhost(?::(\d{1,5}))?\z/', $host, $matches))
        {
            $base = Base::local(isset($matches[2]) ? (int) $matches[2] : null);
        }
        elseif (is_string($publicDomain) && '' !== $publicDomain
            && preg_match('/\A(?:([a-z]+)\.)?' . preg_quote($publicDomain, '/') . '\z/', $host, $matches))
        {
            $base = Base::online($publicDomain);
        }
        else
        {
            return null;
        }
        $name = isset($matches[1]) && '' !== $matches[1] ? $matches[1] : self::HOME;
        if (self::HOME !== $name && self::IDP !== $name && !isset(self::APPS[$name]))
        {
            return null;
        }

        return ['site' => $name, 'base' => $base];
    }

    /**
     * Returns the origin of a site, e.g. "http://mail.localhost:8090".
     *
     * @param string $site
     * @param Base $base
     *
     * @return string
     */
    public static function origin($site, Base $base)
    {
        return $base->origin($site);
    }

    /**
     * Returns the address an application receives its tokens at (its
     * "assertion consumer service" in SAML words).
     *
     * @param string $app
     * @param Base $base
     *
     * @return string
     */
    public static function acsUrl($app, Base $base)
    {
        return $base->origin($app) . '/acs';
    }

    /**
     * Returns the name of a site as the pages and the trace write it, in
     * capitals: IDP, MAIL, CRM. Host names, addresses, cookie names and the
     * values a token carries keep the lowercase identifier.
     *
     * @param string $site
     *
     * @return string
     */
    public static function name($site)
    {
        return strtoupper($site);
    }

    /**
     * Returns the name of the session cookie of a site.
     *
     * @param string $site
     *
     * @return string
     */
    public static function sessionCookie($site)
    {
        return $site . '_session';
    }
}
