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
 * ports, give each site cookies of its own.
 */
final class Sites
{
    /** The identity provider. */
    const IDP = 'idp';

    /** The home page of the demo (plain localhost). */
    const HOME = 'home';

    /** The applications: name => what the demo shows of them. */
    const APPS = [
        'mail' => ['title' => 'Mail', 'tagline' => 'Your messages'],
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
     * Only *.localhost host names are answered: another name that resolves
     * to this machine (DNS rebinding) is refused.
     *
     * @param string $host The Host header, e.g. "mail.localhost:8090".
     *
     * @return array|null ['site' => 'idp', 'mail', 'crm' or 'home',
     *     'port' => int|null]
     */
    public static function parseHost($host)
    {
        if (!is_string($host) || !preg_match('/\A(?:([a-z]+)\.)?localhost(?::(\d{1,5}))?\z/', $host, $matches))
        {
            return null;
        }
        $name = isset($matches[1]) && '' !== $matches[1] ? $matches[1] : self::HOME;
        if (self::HOME !== $name && self::IDP !== $name && !isset(self::APPS[$name]))
        {
            return null;
        }

        return ['site' => $name, 'port' => isset($matches[2]) ? (int) $matches[2] : null];
    }

    /**
     * Returns the origin of a site, e.g. "http://mail.localhost:8090".
     *
     * @param string $site
     * @param int|null $port
     *
     * @return string
     */
    public static function origin($site, $port)
    {
        $host = self::HOME === $site ? 'localhost' : $site . '.localhost';

        return 'http://' . $host . (is_null($port) ? '' : ':' . $port);
    }

    /**
     * Returns the address an application receives its tokens at (its
     * "assertion consumer service" in SAML words).
     *
     * @param string $app
     * @param int|null $port
     *
     * @return string
     */
    public static function acsUrl($app, $port)
    {
        return self::origin($app, $port) . '/acs';
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
