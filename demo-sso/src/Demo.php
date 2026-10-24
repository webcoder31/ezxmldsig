<?php

namespace webcoder31\ezxmldsig\DemoSso;

/**
 * Routes a request to the site its Host header names, and serves what the
 * three sites share: the trace of the flow and its reset, and the home page
 * of the demo (plain localhost).
 */
final class Demo
{
    /** @var string */
    private $varDir;

    /** @var Settings|null */
    private $settings;

    /** @var string|null */
    private $publicDomain;

    /**
     * @param string $varDir Where the sessions, the trace, the replay
     *     memories and the settings are kept (demo-sso/var/).
     * @param Settings|null $settings The protections in force, NULL to read
     *     them from $varDir/settings.json (see Settings).
     * @param string|null $publicDomain The domain of the demo online, whose
     *     subdomains are its sites (see Sites::parseHost()), or NULL.
     */
    public function __construct($varDir, Settings $settings = null, $publicDomain = null)
    {
        $this->varDir = $varDir;
        $this->settings = $settings;
        $this->publicDomain = $publicDomain;
    }

    /**
     * Returns the directory of the sessions, the trace and the settings.
     *
     * @return string
     */
    public function varDir()
    {
        return $this->varDir;
    }

    /**
     * Returns the protections in force.
     *
     * @return Settings
     */
    public function settings()
    {
        return is_null($this->settings) ? Settings::load($this->varDir . '/settings.json') : $this->settings;
    }

    /**
     * Returns the colour theme the visitor chose on one of the sites, kept
     * in $varDir/theme.json: the browser could not share it between the
     * host names of the demo (a cookie set on localhost is refused).
     *
     * @return string One of Html::THEMES, 'auto' by default.
     */
    public function theme()
    {
        $path = $this->varDir . '/theme.json';
        $theme = is_file($path) ? json_decode((string) file_get_contents($path), true) : null;

        return in_array($theme, Html::THEMES, true) ? $theme : 'auto';
    }

    /**
     * Handles a request.
     *
     * @param array $request See Http::request().
     *
     * @return array A response (see Http), with 'site' => the site that
     *     answered (NULL when the host is refused).
     */
    public function handle(array $request)
    {
        $parsed = Sites::parseHost($request['host'], $this->publicDomain);
        if (is_null($parsed))
        {
            return Http::text('The SSO demo only answers on its own host names: localhost, idp.localhost, mail.localhost and crm.localhost on this machine.', 421) + ['site' => null];
        }
        $site = $parsed['site'];
        $base = $parsed['base'];
        // The colour theme the visitor chose, the same on every site.
        $request['theme'] = $this->theme();
        $trace = new Trace($this->varDir . '/trace.json');
        $sessions = new SessionStore($this->varDir . '/sessions');
        $route = $request['method'] . ' ' . $request['path'];

        if ('GET /trace.json' === $route)
        {
            return Http::json(['events' => $trace->all()]) + ['site' => $site];
        }
        // A request that changes the state of the demo must come from one of
        // its own pages.
        $isOwnPage = !is_null($request['origin']) && Sites::origin($site, $base) === $request['origin'];

        if ('GET /lab.json' === $route)
        {
            return Http::json(['attacks' => AttackLab::catalog(), 'settings' => $this->settings()->all()]) + ['site' => $site];
        }
        if ('POST /lab/run' === $route)
        {
            if (!$isOwnPage)
            {
                return Http::text('Cross-origin request refused.', 403) + ['site' => $site];
            }
            try
            {
                $result = (new AttackLab($this->varDir, $base))->run(
                    isset($request['post']['id']) ? $request['post']['id'] : null,
                    !isset($request['post']['protected']) || 'false' !== $request['post']['protected']
                );
            }
            catch (\InvalidArgumentException $e)
            {
                return Http::json(['error' => $e->getMessage()], 400) + ['site' => $site];
            }

            return Http::json($result) + ['site' => $site];
        }
        if ('POST /settings' === $route)
        {
            if (!$isOwnPage)
            {
                return Http::text('Cross-origin request refused.', 403) + ['site' => $site];
            }
            $values = [];
            foreach (array_keys(Settings::DEFAULTS) as $name)
            {
                if (isset($request['post'][$name]))
                {
                    $values[$name] = 'true' === $request['post'][$name];
                }
            }
            $before = $this->settings();
            $settings = new Settings($values + $before->all());
            $settings->save($this->varDir . '/settings.json');
            $changes = self::describeChanges($before, $settings);
            if ('' !== $changes)
            {
                $trace->add([
                    'from' => 'browser', 'to' => 'browser', 'kind' => 'info',
                    'title' => $changes,
                ]);
            }

            return Http::json(['settings' => $settings->all()]) + ['site' => $site];
        }
        if ('POST /theme' === $route)
        {
            if (!$isOwnPage)
            {
                return Http::text('Cross-origin request refused.', 403) + ['site' => $site];
            }
            $theme = isset($request['post']['theme']) ? $request['post']['theme'] : null;
            if (!in_array($theme, Html::THEMES, true))
            {
                return Http::json(['error' => 'Unknown theme.'], 400) + ['site' => $site];
            }
            if (!is_dir($this->varDir))
            {
                mkdir($this->varDir, 0700, true);
            }
            file_put_contents($this->varDir . '/theme.json', json_encode($theme), LOCK_EX);

            return Http::json(['theme' => $theme]) + ['site' => $site];
        }
        if ('POST /trace/reset' === $route)
        {
            // Only a page of the demo may reset it.
            if (!$isOwnPage)
            {
                return Http::text('Cross-origin request refused.', 403) + ['site' => $site];
            }
            $trace->clear();
            $sessions->clear();
            foreach (glob($this->varDir . '/replay-*.json') ?: [] as $file)
            {
                unlink($file);
            }

            return Http::json(['events' => []]) + ['site' => $site];
        }

        if (Sites::HOME === $site)
        {
            return ('GET /' === $route ? $this->home($request, $base) : Http::text('Not found.', 404)) + ['site' => $site];
        }
        if (Sites::IDP === $site)
        {
            return (new IdentityProvider($sessions, $trace, $base, $this->settings()))->handle($request) + ['site' => $site];
        }

        return (new Application($site, $sessions, $trace, $base, $this->varDir, $this->settings()))->handle($request) + ['site' => $site];
    }

    /**
     * The illustration of the home page: the user opens MAIL, which has no
     * session and asks IDP; IDP does not know them yet, so they log in on
     * IDP, which signs a token for MAIL, and carry it to MAIL, which accepts
     * it and opens its session. They open CRM, which asks IDP; IDP knows
     * them now, asks for no password, and returns a token for CRM, which CRM
     * accepts. Animated by the .sso-art rules of sso.css.
     */
    const HERO_ART = '<svg class="sso-art" viewBox="0 0 360 210" focusable="false">'
        . '<path class="sa-link" d="M180 56L56 140M180 56L304 140"/>'
        . '<g class="sa-site sa-idp"><rect x="140" y="12" width="80" height="44" rx="9"/><text x="180" y="38">IDP</text></g>'
        . '<g class="sa-site sa-mail"><rect x="16" y="140" width="80" height="44" rx="9"/><text x="56" y="166">MAIL</text></g>'
        . '<g class="sa-site sa-crm"><rect x="264" y="140" width="80" height="44" rx="9"/><text x="304" y="166">CRM</text></g>'
        . '<g class="sa-session sa-idp-session"><rect x="82" y="26" width="50" height="16" rx="8"/><text x="107" y="37">session</text></g>'
        . '<g class="sa-session sa-mail-session"><rect x="31" y="190" width="50" height="16" rx="8"/><text x="56" y="201">session</text></g>'
        . '<g class="sa-session sa-crm-session"><rect x="279" y="190" width="50" height="16" rx="8"/><text x="304" y="201">session</text></g>'
        . '<g class="sa-panel sa-login"><rect x="230" y="14" width="112" height="40" rx="7"/><text class="sa-caption" x="240" y="29">password</text><rect class="sa-field" x="240" y="34" width="92" height="14" rx="3"/><circle class="sa-d1" cx="250" cy="41" r="2.4"/><circle class="sa-d2" cx="259" cy="41" r="2.4"/><circle class="sa-d3" cx="268" cy="41" r="2.4"/><circle class="sa-d4" cx="277" cy="41" r="2.4"/><circle class="sa-d5" cx="286" cy="41" r="2.4"/></g>'
        . '<g class="sa-panel sa-sso"><rect x="230" y="14" width="112" height="40" rx="7"/><text x="286" y="30">already logged in</text><text class="sa-caption" x="286" y="44">no password asked</text></g>'
        . '<g class="sa-badge sa-ask sa-mail-ask"><circle cx="92" cy="140" r="9"/><text x="92" y="144">?</text></g>'
        . '<g class="sa-badge sa-ask sa-crm-ask"><circle cx="340" cy="140" r="9"/><text x="340" y="144">?</text></g>'
        . '<g class="sa-badge sa-ok sa-mail-ok"><circle cx="92" cy="140" r="9"/><path d="M88 140l3 3 6-6"/></g>'
        . '<g class="sa-badge sa-ok sa-crm-ok"><circle cx="340" cy="140" r="9"/><path d="M336 140l3 3 6-6"/></g>'
        . '<g class="sa-user"><circle cx="0" cy="-7" r="5"/><path d="M-8 7a8 7 0 0 1 16 0z"/></g>'
        . '<g class="sa-token sa-tok-mail"><rect x="-17" y="-9" width="34" height="18" rx="4"/><text x="-4" y="3">MAIL</text><circle cx="11" cy="0" r="3"/></g>'
        . '<g class="sa-request sa-req-mail"><rect x="-11" y="-9" width="22" height="18" rx="4"/><text x="0" y="4">?</text></g>'
        . '<g class="sa-request sa-reply"><rect x="-11" y="-9" width="22" height="18" rx="4"/><text x="0" y="4">x</text></g>'
        . '<g class="sa-request sa-req-crm"><rect x="-11" y="-9" width="22" height="18" rx="4"/><text x="0" y="4">?</text></g>'
        . '<g class="sa-token sa-tok-crm"><rect x="-17" y="-9" width="34" height="18" rx="4"/><text x="-4" y="3">CRM</text><circle cx="11" cy="0" r="3"/></g>'
        . '</svg>';

    /** The library, and its Node.js version, linked from the home page. */
    const PHP_PACKAGE = 'https://packagist.org/packages/webcoder31/ezxmldsig';
    const NODE_PACKAGE = 'https://www.npmjs.com/package/@webcoder31/ezxmldsig';

    /** What the trace calls each setting. */
    const SETTING_LABELS = [
        'audience' => 'Protection "audience"',
        'returnUrl' => 'Protection "return address"',
        'freshness' => 'Protection "freshness"',
        'replay' => 'Protection "replay"',
        'encrypt' => 'Encryption of the tokens',
    ];

    /**
     * Describes in one sentence the settings that changed, in the order of
     * Settings::DEFAULTS, or '' if none did.
     */
    private static function describeChanges(Settings $before, Settings $after)
    {
        $parts = [];
        foreach (array_keys(Settings::DEFAULTS) as $name)
        {
            if ($before->on($name) !== $after->on($name))
            {
                $parts[] = self::SETTING_LABELS[$name] . ' turned ' . ($after->on($name) ? 'on' : 'off');
            }
        }

        return empty($parts) ? '' : implode(', ', $parts) . '.';
    }

    /**
     * The home page: what the demo shows, and where to start.
     */
    private function home(array $request, Base $base)
    {
        $content = '<section class="hero sso-hero" aria-labelledby="hero-title">
  <div class="sso-hero-head">
    <div>
      <p class="eyebrow">Single sign-on · signed XML tokens · ezxmldsig</p>
      <h1 id="hero-title">Log in once.<br><span class="hero-accent">Watch every hop.</span></h1>
    </div>
    <div class="hero-art" aria-hidden="true">' . self::HERO_ART . '</div>
  </div>
  <p class="hero-lead">Three sites on three host names: <strong>IDP</strong>, the identity provider, which alone knows the passwords, and two applications, <strong>MAIL</strong> and <strong>CRM</strong>, which trust the tokens IDP signs with <a href="' . Html::e(self::PHP_PACKAGE) . '"><strong>ezxmldsig</strong></a>. The trace on the right shows each hop, each token and each check. Here the three sites run PHP; any of them could run Node.js instead, with the npm package <a href="' . Html::e(self::NODE_PACKAGE) . '"><strong>@webcoder31/ezxmldsig</strong></a>, which creates and verifies the same tokens.</p>
  <ol class="sso-steps">
    <li>Open <a href="' . Html::e(Sites::origin('mail', $base) . '/') . '">' . Html::e($base->host('mail')) . '</a>: it has no session, so it sends you to IDP.</li>
    <li>Log in on IDP. IDP signs a token for MAIL, and your browser posts it to MAIL.</li>
    <li>MAIL verifies the token and opens its own session.</li>
    <li>Open <a href="' . Html::e(Sites::origin('crm', $base) . '/') . '">' . Html::e($base->host('crm')) . '</a>: IDP recognizes you and signs a token for CRM, without asking for your password again. That is single sign-on.</li>
    <li>Rights: log out of IDP, then log in as another user. IDP signs no token for CRM to <code>bjorn</code>, who may only enter MAIL: IDP decides who enters which application. In CRM, <code>lagertha</code>, a Shieldmaiden, may read the customers but not delete them: CRM decides, from the role IDP wrote in the token.</li>
  </ol>
  <p class="actions"><a class="btn btn-primary" href="' . Html::e(Sites::origin('mail', $base) . '/') . '">Start with ' . Html::e($base->host('mail')) . '</a></p>
  <p class="notice" role="note"><span>For a single sign-on in production, prefer a standard, OpenID Connect or SAML, with a maintained library: this demo shows the mechanisms, and what a receiver must check. The keys of <code>demo/certs/</code> and <code>demo-sso/certs/</code> it uses are public: never trust them outside this demo.</span></p>
</section>

<section class="panel" id="protections" aria-labelledby="protections-title">
  <header class="panel-head"><span class="panel-num">01</span><div><h2 id="protections-title">Protections of the live demo</h2><p class="panel-sub">They apply to your own browsing of IDP, MAIL and CRM. Each one is code of IDP or of the applications, never of the library.</p></div></header>
  <form class="panel-body protection-list" id="protection-form" novalidate></form>
</section>

<section class="panel" id="lab" aria-labelledby="lab-title">
  <header class="panel-head"><span class="panel-num">02</span><div><h2 id="lab-title">Attack lab</h2><p class="panel-sub">Each attack runs in a sandbox of its own, with a victim and an attacker, through the very code of the three sites. Your own sessions are not touched.</p></div>
    <div class="panel-tools"><button type="button" class="btn btn-ghost btn-sm" id="run-all">Run all</button></div></header>
  <div class="panel-body lab-cards" id="lab-cards"></div>
</section>';

        return Http::html(Html::page(Sites::HOME, $base, 'Single sign-on demo', $content, $request, ['/lab.js']));
    }
}
