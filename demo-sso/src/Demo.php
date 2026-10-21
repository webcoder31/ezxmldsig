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
  <p class="eyebrow">Single sign-on · signed XML tokens · ezxmldsig</p>
  <h1 id="hero-title">Log in once.<br><span class="hero-accent">Watch every hop.</span></h1>
  <p class="hero-lead">Three sites on three host names: <strong>idp</strong>, the identity provider, which alone knows the passwords, and two applications, <strong>mail</strong> and <strong>crm</strong>, which trust the tokens idp signs with ezxmldsig. The trace on the right shows each hop, each token and each check.</p>
  <ol class="sso-steps">
    <li>Open <a href="' . Html::e(Sites::origin('mail', $base) . '/') . '">' . Html::e($base->host('mail')) . '</a>: it has no session, so it sends you to idp.</li>
    <li>Log in on idp. idp signs a token for mail, and your browser posts it to mail.</li>
    <li>mail verifies the token and opens its own session.</li>
    <li>Open <a href="' . Html::e(Sites::origin('crm', $base) . '/') . '">' . Html::e($base->host('crm')) . '</a>: idp recognizes you and signs a token for crm, without asking for your password again. That is single sign-on.</li>
    <li>Rights: log out of idp, then log in as another user. idp signs no token for crm to <code>bjorn</code>, who may only enter mail: idp decides who enters which application. In crm, <code>lagertha</code>, a Shieldmaiden, may read the customers but not delete them: crm decides, from the role idp wrote in the token.</li>
  </ol>
  <p class="actions"><a class="btn btn-primary" href="' . Html::e(Sites::origin('mail', $base) . '/') . '">Start with ' . Html::e($base->host('mail')) . '</a></p>
  <p class="notice" role="note"><span>For a single sign-on in production, prefer a standard, OpenID Connect or SAML, with a maintained library: this demo shows the mechanisms, and what a receiver must check. The keys of <code>demo/certs/</code> and <code>demo-sso/certs/</code> it uses are public: never trust them outside this demo.</span></p>
</section>

<section class="panel" id="protections" aria-labelledby="protections-title">
  <header class="panel-head"><span class="panel-num">01</span><div><h2 id="protections-title">Protections of the live demo</h2><p class="panel-sub">They apply to your own browsing of idp, mail and crm. Each one is code of idp or of the applications, never of the library.</p></div></header>
  <form class="panel-body protection-list" id="protection-form" novalidate></form>
</section>

<section class="panel" id="lab" aria-labelledby="lab-title">
  <header class="panel-head"><span class="panel-num">02</span><div><h2 id="lab-title">Attack lab</h2><p class="panel-sub">Each attack runs in a sandbox of its own, with a victim and an attacker, through the very code of the three sites. Your own sessions are not touched.</p></div>
    <div class="panel-tools"><button type="button" class="btn btn-ghost btn-sm" id="run-all">Run all</button></div></header>
  <div class="panel-body lab-cards" id="lab-cards"></div>
</section>';

        return Http::html(Html::page(Sites::HOME, $base, 'Single sign-on demo', $content, $request['cookies'], ['/lab.js']));
    }
}
