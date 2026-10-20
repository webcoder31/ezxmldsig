<?php

namespace webcoder31\ezxmldsig\DemoSso;

/**
 * The pages of the three sites: a common layout (top bar, the trace of the
 * flow, the cookies of the site) around the content of each page.
 *
 * Every value written in a page goes through e().
 */
final class Html
{
    /** What the top bar shows of each site. */
    const IDENTITY = [
        'idp' => ['label' => 'Identity provider', 'mark' => 'IdP'],
        'mail' => ['label' => 'Application', 'mark' => 'Mail'],
        'crm' => ['label' => 'Application', 'mark' => 'CRM'],
        'home' => ['label' => 'SSO demo', 'mark' => 'SSO'],
    ];

    /** The banner of each site: its icon (inline SVG, drawn in the colour
    of the site), and what it is. */
    const BANNER = [
        'idp' => [
            'icon' => '<path d="M12 3l7 2.7v5.6c0 4.5-3 7.9-7 9.2-4-1.3-7-4.7-7-9.2V5.7z"/><circle cx="12" cy="10.5" r="2.2"/><path d="M12 12.7v3.3"/>',
            'role' => 'Identity provider: knows the users and their passwords, signs the tokens.',
        ],
        'mail' => [
            'icon' => '<rect x="3.5" y="5.5" width="17" height="13" rx="2"/><path d="M4 7l8 6 8-6"/>',
            'role' => 'Application: no password of its own, trusts the tokens of idp.',
        ],
        'crm' => [
            'icon' => '<circle cx="9" cy="9" r="3"/><path d="M3.5 19a5.5 5.5 0 0 1 11 0"/><circle cx="17" cy="9.5" r="2.4"/><path d="M15.5 14.2a4.6 4.6 0 0 1 5 4.8"/>',
            'role' => 'Application: no password of its own, trusts the tokens of idp.',
        ],
    ];

    /**
     * Escapes a value for HTML text or a quoted attribute.
     *
     * @param mixed $value
     *
     * @return string
     */
    public static function e($value)
    {
        return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    /**
     * Returns a whole page.
     *
     * @param string $site The site that serves it.
     * @param int|null $port
     * @param string $title
     * @param string $content The HTML of the page content.
     * @param array $cookies The cookies the browser sent to this site.
     * @param array $scripts Extra scripts of this server, e.g. ['/post.js'].
     *
     * @return string
     */
    public static function page($site, $port, $title, $content, array $cookies, array $scripts = [])
    {
        $identity = self::IDENTITY[$site];
        $nav = '<a href="' . self::e(Sites::origin(Sites::HOME, $port) . '/') . '"' . (Sites::HOME === $site ? ' aria-current="page"' : '') . ' data-site="home" class="home-link">'
            . '<svg class="home-icon" viewBox="0 0 16 16" aria-hidden="true" focusable="false"><path d="M2.5 7.5L8 3l5.5 4.5M4 6.5V13h3V9.5h2V13h3V6.5"/></svg>Home</a>';
        foreach (array_merge([Sites::IDP], array_keys(Sites::APPS)) as $other)
        {
            $nav .= '<a href="' . self::e(Sites::origin($other, $port) . '/') . '"' . ($other === $site ? ' aria-current="page"' : '') . ' data-site="' . self::e($other) . '">'
                . '<span class="site-dot" aria-hidden="true"></span>' . self::e($other . '.localhost') . '</a>';
        }
        $scriptTags = '';
        foreach (array_merge(['/sso.js'], $scripts) as $src)
        {
            $scriptTags .= '<script src="' . self::e($src) . '" defer></script>';
        }

        return '<!doctype html>
<html lang="en" data-site="' . self::e($site) . '" data-home="' . self::e(Sites::origin(Sites::HOME, $port) . '/') . '">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>' . self::e($title) . ' · ' . self::e(Sites::HOME === $site ? 'SSO demo' : $site . '.localhost') . '</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/app.css">
<link rel="stylesheet" href="/sso.css">
' . $scriptTags . '
</head>
<body>
<a class="skip-link" href="#main">Skip to content</a>
<header class="topbar">
  <div class="topbar-inner">
    <a class="brand site-brand" href="' . self::e(Sites::origin(Sites::HOME, $port) . '/') . '">
      <span class="site-mark">' . self::e($identity['mark']) . '</span>
      <span class="brand-name">' . self::e(Sites::HOME === $site ? 'ezxmldsig' : $site . '.localhost') . '</span>
      <span class="brand-sep" aria-hidden="true">/</span>
      <span class="brand-tag">' . self::e($identity['label']) . '</span>
    </a>
    <nav class="topnav site-nav" aria-label="Sites of the demo">' . $nav . '</nav>
  </div>
</header>
<main id="main" tabindex="-1" class="sso-layout">
  <div class="sso-page">
' . (Sites::HOME === $site ? '' : self::banner($site)) . $content . '
' . (Sites::HOME === $site ? '' : self::cookiePanel($site, $cookies)) . '
  </div>
  <aside class="panel trace-panel" aria-labelledby="trace-title">
    <header class="panel-head">
      <div>
        <h2 id="trace-title">What happened</h2>
        <p class="panel-sub">The trace of the flow, shared by the three sites.</p>
      </div>
      <div class="panel-tools">
        <button type="button" class="btn btn-ghost btn-xs" id="trace-reset">Reset the demo</button>
      </div>
    </header>
    <div class="trace-lanes" aria-hidden="true"><span>Browser</span><span>idp</span><span>mail</span><span>crm</span></div>
    <ol class="trace-list" id="trace-list" aria-live="polite"></ol>
  </aside>
</main>
</body>
</html>
';
    }

    /**
     * Returns the banner of a site: its icon and its name, in the colour
     * that stands for it in the trace, and what it is.
     */
    private static function banner($site)
    {
        return '<div class="site-banner">
  <svg class="site-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">' . self::BANNER[$site]['icon'] . '</svg>
  <div><p class="site-title">' . self::e($site . '.localhost') . '</p><p class="site-role">' . self::e(self::BANNER[$site]['role']) . '</p></div>
</div>
';
    }

    /**
     * Returns the panel that lists the cookies the browser sent to a site.
     *
     * Session cookies are HttpOnly: no script can read them, so the server
     * lists them, as it receives them.
     */
    private static function cookiePanel($site, array $cookies)
    {
        $name = Sites::sessionCookie($site);
        if (isset($cookies[$name]) && '' !== $cookies[$name])
        {
            $items = '<li><code>' . self::e($name) . '</code> = <code>' . self::e(substr($cookies[$name], 0, 8)) . '…</code>'
                . '<p class="muted">Set by ' . self::e($site) . '.localhost when it opened its session. Host-only (no Domain attribute): the browser sends it to ' . self::e($site) . '.localhost only, never to the other sites. HttpOnly: no script can read it. SameSite=Lax.</p></li>';
        }
        else
        {
            $items = '<li class="muted">No session cookie: the browser sent nothing to ' . self::e($site) . '.localhost. The cookies of the other sites are not sent here, and a cookie this very page sets is only sent with the next request.</li>';
        }

        return '<section class="panel cookie-panel" aria-labelledby="cookies-title">
  <header class="panel-head"><div><h2 id="cookies-title">Cookies of ' . self::e($site) . '.localhost</h2><p class="panel-sub">What the browser sent with this request.</p></div></header>
  <div class="panel-body"><ul class="cookie-list">' . $items . '</ul></div>
</section>';
    }
}
