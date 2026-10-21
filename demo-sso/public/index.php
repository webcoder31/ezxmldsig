<?php
/**
 * Entry point of the SSO demo, run by the PHP built-in web server as its
 * router script (see bin/demo-sso):
 *
 *     php -S 0.0.0.0:8080 -t demo-sso/public demo-sso/public/index.php
 *
 * or by Apache in the image of demo-sso/Dockerfile, every request routed to
 * it.
 *
 * One server answers for the three sites, told apart by the Host header
 * (see demo-sso/src/Sites.php). It serves their pages, the trace of the
 * flow, the style sheet and scripts, and GET /health, with a Content
 * Security Policy that only lets a page load what this server serves.
 *
 * Online, DEMO_SSO_PUBLIC_DOMAIN names the domain whose subdomains are the
 * sites (idp.<domain>, mail.<domain>, crm.<domain>, the home page on the
 * domain itself), served over HTTPS by a proxy in front of it. Each visitor
 * then has a directory of their own (see demo-sso/src/Visitors.php).
 *
 * WARNING: the demo signs with the keys of demo/certs/, which are public:
 * anyone can create the tokens it trusts. Never trust them elsewhere.
 */

require dirname(__DIR__) . '/src/autoload.php';

use webcoder31\ezxmldsig\DemoSso\Demo;
use webcoder31\ezxmldsig\DemoSso\Http;
use webcoder31\ezxmldsig\DemoSso\Settings;
use webcoder31\ezxmldsig\DemoSso\Sites;
use webcoder31\ezxmldsig\DemoSso\Visitors;

$host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '';
$uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';
$method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';
$path = parse_url($uri, PHP_URL_PATH);
$publicDomain = getenv('DEMO_SSO_PUBLIC_DOMAIN') ?: null;

// The health check of the deployment, on any host name: the server
// answers, and PHP runs.
if ('GET' === $method && '/health' === $path)
{
    header('Content-Type: text/plain; charset=utf-8');
    echo "ok\n";
    return true;
}

$parsed = Sites::parseHost($host, $publicDomain);
$online = !is_null($parsed) && $parsed['base']->isOnline();

// Online, the sessions, the trace, the protections and the replay memories
// of this visitor, in a directory of their own.
$varDir = dirname(__DIR__) . '/var';
if ($online)
{
    $visitor = Visitors::fromCookie(isset($_COOKIE[Visitors::COOKIE]) ? $_COOKIE[Visitors::COOKIE] : null);
    if (is_null($visitor))
    {
        $visitor = Visitors::newId();
        setcookie(Visitors::COOKIE, $visitor, ['path' => '/', 'domain' => $publicDomain, 'httponly' => true, 'samesite' => 'Lax', 'secure' => true]);
        Visitors::forgetIdle($varDir . '/visitors');
    }
    $varDir .= '/visitors/' . $visitor;
}

// A page of idp posts the token to an application: the form may target the
// applications, and nothing else. With the protection "returnUrl" turned off
// on the home page, idp posts the token wherever the request says, and the
// policy lets it, so that the demo shows what happens then.
$formAction = "'self'";
if (!is_null($parsed) && Sites::IDP === $parsed['site'])
{
    if (!Settings::load($varDir . '/settings.json')->on('returnUrl'))
    {
        $formAction .= ' http: https:';
    }
    else
    {
        foreach (array_keys(Sites::APPS) as $app)
        {
            $formAction .= ' ' . Sites::origin($app, $parsed['base']);
        }
    }
}
header("Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action " . $formAction . "; frame-ancestors 'none'");
header('X-Content-Type-Options: nosniff');
// same-origin rather than no-referrer: with no-referrer, a form posted to
// its own site carries "Origin: null", which the checks of the login and
// logout forms would refuse.
header('Referrer-Policy: same-origin');
header('Cache-Control: no-store');

// The style sheet and the icon of the token demo, and those of this one.
$files = [
    '/app.css' => [dirname(__DIR__, 2) . '/demo/public/app.css', 'text/css; charset=utf-8'],
    '/favicon.svg' => [dirname(__DIR__, 2) . '/demo/public/favicon.svg', 'image/svg+xml'],
    '/sso.css' => [__DIR__ . '/sso.css', 'text/css; charset=utf-8'],
    '/sso.js' => [__DIR__ . '/sso.js', 'text/javascript; charset=utf-8'],
    '/post.js' => [__DIR__ . '/post.js', 'text/javascript; charset=utf-8'],
    '/login.js' => [__DIR__ . '/login.js', 'text/javascript; charset=utf-8'],
    '/lab.js' => [__DIR__ . '/lab.js', 'text/javascript; charset=utf-8'],
];
if ('GET' === $method && is_string($path) && isset($files[$path]) && !is_null($parsed))
{
    header('Content-Type: ' . $files[$path][1]);
    readfile($files[$path][0]);
    return true;
}

$demo = new Demo($varDir, null, $publicDomain);
$response = $demo->handle(Http::request(
    $method,
    $host,
    $uri,
    'POST' === $method ? $_POST : [],
    $_COOKIE,
    isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : null
));

http_response_code($response['status']);
foreach ($response['headers'] as $name => $value)
{
    header($name . ': ' . $value);
}
foreach ($response['cookies'] as $cookie)
{
    // Host-only (no Domain), HttpOnly, SameSite=Lax, and Secure online; an
    // empty value deletes the cookie.
    setcookie($cookie['name'], $cookie['value'], [
        'expires' => '' === $cookie['value'] ? time() - 3600 : 0,
        'path' => '/',
        'httponly' => true,
        'samesite' => 'Lax',
        'secure' => $online,
    ]);
}
echo $response['body'];
return true;
