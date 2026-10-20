<?php
/**
 * Entry point of the SSO demo, run by the PHP built-in web server as its
 * router script (see bin/demo-sso):
 *
 *     php -S 0.0.0.0:8080 -t demo-sso/public demo-sso/public/index.php
 *
 * One server answers for the three sites, told apart by the Host header
 * (see demo-sso/src/Sites.php). It serves their pages, the trace of the
 * flow, and the style sheet and scripts, with a Content Security Policy
 * that only lets a page load what this server serves.
 *
 * WARNING: the demo signs with the keys of demo/certs/, which are public.
 * Serve it on your own machine only.
 */

require dirname(__DIR__) . '/src/autoload.php';

use webcoder31\ezxmldsig\DemoSso\Demo;
use webcoder31\ezxmldsig\DemoSso\Http;
use webcoder31\ezxmldsig\DemoSso\Settings;
use webcoder31\ezxmldsig\DemoSso\Sites;

$host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '';
$uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';
$method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';
$path = parse_url($uri, PHP_URL_PATH);

// A page of idp posts the token to an application: the form may target the
// applications, and nothing else. With the protection "returnUrl" turned off
// on the home page, idp posts the token wherever the request says, and the
// policy lets it, so that the demo shows what happens then.
$parsed = Sites::parseHost($host);
$formAction = "'self'";
if (!is_null($parsed) && Sites::IDP === $parsed['site'])
{
    if (!Settings::load(dirname(__DIR__) . '/var/settings.json')->on('returnUrl'))
    {
        $formAction .= ' http: https:';
    }
    else
    {
        foreach (array_keys(Sites::APPS) as $app)
        {
            $formAction .= ' ' . Sites::origin($app, $parsed['port']);
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

$demo = new Demo(dirname(__DIR__) . '/var');
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
    // Host-only (no Domain), HttpOnly, SameSite=Lax; an empty value deletes
    // the cookie.
    setcookie($cookie['name'], $cookie['value'], [
        'expires' => '' === $cookie['value'] ? time() - 3600 : 0,
        'path' => '/',
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}
echo $response['body'];
return true;
