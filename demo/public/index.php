<?php
/**
 * Entry point of the demo, run by the PHP built-in web server as its router
 * script (see bin/demo):
 *
 *     php -S 127.0.0.1:8080 -t demo/public demo/public/index.php
 *
 * or by Apache in the image of demo/Dockerfile, every request routed to it.
 *
 * It serves the files of the interface, the JSON API (see demo/src/Api.php)
 * and GET /health, with a Content Security Policy that only lets the page
 * load what this server serves.
 *
 * On this machine, the demo answers on 127.0.0.1 and localhost only. Online,
 * DEMO_PUBLIC_HOST names the host it also answers on, served over HTTPS by a
 * proxy in front of it.
 *
 * Each visitor has a replay memory of their own, named by a cookie: "Forget
 * all" only forgets theirs.
 *
 * WARNING: the demo signs and decrypts with the keys of demo/certs/, which
 * are public: anyone can create the tokens it trusts. Never trust them
 * elsewhere.
 */

require dirname(__DIR__) . '/src/autoload.php';

use webcoder31\ezxmldsig\Demo\Api;
use webcoder31\ezxmldsig\Demo\ReplayStore;

header("Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store');

// Only a page served from this machine, or from the public host, may reach
// the server: another host name resolving to it (DNS rebinding) is refused.
$host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '';
$publicHost = getenv('DEMO_PUBLIC_HOST') ?: null;
$public = !is_null($publicHost) && $host === $publicHost;
if (!$public && !preg_match('/\A(127\.0\.0\.1|localhost|\[::1\])(:\d+)?\z/', $host))
{
    http_response_code(421);
    header('Content-Type: text/plain; charset=utf-8');
    echo "The demo only answers on 127.0.0.1 or localhost.\n";
    return true;
}
$origin = ($public ? 'https://' : 'http://') . $host;

$path = parse_url(isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/', PHP_URL_PATH);
$method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';

// The health check of the deployment: the server answers, and PHP runs.
if ('GET' === $method && '/health' === $path)
{
    header('Content-Type: text/plain; charset=utf-8');
    echo "ok\n";
    return true;
}

if (is_string($path) && 0 === strpos($path, '/api/'))
{
    // A request sent by another site is refused.
    if ('POST' === $method && isset($_SERVER['HTTP_ORIGIN']) && $_SERVER['HTTP_ORIGIN'] !== $origin)
    {
        http_response_code(403);
        $response = ['error' => 'Cross-origin request refused.'];
    }
    else
    {
        // The replay memory of this visitor, in a file of its own, created
        // when the receiver first accepts a token. A new visitor gets a new
        // identifier; the memories left unwritten for two days are removed.
        $visitor = isset($_COOKIE['demo_visitor']) && is_string($_COOKIE['demo_visitor']) && preg_match('/\A[0-9a-f]{32}\z/', $_COOKIE['demo_visitor'])
            ? $_COOKIE['demo_visitor'] : null;
        $replayDir = dirname(__DIR__) . '/var/replay';
        if (is_null($visitor))
        {
            $visitor = bin2hex(random_bytes(16));
            setcookie('demo_visitor', $visitor, ['path' => '/', 'httponly' => true, 'samesite' => 'Strict', 'secure' => $public]);
            ReplayStore::forgetIdle($replayDir, 2 * 86400);
        }
        $api = new Api(new ReplayStore($replayDir . '/' . $visitor . '.json'));
        list($status, $response) = $api->handle($method, $path, file_get_contents('php://input'));
        http_response_code($status);
    }
    header('Content-Type: application/json; charset=utf-8');
    echo Api::encode($response);
    return true;
}

$files = [
    '/' => ['index.html', 'text/html; charset=utf-8'],
    '/app.css' => ['app.css', 'text/css; charset=utf-8'],
    '/app.js' => ['app.js', 'text/javascript; charset=utf-8'],
    '/favicon.svg' => ['favicon.svg', 'image/svg+xml'],
];
if ('GET' !== $method || !isset($files[$path]))
{
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Not found.\n";
    return true;
}
header('Content-Type: ' . $files[$path][1]);
readfile(__DIR__ . '/' . $files[$path][0]);
return true;
