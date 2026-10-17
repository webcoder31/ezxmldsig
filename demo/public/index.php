<?php
/**
 * Entry point of the demo, run by the PHP built-in web server as its router
 * script (see bin/demo):
 *
 *     php -S 127.0.0.1:8080 -t demo/public demo/public/index.php
 *
 * It serves the files of the interface and the JSON API (see
 * demo/src/Api.php), with a Content Security Policy that only lets the page
 * load what this server serves.
 *
 * WARNING: the demo signs and decrypts with the keys of demo/certs/, which
 * are public. Serve it on your own machine only.
 */

require dirname(__DIR__) . '/src/autoload.php';

use webcoder31\ezxmldsig\Demo\Api;
use webcoder31\ezxmldsig\Demo\ReplayStore;

header("Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store');

// Only a page served from this machine may reach the server: another host
// name resolving to 127.0.0.1 (DNS rebinding) is refused.
$host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '';
if (!preg_match('/\A(127\.0\.0\.1|localhost|\[::1\])(:\d+)?\z/', $host))
{
    http_response_code(421);
    header('Content-Type: text/plain; charset=utf-8');
    echo "The demo only answers on 127.0.0.1 or localhost.\n";
    return true;
}

$path = parse_url(isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/', PHP_URL_PATH);
$method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';

if (is_string($path) && 0 === strpos($path, '/api/'))
{
    // A request sent by another site is refused.
    if ('POST' === $method && isset($_SERVER['HTTP_ORIGIN']) && $_SERVER['HTTP_ORIGIN'] !== 'http://' . $host)
    {
        http_response_code(403);
        $response = ['error' => 'Cross-origin request refused.'];
    }
    else
    {
        $api = new Api(new ReplayStore(dirname(__DIR__) . '/var/replay.json'));
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
