<?php

namespace webcoder31\ezxmldsig\Tests\helpers;

/**
 * Runs requests against the Node.js library ezxmldsig-js, served by
 * bin/js-ezxmldsig at the URL of EZXMLDSIG_JS_URL, which bin/test sets (see
 * tests/js/ezxmldsig.ts for the requests and their results). A port of
 * test/helpers/php.ts of the Node.js library.
 *
 * The tests that need it are skipped, with the reason, when the URL is not
 * set (PHPUnit run without bin/test). In continuous integration (CI=true),
 * they fail instead: a run that skipped them has not checked the
 * interoperability.
 */
class Js
{
    /**
     * Why the tests that need the Node.js library are skipped, or NULL when
     * they run.
     */
    public static function skipReason()
    {
        if (false !== self::url() || 'true' === getenv('CI'))
        {
            return null;
        }
        return 'EZXMLDSIG_JS_URL is not set: run the tests with bin/test, which serves the Node.js library.';
    }

    /**
     * Runs the requests, and returns one result per request.
     */
    public static function run(array $requests)
    {
        $url = self::url();
        if (false === $url)
        {
            throw new \RuntimeException('EZXMLDSIG_JS_URL is not set: run the tests with bin/test.');
        }
        $context = stream_context_create(['http' => [
            'method' => 'POST',
            'header' => "Content-Type: application/json\r\n",
            'content' => json_encode($requests, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            'timeout' => 120,
            'ignore_errors' => true,
        ]]);
        $body = @file_get_contents($url . '/', false, $context);
        $status = isset($http_response_header[0]) ? $http_response_header[0] : 'no answer';
        if (false === $body || false === strpos($status, ' 200 '))
        {
            throw new \RuntimeException('The ezxmldsig-js service failed (' . $status . '): ' . $body);
        }
        $results = json_decode($body, true);
        if (!is_array($results) || count($results) !== count($requests))
        {
            throw new \RuntimeException('The ezxmldsig-js service returned ' . $body . ' for ' . count($requests) . ' requests.');
        }
        return $results;
    }

    private static function url()
    {
        $url = getenv('EZXMLDSIG_JS_URL');
        return false === $url || '' === $url ? false : rtrim($url, '/');
    }
}
