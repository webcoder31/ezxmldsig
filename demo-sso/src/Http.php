<?php

namespace webcoder31\ezxmldsig\DemoSso;

/**
 * A request and the response to it, as plain arrays, so that the sites can
 * be run and tested without a web server.
 */
final class Http
{
    /**
     * Builds a request.
     *
     * @param string $method
     * @param string $host The Host header.
     * @param string $uri Path and query string.
     * @param array $post The fields of a form.
     * @param array $cookies Name => value.
     * @param string|null $origin The Origin header.
     *
     * @return array
     */
    public static function request($method, $host, $uri, array $post = [], array $cookies = [], $origin = null)
    {
        $path = parse_url($uri, PHP_URL_PATH);
        $queryString = parse_url($uri, PHP_URL_QUERY);
        parse_str(is_string($queryString) ? $queryString : '', $query);

        return [
            'method' => $method,
            'host' => $host,
            'path' => is_string($path) ? $path : '/',
            'query' => $query,
            'post' => $post,
            'cookies' => $cookies,
            'origin' => $origin,
        ];
    }

    /**
     * Builds an HTML response.
     *
     * @param string $body
     * @param int $status
     *
     * @return array
     */
    public static function html($body, $status = 200)
    {
        return ['status' => $status, 'headers' => ['Content-Type' => 'text/html; charset=utf-8'], 'cookies' => [], 'body' => $body];
    }

    /**
     * Builds a JSON response. The JSON is written with `<`, `>`, `&`, `'`
     * and `"` escaped, so that no value reads as markup.
     *
     * @param mixed $data
     * @param int $status
     *
     * @return array
     */
    public static function json($data, $status = 200)
    {
        $flags = JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE;

        return ['status' => $status, 'headers' => ['Content-Type' => 'application/json; charset=utf-8'], 'cookies' => [], 'body' => json_encode($data, $flags)];
    }

    /**
     * Builds a redirection (303 See Other: the browser follows it with a
     * GET, whatever the method of the request).
     *
     * @param string $location
     *
     * @return array
     */
    public static function redirect($location)
    {
        return ['status' => 303, 'headers' => ['Location' => $location], 'cookies' => [], 'body' => ''];
    }

    /**
     * Builds a plain text response.
     *
     * @param string $text
     * @param int $status
     *
     * @return array
     */
    public static function text($text, $status)
    {
        return ['status' => $status, 'headers' => ['Content-Type' => 'text/plain; charset=utf-8'], 'cookies' => [], 'body' => $text . "\n"];
    }

    /**
     * Adds a cookie to a response. Cookies are host-only (no Domain
     * attribute), HttpOnly and SameSite=Lax: a site never sees the cookies
     * of another, and no script reads them.
     *
     * @param array $response
     * @param string $name
     * @param string $value The value, or '' to delete the cookie.
     *
     * @return array
     */
    public static function withCookie(array $response, $name, $value)
    {
        $response['cookies'][] = ['name' => $name, 'value' => $value];

        return $response;
    }
}
