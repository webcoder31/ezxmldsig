<?php

namespace webcoder31\ezxmldsig\DemoSso;

/**
 * A browser without a screen: it sends requests to the sites of the demo
 * (Demo::handle()), with the cookies of each host, and keeps those the
 * responses set. The attack lab plays the victim and the attacker with
 * such browsers, each with cookies of its own.
 */
final class Browser
{
    /** @var Demo */
    private $demo;

    /** @var array Host => [cookie name => value]. */
    private $jar = [];

    public function __construct(Demo $demo)
    {
        $this->demo = $demo;
    }

    /**
     * Sends a request.
     *
     * @param string $method
     * @param string $url An absolute URL, e.g. "http://mail.localhost:8090/".
     * @param array $post The fields of a form.
     * @param string|null $origin The Origin header.
     *
     * @return array The response (see Http).
     */
    public function request($method, $url, array $post = [], $origin = null)
    {
        $host = parse_url($url, PHP_URL_HOST) . (is_null(parse_url($url, PHP_URL_PORT)) ? '' : ':' . parse_url($url, PHP_URL_PORT));
        $query = parse_url($url, PHP_URL_QUERY);
        $uri = (parse_url($url, PHP_URL_PATH) ?: '/') . (is_null($query) ? '' : '?' . $query);
        $response = $this->demo->handle(Http::request($method, $host, $uri, $post, isset($this->jar[$host]) ? $this->jar[$host] : [], $origin));
        foreach ($response['cookies'] as $cookie)
        {
            if ('' === $cookie['value'])
            {
                unset($this->jar[$host][$cookie['name']]);
            }
            else
            {
                $this->jar[$host][$cookie['name']] = $cookie['value'];
            }
        }

        return $response;
    }

    /**
     * Follows a response: a redirection is followed with a GET, as long as
     * there is one.
     *
     * @param array $response
     *
     * @return array The last response.
     */
    public function follow(array $response)
    {
        for ($i = 0; $i < 10 && isset($response['headers']['Location']); $i++)
        {
            $response = $this->request('GET', $response['headers']['Location']);
        }

        return $response;
    }

    /**
     * Returns the cookies the browser keeps for a host.
     *
     * @param string $host e.g. "mail.localhost:8090".
     *
     * @return array
     */
    public function cookies($host)
    {
        return isset($this->jar[$host]) ? $this->jar[$host] : [];
    }

    /**
     * Returns the form of a page of idp that posts a token: where it posts
     * it, and the token (decoded), or NULL if the page has none.
     *
     * @param array $response
     *
     * @return array|null ['action' => URL, 'token' => base64 token, 'xml' =>
     *     XML token]
     */
    public static function postedToken(array $response)
    {
        if (!preg_match('/<form id="post-token" method="post" action="([^"]+)">/', $response['body'], $action)
            || !preg_match('/name="token" value="([^"]+)"/', $response['body'], $token))
        {
            return null;
        }
        $encoded = html_entity_decode($token[1], ENT_QUOTES, 'UTF-8');

        return [
            'action' => html_entity_decode($action[1], ENT_QUOTES, 'UTF-8'),
            'token' => $encoded,
            'xml' => base64_decode($encoded),
        ];
    }
}
