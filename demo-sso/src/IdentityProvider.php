<?php

namespace webcoder31\ezxmldsig\DemoSso;

use webcoder31\ezxmldsig\Demo\Certs;
use webcoder31\ezxmldsig\XMLDSigToken;

/**
 * idp.localhost: the identity provider.
 *
 * It is the only site that knows the users and their passwords. When an
 * application sends the browser to it (GET /sso?app=...&return=...), it
 * logs the user in, or recognizes them by its own session, and sends the
 * browser back to the application with a signed token, in a form the
 * browser posts to the application (as the HTTP-POST binding of SAML does).
 *
 * The token is created by ezxmldsig: signed with the key of
 * demo/certs/sign.key.pem, addressed to the application (option
 * "audience", unless the protection "audience" is off), valid for
 * Sites::TOKEN_VALIDITY seconds (option "validity"), and encrypted for the
 * application when the setting "encrypt" is on (see Settings).
 */
final class IdentityProvider
{
    /** @var SessionStore */
    private $sessions;

    /** @var Trace */
    private $trace;

    /** @var Base Where the sites live. */
    private $base;

    /** @var Settings */
    private $settings;

    public function __construct(SessionStore $sessions, Trace $trace, Base $base, Settings $settings)
    {
        $this->sessions = $sessions;
        $this->trace = $trace;
        $this->base = $base;
        $this->settings = $settings;
    }

    /**
     * Handles a request to idp.localhost.
     *
     * @param array $request See Http::request().
     *
     * @return array A response (see Http).
     */
    public function handle(array $request)
    {
        $route = $request['method'] . ' ' . $request['path'];
        $sessionId = isset($request['cookies'][Sites::sessionCookie(Sites::IDP)]) ? $request['cookies'][Sites::sessionCookie(Sites::IDP)] : null;
        $session = $this->sessions->get(Sites::IDP, $sessionId);

        if (('POST /login' === $route || 'POST /logout' === $route)
            && !is_null($request['origin']) && Sites::origin(Sites::IDP, $this->base) !== $request['origin'])
        {
            return Http::text('Cross-origin request refused.', 403);
        }

        switch ($route)
        {
            case 'GET /':
                return $this->home($request, $session);
            case 'GET /sso':
                return $this->sso($request, $session);
            case 'POST /login':
                return $this->login($request);
            case 'POST /logout':
                return $this->logout($sessionId, $session);
        }

        return Http::text('Not found.', 404);
    }

    /**
     * GET /sso?app=...&return=...: an application asks who the user is.
     */
    private function sso(array $request, $session)
    {
        $app = isset($request['query']['app']) ? $request['query']['app'] : null;
        $return = isset($request['query']['return']) ? $request['query']['return'] : null;
        $error = $this->checkReturn($app, $return);
        if (!is_null($error))
        {
            $this->trace->add(['from' => 'idp', 'to' => 'idp', 'kind' => 'bad', 'title' => 'IDP refuses the request: ' . $error]);

            return $this->errorPage($request, $error);
        }

        if (is_null($session))
        {
            $this->trace->add([
                'from' => 'idp', 'to' => 'browser',
                'title' => 'IDP does not know the user yet: it shows its login form.',
                'detail' => Sites::name($app) . ' sent the browser here. The password is typed on IDP only: ' . Sites::name($app) . ' never sees it.',
            ]);

            return $this->loginPage($request, $app, $return, null);
        }

        $this->trace->add([
            'from' => 'idp', 'to' => 'idp', 'kind' => 'sso',
            'title' => 'Single sign-on: IDP already knows ' . Sites::USERS[$session['user']]['name'] . ' by its own session cookie, idp_session. No login.',
            'detail' => 'The browser sent idp_session to ' . $this->base->host(Sites::IDP) . ': the session opened when the user logged in, for another application. IDP signs a new token, for ' . Sites::name($app) . ' this time.',
        ]);

        return $this->issue($request, $session['user'], $app, $return);
    }

    /**
     * POST /login: the user submits the login form.
     */
    private function login(array $request)
    {
        $post = $request['post'];
        $app = isset($post['app']) ? $post['app'] : null;
        $return = isset($post['return']) ? $post['return'] : null;
        $error = $this->checkReturn($app, $return);
        if (!is_null($error))
        {
            return $this->errorPage($request, $error);
        }

        $user = isset($post['username']) && is_string($post['username']) ? $post['username'] : '';
        $password = isset($post['password']) && is_string($post['password']) ? $post['password'] : '';
        if (!isset(Sites::USERS[$user]) || !hash_equals(Sites::USERS[$user]['password'], $password))
        {
            $this->trace->add(['from' => 'browser', 'to' => 'idp', 'kind' => 'bad', 'title' => 'Wrong user name or password: IDP shows its form again.']);

            return $this->loginPage($request, $app, $return, 'Wrong user name or password.');
        }

        $sessionId = $this->sessions->open(Sites::IDP, ['user' => $user]);
        $this->trace->add([
            'from' => 'browser', 'to' => 'idp', 'kind' => 'ok',
            'title' => Sites::USERS[$user]['name'] . ' logs in on IDP: IDP opens its own session.',
            'detail' => 'IDP sets the cookie idp_session on ' . $this->base->host(Sites::IDP) . '. The applications never see it: it is how IDP will recognize the user next time, for any application.',
            'cookie' => ['site' => 'idp', 'host' => $this->base->host(Sites::IDP), 'name' => Sites::sessionCookie(Sites::IDP), 'action' => 'set'],
        ]);

        return Http::withCookie($this->issue($request, $user, $app, $return), Sites::sessionCookie(Sites::IDP), $sessionId);
    }

    /**
     * POST /logout: closes the session of idp, and only it.
     */
    private function logout($sessionId, $session)
    {
        $this->sessions->close(Sites::IDP, $sessionId);
        $this->trace->add([
            'from' => 'browser', 'to' => 'idp',
            'title' => 'Logout from IDP: IDP closes its own session.',
            'detail' => 'The sessions of MAIL and CRM stay open: each application has its own. Logging out of every site at once (single logout) is a separate mechanism, which this demo does not implement.',
            'cookie' => ['site' => 'idp', 'host' => $this->base->host(Sites::IDP), 'name' => Sites::sessionCookie(Sites::IDP), 'action' => 'deleted'],
        ]);

        return Http::withCookie(Http::redirect(Sites::origin(Sites::IDP, $this->base) . '/'), Sites::sessionCookie(Sites::IDP), '');
    }

    /**
     * Signs a token for an application and returns the page that posts it.
     */
    private function issue(array $request, $user, $app, $return)
    {
        $account = Sites::USERS[$user];

        // Access to the application: idp decides, and signs no token for an
        // application the user may not enter. The application never sees
        // the request.
        if (!in_array($app, $account['apps'], true))
        {
            $this->trace->add([
                'from' => 'idp', 'to' => 'idp', 'kind' => 'bad',
                'title' => 'IDP refuses to sign a token for ' . Sites::name($app) . ': ' . $account['name'] . ' has no access to ' . Sites::name($app) . '.',
                'detail' => 'Access to an application is decided by IDP, from its own list of the applications each user may enter (' . $account['name'] . ': ' . implode(', ', array_map([Sites::class, 'name'], $account['apps'])) . '). No token is signed, so ' . Sites::name($app) . ' cannot let the user in: it is not even asked.',
            ]);
            $content = '<section class="panel" aria-labelledby="denied-title">
  <header class="panel-head"><span class="panel-num">!</span><div><h2 id="denied-title">No access to ' . Html::e(Sites::name($app)) . '</h2><p class="panel-sub">Decided by IDP, which signs no token for this application.</p></div></header>
  <div class="panel-body"><div class="form-error" role="alert">' . Html::e($account['name']) . ' may enter ' . Html::e(implode(', ', array_map([Sites::class, 'name'], $account['apps']))) . ' only.</div>
    <div class="actions"><a class="btn btn-ghost" href="' . Html::e(Sites::origin($account['apps'][0], $this->base) . '/') . '">Open ' . Html::e($this->base->host($account['apps'][0])) . '</a></div></div>
</section>';

            return Http::html(Html::page(Sites::IDP, $this->base, 'No access', $content, $request), 403);
        }

        $data = ['user' => $user, 'name' => $account['name'], 'role' => $account['role'], 'email' => $account['email']];
        $options = ['validity' => Sites::TOKEN_VALIDITY];
        if ($this->settings->on('audience'))
        {
            $options['audience'] = $app;
        }
        if ($this->settings->on('encrypt'))
        {
            // Encrypted for the application, with its certificate: the
            // private key stays with the application (null).
            $token = XMLDSigToken::createSecureXMLToken(
                $data, Certs::path('sign.key.pem'), Certs::path('sign.cert.pem'),
                null, Settings::cryptFile($app, 'cert'), Certs::SIGN_KEY_PASSWORD, null, $options
            );
        }
        else
        {
            $token = XMLDSigToken::createXMLToken($data, Certs::path('sign.key.pem'), Certs::path('sign.cert.pem'), Certs::SIGN_KEY_PASSWORD, $options);
        }
        if (!is_null($token->getError()))
        {
            return $this->errorPage($request, 'The token could not be created: ' . $token->getError());
        }

        $this->trace->add([
            'from' => 'idp', 'to' => $app,
            'title' => 'IDP signs a token for ' . Sites::name($app) . ', and the browser posts it to ' . (Sites::acsUrl($app, $this->base) === $return ? 'the /acs address of ' . Sites::name($app) . '.' : $return . ', which is not the address of ' . Sites::name($app) . '!'),
            'kind' => Sites::acsUrl($app, $this->base) === $return ? 'info' : 'bad',
            'detail' => ($this->settings->on('audience') ? 'Addressed to "' . $app . '" (audience)' : 'Addressed to no one: the protection "audience" is off'). ', valid ' . Sites::TOKEN_VALIDITY . ' s (validity)' . ($this->settings->on('encrypt') ? ', encrypted for ' . Sites::name($app) . ' with ' . $app . '.crypt.cert.pem' : '') . '. It travels through the browser, as a hidden form field: IDP and ' . Sites::name($app) . ' never talk to each other directly.',
            'http' => 'POST ' . $return,
            'xml' => $token->getXML(),
        ]);

        $content = '<section class="panel" aria-labelledby="post-title">
  <header class="panel-head"><span class="panel-num">→</span><div><h2 id="post-title">Sending you back to ' . Html::e(Sites::name($app)) . '</h2><p class="panel-sub">Signed in as ' . Html::e($account['name']) . '. IDP signed a token for ' . Html::e(Sites::name($app)) . '; your browser now posts it to ' . Html::e($return) . '.</p></div></header>
  <div class="panel-body">
    <form id="post-token" method="post" action="' . Html::e($return) . '">
      <input type="hidden" name="token" value="' . Html::e(base64_encode($token->getXML())) . '">
      <p class="post-countdown" id="post-countdown">Posting in a moment…</p>
      <p class="hint">The token is valid for ' . Html::e(Sites::TOKEN_VALIDITY) . ' s: paused longer than that, it reaches ' . Html::e(Sites::name($app)) . ' out of date, and ' . Html::e(Sites::name($app)) . ' refuses it (freshness).</p>
      <div class="actions">
        <button type="submit" class="btn btn-primary">Post the token now</button>
        <button type="button" class="btn btn-ghost" id="post-pause" aria-pressed="false">Pause</button>
      </div>
    </form>
    <dl class="facts">
      <dt>Audience</dt><dd>' . ($this->settings->on('audience') ? '<code>' . Html::e($app) . '</code>' : '<span class="muted">none (protection off)</span>') . '</dd>
      <dt>Valid for</dt><dd>' . Html::e(Sites::TOKEN_VALIDITY) . ' s</dd>
      <dt>Encrypted</dt><dd>' . ($this->settings->on('encrypt') ? 'for ' . Html::e(Sites::name($app)) . ', with <code>' . Html::e($app) . '.crypt.cert.pem</code>' : 'no') . '</dd>
    </dl>
    <details class="code-details"><summary>The token (XML)</summary><div class="code-block"><pre class="code" data-xml>' . Html::e($token->getPrettyXML()) . '</pre></div></details>
  </div>
</section>';

        return Http::html(Html::page(Sites::IDP, $this->base, 'Sending you back', $content, $request, ['/post.js']));
    }

    /**
     * GET /: what idp knows.
     */
    private function home(array $request, $session)
    {
        if (is_null($session))
        {
            $state = '<p>No one is logged in on IDP. Open <a href="' . Html::e(Sites::origin('mail', $this->base) . '/') . '">' . Html::e($this->base->host('mail')) . '</a> or <a href="' . Html::e(Sites::origin('crm', $this->base) . '/') . '">' . Html::e($this->base->host('crm')) . '</a>: they will send you here to log in.</p>';
        }
        else
        {
            $state = '<p><strong>' . Html::e(Sites::USERS[$session['user']]['name']) . '</strong> is logged in on IDP. Any application that sends the browser here gets a token without a new login.</p>
<div class="actions"><form method="post" action="/logout"><button type="submit" class="btn btn-ghost">Log out of IDP</button></form></div>';
        }
        $content = '<section class="panel" aria-labelledby="idp-title">
  <header class="panel-head"><span class="panel-num">IDP</span><div><h2 id="idp-title">Identity provider</h2><p class="panel-sub">Knows the users and their passwords; signs the tokens.</p></div></header>
  <div class="panel-body">' . $state . '</div>
</section>';

        return Http::html(Html::page(Sites::IDP, $this->base, 'Identity provider', $content, $request));
    }

    /**
     * Returns the login page.
     */
    private function loginPage(array $request, $app, $return, $error)
    {
        $accounts = '';
        foreach (Sites::USERS as $name => $account)
        {
            $accounts .= '<li><button type="button" class="btn btn-ghost btn-xs" data-username="' . Html::e($name) . '" data-password="' . Html::e($account['password']) . '" aria-label="Fill in the form with ' . Html::e($name) . '">Use</button>'
                . '<span><code>' . Html::e($name) . '</code> / <code>' . Html::e($account['password']) . '</code> <span class="muted">(' . Html::e($account['name']) . ', ' . Html::e($account['role']) . '; may enter ' . Html::e(implode(' and ', $account['apps'])) . ')</span></span></li>';
        }
        $content = '<section class="panel" aria-labelledby="login-title">
  <header class="panel-head"><span class="panel-num">IDP</span><div><h2 id="login-title">Log in to continue to ' . Html::e(Sites::name($app)) . '</h2><p class="panel-sub">' . Html::e($this->base->host($app)) . ' sent you here: it has no password of its own.</p></div></header>
  <form class="panel-body login-form" method="post" action="/login">
    <input type="hidden" name="app" value="' . Html::e($app) . '">
    <input type="hidden" name="return" value="' . Html::e($return) . '">
    ' . (is_null($error) ? '' : '<div class="form-error" role="alert">' . Html::e($error) . '</div>') . '
    <label class="field"><span class="field-label">User name</span><input type="text" name="username" value="ragnar" autocomplete="username" required></label>
    <label class="field"><span class="field-label">Password</span><input type="password" name="password" value="kattegat" autocomplete="current-password" required></label>
    <div class="actions"><button type="submit" class="btn btn-primary">Log in</button></div>
    <p class="hint">Demo accounts:</p><ul class="hint accounts">' . $accounts . '</ul>
  </form>
</section>';

        return Http::html(Html::page(Sites::IDP, $this->base, 'Log in', $content, $request, ['/login.js']));
    }

    /**
     * Returns an error page.
     */
    private function errorPage(array $request, $message)
    {
        $content = '<section class="panel"><div class="panel-body"><div class="form-error" role="alert">' . Html::e($message) . '</div></div></section>';

        return Http::html(Html::page(Sites::IDP, $this->base, 'Error', $content, $request), 400);
    }

    /**
     * Checks the application and the address the token is to be posted to,
     * and returns why they are refused, or NULL.
     *
     * The address must be the very address of the application: idp posts
     * a token, which grants access to the application, only there. With the
     * protection "returnUrl" off, any web address is accepted: idp then
     * posts the token wherever the request says, to an attacker included.
     */
    private function checkReturn($app, $return)
    {
        if (!is_string($app) || !isset(Sites::APPS[$app]))
        {
            return 'unknown application.';
        }
        if (!$this->settings->on('returnUrl'))
        {
            return is_string($return) && preg_match('#\Ahttps?://[^\s<>"]+\z#', $return) ? null : 'the return address is not a web address.';
        }
        if (!is_string($return) || Sites::acsUrl($app, $this->base) !== $return)
        {
            return 'the return address is not the one registered for ' . Sites::name($app) . ' (' . Sites::acsUrl($app, $this->base) . ').';
        }

        return null;
    }
}
