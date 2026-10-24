<?php

namespace webcoder31\ezxmldsig\DemoSso;

use webcoder31\ezxmldsig\Demo\Receiver;
use webcoder31\ezxmldsig\Demo\ReplayStore;

/**
 * mail.localhost and crm.localhost: two applications without passwords.
 *
 * Without a session, an application sends the browser to idp
 * (GET /sso?app=...&return=...). It receives the token idp signed as a form
 * field posted to POST /acs, verifies it, and opens a session of its own.
 *
 * The verification is that of the receiver of the token demo
 * (Demo\Receiver): the checks of the library (structure, algorithms,
 * digest, signature, trust in the certificate of idp, audience), then those
 * left to the application (freshness, replay).
 */
final class Application
{
    /** @var string */
    private $app;

    /** @var SessionStore */
    private $sessions;

    /** @var Trace */
    private $trace;

    /** @var Base Where the sites live. */
    private $base;

    /** @var string */
    private $varDir;

    /** @var Settings */
    private $settings;

    /**
     * @param string $app 'mail' or 'crm'.
     * @param SessionStore $sessions
     * @param Trace $trace
     * @param Base $base Where the sites live.
     * @param string $varDir Where the replay memory of the application is
     *     kept.
     * @param Settings $settings The protections in force.
     */
    public function __construct($app, SessionStore $sessions, Trace $trace, Base $base, $varDir, Settings $settings)
    {
        $this->app = $app;
        $this->sessions = $sessions;
        $this->trace = $trace;
        $this->base = $base;
        $this->varDir = $varDir;
        $this->settings = $settings;
    }

    /**
     * Returns the receiver of the application: it trusts the CA of idp and
     * its subject, expects tokens addressed to itself, checks their
     * freshness and refuses a replayed one, each as the protections say
     * (see Settings), and decrypts with its own key.
     *
     * @return Receiver
     */
    public function receiver()
    {
        return Receiver::fromArray([
            'decrypt' => $this->settings->on('encrypt'),
            'audience' => $this->settings->on('audience'),
            'expectedAudience' => $this->app,
            'ttl' => Sites::APP_TTL,
            'freshness' => $this->settings->on('freshness'),
            'replay' => $this->settings->on('replay'),
        ])->withCryptKey(Settings::cryptFile($this->app, 'key'), null);
    }

    /**
     * Handles a request to the application.
     *
     * @param array $request See Http::request().
     *
     * @return array A response (see Http).
     */
    public function handle(array $request)
    {
        $route = $request['method'] . ' ' . $request['path'];
        $cookie = Sites::sessionCookie($this->app);
        $sessionId = isset($request['cookies'][$cookie]) ? $request['cookies'][$cookie] : null;
        $session = $this->sessions->get($this->app, $sessionId);

        switch ($route)
        {
            case 'GET /':
                return is_null($session) ? $this->askIdp() : $this->home($request, $session);
            case 'POST /acs':
                return $this->acs($request);
            case 'GET /loggedout':
                return $this->loggedOut($request);
            case 'POST /customers/delete':
                if ('crm' !== $this->app || is_null($session))
                {
                    break;
                }
                if (!is_null($request['origin']) && Sites::origin($this->app, $this->base) !== $request['origin'])
                {
                    return Http::text('Cross-origin request refused.', 403);
                }

                return $this->deleteCustomer($request, $sessionId, $session);
            case 'POST /logout':
                if (!is_null($request['origin']) && Sites::origin($this->app, $this->base) !== $request['origin'])
                {
                    return Http::text('Cross-origin request refused.', 403);
                }

                return $this->logout($sessionId);
        }

        return Http::text('Not found.', 404);
    }

    /**
     * No session: sends the browser to idp.
     */
    private function askIdp()
    {
        $location = Sites::origin(Sites::IDP, $this->base) . '/sso?' . http_build_query([
            'app' => $this->app,
            'return' => Sites::acsUrl($this->app, $this->base),
        ]);
        $this->trace->add([
            'from' => $this->app, 'to' => 'idp',
            'title' => Sites::name($this->app) . ' has no session for this browser: it sends the browser to IDP.',
            'detail' => 'No cookie ' . Sites::sessionCookie($this->app) . ' came with the request. ' . Sites::name($this->app) . ' has no password: it asks IDP who the user is, and where to post the answer (its own address, /acs).',
            'http' => '303 → ' . $location,
        ]);

        return Http::redirect($location);
    }

    /**
     * POST /acs: receives and verifies a token posted by the browser.
     */
    private function acs(array $request)
    {
        $encoded = isset($request['post']['token']) && is_string($request['post']['token']) ? $request['post']['token'] : '';
        $xml = base64_decode($encoded, true);
        if (false === $xml || '' === $xml)
        {
            $this->trace->add(['from' => 'browser', 'to' => $this->app, 'kind' => 'bad', 'title' => Sites::name($this->app) . ' received no token.']);

            return $this->refusedPage($request, null, 'No token was posted.');
        }

        $receiver = $this->receiver();
        $result = $receiver->verify($xml, new ReplayStore($this->varDir . '/replay-' . $this->app . '.json'));
        if (!$result['accepted'])
        {
            $failure = null;
            foreach ($result['steps'] as $step)
            {
                if ('fail' === $step['status'])
                {
                    $failure = $step;
                    break;
                }
            }
            $this->trace->add([
                'from' => $this->app, 'to' => $this->app, 'kind' => 'bad',
                'title' => Sites::name($this->app) . ' refuses the token' . (is_null($failure) ? '.' : ' at "' . $failure['label'] . '" (' . ('caller' === $failure['by'] ? 'its own check' : 'library') . ').'),
                'detail' => is_null($failure) ? null : $failure['message'],
                'xml' => $xml,
                'steps' => $result['steps'],
            ]);

            return $this->refusedPage($request, $result, is_null($failure) ? 'The token was refused.' : $failure['message']);
        }

        $sessionId = $this->sessions->open($this->app, ['user' => $result['data'], 'verified' => $result['steps'], 'tokenId' => $result['token']['tokenId']]);
        $this->trace->add([
            'from' => $this->app, 'to' => $this->app, 'kind' => 'ok',
            'title' => Sites::name($this->app) . ' verifies the token and opens its own session for ' . $result['data']['name'] . '.',
            'detail' => 'Library: signature, trust in the certificate of IDP, audience "' . $this->app . '". Application: freshness and replay. Then ' . Sites::name($this->app) . ' sets its cookie ' . Sites::sessionCookie($this->app) . ': it will not need IDP again until this session ends.',
            'xml' => $xml,
            'steps' => $result['steps'],
            'cookie' => ['site' => $this->app, 'host' => $this->base->host($this->app), 'name' => Sites::sessionCookie($this->app), 'action' => 'set'],
        ]);

        return Http::withCookie(Http::redirect(Sites::origin($this->app, $this->base) . '/'), Sites::sessionCookie($this->app), $sessionId);
    }

    /**
     * POST /logout: closes the session of the application, and only it.
     */
    private function logout($sessionId)
    {
        $this->sessions->close($this->app, $sessionId);
        $this->trace->add([
            'from' => 'browser', 'to' => $this->app,
            'title' => 'Logout from ' . Sites::name($this->app) . ': ' . Sites::name($this->app) . ' closes its own session.',
            'detail' => 'IDP still knows the user: opening ' . Sites::name($this->app) . ' again signs the user back in without a password. The session of the other application stays open too.',
            'cookie' => ['site' => $this->app, 'host' => $this->base->host($this->app), 'name' => Sites::sessionCookie($this->app), 'action' => 'deleted'],
        ]);

        return Http::withCookie(Http::redirect(Sites::origin($this->app, $this->base) . '/loggedout'), Sites::sessionCookie($this->app), '');
    }

    /**
     * GET / with a session: the application itself.
     */
    private function home(array $request, array $session)
    {
        $user = $session['user'];
        $other = 'mail' === $this->app ? 'crm' : 'mail';
        $info = Sites::APPS[$this->app];
        $content = '<section class="panel app-panel" aria-labelledby="app-title">
  <header class="panel-head"><span class="panel-num">' . Html::e($info['title']) . '</span><div><h2 id="app-title">' . Html::e($info['tagline']) . ', ' . Html::e($user['name']) . '</h2><p class="panel-sub">Signed in through IDP: ' . Html::e(Sites::name($this->app)) . ' never saw a password.</p></div></header>
  <div class="panel-body">
    <dl class="facts">
      <dt>User</dt><dd><code>' . Html::e($user['user']) . '</code></dd>
      <dt>Name</dt><dd>' . Html::e($user['name']) . '</dd>
      <dt>Role</dt><dd>' . Html::e($user['role']) . '</dd>
      <dt>Email</dt><dd>' . Html::e($user['email']) . '</dd>
    </dl>
    <p class="hint">These values come from the token IDP signed, read with <code>getData()</code> once every check passed.</p>
    ' . $this->rights($user) . $this->customers($session) . '
    <div class="actions">
      <a class="btn btn-primary" href="' . Html::e(Sites::origin($other, $this->base) . '/') . '">Open ' . Html::e($this->base->host($other)) . '</a>
      <form method="post" action="/logout"><button type="submit" class="btn btn-ghost">Log out of ' . Html::e(Sites::name($this->app)) . '</button></form>
    </div>
    <details class="code-details"><summary>How ' . Html::e(Sites::name($this->app)) . ' verified the token</summary>' . self::stepList($session['verified']) . '
      <div class="code-block"><pre class="code" data-php>' . Html::e($this->receiver()->phpCode()) . '</pre></div></details>
  </div>
</section>';

        return Http::html(Html::page($this->app, $this->base, $info['title'], $content, $request));
    }

    /**
     * The rights of the user here, and who decides each one.
     */
    private function rights(array $user)
    {
        $items = '<li><span class="right-by right-by-idp">IDP</span> Access to ' . Html::e(Sites::name($this->app)) . ': granted, since IDP signed a token for ' . Html::e(Sites::name($this->app)) . '. IDP decides which applications each user may enter; the token does not carry the list.</li>';
        if ('crm' === $this->app)
        {
            $canDelete = in_array($user['role'], Sites::CRM_DELETE_ROLES, true);
            $items .= '<li><span class="right-by right-by-app">CRM</span> Delete customers: ' . ($canDelete ? 'allowed' : 'not allowed') . ' for the role ' . Html::e($user['role'])
                . '. CRM decides, from the role IDP wrote in the token (allowed to: ' . Html::e(implode(', ', Sites::CRM_DELETE_ROLES)) . ').</li>';
        }

        return '<div class="rights"><p class="h-small">Your rights</p><ul class="rights-list">' . $items . '</ul></div>';
    }

    /**
     * The customers of crm, with a delete button each.
     */
    private function customers(array $session)
    {
        if ('crm' !== $this->app)
        {
            return '';
        }
        $deleted = isset($session['deleted']) ? $session['deleted'] : [];
        $rows = '';
        foreach (Sites::CRM_CUSTOMERS as $id => $customer)
        {
            if (in_array($id, $deleted, true))
            {
                continue;
            }
            $rows .= '<li><span><strong>' . Html::e($customer['name']) . '</strong> <span class="muted">' . Html::e($customer['place']) . '</span></span>'
                . '<form method="post" action="/customers/delete"><input type="hidden" name="id" value="' . Html::e($id) . '"><button type="submit" class="btn btn-ghost btn-xs">Delete</button></form></li>';
        }
        if ('' === $rows)
        {
            $rows = '<li class="muted">No customer left (in this session only).</li>';
        }

        return '<div class="customers"><p class="h-small">Customers</p><ul class="customer-list">' . $rows . '</ul></div>';
    }

    /**
     * POST /customers/delete: crm allows it from the role in the token.
     */
    private function deleteCustomer(array $request, $sessionId, array $session)
    {
        $user = $session['user'];
        $id = isset($request['post']['id']) && is_string($request['post']['id']) ? $request['post']['id'] : '';
        if (!isset(Sites::CRM_CUSTOMERS[$id]))
        {
            return Http::text('Unknown customer.', 404);
        }
        $customer = Sites::CRM_CUSTOMERS[$id]['name'];
        if (!in_array($user['role'], Sites::CRM_DELETE_ROLES, true))
        {
            $this->trace->add([
                'from' => 'browser', 'to' => 'crm', 'kind' => 'bad',
                'title' => 'CRM refuses to let ' . $user['name'] . ' delete ' . $customer . ': the role ' . $user['role'] . ' may only read.',
                'detail' => 'Decided by CRM, from the role IDP wrote in the token (' . $user['role'] . '). IDP let the user in; what the user may do inside is up to CRM.',
            ]);
            $content = '<section class="panel"><header class="panel-head"><span class="panel-num">!</span><div><h2>Not allowed</h2><p class="panel-sub">Decided by CRM, from your role.</p></div></header>
  <div class="panel-body"><div class="form-error" role="alert">The role ' . Html::e($user['role']) . ' may not delete customers: only ' . Html::e(implode(', ', Sites::CRM_DELETE_ROLES)) . ' may.</div>
    <div class="actions"><a class="btn btn-ghost" href="/">Back to CRM</a></div></div></section>';

            return Http::html(Html::page($this->app, $this->base, 'Not allowed', $content, $request), 403);
        }

        $session['deleted'] = array_values(array_unique(array_merge(isset($session['deleted']) ? $session['deleted'] : [], [$id])));
        $this->sessions->update($this->app, $sessionId, $session);
        $this->trace->add([
            'from' => 'browser', 'to' => 'crm', 'kind' => 'ok',
            'title' => $user['name'] . ' deletes ' . $customer . ': CRM allows it for the role ' . $user['role'] . '.',
            'detail' => 'Decided by CRM, from the role IDP wrote in the token. The customer is only hidden in this session: the demo deletes nothing.',
        ]);

        return Http::redirect(Sites::origin($this->app, $this->base) . '/');
    }

    /**
     * The page of a refused token.
     */
    private function refusedPage(array $request, $result, $message)
    {
        $content = '<section class="panel" aria-labelledby="refused-title">
  <header class="panel-head"><span class="panel-num">!</span><div><h2 id="refused-title">' . Html::e(Sites::name($this->app)) . ' refused the token</h2><p class="panel-sub">No session was opened.</p></div></header>
  <div class="panel-body"><div class="form-error" role="alert">' . Html::e($message) . '</div>' . (is_null($result) ? '' : self::stepList($result['steps'])) . '</div>
</section>';

        return Http::html(Html::page($this->app, $this->base, 'Token refused', $content, $request), 403);
    }

    /**
     * The checks of a verification, as a list.
     */
    private static function stepList(array $steps)
    {
        $items = '';
        foreach ($steps as $step)
        {
            $items .= '<li class="step" data-status="' . Html::e($step['status']) . '"><span class="step-icon" aria-hidden="true"></span><div class="step-main"><div class="step-title"><span>' . Html::e($step['label']) . '</span>'
                . '<span class="step-by step-by-' . Html::e($step['by']) . '">' . ('caller' === $step['by'] ? 'application' : 'library') . '</span>'
                . '<span class="sr-only">: ' . Html::e($step['status']) . '</span></div>'
                . '<p class="step-detail">' . Html::e($step['detail']) . '</p>'
                . (empty($step['message']) ? '' : '<p class="step-message">' . Html::e($step['message']) . '</p>') . '</div></li>';
        }

        return '<ol class="pipeline">' . $items . '</ol>';
    }

    /**
     * GET /loggedout: the page after a logout, which does not ask idp
     * again (GET / would).
     *
     * @param array $request
     *
     * @return array
     */
    public function loggedOut(array $request)
    {
        $content = '<section class="panel"><header class="panel-head"><div><h2>Logged out of ' . Html::e(Sites::name($this->app)) . '</h2><p class="panel-sub">' . Html::e(Sites::name($this->app)) . ' closed its session. IDP did not.</p></div></header>
  <div class="panel-body"><div class="actions"><a class="btn btn-primary" href="/">Open ' . Html::e(Sites::name($this->app)) . ' again</a></div></div></section>';

        return Http::html(Html::page($this->app, $this->base, 'Logged out', $content, $request));
    }
}
