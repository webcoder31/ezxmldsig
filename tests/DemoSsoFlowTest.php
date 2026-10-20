<?php

namespace webcoder31\ezxmldsig\Tests;

use webcoder31\ezxmldsig\DemoSso\Browser;
use webcoder31\ezxmldsig\DemoSso\Demo;
use webcoder31\ezxmldsig\DemoSso\Http;
use webcoder31\ezxmldsig\DemoSso\Settings;

/**
 * The single sign-on demo, run without a web server: requests go to
 * Demo::handle(), and a cookie jar per host plays the browser.
 */
class DemoSsoFlowTest extends TestCase
{
    const PORT = 8090;

    /** @var string */
    private $varDir;

    /** @var Demo */
    private $demo;

    /** @var Browser */
    private $browser;

    protected function setUp(): void
    {
        parent::setUp();
        $this->varDir = sys_get_temp_dir() . '/ezxmldsig-sso-' . bin2hex(random_bytes(8));
        $this->demo = new Demo($this->varDir);
        $this->browser = new Browser($this->demo);
    }

    protected function tearDown(): void
    {
        $remove = function ($dir) use (&$remove) {
            foreach (glob($dir . '/*') ?: [] as $file)
            {
                is_dir($file) ? $remove($file) : unlink($file);
            }
            if (is_dir($dir))
            {
                rmdir($dir);
            }
        };
        $remove($this->varDir);
        parent::tearDown();
    }

    /**
     * Sends a request as the browser does: with the cookies of the host,
     * keeping those the response sets.
     */
    private function browse($method, $url, array $post = [], $origin = null)
    {
        return $this->browser->request($method, $url, $post, $origin);
    }

    /**
     * Returns the cookies the browser keeps for a host, NULL if none.
     */
    private function cookies($host)
    {
        $cookies = $this->browser->cookies($host);

        return empty($cookies) ? null : $cookies;
    }

    private static function url($site, $path = '/')
    {
        return 'http://' . $site . '.localhost:' . self::PORT . $path;
    }

    /**
     * Returns the token of the page of idp that posts it, and the address
     * it posts it to.
     */
    private static function postedToken(array $response)
    {
        self::assertSame(200, $response['status']);
        $posted = Browser::postedToken($response);
        self::assertNotNull($posted, 'The page posts a token.');

        return [$posted['action'], $posted['token']];
    }

    /**
     * Logs in through mail: mail sends the browser to idp, idp asks for the
     * password and posts a token to mail, mail opens its session.
     *
     * @return string The token idp signed for mail.
     */
    private function logInThroughMail()
    {
        $response = $this->browse('GET', self::url('mail'));
        $this->assertSame(303, $response['status']);
        $location = $response['headers']['Location'];
        $this->assertStringStartsWith(self::url('idp', '/sso?'), $location);

        $response = $this->browse('GET', $location);
        $this->assertSame(200, $response['status']);
        $this->assertStringContainsString('Log in to continue to mail', $response['body']);

        $response = $this->browse('POST', self::url('idp', '/login'), [
            'app' => 'mail', 'return' => self::url('mail', '/acs'), 'username' => 'ragnar', 'password' => 'kattegat',
        ], 'http://idp.localhost:' . self::PORT);
        $this->assertArrayHasKey('idp_session', $this->cookies('idp.localhost:' . self::PORT));
        list($action, $token) = self::postedToken($response);
        $this->assertSame(self::url('mail', '/acs'), $action);

        $response = $this->browse('POST', $action, ['token' => $token], 'http://idp.localhost:' . self::PORT);
        $this->assertSame(303, $response['status'], $response['body']);
        $this->assertSame(self::url('mail'), $response['headers']['Location']);
        $this->assertArrayHasKey('mail_session', $this->cookies('mail.localhost:' . self::PORT));

        return $token;
    }

    public function testTheWholeFlowWithSingleSignOn()
    {
        $this->logInThroughMail();

        $response = $this->browse('GET', self::url('mail'));
        $this->assertSame(200, $response['status']);
        $this->assertStringContainsString('Ragnar Lothbrok', $response['body']);

        // crm has no session: idp recognizes the user, without a login.
        $response = $this->browse('GET', self::url('crm'));
        $this->assertSame(303, $response['status']);
        $response = $this->browse('GET', $response['headers']['Location']);
        $this->assertStringNotContainsString('Log in to continue', $response['body']);
        list($action, $token) = self::postedToken($response);
        $this->assertSame(self::url('crm', '/acs'), $action);
        $response = $this->browse('POST', $action, ['token' => $token], 'http://idp.localhost:' . self::PORT);
        $this->assertSame(303, $response['status']);
        $this->assertStringContainsString('Ragnar Lothbrok', $this->browse('GET', self::url('crm'))['body']);

        // The trace tells the story, single sign-on included.
        $events = json_decode($this->browse('GET', self::url('crm', '/trace.json'))['body'], true)['events'];
        $kinds = array_column($events, 'kind');
        $this->assertContains('sso', $kinds);
        $this->assertSame(2, count(array_keys($kinds, 'ok')) - 1, 'Login on idp, then mail and crm accept a token.');
    }

    public function testEachSiteHasItsOwnSessionCookie()
    {
        $this->logInThroughMail();

        $this->assertSame(['idp_session'], array_keys($this->cookies('idp.localhost:' . self::PORT)));
        $this->assertSame(['mail_session'], array_keys($this->cookies('mail.localhost:' . self::PORT)));
        $this->assertNull($this->cookies('crm.localhost:' . self::PORT));

        // Logging out of mail leaves idp logged in.
        $this->browse('POST', self::url('mail', '/logout'), [], 'http://mail.localhost:' . self::PORT);
        $this->assertNull($this->cookies('mail.localhost:' . self::PORT));
        $this->assertArrayHasKey('idp_session', $this->cookies('idp.localhost:' . self::PORT));
    }

    public function testAReplayedTokenIsRefused()
    {
        $token = $this->logInThroughMail();

        $response = $this->browse('POST', self::url('mail', '/acs'), ['token' => $token]);

        $this->assertSame(403, $response['status']);
        $this->assertStringContainsString('Token already used!', $response['body']);
    }

    public function testATokenForMailIsRefusedByCrm()
    {
        $token = $this->logInThroughMail();

        $response = $this->browse('POST', self::url('crm', '/acs'), ['token' => $token]);

        $this->assertSame(403, $response['status']);
        $this->assertStringContainsString('Token is not addressed to the expected audience! Expected: &#039;crm&#039;. Token audience: &#039;mail&#039;.', $response['body']);
        $this->assertNull($this->cookies('crm.localhost:' . self::PORT));
    }

    public function testIdpOnlyPostsTokensToTheRegisteredAddress()
    {
        $response = $this->browse('GET', self::url('idp', '/sso?app=mail&return=' . rawurlencode('http://evil.example/steal')));

        $this->assertSame(400, $response['status']);
        $this->assertStringContainsString('the return address is not the one registered for mail', $response['body']);
    }

    public function testAWrongPasswordIsRefused()
    {
        $response = $this->browse('POST', self::url('idp', '/login'), [
            'app' => 'mail', 'return' => self::url('mail', '/acs'), 'username' => 'ragnar', 'password' => 'wrong',
        ], 'http://idp.localhost:' . self::PORT);

        $this->assertSame(200, $response['status']);
        $this->assertStringContainsString('Wrong user name or password.', $response['body']);
        $this->assertNull($this->cookies('idp.localhost:' . self::PORT));
    }

    public function testOtherHostNamesAreRefused()
    {
        $response = $this->demo->handle(Http::request('GET', 'attacker.example:' . self::PORT, '/'));
        $this->assertSame(421, $response['status']);

        $response = $this->demo->handle(Http::request('GET', 'evil.localhost:' . self::PORT, '/'));
        $this->assertSame(421, $response['status']);
    }

    public function testTheTraceIsOnlyResetByAPageOfTheDemo()
    {
        $this->logInThroughMail();

        $refused = $this->browse('POST', self::url('mail', '/trace/reset'), [], 'http://attacker.example');
        $this->assertSame(403, $refused['status']);

        $this->browse('POST', self::url('mail', '/trace/reset'), [], 'http://mail.localhost:' . self::PORT);
        $this->assertSame([], json_decode($this->browse('GET', self::url('mail', '/trace.json'))['body'], true)['events']);
        // The sessions are closed too: mail asks idp again, which asks for the password.
        $this->assertSame(303, $this->browse('GET', self::url('mail'))['status']);
    }

    public function testTheFlowWithEncryptedTokens()
    {
        $this->requireSymmetricEncryption();
        $this->demo = new Demo($this->varDir, new Settings(['encrypt' => true]));
        $this->browser = new Browser($this->demo);

        $response = $this->browse('GET', self::url('mail'));
        $response = $this->browse('GET', $response['headers']['Location']);
        $response = $this->browse('POST', self::url('idp', '/login'), [
            'app' => 'mail', 'return' => self::url('mail', '/acs'), 'username' => 'lagertha', 'password' => 'shieldmaiden',
        ], 'http://idp.localhost:' . self::PORT);
        list($action, $token) = self::postedToken($response);
        $xml = base64_decode($token);
        $this->assertStringContainsString('EncryptedData', $xml);
        $this->assertStringNotContainsString('Lagertha', $xml, 'The data are not readable in the token.');

        $response = $this->browse('POST', $action, ['token' => $token]);
        $this->assertSame(303, $response['status'], $response['body']);
        $this->assertStringContainsString('Shieldmaiden', $this->browse('GET', self::url('mail'))['body']);
    }

    public function testTheSettingsAreOnlyChangedByAPageOfTheDemo()
    {
        $refused = $this->browse('POST', 'http://localhost:' . self::PORT . '/settings', ['replay' => 'false'], 'http://attacker.example');
        $this->assertSame(403, $refused['status']);
        $this->assertTrue($this->demo->settings()->on('replay'));

        $this->browse('POST', 'http://localhost:' . self::PORT . '/settings', ['replay' => 'false'], 'http://localhost:' . self::PORT);
        $this->assertFalse($this->demo->settings()->on('replay'));
        $this->assertTrue($this->demo->settings()->on('audience'), 'The other settings are kept.');
    }

    /**
     * Logs in as a user through an application, and posts the token idp
     * signs, if it signs one.
     *
     * @return array The response of idp, or of the application.
     */
    private function logInAs($user, $password, $app)
    {
        $response = $this->browse('GET', self::url($app));
        $response = $this->browse('GET', $response['headers']['Location']);
        if (200 === $response['status'] && false !== strpos($response['body'], 'Log in to continue'))
        {
            $response = $this->browse('POST', self::url('idp', '/login'), [
                'app' => $app, 'return' => self::url($app, '/acs'), 'username' => $user, 'password' => $password,
            ], 'http://idp.localhost:' . self::PORT);
        }
        $posted = Browser::postedToken($response);

        return is_null($posted) ? $response : $this->browse('POST', $posted['action'], ['token' => $posted['token']]);
    }

    public function testIdpSignsNoTokenForAnApplicationTheUserMayNotEnter()
    {
        $this->assertSame(303, $this->logInAs('bjorn', 'ironside', 'mail')['status']);

        $response = $this->logInAs('bjorn', 'ironside', 'crm');

        $this->assertSame(403, $response['status']);
        $this->assertStringContainsString('No access to crm', $response['body']);
        $this->assertNull(Browser::postedToken($response));
        $this->assertNull($this->cookies('crm.localhost:' . self::PORT));
    }

    public function testCrmLetsOnlySomeRolesDeleteACustomer()
    {
        $this->logInAs('lagertha', 'shieldmaiden', 'crm');
        $page = $this->browse('GET', self::url('crm'))['body'];
        $this->assertStringContainsString('Delete customers: not allowed for the role Shieldmaiden', $page);
        $refused = $this->browse('POST', self::url('crm', '/customers/delete'), ['id' => 'c2'], 'http://crm.localhost:' . self::PORT);
        $this->assertSame(403, $refused['status']);
        $this->assertStringContainsString('King Ecbert', $this->browse('GET', self::url('crm'))['body']);
    }

    public function testAJarlDeletesACustomer()
    {
        $this->logInAs('ragnar', 'kattegat', 'crm');
        $this->assertStringContainsString('King Ecbert', $this->browse('GET', self::url('crm'))['body']);

        $response = $this->browse('POST', self::url('crm', '/customers/delete'), ['id' => 'c2'], 'http://crm.localhost:' . self::PORT);

        $this->assertSame(303, $response['status']);
        $this->assertStringNotContainsString('King Ecbert', $this->browse('GET', self::url('crm'))['body']);
        // A request from another site is refused.
        $this->assertSame(403, $this->browse('POST', self::url('crm', '/customers/delete'), ['id' => 'c1'], 'http://attacker.example')['status']);
    }

    public function testThePagesEscapeWhatTheyShow()
    {
        $response = $this->browse('GET', self::url('idp', '/sso?app=mail&return=' . rawurlencode('<script>alert(1)</script>')));

        $this->assertStringNotContainsString('<script>alert(1)', $response['body']);
    }
}
