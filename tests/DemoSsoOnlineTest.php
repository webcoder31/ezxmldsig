<?php

namespace webcoder31\ezxmldsig\Tests;

use webcoder31\ezxmldsig\DemoSso\AttackLab;
use webcoder31\ezxmldsig\DemoSso\Base;
use webcoder31\ezxmldsig\DemoSso\Browser;
use webcoder31\ezxmldsig\DemoSso\Demo;
use webcoder31\ezxmldsig\DemoSso\Http;
use webcoder31\ezxmldsig\DemoSso\Sites;
use webcoder31\ezxmldsig\DemoSso\Visitors;

/**
 * The single sign-on demo online: its sites are the subdomains of a public
 * domain, served over HTTPS, and each visitor has a directory of their own.
 */
class DemoSsoOnlineTest extends TestCase
{
    const DOMAIN = 'sso.example.org';

    /** @var string */
    private $varDir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->varDir = sys_get_temp_dir() . '/ezxmldsig-sso-online-' . bin2hex(random_bytes(8));
    }

    protected function tearDown(): void
    {
        Visitors::remove($this->varDir);
        parent::tearDown();
    }

    private static function url($site, $path = '/')
    {
        return 'https://' . (Sites::HOME === $site ? '' : $site . '.') . self::DOMAIN . $path;
    }

    public function testThePublicDomainAndItsSitesAreAnsweredWithoutAPort()
    {
        $parsed = Sites::parseHost('mail.' . self::DOMAIN, self::DOMAIN);
        $this->assertSame('mail', $parsed['site']);
        $this->assertSame('https://mail.' . self::DOMAIN, $parsed['base']->origin('mail'));
        $this->assertTrue($parsed['base']->isOnline());
        $this->assertSame('home', Sites::parseHost(self::DOMAIN, self::DOMAIN)['site']);
        $this->assertSame('https://' . self::DOMAIN, $parsed['base']->origin(Sites::HOME));

        // The local names are still answered, and another name is refused.
        $this->assertSame('idp', Sites::parseHost('idp.localhost:8090', self::DOMAIN)['site']);
        $this->assertFalse(Sites::parseHost('idp.localhost:8090', self::DOMAIN)['base']->isOnline());
        $this->assertNull(Sites::parseHost('mail.' . self::DOMAIN . ':8090', self::DOMAIN));
        $this->assertNull(Sites::parseHost('evil.' . self::DOMAIN, self::DOMAIN));
        $this->assertNull(Sites::parseHost('mail.' . self::DOMAIN . '.evil.org', self::DOMAIN));
        $this->assertNull(Sites::parseHost('mail.' . self::DOMAIN));
    }

    public function testTheWholeFlowOverHttps()
    {
        $browser = new Browser(new Demo($this->varDir, null, self::DOMAIN));

        $response = $browser->request('GET', self::url('mail'));
        $this->assertSame(303, $response['status']);
        $this->assertStringStartsWith(self::url('idp', '/sso?'), $response['headers']['Location']);
        $this->assertStringContainsString(rawurlencode(self::url('mail', '/acs')), $response['headers']['Location']);

        $response = $browser->request('GET', $response['headers']['Location']);
        $this->assertStringContainsString('mail.' . self::DOMAIN . ' sent you here', $response['body']);

        $response = $browser->request('POST', self::url('idp', '/login'), [
            'app' => 'mail', 'return' => self::url('mail', '/acs'), 'username' => 'ragnar', 'password' => 'kattegat',
        ], self::url('idp', ''));
        $posted = Browser::postedToken($response);
        $this->assertSame(self::url('mail', '/acs'), $posted['action']);

        $response = $browser->request('POST', $posted['action'], ['token' => $posted['token']], self::url('idp', ''));
        $this->assertSame(303, $response['status'], $response['body']);
        $this->assertArrayHasKey('mail_session', $browser->cookies('mail.' . self::DOMAIN));

        // Single sign-on to crm, without the password.
        $response = $browser->follow($browser->request('GET', self::url('crm')));
        $posted = Browser::postedToken($response);
        $this->assertSame(self::url('crm', '/acs'), $posted['action']);
        $response = $browser->follow($browser->request('POST', $posted['action'], ['token' => $posted['token']], self::url('idp', '')));
        $this->assertStringContainsString('Your customers, Ragnar Lothbrok', $response['body']);
        $this->assertStringContainsString('Cookies of crm.' . self::DOMAIN, $response['body']);
    }

    public function testAnHttpOriginIsRefusedOnline()
    {
        $browser = new Browser(new Demo($this->varDir, null, self::DOMAIN));

        $refused = $browser->request('POST', self::url(Sites::HOME, '/settings'), ['replay' => 'false'], 'http://' . self::DOMAIN);
        $this->assertSame(403, $refused['status']);

        $accepted = $browser->request('POST', self::url(Sites::HOME, '/settings'), ['replay' => 'false'], self::url(Sites::HOME, ''));
        $this->assertSame(200, $accepted['status']);
    }

    public function testTheAttackLabGivesTheSameVerdictsOnline()
    {
        foreach (AttackLab::catalog() as $attack)
        {
            foreach ([true, false] as $protected)
            {
                $local = (new AttackLab($this->varDir, Base::local(8090)))->run($attack['id'], $protected);
                $online = (new AttackLab($this->varDir, Base::online(self::DOMAIN)))->run($attack['id'], $protected);

                $this->assertSame($local['accepted'], $online['accepted'], $attack['id']);
                // A message may name an address of the sites, which differs.
                $this->assertSame(
                    json_encode($local['stoppedBy']),
                    str_replace(['https:\\/\\/mail.' . self::DOMAIN, 'https:\\/\\/crm.' . self::DOMAIN], ['http:\\/\\/mail.localhost:8090', 'http:\\/\\/crm.localhost:8090'], json_encode($online['stoppedBy'])),
                    $attack['id']
                );
            }
        }
    }

    public function testForgetIdleRemovesOnlyTheVisitorsGoneForLonger()
    {
        $gone = $this->varDir . '/visitors/' . Visitors::newId();
        $back = $this->varDir . '/visitors/' . Visitors::newId();
        mkdir($gone . '/sessions', 0700, true);
        mkdir($back . '/sessions', 0700, true);
        file_put_contents($gone . '/trace.json', '[]');
        file_put_contents($back . '/trace.json', '[]');
        file_put_contents($back . '/sessions/mail-x.json', '{}');
        touch($gone . '/trace.json', time() - 7200);
        touch($gone . '/sessions', time() - 7200);
        touch($gone, time() - 7200);
        touch($back . '/trace.json', time() - 7200);
        touch($back, time() - 7200);

        Visitors::forgetIdle($this->varDir . '/visitors', 3600);

        $this->assertDirectoryDoesNotExist($gone);
        // A session written recently keeps the whole directory.
        $this->assertDirectoryExists($back);
    }

    public function testAVisitorCookieIsAnIdentifierOrNothing()
    {
        $this->assertSame(str_repeat('a', 32), Visitors::fromCookie(str_repeat('a', 32)));
        $this->assertNull(Visitors::fromCookie('../../etc'));
        $this->assertNull(Visitors::fromCookie(null));
        $this->assertNull(Visitors::fromCookie(['x']));
    }

    public function testTheHealthCheckAnswersOnAnyHost()
    {
        $source = file_get_contents(dirname(__DIR__) . '/demo-sso/public/index.php');

        // Before the host check, so that the health check of the container
        // (on 127.0.0.1) gets it.
        $this->assertLessThan(strpos($source, 'Sites::parseHost('), strpos($source, "'/health' === \$path"));
        $this->assertSame(421, (new Demo($this->varDir, null, self::DOMAIN))->handle(Http::request('GET', '127.0.0.1:8000', '/'))['status']);
    }
}
