<?php

namespace webcoder31\ezxmldsig\DemoSso;

use webcoder31\ezxmldsig\Demo\Certs;
use webcoder31\ezxmldsig\Demo\Forge;
use webcoder31\ezxmldsig\token\XMLDSigToken;

/**
 * The attack lab of the SSO demo.
 *
 * Each attack is played from start to end in a sandbox of its own (a
 * temporary directory for the sessions, the trace and the replay
 * memories), with two browsers: the victim, who logs in, and the attacker.
 * It runs the very code of the sites, with the protections given.
 *
 * Four attacks are stopped by a protection of the code of idp or of the
 * applications, which the lab can turn off for a run: the attack then
 * succeeds. Three are stopped by the library itself: they have no switch,
 * since turning the library off would show nothing true.
 */
final class AttackLab
{
    /**
     * The attacks. Each one has:
     * - title, summary: what the attacker does;
     * - protection: the setting that stops it (see Settings), or NULL when
     *   the library stops it;
     * - by: who makes the check that stops it ('application', 'idp' or
     *   'library');
     * - lesson: what it teaches, in one sentence.
     */
    const ATTACKS = [
        'other-app' => [
            'title' => 'Token for another application',
            'summary' => 'The operator of MAIL, or anyone who reads its traffic, presents to CRM the token IDP signed for MAIL.',
            'protection' => 'audience',
            'by' => 'library',
            'lesson' => 'A token must name the application it is for, and each application must check it: IDP writes "audience", the application passes "expectedAudience", and isSignatureValid() refuses a token addressed to another one.',
        ],
        'replay' => [
            'title' => 'Replayed token',
            'summary' => 'An attacker captures the token the victim posted to MAIL, and posts it again from their own browser.',
            'protection' => 'replay',
            'by' => 'application',
            'lesson' => 'The library keeps no list of the tokens it has seen: the application stores getTokenId() and refuses an identifier it has already accepted.',
        ],
        'expired' => [
            'title' => 'Old token',
            'summary' => 'An attacker posts a token IDP signed for the victim ten minutes ago, long past its validity of ' . Sites::TOKEN_VALIDITY . ' s.',
            'protection' => 'freshness',
            'by' => 'application',
            'lesson' => 'isSignatureValid() does not check the age of a token: the application calls isOutOfDate(), which also enforces the expiry IDP wrote (option "validity").',
        ],
        'return-url' => [
            'title' => 'Hijacked return address',
            'summary' => 'The victim, logged in on IDP, follows a link the attacker made: idp/sso?app=mail, with an address of the attacker, evil…/steal, as return address. The token goes to the attacker, who presents it to MAIL.',
            'protection' => 'returnUrl',
            'by' => 'idp',
            'lesson' => 'IDP must only post a token to the address registered for the application; any other return address is a way to steal tokens. Every check of the library passes: the token is genuine, only its destination is wrong.',
        ],
        'tamper' => [
            'title' => 'Tampered token',
            'summary' => 'An attacker captures the victim\'s token and changes the role in it to "admin" before posting it to MAIL.',
            'protection' => null,
            'by' => 'library',
            'lesson' => 'The digest covers every byte of the token: a single change is detected. Computing the digest again does not help, since the signature covers the digest.',
        ],
        'other-idp' => [
            'title' => 'Token of another identity provider',
            'summary' => 'An attacker signs a token of their own with a certificate that another CA issued, with the very subject of IDP\'s certificate.',
            'protection' => null,
            'by' => 'library',
            'lesson' => 'The signature alone proves nothing: the application only trusts the CA of IDP (caCertPath) and its subject (expectedSubject).',
        ],
        'wrong-key' => [
            'title' => 'Encrypted token read by another application',
            'summary' => 'IDP encrypts each token for its application. The token encrypted for MAIL is presented to CRM, with the protection "audience" off.',
            'protection' => null,
            'by' => 'library',
            'lesson' => 'Encrypted with the certificate of MAIL, the token can only be decrypted with the private key of MAIL: CRM cannot even read it, whatever its audience.',
        ],
    ];

    /** The address of the attacker in the "return-url" attack. */
    const EVIL_PATH = '/steal';

    /** @var string */
    private $varDir;

    /** @var Base Where the sites live. */
    private $base;

    /**
     * @param string $varDir The directory under which each run gets a
     *     sandbox of its own (demo-sso/var/).
     * @param Base $base Where the sites live.
     */
    public function __construct($varDir, Base $base)
    {
        $this->varDir = $varDir;
        $this->base = $base;
    }

    /**
     * Returns the attacks, as the interface lists them.
     *
     * @return array[]
     */
    public static function catalog()
    {
        $catalog = [];
        foreach (self::ATTACKS as $id => $attack)
        {
            $catalog[] = ['id' => $id] + $attack;
        }

        return $catalog;
    }

    /**
     * Runs an attack.
     *
     * @param string $id The attack.
     * @param bool $protected Whether its protection is on (ignored for an
     *     attack the library stops).
     *
     * @return array
     *     - attack: the entry of catalog();
     *     - protected: whether the protection was on;
     *     - accepted: whether the attacker got a session;
     *     - stoppedBy: ['by' => 'library', 'application' or 'idp',
     *       'label' => the check, 'message' => its error], or NULL;
     *     - events: the trace of the run (see Trace).
     *
     * @throws \InvalidArgumentException For an unknown attack.
     */
    public function run($id, $protected)
    {
        if (!is_string($id) || !isset(self::ATTACKS[$id]))
        {
            throw new \InvalidArgumentException('Unknown attack.');
        }
        $attack = ['id' => $id] + self::ATTACKS[$id];
        $protected = is_null($attack['protection']) ? true : (bool) $protected;

        $values = [];
        if (!is_null($attack['protection']))
        {
            $values[$attack['protection']] = $protected;
        }
        if ('wrong-key' === $id)
        {
            $values = ['encrypt' => true, 'audience' => false];
        }

        $sandbox = $this->varDir . '/lab-' . bin2hex(random_bytes(8));
        try
        {
            $demo = new Demo($sandbox, new Settings($values), $this->base->isOnline() ? $this->base->domain() : null);
            $method = 'attack' . str_replace(' ', '', ucwords(str_replace('-', ' ', $id)));
            $accepted = $this->$method($demo);
            $events = (new Trace($sandbox . '/trace.json'))->all();
        }
        finally
        {
            Visitors::remove($sandbox);
        }

        return [
            'attack' => $attack,
            'protected' => $protected,
            'accepted' => $accepted,
            'stoppedBy' => $accepted ? null : self::stoppedBy($events),
            'events' => $events,
        ];
    }

    /**
     * The victim logs in through mail: returns the token idp posts to mail,
     * without posting it.
     */
    private function victimToken(Browser $victim)
    {
        $response = $victim->request('GET', $this->url('mail', '/'));
        $response = $victim->request('GET', $response['headers']['Location']);
        $response = $victim->request('POST', $this->url(Sites::IDP, '/login'), [
            'app' => 'mail', 'return' => Sites::acsUrl('mail', $this->base), 'username' => 'ragnar', 'password' => 'kattegat',
        ], Sites::origin(Sites::IDP, $this->base));

        return Browser::postedToken($response);
    }

    /**
     * Posts a token to an application, and tells whether it opened a
     * session.
     */
    private function present(Browser $browser, $acsUrl, $encodedToken)
    {
        $response = $browser->request('POST', $acsUrl, ['token' => $encodedToken]);

        return 303 === $response['status'];
    }

    private function attackOtherApp(Demo $demo)
    {
        $posted = $this->victimToken(new Browser($demo));

        return $this->present(new Browser($demo), Sites::acsUrl('crm', $this->base), $posted['token']);
    }

    private function attackReplay(Demo $demo)
    {
        $victim = new Browser($demo);
        $posted = $this->victimToken($victim);
        $this->present($victim, $posted['action'], $posted['token']);

        return $this->present(new Browser($demo), $posted['action'], $posted['token']);
    }

    private function attackExpired(Demo $demo)
    {
        $posted = $this->victimToken(new Browser($demo));

        // The token idp signed ten minutes ago: its dates are moved back and
        // it is signed again with the key of idp, as idp signed it then.
        $forge = new Forge($posted['xml']);
        $token = '/ds:Signature/ds:Object/Token/';
        $forge->node($token . 'TokenTimestamp')->nodeValue = gmdate('Y-m-d\TH:i:s\Z', time() - 600);
        $forge->node($token . 'TokenExpiry')->nodeValue = gmdate('Y-m-d\TH:i:s\Z', time() - 600 + Sites::TOKEN_VALIDITY);
        $forge->redigest();
        $forge->resign(Certs::path('sign.key.pem'), Certs::SIGN_KEY_PASSWORD, Certs::path('sign.cert.pem'));

        return $this->present(new Browser($demo), $posted['action'], base64_encode($forge->xml()));
    }

    private function attackReturnUrl(Demo $demo)
    {
        $victim = new Browser($demo);
        $posted = $this->victimToken($victim);
        $this->present($victim, $posted['action'], $posted['token']);

        // The victim follows the link of the attacker.
        $evil = $this->base->origin('evil') . self::EVIL_PATH;
        $response = $victim->request('GET', $this->url(Sites::IDP, '/sso?' . http_build_query(['app' => 'mail', 'return' => $evil])));
        $stolen = Browser::postedToken($response);
        if (is_null($stolen))
        {
            return false;
        }
        (new Trace($this->sandboxOf($demo) . '/trace.json'))->add([
            'from' => 'browser', 'to' => 'browser', 'kind' => 'bad',
            'title' => 'The browser of the victim posts the token to ' . $stolen['action'] . ': the attacker has it.',
        ]);

        return $this->present(new Browser($demo), Sites::acsUrl('mail', $this->base), $stolen['token']);
    }

    private function attackTamper(Demo $demo)
    {
        $posted = $this->victimToken(new Browser($demo));
        $forge = new Forge($posted['xml']);
        $forge->changeDataValue('admin');

        return $this->present(new Browser($demo), $posted['action'], base64_encode($forge->xml()));
    }

    private function attackOtherIdp(Demo $demo)
    {
        $posted = $this->victimToken(new Browser($demo));
        $forge = new Forge($posted['xml']);
        $forge->changeDataValue('admin');
        $forge->redigest();
        $forge->resign(Certs::path('rogue.key.pem'), null, Certs::path('rogue.cert.pem'));

        return $this->present(new Browser($demo), $posted['action'], base64_encode($forge->xml()));
    }

    private function attackWrongKey(Demo $demo)
    {
        $posted = $this->victimToken(new Browser($demo));

        return $this->present(new Browser($demo), Sites::acsUrl('crm', $this->base), $posted['token']);
    }

    /**
     * Returns the check that refused the token, read from the trace of the
     * run: the failed step of the application that refused it, or the
     * refusal of idp.
     */
    private static function stoppedBy(array $events)
    {
        foreach (array_reverse($events) as $event)
        {
            if ('bad' !== $event['kind'])
            {
                continue;
            }
            if (!empty($event['steps']))
            {
                foreach ($event['steps'] as $step)
                {
                    if ('fail' === $step['status'])
                    {
                        return ['by' => 'caller' === $step['by'] ? 'application' : 'library', 'label' => $step['label'], 'message' => $step['message']];
                    }
                }
            }
            if ('idp' === $event['from'])
            {
                return ['by' => 'idp', 'label' => 'Return address', 'message' => $event['title']];
            }
        }

        return null;
    }

    private function url($site, $path)
    {
        return Sites::origin($site, $this->base) . $path;
    }

    /**
     * Returns the sandbox of a run, from its Demo.
     */
    private function sandboxOf(Demo $demo)
    {
        return $demo->varDir();
    }
}
