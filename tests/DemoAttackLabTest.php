<?php

namespace webcoder31\ezxmldsig\Tests;

use webcoder31\ezxmldsig\Demo\AttackLab;
use webcoder31\ezxmldsig\Demo\Issuer;
use webcoder31\ezxmldsig\Demo\Receiver;

/**
 * Each attack of the attack lab of the demo, run by the very code the demo
 * runs: the legitimate token is accepted, the forged one is refused by the
 * expected check with the expected message.
 */
class DemoAttackLabTest extends TestCase
{
    const UNTRUSTED_CA = "Signing certificate is not issued by a trusted CA: its chain could not be verified up to the CA certificates of the option 'caCertPath', which must hold the issuing CA and the certificates up to its root!";

    /**
     * Attack => [step that refuses it, who makes it, its message]. For a
     * check of the library, the message is what getError() returns.
     */
    const EXPECTED = [
        'tamper' => ['digest', 'library', '1 anomaly detected: Token hash verification failed!'],
        'wrapping' => ['structure', 'library', 'XML digital signature is malformed! Exactly one element must have the attribute Id="Token".'],
        'copied-name' => ['trust', 'library', self::UNTRUSTED_CA],
        'ec-key' => ['signature', 'library', '1 anomaly detected: Token hash signature verification failed!'],
        'replay' => ['replay', 'caller', 'Token already used!'],
        'expired' => ['freshness', 'caller', 'Token is out of date!'],
        'other-audience' => ['audience', 'library', "Token is not addressed to the expected audience! Expected: 'receiver'. Token audience: 'mail'."],
        'past-expiry' => ['freshness', 'caller', 'Token is out of date!'],
        'doctype' => ['structure', 'library', 'XML Digital Signature must not have a document type declaration (DOCTYPE)!'],
        'ciphertext' => ['decryption', 'library', 'Token decryption failed!'],
        'untrusted-ca' => ['trust', 'library', self::UNTRUSTED_CA],
    ];

    public function provideRefusedAttacks()
    {
        $cases = [];
        foreach (self::EXPECTED as $id => $expected)
        {
            $cases[$id] = array_merge([$id], $expected);
        }

        return $cases;
    }

    /**
     * Runs an attack from a legitimate token of the kind it needs.
     */
    private function runAttack($id, array $receiver = [])
    {
        $base = AttackLab::ATTACKS[$id]['base'];
        if ('encrypted' === $base)
        {
            $this->requireSymmetricEncryption();
        }
        $lastXml = Issuer::create(Issuer::DEFAULT_DATA, 'encrypted' === $base)->getXML();

        $result = (new AttackLab(Receiver::fromArray($receiver)))->run($id, $lastXml);

        $this->assertSame('last', $result['base']['origin'], 'The attack starts from the last token.');
        $this->assertTrue($result['base']['verdict']['accepted'], 'The legitimate token is accepted.');
        $this->assertSame(Issuer::DEFAULT_DATA, $result['base']['verdict']['data']);

        return $result;
    }

    /**
     * @dataProvider provideRefusedAttacks
     */
    public function testTheAttackIsRefused($id, $step, $by, $message)
    {
        $result = $this->runAttack($id);

        $this->assertFalse($result['verdict']['accepted']);
        $this->assertNull($result['verdict']['data']);
        $this->assertSame($step, $result['stoppedBy']['id']);
        $this->assertSame($by, $result['stoppedBy']['by']);
        if ('library' === $by)
        {
            $this->assertFalse($result['verdict']['signatureValid']);
            $this->assertSame($message, $result['verdict']['error']);
        }
        else
        {
            // The library accepted the token: the caller's check refuses it.
            $this->assertTrue($result['verdict']['signatureValid']);
            $this->assertNull($result['verdict']['error']);
            $this->assertSame($message, $result['stoppedBy']['message']);
        }
        $this->assertNotEmpty($result['changes']);
    }

    public function testEveryAttackOfTheLabIsTested()
    {
        $this->assertEqualsCanonicalizing(
            array_keys(AttackLab::ATTACKS),
            array_merge(array_keys(self::EXPECTED), ['script'])
        );
    }

    public function testTheForgedDataNeverReachTheReceiver()
    {
        foreach (['tamper', 'wrapping', 'copied-name', 'ec-key', 'untrusted-ca'] as $id)
        {
            $result = $this->runAttack($id);
            $this->assertStringContainsString(base64_encode(AttackLab::FORGED_ROLE), $result['forged'], $id);
            $this->assertNull($result['verdict']['data'], $id);
        }
    }

    public function testAPinnedSignerRefusesTheCopiedCertificate()
    {
        $result = $this->runAttack('copied-name', ['ca' => false, 'pin' => true, 'subject' => false]);

        $this->assertSame('trust', $result['stoppedBy']['id']);
        $this->assertSame('Signing certificate is not the pinned certificate!', $result['verdict']['error']);
    }

    public function testTheExpiredTokenIsOlderThanTheTimeToLive()
    {
        $result = $this->runAttack('expired', ['ttl' => 300]);

        $this->assertSame('freshness', $result['stoppedBy']['id']);
    }

    /**
     * A token whose data hold HTML and script is legitimate: it is
     * accepted, and getHTMLDump() shows the value escaped.
     */
    public function testAScriptInTheDataIsAcceptedAsDataAndEscapedByTheHTMLDump()
    {
        $result = $this->runAttack('script');

        $this->assertTrue($result['verdict']['accepted']);
        $this->assertNull($result['stoppedBy']);
        $this->assertSame(AttackLab::SCRIPT_VALUE, $result['verdict']['data']['note']);
        $this->assertStringContainsString('&lt;script&gt;alert(1)&lt;/script&gt;', $result['htmlDump']);
        $this->assertStringNotContainsString('<script', $result['htmlDump']);
    }

    public function testAnAttackStartsFromAFreshTokenWhenTheLastOneDoesNotSuitIt()
    {
        $this->requireSymmetricEncryption();
        $lab = new AttackLab(Receiver::fromArray([]));

        // The last token is not encrypted: the encrypted attack creates one.
        $result = $lab->run('ciphertext', Issuer::create(Issuer::DEFAULT_DATA, false)->getXML());
        $this->assertSame('fresh', $result['base']['origin']);
        $this->assertTrue($result['base']['verdict']['accepted']);

        // No last token.
        $result = $lab->run('tamper', null);
        $this->assertSame('fresh', $result['base']['origin']);
        $this->assertSame('digest', $result['stoppedBy']['id']);
    }
}
