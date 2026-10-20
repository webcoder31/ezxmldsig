<?php

namespace webcoder31\ezxmldsig\Tests;

use webcoder31\ezxmldsig\DemoSso\AttackLab;

/**
 * Each attack of the attack lab of the SSO demo, run by the very code the
 * demo runs: refused with its protection on, by the expected check;
 * successful with its protection off.
 */
class DemoSsoAttackLabTest extends TestCase
{
    const UNTRUSTED_CA = "Signing certificate is not issued by a trusted CA: its chain could not be verified up to the CA certificates of the option 'caCertPath', which must hold the issuing CA and the certificates up to its root!";

    /**
     * Attack => [who stops it, the check, its message (or a part of it)].
     */
    const EXPECTED = [
        'other-app' => ['library', 'Audience', "Token is not addressed to the expected audience! Expected: 'crm'. Token audience: 'mail'."],
        'replay' => ['application', 'Replay', 'Token already used!'],
        'expired' => ['application', 'Freshness', 'Token is out of date!'],
        'return-url' => ['idp', 'Return address', 'the return address is not the one registered for mail'],
        'tamper' => ['library', 'Digest', 'Token hash verification failed!'],
        'other-idp' => ['library', 'Certificate trust', self::UNTRUSTED_CA],
        'wrong-key' => ['library', 'Decryption', 'Token decryption failed!'],
    ];

    /** @var string */
    private $varDir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->varDir = sys_get_temp_dir() . '/ezxmldsig-sso-lab-' . bin2hex(random_bytes(8));
        mkdir($this->varDir);
    }

    protected function tearDown(): void
    {
        // Each run removes its own sandbox: nothing is left.
        $this->assertSame([], glob($this->varDir . '/*'));
        rmdir($this->varDir);
        parent::tearDown();
    }

    public function provideAttacks()
    {
        $cases = [];
        foreach (self::EXPECTED as $id => $expected)
        {
            $cases[$id] = array_merge([$id], $expected);
        }

        return $cases;
    }

    /**
     * @dataProvider provideAttacks
     */
    public function testTheAttackIsRefusedByItsCheck($id, $by, $label, $message)
    {
        if ('wrong-key' === $id)
        {
            $this->requireSymmetricEncryption();
        }

        $result = (new AttackLab($this->varDir, 8090))->run($id, true);

        $this->assertFalse($result['accepted']);
        $this->assertSame($by, $result['stoppedBy']['by']);
        $this->assertSame($label, $result['stoppedBy']['label']);
        $this->assertStringContainsString($message, $result['stoppedBy']['message']);
        $this->assertNotEmpty($result['events']);
    }

    public function provideProtections()
    {
        $cases = [];
        foreach (AttackLab::ATTACKS as $id => $attack)
        {
            if (!is_null($attack['protection']))
            {
                $cases[$id] = [$id];
            }
        }

        return $cases;
    }

    /**
     * @dataProvider provideProtections
     */
    public function testTheAttackSucceedsWithItsProtectionOff($id)
    {
        $result = (new AttackLab($this->varDir, 8090))->run($id, false);

        $this->assertFalse($result['protected']);
        $this->assertTrue($result['accepted'], 'The attacker gets a session.');
        $this->assertNull($result['stoppedBy']);
    }

    public function testTheAttacksOfTheLibraryHaveNoSwitch()
    {
        foreach (['tamper', 'other-idp'] as $id)
        {
            $result = (new AttackLab($this->varDir, 8090))->run($id, false);
            $this->assertTrue($result['protected'], $id);
            $this->assertFalse($result['accepted'], $id);
        }
    }

    public function testEveryAttackIsTested()
    {
        $this->assertEqualsCanonicalizing(array_keys(AttackLab::ATTACKS), array_keys(self::EXPECTED));
    }
}
