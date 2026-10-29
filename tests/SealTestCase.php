<?php

namespace webcoder31\ezxmldsig\Tests;

use webcoder31\ezxmldsig\Tests\helpers\SealPki;
use webcoder31\ezxmldsig\Tests\helpers\TestCrl;
use webcoder31\ezxmldsig\Tests\helpers\TestOcsp;
use webcoder31\ezxmldsig\Tests\helpers\TestTsa;
use webcoder31\ezxmldsig\core\Algorithms;
use webcoder31\ezxmldsig\seal\Seal;
use webcoder31\ezxmldsig\seal\Zip;

/**
 * Base class of the tests of the seals ported from the Node.js library: a
 * seal of the test PKI, its time-stamp by the test authority, and the
 * rewriting of a container. The times of a test are relative to its start
 * (ago()): a seal time-stamped at its start keeps its place among the CRLs
 * and responses the test makes later.
 */
abstract class SealTestCase extends TestCase
{
    const SIGNATURE = 'META-INF/signatures001.xml';

    /** @var float The start of the test, a UNIX time. */
    protected $now;

    protected function setUp(): void
    {
        parent::setUp();
        $this->now = microtime(true);
    }

    /** The UNIX time some seconds before the start of the test. */
    protected function ago($seconds)
    {
        return $this->now - $seconds;
    }

    /** Subjects of the test PKI, as the messages quote them. */
    protected static function subject($ou)
    {
        return '"/C=DK/O=Lothbrok Ltd/OU=' . $ou . '/CN=Lothbrok Seal Test"';
    }

    protected static function seal($key = 'rsa3072', array $options = [], array $files = null)
    {
        $files = null === $files ? [['name' => 'contrat.pdf', 'content' => "%PDF-1.4\n"]] : $files;
        $chain = SealPki::cert('offline' === $key ? 'intermediate-offline' : 'intermediate');
        return Seal::createSeal($files, SealPki::key($key), SealPki::cert($key), SealPki::PASSWORD, $options + ['chain' => [$chain]]);
    }

    /** A container time-stamped by the test authority (see TestTsa::response()). */
    protected static function timestamp($container, array $tsaOptions = [])
    {
        return Seal::addSignatureTimestamp($container, TestTsa::response(Seal::timestampRequest($container), $tsaOptions), ['tsaCertPath' => SealPki::cert('tsa-root')]);
    }

    /** The trust of the tests: the root of the signers and that of the authority. */
    protected static function trust(array $more = [])
    {
        return $more + ['caCertPath' => SealPki::cert('root'), 'tsaCertPath' => SealPki::cert('tsa-root')];
    }

    /** The entries of a container: each 'name', 'content', 'stored'. */
    protected static function entries($container)
    {
        return array_map(function ($e) { return ['name' => $e['name'], 'content' => $e['content'], 'stored' => 0 === $e['method']]; }, Zip::read($container));
    }

    /** The container with its entries changed. */
    protected static function rebuild($container, callable $change)
    {
        return Zip::write(array_values($change(self::entries($container))), gmmktime(12, 0, 0, 10, 28, 2026));
    }

    protected static function signatureXml($container)
    {
        foreach (Zip::read($container) as $entry)
        {
            if (self::SIGNATURE === $entry['name'])
            {
                return $entry['content'];
            }
        }
        return null;
    }

    /** The container with its signature file changed, as text; the change must apply. */
    protected function editSignature($container, callable $change)
    {
        return self::rebuild($container, function (array $entries) use ($change)
        {
            foreach ($entries as &$entry)
            {
                if (self::SIGNATURE === $entry['name'])
                {
                    $xml = $change($entry['content']);
                    $this->assertNotSame($entry['content'], $xml, 'the change applies');
                    $entry['content'] = $xml;
                }
            }
            return $entries;
        });
    }

    /**
     * The files of the sample seals: names a verifier could get wrong
     * (spaces, accents, a directory, # and %), and a media type with
     * parameters; those of the validation by DSS in test/seal/seal.test.ts
     * of the Node.js library.
     */
    protected static function sampleFiles()
    {
        return [
            ['name' => 'contrat final.pdf', 'content' => "%PDF-1.4\n"],
            ['name' => "notes d'\u{e9}t\u{e9}.md", 'content' => "# Notes d'\u{e9}t\u{e9}\n"],
            ['name' => 'docs/a#b%c.txt', 'content' => "odd name\n"],
            ['name' => 'data.bin', 'content' => "\x00\x01\x02\xff", 'mimeType' => 'application/x-test; charset="none"'],
        ];
    }

    /**
     * The seals made here that the verifiers apart from this library check
     * (SealJsTest: the Node.js library; SealDssTest: DSS): each algorithm at
     * level B, each level with RSA 3072, and level LT with an EC key. The
     * keys are the names of sampleSeal().
     */
    public function sampleSeals()
    {
        $names = ['B, RSA 3072, RSA-PSS', 'B, RSA 3072, PKCS#1 v1.5', 'B, RSA 2048, SHA-512 digests', 'B, P-256', 'B, P-384', 'B, P-521',
            'T, RSA 3072', 'LT by CRLs, RSA 3072', 'LT by OCSP, RSA 3072', 'LT by CRLs, P-384'];
        return array_combine($names, array_map(function ($name) { return [$name]; }, $names));
    }

    /**
     * A sample seal of sampleSeals(), of the files of sampleFiles():
     * 'container', 'key', 'level', and 'crls', the CRLs its verifier needs (none at
     * level LT: the seal embeds its own). It is signed 30 seconds ago and
     * time-stamped 20 seconds ago, before its validation data is issued.
     */
    protected static function sampleSeal($name)
    {
        list($level, $what) = explode(', ', $name, 2);
        $options = ['signingTime' => (int) microtime(true) - 30];
        switch ($what)
        {
            case 'RSA 3072, PKCS#1 v1.5': $key = 'rsa3072'; $options['signatureAlgorithm'] = Algorithms::RSA_SHA256; break;
            case 'RSA 2048, SHA-512 digests': $key = 'rsa2048'; $options['digestAlgorithm'] = Algorithms::SHA512; break;
            case 'P-256': $key = 'p256'; break;
            case 'P-384': $key = 'p384'; break;
            case 'P-521': $key = 'p521'; break;
            default: $key = 'rsa3072';
        }
        $container = self::seal($key, $options, self::sampleFiles());
        if ('B' !== $level)
        {
            $container = self::timestamp($container, ['time' => microtime(true) - 20]);
        }
        if ('LT by CRLs' === $level)
        {
            $container = Seal::addValidationData($container, self::trust(['crls' => TestCrl::current()]));
        }
        if ('LT by OCSP' === $level)
        {
            $container = Seal::addValidationData($container, self::trust([
                'crls' => [TestCrl::make(['issuer' => 'root']), TestCrl::make(['issuer' => 'tsa-root'])],
                'ocspResponses' => [TestOcsp::make(['cert' => $key, 'signer' => 'ocsp'])],
            ]));
        }
        $lt = 0 === strpos($level, 'LT');
        return ['container' => $container, 'key' => $key, 'level' => $lt ? 'LT' : $level, 'crls' => $lt ? [] : TestCrl::current()];
    }

    /** Asserts that a call throws an exception whose message matches a pattern. */
    protected function assertThrowsMatching($pattern, callable $run)
    {
        try
        {
            $run();
        }
        catch (\Exception $e)
        {
            $this->assertMatchesRegularExpression($pattern, $e->getMessage());
            return;
        }
        $this->fail('No exception; expected one matching ' . $pattern);
    }
}
