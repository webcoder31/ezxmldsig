<?php

namespace webcoder31\ezxmldsig\Tests;

use webcoder31\ezxmldsig\Tests\helpers\SealPki;
use webcoder31\ezxmldsig\Tests\helpers\TestTsa;
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
