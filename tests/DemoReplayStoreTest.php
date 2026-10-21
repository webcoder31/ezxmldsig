<?php

namespace webcoder31\ezxmldsig\Tests;

use webcoder31\ezxmldsig\Demo\ReplayStore;

/**
 * The replay memory of the demo in a file: online, each visitor has one
 * (see demo/public/index.php), so that reading one creates no file, and the
 * memories left unwritten are removed.
 */
class DemoReplayStoreTest extends TestCase
{
    public function testReadingOrClearingAMemoryNeverWrittenCreatesNoFile()
    {
        $path = dirname($this->tempFile('other.json', '')) . '/visitor.json';
        $store = new ReplayStore($path);

        $this->assertSame(0, $store->size());
        $store->clear();

        $this->assertFileDoesNotExist($path);
    }

    public function testTheFirstAcceptanceCreatesTheMemory()
    {
        $path = dirname($this->tempFile('other.json', '')) . '/visitor.json';
        $store = new ReplayStore($path);

        $this->assertTrue($store->add('id1', 60)['added']);
        $this->assertFalse($store->add('id1', 60)['added']);
        $this->assertSame(1, (new ReplayStore($path))->size());
    }

    public function testForgetIdleRemovesOnlyTheMemoriesUnwrittenForLonger()
    {
        $idle = $this->tempFile('idle.json', '{}');
        $recent = $this->tempFile('recent.json', '{}');
        $other = $this->tempFile('notes.txt', 'not a memory');
        touch($idle, time() - 7200);
        touch($other, time() - 7200);

        ReplayStore::forgetIdle(dirname($idle), 3600);

        $this->assertFileDoesNotExist($idle);
        $this->assertFileExists($recent);
        $this->assertFileExists($other);
    }
}
