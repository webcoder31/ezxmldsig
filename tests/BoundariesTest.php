<?php

namespace webcoder31\ezxmldsig\Tests;

use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

/**
 * The boundaries of the branches of the library: the core
 * (webcoder31\ezxmldsig\core) refers neither to the tokens nor to the seals,
 * and the tokens (webcoder31\ezxmldsig\token) and the seals
 * (webcoder31\ezxmldsig\seal) do not refer to each other. The references are
 * read from the sources, as text.
 */
class BoundariesTest extends TestCase
{
    const ALLOWED = [
        'core' => ['core'],
        'token' => ['core', 'token'],
        'seal' => ['core', 'seal'],
    ];

    /**
     * The PHP files of src/, by their path relative to it.
     */
    private static function sources()
    {
        $src = dirname(__DIR__) . '/src/';
        $files = [];
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($src, RecursiveDirectoryIterator::SKIP_DOTS)) as $file)
        {
            if ('php' === $file->getExtension())
            {
                $files[] = substr($file->getPathname(), strlen($src));
            }
        }
        sort($files);
        return $files;
    }

    public function testEverySourceIsInABranchAndItsNamespace()
    {
        $misplaced = [];
        foreach (self::sources() as $path)
        {
            $branch = explode('/', $path)[0];
            $text = file_get_contents(dirname(__DIR__) . '/src/' . $path);
            if (!isset(self::ALLOWED[$branch]) || 2 !== count(explode('/', $path))
                || 1 !== preg_match('/^namespace webcoder31\\\\ezxmldsig\\\\' . $branch . ';$/m', $text))
            {
                $misplaced[] = $path;
            }
        }
        $this->assertSame([], $misplaced);
    }

    public function testEachBranchRefersOnlyToTheBranchesItMay()
    {
        $crossings = [];
        foreach (self::sources() as $path)
        {
            $branch = explode('/', $path)[0];
            $text = file_get_contents(dirname(__DIR__) . '/src/' . $path);
            preg_match_all('/webcoder31\\\\ezxmldsig\\\\([A-Za-z]+)/', $text, $matches);
            foreach (array_unique($matches[1]) as $to)
            {
                if (!in_array($to, self::ALLOWED[$branch] ?? [], true))
                {
                    $crossings[] = $path . ' refers to ' . $to;
                }
            }
        }
        $this->assertSame([], $crossings);
    }

    /**
     * ezxmldsig.php loads the library without Composer: it must require
     * every file of src/.
     */
    public function testTheLoaderRequiresEverySource()
    {
        $loader = file_get_contents(dirname(__DIR__) . '/ezxmldsig.php');
        preg_match_all("/require \\\$ezxmldsig_srcdir \\. '\\/([^']+)';/", $loader, $matches);
        $this->assertSame(self::sources(), $matches[1]);
    }
}
