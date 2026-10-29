<?php

namespace webcoder31\ezxmldsig\Tests;

/**
 * bin/dss is a copy of bin/dss of the Node.js library: the seals of both
 * libraries are validated by the same DSS only if the copy keeps its image,
 * its trust anchors, its configuration and its test PKI. The original is
 * that of the clone of the Node.js library bin/js-ezxmldsig makes.
 */
class DssScriptTest extends TestCase
{
    /** The values both scripts must give the same. */
    const SETTINGS = ['IMAGE', 'REPOSITORY', 'TAG', 'COMMIT', 'PKI_HOST', 'PKI_IMAGE', 'KEYSTORE_PASSWORD'];

    private static function original()
    {
        preg_match('/^JS_TAG=(\S+)$/m', file_get_contents(dirname(__DIR__) . '/bin/js-ezxmldsig'), $tag);
        return dirname(__DIR__) . '/tests/.cache/ezxmldsig-js-' . $tag[1] . '/bin/dss';
    }

    /** The settings, the trust anchors and the configuration of a script. */
    private static function essentials($script)
    {
        $essentials = [];
        foreach (self::SETTINGS as $name)
        {
            preg_match('/^' . $name . '=(.*)$/m', $script, $value);
            $essentials[$name] = isset($value[1]) ? $value[1] : null;
        }
        preg_match('/^\s*for name in ([^;]+); do$/m', $script, $anchors);
        $essentials['anchors'] = isset($anchors[1]) ? $anchors[1] : null;
        preg_match('/dss-custom\.properties" <<EOF\n(.*?)\nEOF\n/s', $script, $properties);
        $essentials['properties'] = isset($properties[1]) ? $properties[1] : null;
        return $essentials;
    }

    public function testTheCopyKeepsTheImageTheTrustAndTheConfigurationOfTheOriginal()
    {
        $original = self::original();
        if (!is_file($original))
        {
            $this->markTestSkipped($original . ' is missing: bin/test clones the Node.js library.');
        }
        $copy = self::essentials(file_get_contents(dirname(__DIR__) . '/bin/dss'));
        $this->assertNotContains(null, $copy);
        $this->assertSame(self::essentials(file_get_contents($original)), $copy);
    }
}
