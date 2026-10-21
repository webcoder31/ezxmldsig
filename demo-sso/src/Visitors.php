<?php

namespace webcoder31\ezxmldsig\DemoSso;

/**
 * The visitors of the demo online, each with a directory of their own:
 * sessions, trace, protections and replay memories (what demo-sso/var/
 * holds on this machine, for its only visitor).
 *
 * A cookie names the directory. It is set on the domain of the demo, so
 * that the browser sends it to the home page and to the three sites, and to
 * no other host: a session cookie of a site stays host-only, as on this
 * machine. A directory left unwritten for a while is removed when a new
 * visitor arrives.
 */
final class Visitors
{
    /** The name of the cookie. */
    const COOKIE = 'sso_visitor';

    /** How long a directory may stay unwritten, in seconds: two days. */
    const IDLE = 172800;

    /**
     * Returns the identifier a cookie carries, or NULL if it carries none.
     *
     * @param mixed $value The value of the cookie.
     *
     * @return string|null
     */
    public static function fromCookie($value)
    {
        return is_string($value) && preg_match('/\A[0-9a-f]{32}\z/', $value) ? $value : null;
    }

    /**
     * Returns a new identifier.
     *
     * @return string
     */
    public static function newId()
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * Removes the directories of $dir whose files have not been written to
     * for longer than $idle seconds.
     *
     * @param string $dir
     * @param int $idle
     */
    public static function forgetIdle($dir, $idle = self::IDLE)
    {
        $limit = time() - $idle;
        foreach (glob($dir . '/*', GLOB_ONLYDIR) ?: [] as $visitor)
        {
            if (self::lastWritten($visitor) < $limit)
            {
                self::remove($visitor);
            }
        }
    }

    /**
     * Removes a directory and its content.
     *
     * @param string $dir
     */
    public static function remove($dir)
    {
        foreach (glob($dir . '/*') ?: [] as $file)
        {
            is_dir($file) ? self::remove($file) : unlink($file);
        }
        if (is_dir($dir))
        {
            rmdir($dir);
        }
    }

    /**
     * Returns when a directory or one of its files was last written to.
     */
    private static function lastWritten($dir)
    {
        $last = (int) @filemtime($dir);
        foreach (glob($dir . '/*') ?: [] as $file)
        {
            $last = max($last, is_dir($file) ? self::lastWritten($file) : (int) @filemtime($file));
        }

        return $last;
    }
}
