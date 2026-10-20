<?php

namespace webcoder31\ezxmldsig\DemoSso;

/**
 * The sessions of the three sites, one JSON file per session in
 * demo-sso/var/sessions/.
 *
 * Each site keeps its own sessions, under its own cookie
 * (`<site>_session`): the session of idp is not that of mail, which is not
 * that of crm. That is what single sign-on is about: idp remembers who
 * logged in, and each application, once it has verified a token from idp,
 * opens a session of its own.
 */
final class SessionStore
{
    /** @var string */
    private $dir;

    /**
     * @param string $dir The directory of the session files, created if
     *     needed.
     */
    public function __construct($dir)
    {
        $this->dir = $dir;
    }

    /**
     * Returns the session of a site that a cookie names, or NULL.
     *
     * @param string $site
     * @param string|null $id The value of the session cookie.
     *
     * @return array|null
     */
    public function get($site, $id)
    {
        $file = $this->file($site, $id);
        if (is_null($file) || !is_file($file))
        {
            return null;
        }
        $session = json_decode((string) file_get_contents($file), true);

        return is_array($session) ? $session : null;
    }

    /**
     * Opens a session, and returns its identifier, to be set in the session
     * cookie of the site.
     *
     * @param string $site
     * @param array $session
     *
     * @return string
     */
    public function open($site, array $session)
    {
        $id = bin2hex(random_bytes(16));
        if (!is_dir($this->dir))
        {
            mkdir($this->dir, 0700, true);
        }
        file_put_contents($this->file($site, $id), json_encode($session + ['openedAt' => time()]), LOCK_EX);

        return $id;
    }

    /**
     * Replaces the content of an open session.
     *
     * @param string $site
     * @param string $id
     * @param array $session
     */
    public function update($site, $id, array $session)
    {
        $file = $this->file($site, $id);
        if (!is_null($file) && is_file($file))
        {
            file_put_contents($file, json_encode($session), LOCK_EX);
        }
    }

    /**
     * Closes a session.
     *
     * @param string $site
     * @param string|null $id
     */
    public function close($site, $id)
    {
        $file = $this->file($site, $id);
        if (!is_null($file) && is_file($file))
        {
            unlink($file);
        }
    }

    /**
     * Closes every session of every site.
     */
    public function clear()
    {
        foreach (glob($this->dir . '/*.json') ?: [] as $file)
        {
            unlink($file);
        }
    }

    /**
     * Returns the file of a session, or NULL for an identifier that cannot
     * be one.
     */
    private function file($site, $id)
    {
        if (!is_string($id) || !preg_match('/\A[0-9a-f]{32}\z/', $id) || !preg_match('/\A[a-z]+\z/', $site))
        {
            return null;
        }

        return $this->dir . '/' . $site . '-' . $id . '.json';
    }
}
