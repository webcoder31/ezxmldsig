<?php

namespace webcoder31\ezxmldsig\DemoSso;

/**
 * The trace of the SSO flow, shown by every site: what each site did, in
 * order, and what passed between them.
 *
 * The three sites write it to one JSON file (demo-sso/var/trace.json),
 * under an exclusive lock. The demo runs on one machine for one person: the
 * trace is not split by browser.
 */
final class Trace
{
    /** The events kept, the oldest dropped first. */
    const MAX_EVENTS = 200;

    /** @var string */
    private $path;

    /**
     * @param string $path The JSON file, created if needed.
     */
    public function __construct($path)
    {
        $this->path = $path;
    }

    /**
     * Adds an event.
     *
     * @param array $event
     *     - from, to: the lanes the event goes between ('browser', 'idp',
     *       'mail', 'crm'); the same lane for an event within a site;
     *     - title: what happened, in one sentence;
     *     - detail: more about it (optional);
     *     - kind: 'info', 'ok', 'bad' or 'sso' (optional, default 'info');
     *     - http: the request or response, e.g. "303 → http://idp…"
     *       (optional);
     *     - xml: a token that passed (optional);
     *     - steps: the checks of a receiver (optional, see
     *       Demo\Receiver::verify());
     *     - cookie: a cookie set or deleted, ['site', 'name', 'action']
     *       (optional).
     */
    public function add(array $event)
    {
        $this->update(function (array $events) use ($event) {
            $last = end($events);
            $events[] = $event + [
                'id' => (false === $last ? 0 : $last['id']) + 1,
                'at' => gmdate('H:i:s'),
                'kind' => 'info',
            ];

            return [array_slice($events, -self::MAX_EVENTS), null];
        });
    }

    /**
     * Returns the events, oldest first.
     *
     * @return array[]
     */
    public function all()
    {
        return $this->update(function (array $events) {
            return [$events, $events];
        });
    }

    /**
     * Forgets every event.
     */
    public function clear()
    {
        $this->update(function () {
            return [[], null];
        });
    }

    /**
     * Reads the events, changes them under the lock, and returns a result.
     */
    private function update(callable $change)
    {
        $dir = dirname($this->path);
        if (!is_dir($dir))
        {
            mkdir($dir, 0700, true);
        }
        $handle = fopen($this->path, 'c+');
        if (false === $handle || !flock($handle, LOCK_EX))
        {
            throw new \RuntimeException('Cannot open the trace.');
        }
        try
        {
            $events = json_decode((string) stream_get_contents($handle), true);
            list($events, $result) = $change(is_array($events) ? $events : []);
            ftruncate($handle, 0);
            rewind($handle);
            fwrite($handle, json_encode(array_values($events)));
            fflush($handle);

            return $result;
        }
        finally
        {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }
}
