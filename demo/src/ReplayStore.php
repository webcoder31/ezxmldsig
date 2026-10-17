<?php

namespace webcoder31\ezxmldsig\Demo;

/**
 * The memory of the token identifiers the receiver has accepted (see the
 * README, section "Replay").
 *
 * The library keeps no list of the tokens it has analyzed: refusing a token
 * already accepted is up to the receiver. This store keeps each identifier
 * in a JSON file, read, checked and written under an exclusive lock, so that
 * two requests carrying the same token cannot both be accepted. An
 * application would use a store shared by all its servers instead
 * (`apcu_add()`, a unique key in a database, `SET NX` in Redis...).
 *
 * Without a file, the identifiers are kept in memory, for the time of the
 * request: the attack lab runs on such a store, so that its replay attack
 * does not depend on what the receiver has already seen.
 */
final class ReplayStore
{
    /** @var string|null */
    private $path;

    /** @var array Identifier => expiry (UNIX time), for a store in memory. */
    private $memory = [];

    /**
     * @param string|null $path The JSON file, created if needed (with its
     *     directory), or NULL to keep the identifiers in memory.
     */
    public function __construct($path = null)
    {
        $this->path = $path;
    }

    /**
     * Stores an identifier unless it is already stored.
     *
     * @param string $id The token identifier.
     * @param int $retention How long to keep it, in seconds: at least the
     *     time to live of the tokens plus `XMLDSigToken::DESYNC_TOLERANCE`.
     *
     * @return array ['added' => bool, 'storedAt' => UNIX time of the first
     *     acceptance, 'size' => number of identifiers stored]
     */
    public function add($id, $retention)
    {
        return $this->update(function (array $ids, $now) use ($id, $retention) {
            if (isset($ids[$id]))
            {
                return [$ids, ['added' => false, 'storedAt' => $ids[$id][0], 'size' => count($ids)]];
            }
            $ids[$id] = [$now, $now + $retention];

            return [$ids, ['added' => true, 'storedAt' => $now, 'size' => count($ids)]];
        });
    }

    /**
     * Returns the number of identifiers stored.
     *
     * @return int
     */
    public function size()
    {
        return $this->update(function (array $ids) {
            return [$ids, count($ids)];
        });
    }

    /**
     * Forgets every identifier.
     */
    public function clear()
    {
        $this->update(function () {
            return [[], null];
        });
    }

    /**
     * Applies a change to the stored identifiers, the expired ones removed,
     * under an exclusive lock.
     *
     * @param callable $change Receives the identifiers (id => [stored at,
     *     expiry]) and the current time; returns [new identifiers, result].
     *
     * @return mixed The result of $change.
     *
     * @throws \RuntimeException If the file cannot be used.
     */
    private function update(callable $change)
    {
        $now = time();

        if (is_null($this->path))
        {
            list($this->memory, $result) = $change(self::purge($this->memory, $now), $now);

            return $result;
        }

        $dir = dirname($this->path);
        if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir))
        {
            throw new \RuntimeException('Cannot create the directory of the replay store.');
        }
        $handle = @fopen($this->path, 'c+');
        if (false === $handle)
        {
            throw new \RuntimeException('Cannot open the replay store.');
        }
        try
        {
            if (!flock($handle, LOCK_EX))
            {
                throw new \RuntimeException('Cannot lock the replay store.');
            }
            $json = stream_get_contents($handle);
            $ids = json_decode((string) $json, true);
            list($ids, $result) = $change(self::purge(is_array($ids) ? $ids : [], $now), $now);
            ftruncate($handle, 0);
            rewind($handle);
            fwrite($handle, json_encode((object) $ids));
            fflush($handle);

            return $result;
        }
        finally
        {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    /**
     * Removes the expired identifiers.
     */
    private static function purge(array $ids, $now)
    {
        return array_filter($ids, function ($entry) use ($now) {
            return is_array($entry) && isset($entry[1]) && $entry[1] > $now;
        });
    }
}
