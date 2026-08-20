<?php
declare(strict_types=1);

namespace vielhuber\keepassmcp;

use vielhuber\simplemcp\Attributes\McpTool;
use vielhuber\simplemcp\Attributes\Schema;

final class VaultException extends \RuntimeException
{
    public static function notConfigured(string $variable): self
    {
        return new self('Missing configuration: ' . $variable . '.');
    }

    public static function readerFailed(string $message): self
    {
        return new self($message);
    }
}

interface Reader
{
    /**
     * Run one read-only command against the database and return its decoded result.
     *
     * @return array<string, mixed>
     */
    public function read(string $database, string $password, string $command, string $argument = ''): array;
}

final class PythonReader implements Reader
{
    public function __construct(private readonly string $interpreter, private readonly string $script) {}

    public function read(string $database, string $password, string $command, string $argument = ''): array
    {
        $arguments = [$this->interpreter, $this->script, $database, $command];
        if ($argument !== '') {
            $arguments[] = $argument;
        }
        $process = proc_open($arguments, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($process)) {
            throw VaultException::readerFailed('The KeePass reader could not be started.');
        }
        // the password travels through stdin so it never lands in a process argument
        fwrite($pipes[0], $password);
        fclose($pipes[0]);
        $output = (string) stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        $error = trim((string) stream_get_contents($pipes[2]));
        fclose($pipes[2]);
        proc_close($process);

        $decoded = json_decode(trim($output), true);
        if (!is_array($decoded)) {
            throw VaultException::readerFailed(
                'The KeePass reader returned no usable response.' . ($error !== '' ? ' ' . $error : '')
            );
        }
        if (isset($decoded['error'])) {
            throw VaultException::readerFailed((string) $decoded['error']);
        }
        return $decoded;
    }
}

final class keepassmcp
{
    private string $database;

    private string $password;

    public function __construct(?string $database = null, ?string $password = null, private ?Reader $reader = null)
    {
        $this->database = trim($database ?? (string) getenv('KEEPASS_DATABASE'));
        // a password file is preferred over the variable: an environment travels
        // into every child process and stays readable in /proc/<pid>/environ,
        // while the variable that is read here is dropped right away
        $this->password = trim($password ?? self::passwordFromEnvironment());
        putenv('KEEPASS_PASSWORD');
        if ($this->reader === null) {
            $this->reader = new PythonReader(
                interpreter: (string) (getenv('KEEPASS_PYTHON') ?: 'python3'),
                script: __DIR__ . '/reader.py'
            );
        }
    }

    /**
     * List every entry of the database without any secret value.
     *
     * Returns titles, group paths, usernames and urls plus the flags `has_password`
     * and `has_notes`, so an entry can be picked before anything confidential is
     * requested. The response includes a `count` field with the exact number of
     * entries — use this authoritative value instead of counting the items array.
     *
     * @return array{count: int, items: array<mixed>} Envelope with `count` and `items` (the entries, without secrets)
     * @throws VaultException If the database is not configured or cannot be opened.
     */
    #[McpTool(name: 'list_entries')]
    public function listEntries(): array
    {
        return $this->call('list');
    }

    /**
     * Search entries by any text they carry, notes included.
     *
     * The query is matched case-insensitively against title, username, url, group
     * path, custom property names and the full note text, which is where longer
     * documentation usually lives. Secret values stay out of the result.
     *
     * @param string $query Substring to look for
     * @return array{count: int, items: array<mixed>} Envelope with `count` and `items` (the matching entries, without secrets)
     * @throws VaultException If the database is not configured or cannot be opened.
     */
    #[McpTool(name: 'search_entries')]
    public function searchEntries(string $query): array
    {
        if (trim($query) === '') {
            throw VaultException::readerFailed('Parameter "query" must not be empty.');
        }
        return $this->call('search', trim($query));
    }

    /**
     * Read one entry completely, including its password, notes and custom properties.
     *
     * This is the only tool that returns confidential values, so call it once the
     * wanted entry is identified rather than to browse the database.
     *
     * @param string $uuid Entry uuid as returned by list_entries or search_entries
     * @param array<string> $fields Limit the response to these fields, for example ["notes"]; omit for all of them
     * @return array{item: array<string, mixed>} The entry with the requested values
     * @throws VaultException If the database cannot be opened or the uuid is unknown.
     */
    #[McpTool(name: 'get_entry')]
    public function getEntry(string $uuid, array $fields = []): array
    {
        if (trim($uuid) === '') {
            throw VaultException::readerFailed('Parameter "uuid" must not be empty.');
        }
        $result = $this->call('get', trim($uuid));
        $fields = array_values(array_filter(array_map('trim', array_map('strval', $fields))));
        if ($fields === [] || !isset($result['item'])) {
            return $result;
        }
        // the identifying fields stay in, they carry nothing confidential and keep
        // the answer usable without a second lookup
        $keep = array_merge(['uuid', 'title', 'path'], $fields);
        $result['item'] = array_intersect_key($result['item'], array_flip($keep));
        return $result;
    }

    private static function passwordFromEnvironment(): string
    {
        $passwordFile = trim((string) getenv('KEEPASS_PASSWORD_FILE'));
        if ($passwordFile !== '' && is_file($passwordFile)) {
            return rtrim((string) file_get_contents($passwordFile), "\r\n");
        }
        return (string) getenv('KEEPASS_PASSWORD');
    }

    /**
     * @return array<string, mixed>
     */
    private function call(string $command, string $argument = ''): array
    {
        if ($this->database === '') {
            throw VaultException::notConfigured('KEEPASS_DATABASE');
        }
        if ($this->password === '') {
            throw VaultException::notConfigured('KEEPASS_PASSWORD');
        }
        return $this->reader->read($this->database, $this->password, $command, $argument);
    }
}
