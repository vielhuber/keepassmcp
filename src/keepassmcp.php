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
     * Run one command against the database and return its decoded result.
     *
     * @return array<string, mixed>
     */
    public function read(string $database, string $password, string $command, string $argument = ''): array;
}

interface DatabaseStorage
{
    public function prepare(string $database): string;

    public function commit(string $database, string $materializedDatabase): void;

    public function lockPath(string $database): string;
}

final class LocalDatabaseStorage implements DatabaseStorage
{
    public function prepare(string $database): string
    {
        return $database;
    }

    public function commit(string $database, string $materializedDatabase): void {}

    public function lockPath(string $database): string
    {
        return rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) .
            DIRECTORY_SEPARATOR .
            'keepassmcp-' .
            hash('sha256', $database) .
            '.lock';
    }
}

final class CommandDatabaseStorage implements DatabaseStorage
{
    private ?string $materializedDatabase;

    public function __construct(private readonly string $command, ?string $materializedDatabase = null)
    {
        $this->materializedDatabase =
            $materializedDatabase !== null && trim($materializedDatabase) !== '' ? trim($materializedDatabase) : null;
    }

    public function prepare(string $database): string
    {
        $result = $this->run('prepare', $database);
        $materializedDatabase = trim((string) ($result['database'] ?? $this->materializedPath($database)));
        if ($materializedDatabase === '' || !is_file($materializedDatabase)) {
            throw VaultException::readerFailed('The synchronized KeePass database is unavailable.');
        }
        return $materializedDatabase;
    }

    public function commit(string $database, string $materializedDatabase): void
    {
        $this->run('commit', $database, $materializedDatabase);
    }

    public function lockPath(string $database): string
    {
        return $this->materializedPath($database) . '.lock';
    }

    /** @return array<string, mixed> */
    private function run(string $operation, string $database, ?string $materializedDatabase = null): array
    {
        $process = proc_open(
            [$this->command, $operation, $database, $materializedDatabase ?? $this->materializedPath($database)],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes
        );
        if (!is_resource($process)) {
            throw VaultException::readerFailed('The KeePass storage adapter could not be started.');
        }
        fclose($pipes[0]);
        $output = (string) stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        $error = trim((string) stream_get_contents($pipes[2]));
        fclose($pipes[2]);
        $exitCode = proc_close($process);
        $decoded = json_decode(trim($output), true);
        if ($exitCode !== 0 || !is_array($decoded)) {
            throw VaultException::readerFailed(
                'The KeePass storage adapter returned no usable response.' . ($error !== '' ? ' ' . $error : '')
            );
        }
        if (isset($decoded['error'])) {
            throw VaultException::readerFailed((string) $decoded['error']);
        }
        return $decoded;
    }

    private function materializedPath(string $database): string
    {
        if ($this->materializedDatabase !== null) {
            return $this->materializedDatabase;
        }
        $temporaryDirectory = is_dir('/dev/shm') ? '/dev/shm' : sys_get_temp_dir();
        return rtrim($temporaryDirectory, DIRECTORY_SEPARATOR) .
            DIRECTORY_SEPARATOR .
            'keepassmcp-' .
            hash('sha256', $database) .
            '.kdbx';
    }
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

    private DatabaseStorage $storage;

    public function __construct(
        ?string $database = null,
        ?string $password = null,
        private ?Reader $reader = null,
        ?DatabaseStorage $storage = null
    ) {
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
        $syncCommand = trim((string) getenv('KEEPASS_SYNC_COMMAND'));
        $this->storage =
            $storage ??
            ($syncCommand !== ''
                ? new CommandDatabaseStorage(
                    command: $syncCommand,
                    materializedDatabase: (string) getenv('KEEPASS_LOCAL_DATABASE')
                )
                : new LocalDatabaseStorage());
    }

    /**
     * List every entry of the database without any secret value.
     *
     * Returns titles, group paths, usernames and urls plus the flags `has_password`,
     * `has_notes` and `has_totp`, so an entry can be picked before requesting secrets.
     * The response includes a `count` field with the exact number of
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
     * Call this once the wanted entry is identified rather than to browse the database.
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

    /**
     * Generate the current code from an entry's existing KeePassXC TOTP configuration.
     *
     * Returns only entry identification, the code and its expiry, never the shared secret.
     * Use search_entries first to identify the entry; has_totp indicates stored OTP settings.
     *
     * @param string $uuid Entry uuid as returned by list_entries or search_entries
     * @return array{item: array{uuid: string, title: string, path: string, totp: string, valid_until: int, remaining_seconds: int}}
     * @throws VaultException If the entry has no supported TOTP configuration or cannot be read.
     */
    #[McpTool(name: 'get_totp')]
    public function getTotp(string $uuid): array
    {
        if (trim($uuid) === '') {
            throw VaultException::readerFailed('Parameter "uuid" must not be empty.');
        }
        return $this->call('totp', trim($uuid));
    }

    /**
     * Create an entry without returning its confidential values.
     *
     * Missing groups in the slash-separated path are created automatically.
     *
     * @param array<string, string> $customProperties Additional values stored under their exact field names
     * @return array{item: array<string, mixed>} The created entry without confidential values
     */
    #[McpTool(name: 'create_entry')]
    public function createEntry(
        string $title,
        string $username = '',
        string $password = '',
        string $url = '',
        string $notes = '',
        string $group = '',
        array $customProperties = []
    ): array {
        if (trim($title) === '') {
            throw VaultException::readerFailed('Parameter "title" must not be empty.');
        }
        return $this->call(
            'create',
            json_encode(
                [
                    'title' => trim($title),
                    'username' => $username,
                    'password' => $password,
                    'url' => $url,
                    'notes' => $notes,
                    'group' => trim($group),
                    'custom_properties' => $customProperties
                ],
                JSON_THROW_ON_ERROR
            ),
            true
        );
    }

    /**
     * Update only the supplied fields of an entry and preserve its history.
     *
     * A null custom-property value deletes that property. Missing groups in a
     * supplied slash-separated path are created automatically.
     *
     * @param array<string, string|null>|null $customProperties Values to set or delete by exact field name
     * @return array{item: array<string, mixed>} The updated entry without confidential values
     */
    #[McpTool(name: 'update_entry')]
    public function updateEntry(
        string $uuid,
        ?string $title = null,
        ?string $username = null,
        ?string $password = null,
        ?string $url = null,
        ?string $notes = null,
        ?string $group = null,
        ?array $customProperties = null
    ): array {
        if (trim($uuid) === '') {
            throw VaultException::readerFailed('Parameter "uuid" must not be empty.');
        }
        $values = [
            'uuid' => trim($uuid),
            'title' => $title,
            'username' => $username,
            'password' => $password,
            'url' => $url,
            'notes' => $notes,
            'group' => $group,
            'custom_properties' => $customProperties
        ];
        $values = array_filter($values, static fn(mixed $value): bool => $value !== null);
        if (count($values) === 1) {
            throw VaultException::readerFailed('At least one field must be supplied for an update.');
        }
        return $this->call('update', json_encode($values, JSON_THROW_ON_ERROR), true);
    }

    /**
     * Delete one explicitly identified entry without returning its values.
     *
     * @return array{deleted: array<string, string>} Identification of the deleted entry
     */
    #[McpTool(name: 'delete_entry')]
    public function deleteEntry(string $uuid): array
    {
        if (trim($uuid) === '') {
            throw VaultException::readerFailed('Parameter "uuid" must not be empty.');
        }
        return $this->call('delete', trim($uuid), true);
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
    private function call(string $command, string $argument = '', bool $writes = false): array
    {
        if ($this->database === '') {
            throw VaultException::notConfigured('KEEPASS_DATABASE');
        }
        if ($this->password === '') {
            throw VaultException::notConfigured('KEEPASS_PASSWORD');
        }
        $lock = fopen($this->storage->lockPath($this->database), 'c');
        if ($lock === false || !flock($lock, LOCK_EX)) {
            throw VaultException::readerFailed('The KeePass database lock could not be acquired.');
        }
        try {
            $materializedDatabase = $this->storage->prepare($this->database);
            $result = $this->reader->read($materializedDatabase, $this->password, $command, $argument);
            if ($writes) {
                $this->storage->commit($this->database, $materializedDatabase);
            }
            return $result;
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }
}
