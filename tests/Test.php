<?php
declare(strict_types=1);

use vielhuber\keepassmcp\keepassmcp;
use vielhuber\keepassmcp\Reader;
use vielhuber\keepassmcp\VaultException;

final class Test extends \PHPUnit\Framework\TestCase
{
    public function test__lists_entries_without_secrets(): void
    {
        $reader = new FakeReader([
            'count' => 1,
            'items' => [['uuid' => 'abc', 'title' => 'tld.com', 'has_password' => true, 'has_notes' => true]]
        ]);
        $vault = new keepassmcp(database: '/tmp/example.kdbx', password: 'pw', reader: $reader);

        $result = $vault->listEntries();

        $this->assertSame(1, $result['count']);
        $this->assertSame('list', $reader->calls[0]['command']);
        $this->assertArrayNotHasKey('password', $result['items'][0]);
    }

    public function test__searches_across_notes(): void
    {
        $reader = new FakeReader(['count' => 0, 'items' => []]);
        $vault = new keepassmcp(database: '/tmp/example.kdbx', password: 'pw', reader: $reader);

        $vault->searchEntries('  api-key  ');

        $this->assertSame('search', $reader->calls[0]['command']);
        $this->assertSame('api-key', $reader->calls[0]['argument']);
    }

    public function test__rejects_an_empty_query(): void
    {
        $vault = new keepassmcp(database: '/tmp/example.kdbx', password: 'pw', reader: new FakeReader([]));

        $this->expectException(VaultException::class);
        $vault->searchEntries('   ');
    }

    public function test__returns_one_entry_with_all_of_its_values(): void
    {
        $reader = new FakeReader(['item' => ['uuid' => 'abc', 'password' => 's3cret', 'notes' => "line 1\nline 2"]]);
        $vault = new keepassmcp(database: '/tmp/example.kdbx', password: 'pw', reader: $reader);

        $result = $vault->getEntry('abc');

        $this->assertSame('s3cret', $result['item']['password']);
        $this->assertSame("line 1\nline 2", $result['item']['notes']);
        $this->assertSame('get', $reader->calls[0]['command']);
    }

    public function test__limits_an_entry_to_the_requested_fields(): void
    {
        $reader = new FakeReader([
            'item' => ['uuid' => 'abc', 'title' => 'x', 'path' => 'g/x', 'password' => 's3cret', 'notes' => 'n']
        ]);
        $vault = new keepassmcp(database: '/tmp/example.kdbx', password: 'pw', reader: $reader);

        $result = $vault->getEntry('abc', ['notes']);

        $this->assertSame(['uuid', 'title', 'path', 'notes'], array_keys($result['item']));
        $this->assertArrayNotHasKey('password', $result['item']);
    }

    public function test__returns_every_field_without_a_selection(): void
    {
        $reader = new FakeReader(['item' => ['uuid' => 'abc', 'password' => 's3cret', 'notes' => 'n']]);
        $vault = new keepassmcp(database: '/tmp/example.kdbx', password: 'pw', reader: $reader);

        $this->assertSame('s3cret', $vault->getEntry('abc')['item']['password']);
    }

    public function test__fails_without_a_configured_database(): void
    {
        $vault = new keepassmcp(database: '', password: 'pw', reader: new FakeReader([]));

        $this->expectException(VaultException::class);
        $vault->listEntries();
    }

    public function test__fails_without_a_master_password(): void
    {
        $vault = new keepassmcp(database: '/tmp/example.kdbx', password: '', reader: new FakeReader([]));

        $this->expectException(VaultException::class);
        $vault->listEntries();
    }

    public function test__removes_the_password_from_the_environment(): void
    {
        putenv('KEEPASS_PASSWORD=from-environment');

        new keepassmcp(database: '/tmp/example.kdbx', reader: new FakeReader([]));

        $this->assertFalse(getenv('KEEPASS_PASSWORD'));
    }

    public function test__prefers_the_password_file_over_the_variable(): void
    {
        $passwordFile = tempnam(sys_get_temp_dir(), 'keepass');
        file_put_contents($passwordFile, "from-file\n");
        putenv('KEEPASS_PASSWORD=from-environment');
        putenv('KEEPASS_PASSWORD_FILE=' . $passwordFile);
        $reader = new FakeReader(['count' => 0, 'items' => []]);

        new keepassmcp(database: '/tmp/example.kdbx', reader: $reader)->listEntries();

        $this->assertSame('from-file', $reader->calls[0]['password']);
        putenv('KEEPASS_PASSWORD_FILE');
        unlink($passwordFile);
    }

    public function test__creates_an_entry_and_commits_the_materialized_database(): void
    {
        $reader = new FakeReader(['item' => ['uuid' => 'abc', 'title' => 'Example']]);
        $storage = new FakeStorage('/tmp/materialized.kdbx');
        $vault = new keepassmcp(database: 'remote://vault.kdbx', password: 'pw', reader: $reader, storage: $storage);

        $result = $vault->createEntry(
            title: 'Example',
            username: 'user',
            password: 'secret',
            group: 'Customers/Example'
        );

        $this->assertSame('abc', $result['item']['uuid']);
        $this->assertSame('create', $reader->calls[0]['command']);
        $this->assertSame('/tmp/materialized.kdbx', $reader->calls[0]['database']);
        $this->assertSame(1, $storage->commits);
        $payload = json_decode($reader->calls[0]['argument'], true, flags: JSON_THROW_ON_ERROR);
        $this->assertSame('Customers/Example', $payload['group']);
        $this->assertSame('secret', $payload['password']);
    }

    public function test__updates_only_supplied_fields_and_commits(): void
    {
        $reader = new FakeReader(['item' => ['uuid' => 'abc', 'title' => 'Changed']]);
        $storage = new FakeStorage('/tmp/materialized.kdbx');
        $vault = new keepassmcp(database: 'remote://vault.kdbx', password: 'pw', reader: $reader, storage: $storage);

        $vault->updateEntry(uuid: 'abc', title: 'Changed', customProperties: ['obsolete' => null]);

        $payload = json_decode($reader->calls[0]['argument'], true, flags: JSON_THROW_ON_ERROR);
        $this->assertSame(['uuid', 'title', 'custom_properties'], array_keys($payload));
        $this->assertNull($payload['custom_properties']['obsolete']);
        $this->assertSame(1, $storage->commits);
    }

    public function test__does_not_commit_read_operations(): void
    {
        $storage = new FakeStorage('/tmp/materialized.kdbx');
        $vault = new keepassmcp(
            database: 'remote://vault.kdbx',
            password: 'pw',
            reader: new FakeReader(['count' => 0, 'items' => []]),
            storage: $storage
        );

        $vault->listEntries();

        $this->assertSame(0, $storage->commits);
    }
}

final class FakeReader implements Reader
{
    /** @var array<int, array<string, string>> */
    public array $calls = [];

    /**
     * @param array<string, mixed> $result
     */
    public function __construct(private readonly array $result) {}

    public function read(string $database, string $password, string $command, string $argument = ''): array
    {
        $this->calls[] = [
            'database' => $database,
            'password' => $password,
            'command' => $command,
            'argument' => $argument
        ];
        return $this->result;
    }
}

final class FakeStorage implements \vielhuber\keepassmcp\DatabaseStorage
{
    public int $commits = 0;

    public function __construct(private readonly string $database) {}

    public function prepare(string $database): string
    {
        return $this->database;
    }

    public function commit(string $database, string $materializedDatabase): void
    {
        $this->commits++;
    }

    public function lockPath(string $database): string
    {
        return sys_get_temp_dir() . '/keepassmcp-test-' . hash('sha256', $database) . '.lock';
    }
}
