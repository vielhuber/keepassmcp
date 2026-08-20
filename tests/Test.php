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
