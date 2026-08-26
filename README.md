[![build status](https://github.com/vielhuber/keepassmcp/actions/workflows/ci.yml/badge.svg)](https://github.com/vielhuber/keepassmcp/actions)
[![GitHub Tag](https://img.shields.io/github/v/tag/vielhuber/keepassmcp)](https://github.com/vielhuber/keepassmcp/tags)
[![Code Style](https://img.shields.io/badge/code_style-psr--12-ff69b4.svg)](https://www.php-fig.org/psr/psr-12/)
[![License](https://img.shields.io/github/license/vielhuber/keepassmcp)](https://github.com/vielhuber/keepassmcp/blob/main/LICENSE.md)
[![Last Commit](https://img.shields.io/github/last-commit/vielhuber/keepassmcp)](https://github.com/vielhuber/keepassmcp/commits)
[![PHP Version Support](https://img.shields.io/packagist/php-v/vielhuber/keepassmcp)](https://packagist.org/packages/vielhuber/keepassmcp)
[![Packagist Downloads](https://img.shields.io/packagist/dt/vielhuber/keepassmcp)](https://packagist.org/packages/vielhuber/keepassmcp)

# 🔐keepassmcp🔐

keepassmcp is a PHP helper and MCP server that reads and writes KeePass databases — entries, notes, custom properties and passwords.

keepassmcp requires PHP 8.5 or newer and Python 3 with [pykeepass](https://pypi.org/project/pykeepass/). the decryption itself is delegated to pykeepass because no PHP library reads KDBX 4.x reliably; every KDBX variant, including Argon2 key derivation, is therefore supported.

## installation

```bash
composer require vielhuber/keepassmcp
pip install pykeepass
```

## configuration

copy `.env.example` to `.env` or provide the same variables through the process environment:

```dotenv
KEEPASS_DATABASE=/path/to/passwords.kdbx
KEEPASS_PASSWORD_FILE=/dev/shm/keepass.pass
MCP_TOKEN=
```

the master password can be given either directly as `KEEPASS_PASSWORD` or, preferably, through a file named in `KEEPASS_PASSWORD_FILE`. a file keeps the password out of the process environment, where it would otherwise be inherited by every child process and stay readable in `/proc/<pid>/environ`. whichever channel is used, the value is dropped from the environment as soon as it has been read, and it is handed to the reader through stdin so it never appears in a process argument.

`KEEPASS_PYTHON` optionally points at a specific interpreter, for example one inside a virtualenv.

## PHP

```php
use vielhuber\keepassmcp\keepassmcp;
$vault = new keepassmcp();
$vault->listEntries();
$vault->searchEntries('api-key');
$vault->getEntry('7f9c…');
```

## MCP server

```bash
vendor/bin/mcp-server.php
```

available tools:

- `list_entries`
- `search_entries`
- `get_entry`
- `create_entry`
- `update_entry`
- `delete_entry`

`list_entries` and `search_entries` never return a password, a note body or a custom field value; they report titles, group paths, usernames, urls, the names of the custom fields and the flags `has_password` and `has_notes`. `search_entries` does look _inside_ notes and inside the names and values of custom fields, so an entry stays findable by a mail address or an account number kept there. only `get_entry` returns the confidential values of a single entry, and its optional `fields` parameter narrows the answer — `["notes"]` returns the notes without the password.

write tools never return a password or note body. `create_entry` creates missing groups from its slash-separated `group` path. `update_entry` changes only supplied fields, stores the previous entry in KeePass history and accepts `null` as a custom-property value to delete that property. `delete_entry` requires the exact UUID returned by a list or search call. every local mutation is written to a temporary database and atomically replaces the original only after KeePass has saved it successfully.

remote storage adapters can be connected without coupling keepassmcp to a cloud provider. set `KEEPASS_SYNC_COMMAND` to an executable accepting `prepare|commit`, the configured database identifier and a local materialization path. `prepare` must return `{"database":"/local/file.kdbx"}`; `commit` must persist that file or fail. `KEEPASS_LOCAL_DATABASE` optionally fixes the materialization path. keepassmcp serializes the complete prepare/read-or-write/commit transaction through a local lock.

## tests

```bash
composer install
vendor/bin/phpunit
```

the test suite uses a fake reader and never opens a real database.
