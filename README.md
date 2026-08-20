[![build status](https://github.com/vielhuber/keepassmcp/actions/workflows/ci.yml/badge.svg)](https://github.com/vielhuber/keepassmcp/actions)
[![GitHub Tag](https://img.shields.io/github/v/tag/vielhuber/keepassmcp)](https://github.com/vielhuber/keepassmcp/tags)
[![Code Style](https://img.shields.io/badge/code_style-psr--12-ff69b4.svg)](https://www.php-fig.org/psr/psr-12/)
[![License](https://img.shields.io/github/license/vielhuber/keepassmcp)](https://github.com/vielhuber/keepassmcp/blob/main/LICENSE.md)
[![Last Commit](https://img.shields.io/github/last-commit/vielhuber/keepassmcp)](https://github.com/vielhuber/keepassmcp/commits)
[![PHP Version Support](https://img.shields.io/packagist/php-v/vielhuber/keepassmcp)](https://packagist.org/packages/vielhuber/keepassmcp)
[![Packagist Downloads](https://img.shields.io/packagist/dt/vielhuber/keepassmcp)](https://packagist.org/packages/vielhuber/keepassmcp)

# 🔐keepassmcp🔐

keepassmcp is a PHP helper and MCP server that reads a local KeePass database — entries, notes, custom properties and passwords.

it is read-only by design: nothing in the database is ever written or changed.

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

`list_entries` and `search_entries` never return a password or a note body; they report titles, group paths, usernames, urls and the flags `has_password` and `has_notes`. `search_entries` does look *inside* notes and custom property names, so long-form documentation stored in an entry stays findable. only `get_entry` returns the confidential values of a single entry.

## tests

```bash
composer install
vendor/bin/phpunit
```

the test suite uses a fake reader and never opens a real database.
