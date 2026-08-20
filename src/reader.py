"""Read a KeePass database and print the requested result as JSON on stdout.

PHP owns the MCP surface; this script only decrypts. It exists because no PHP
library reads KDBX 4.x reliably, while pykeepass covers every variant including
Argon2 key derivation.

The database password arrives on stdin so it never appears in a process
argument. Commands: "list", "search <query>", "get <uuid>".
"""

import json
import sys

from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError


def summary(entry):
    """Describe an entry without ever exposing its password."""
    return {
        "uuid": str(entry.uuid),
        "title": entry.title or "",
        "path": "/".join(entry.path or []),
        "username": entry.username or "",
        "url": entry.url or "",
        "has_password": (entry.password or "") != "",
        "has_notes": (entry.notes or "") != "",
        "attachments": [attachment.filename for attachment in entry.attachments],
    }


def detail(entry):
    """Describe an entry including every value it carries."""
    result = summary(entry)
    result["password"] = entry.password or ""
    result["notes"] = entry.notes or ""
    result["custom_properties"] = dict(entry.custom_properties or {})
    return result


def matches(entry, query):
    """Tell whether a query appears anywhere in the entry, notes included."""
    haystack = " ".join(
        [
            entry.title or "",
            entry.username or "",
            entry.url or "",
            entry.notes or "",
            "/".join(entry.path or []),
            " ".join((entry.custom_properties or {}).keys()),
        ]
    ).lower()
    return query.lower() in haystack


def main():
    database = sys.argv[1]
    command = sys.argv[2]
    argument = sys.argv[3] if len(sys.argv) > 3 else ""
    password = sys.stdin.read().rstrip("\n")

    try:
        vault = PyKeePass(database, password=password)
    except CredentialsError:
        print(json.dumps({"error": "The master password does not open the database."}))
        raise SystemExit(1)
    except FileNotFoundError:
        print(json.dumps({"error": "The database does not exist: " + database}))
        raise SystemExit(1)

    if command == "list":
        items = [summary(entry) for entry in vault.entries]
    elif command == "search":
        items = [summary(entry) for entry in vault.entries if matches(entry, argument)]
    elif command == "get":
        entry = next((one for one in vault.entries if str(one.uuid) == argument), None)
        if entry is None:
            print(json.dumps({"error": 'No entry with uuid "' + argument + '".'}))
            raise SystemExit(1)
        print(json.dumps({"item": detail(entry)}))
        return
    else:
        print(json.dumps({"error": 'Unknown command "' + command + '".'}))
        raise SystemExit(1)

    print(json.dumps({"count": len(items), "items": items}))


main()
