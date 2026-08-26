"""Read a KeePass database and print the requested result as JSON on stdout.

PHP owns the MCP surface; this script only decrypts. It exists because no PHP
library reads KDBX 4.x reliably, while pykeepass covers every variant including
Argon2 key derivation.

The database password arrives on stdin so it never appears in a process
argument. Commands: "list", "search", "get", "create", "update", "delete".
"""

import atexit
import json
import os
import shutil
import sys
import tempfile

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
        # the names show what an entry carries, so the right field can be asked for
        # afterwards; the values stay behind get_entry
        "custom_fields": sorted((entry.custom_properties or {}).keys()),
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
    """Tell whether a query appears anywhere in the entry, values included.

    Custom fields are searched by name and by value: a mail address or an account
    number often lives there, and an entry that cannot be found by it is of no use.
    The match only decides *whether* an entry is returned — search results never
    carry the values themselves.
    """
    custom = entry.custom_properties or {}
    haystack = " ".join(
        [
            entry.title or "",
            entry.username or "",
            entry.url or "",
            entry.notes or "",
            "/".join(entry.path or []),
            " ".join(custom.keys()),
            " ".join(str(value or "") for value in custom.values()),
        ]
    ).lower()
    return query.lower() in haystack


def group_for_path(vault, path):
    """Find a group path and create only the missing path segments."""
    group = vault.root_group
    for name in [part for part in path.strip("/").split("/") if part]:
        child = next((item for item in group.subgroups if item.name == name), None)
        group = child if child is not None else vault.add_group(group, name)
    return group


def entry_by_uuid(vault, uuid):
    """Resolve an exact entry UUID or fail with a stable user-facing message."""
    entry = next((item for item in vault.entries if str(item.uuid) == uuid), None)
    if entry is None:
        raise ValueError('No entry with uuid "' + uuid + '".')
    return entry


def main():
    database = sys.argv[1]
    command = sys.argv[2]
    argument = sys.argv[3] if len(sys.argv) > 3 else ""
    password = sys.stdin.read().rstrip("\n")

    mutating = command in {"create", "update", "delete"}
    working_database = database
    temporary_database = None
    if mutating:
        handle, temporary_database = tempfile.mkstemp(
            prefix=".keepassmcp-", suffix=".kdbx", dir=os.path.dirname(database) or None
        )
        os.close(handle)

        def cleanup_temporary_database():
            if temporary_database is not None and os.path.exists(temporary_database):
                os.unlink(temporary_database)

        atexit.register(cleanup_temporary_database)
        shutil.copy2(database, temporary_database)
        os.chmod(temporary_database, 0o600)
        working_database = temporary_database

    try:
        vault = PyKeePass(working_database, password=password)
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
        entry = entry_by_uuid(vault, argument)
        print(json.dumps({"item": detail(entry)}))
        return
    elif command == "create":
        values = json.loads(argument)
        entry = vault.add_entry(
            group_for_path(vault, values.get("group", "")),
            values["title"],
            values.get("username", ""),
            values.get("password", ""),
        )
        entry.url = values.get("url", "")
        entry.notes = values.get("notes", "")
        for key, value in values.get("custom_properties", {}).items():
            entry.set_custom_property(str(key), str(value))
        result = {"item": summary(entry)}
    elif command == "update":
        values = json.loads(argument)
        entry = entry_by_uuid(vault, values["uuid"])
        entry.save_history()
        for field in ["title", "username", "password", "url", "notes"]:
            if field in values:
                setattr(entry, field, values[field])
        if "group" in values:
            vault.move_entry(entry, group_for_path(vault, values["group"]))
        for key, value in values.get("custom_properties", {}).items():
            if value is None and key in entry.custom_properties:
                entry.delete_custom_property(key)
            elif value is not None:
                entry.set_custom_property(str(key), str(value))
        result = {"item": summary(entry)}
    elif command == "delete":
        entry = entry_by_uuid(vault, argument)
        result = {"deleted": {"uuid": str(entry.uuid), "title": entry.title or "", "path": "/".join(entry.path or [])}}
        vault.delete_entry(entry)
    else:
        print(json.dumps({"error": 'Unknown command "' + command + '".'}))
        raise SystemExit(1)

    if mutating:
        vault.save()
        os.replace(working_database, database)
        temporary_database = None
        print(json.dumps(result))
        return

    print(json.dumps({"count": len(items), "items": items}))


try:
    main()
except (json.JSONDecodeError, KeyError, OSError, TypeError, ValueError) as error:
    print(json.dumps({"error": str(error)}))
    raise SystemExit(1)
