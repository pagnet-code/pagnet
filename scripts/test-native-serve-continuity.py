#!/usr/bin/env python3
"""Prove real serve replacement against a loopback backend and fresh PG schema."""

import argparse
import os
import subprocess
import urllib.parse
import uuid
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-helper", required=True, type=Path)
    parser.add_argument("--delete", action="store_true", help="also prove actual owned deletion after controller replacement")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    binary = args.server_helper.resolve()
    if not binary.is_file():
        raise RuntimeError("isolated server helper is missing")

    parsed = urllib.parse.urlsplit(os.environ["TEST_DATABASE_URL"])
    if parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise RuntimeError("requires loopback isolated PostgreSQL")
    env = dict(
        os.environ,
        PGDATABASE=parsed.path.lstrip("/"),
        PGHOST=parsed.hostname,
        PGPORT=str(parsed.port or 5432),
        PGUSER=urllib.parse.unquote(parsed.username or ""),
        PGPASSWORD=urllib.parse.unquote(parsed.password or ""),
    )

    def sql(query):
        result = subprocess.run(
            ["psql", "-X", "-v", "ON_ERROR_STOP=1", "-At", "-c", query],
            env=env, capture_output=True, text=True,
        )
        if result.returncode:
            # Database credentials and server errors stay outside test logs.
            raise RuntimeError("isolated PostgreSQL fixture command failed")
        return result.stdout.strip()

    if "test" not in sql("SELECT current_database()").lower():
        raise RuntimeError("requires dedicated test database")
    schema = "pagnet_serve_proof_" + uuid.uuid4().hex
    sql("CREATE SCHEMA " + schema)
    query = dict(urllib.parse.parse_qsl(parsed.query))
    query["search_path"] = schema
    isolated = urllib.parse.urlunsplit((
        parsed.scheme, parsed.netloc, parsed.path,
        urllib.parse.urlencode(query), parsed.fragment,
    ))
    try:
        testenv = dict(
            os.environ,
            PAGNET_TEST_DSN=isolated,
            GOWORK="off",
            PAGNET_NATIVE_SERVE_PROOF="1",
            PAGNET_NATIVE_SOURCE_BACKEND_TEST_BINARY=str(binary),
        )
        result = subprocess.run(
            ["go", "test", "-race", "./internal/daemon", "-run",
             "^TestActualPagnetServeOwnedDeletion$" if args.delete else "^TestActualPagnetServeControllerReplacementPrivateTerminal$",
             "-count=1", "-timeout=120s", "-v"],
            cwd=root, env=testenv,
        )
        return result.returncode
    finally:
        sql("DROP SCHEMA " + schema + " CASCADE")


if __name__ == "__main__":
    raise SystemExit(main())
