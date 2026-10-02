#!/usr/bin/env python3
"""Run the inactive paired source proof in a fresh schema of a test database.

TEST_DATABASE_URL supplies only a dedicated PostgreSQL test database. The
helper is a server controlplane test binary built from the matching future
server branch; its credentials travel exclusively through private pipes.
"""
import argparse
import os
from pathlib import Path
import subprocess
import urllib.parse
import uuid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server-helper", required=True, type=Path)
    parser.add_argument("--overlay", type=Path)
    parser.add_argument("--turns", action="store_true", help="prove actual native turn delivery")
    parser.add_argument("--cancellations", action="store_true", help="prove actual owned cancellation wire and lost commit reply")
    parser.add_argument("--task-input", action="store_true", help="prove original task read through real native bridge")
    args = parser.parse_args()
    binary = args.server_helper.resolve()
    if not binary.is_file():
        raise RuntimeError("server helper test binary is missing")
    parsed = urllib.parse.urlsplit(os.environ["TEST_DATABASE_URL"])
    pg_env = dict(
        os.environ,
        PGDATABASE=parsed.path.lstrip("/"),
        PGHOST=parsed.hostname or "localhost",
        PGPORT=str(parsed.port or 5432),
        PGUSER=urllib.parse.unquote(parsed.username or ""),
        PGPASSWORD=urllib.parse.unquote(parsed.password or ""),
    )

    def sql(query):
        result = subprocess.run(
            ["psql", "-X", "-v", "ON_ERROR_STOP=1", "-At", "-c", query],
            env=pg_env,
            capture_output=True,
            text=True,
        )
        if result.returncode:
            raise RuntimeError("isolated PostgreSQL fixture operation failed")
        return result.stdout.strip()

    if "test" not in sql("SELECT current_database()").lower():
        raise RuntimeError("refusing a database without test in its name")
    schema = "pagnet_source_proof_" + uuid.uuid4().hex
    sql("CREATE SCHEMA " + schema)
    query = dict(urllib.parse.parse_qsl(parsed.query))
    query["search_path"] = schema
    isolated = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), parsed.fragment)
    )
    try:
        environment = dict(
            os.environ,
            PAGNET_TEST_DSN=isolated,
            GOWORK="off",
            PAGNET_NATIVE_SOURCE_BACKEND_TEST_BINARY=str(binary),
        )
        command = ["go", "test", "-race"]
        if args.overlay:
            command.append("-overlay=" + str(args.overlay.resolve()))
        command.extend(
            [
                "./internal/daemon",
                "-run", "^TestNativeCancellationActualBackendLostReplyAndOriginalWorkerFence$" if args.cancellations else "^TestNativeOriginalTaskInputActualBridgeThroughReplacement$" if args.task_input else "^TestNativeTurnDrainerActualOwnerBackendOriginalSourceAndRollback$" if args.turns else "^TestNativeSourceDrainerActualBackendReconnectAndCiphertextProof$",
                "-count=1", "-timeout=120s", "-v",
            ]
        )
        result = subprocess.run(command, cwd=Path(__file__).resolve().parent.parent, env=environment)
        return result.returncode
    finally:
        sql("DROP SCHEMA " + schema + " CASCADE")


if __name__ == "__main__":
    raise SystemExit(main())
