"""Owner-side receiver initialization, foreground service, and receipt view."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import uuid

import uvicorn

from receiver.app import create_app
from receiver.config import ReceiverSettings
from receiver.credentials import CredentialError, create_admin_credential, read_admin_credential
from receiver.database import ReceiverStore
from receiver.listener import create_ipv6_listener
from receiver.security import StorageProtectionError


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aclais-receiver")
    subcommands = parser.add_subparsers(dest="action", required=True)
    subcommands.add_parser("init", help="initialize the owner-protected runtime once")
    subcommands.add_parser("serve", help="run the fixed IPv6 receiver in the foreground")
    inspect = subcommands.add_parser("inspect", help="show owner-only receipt metadata")
    inspect.add_argument("run_id")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        settings = ReceiverSettings.from_env()
    except (ValueError, OSError):
        print("Receiver configuration is invalid.", file=sys.stderr)
        return 2
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    if args.action == "init":
        return _initialize(settings)
    if args.action == "inspect":
        return _inspect(settings, args.run_id)
    return _serve(settings)


def _initialize(settings: ReceiverSettings) -> int:
    try:
        ReceiverStore(settings.data_root).initialize()
        create_admin_credential(settings.data_root)
    except (CredentialError, StorageProtectionError, OSError, RuntimeError):
        print(
            "Receiver initialization failed; protected runtime data was preserved.",
            file=sys.stderr,
        )
        return 2
    print("Receiver initialized. The administrative credential remains owner-only.")
    return 0


def _serve(settings: ReceiverSettings) -> int:
    try:
        # Validate and protect the runtime before acquiring the public listener.
        ReceiverStore(settings.data_root).initialize()
        token = read_admin_credential(settings.data_root)
        application = create_app(settings, admin_token=token)
        token = ""
        listener = create_ipv6_listener(settings.port)
    except (CredentialError, StorageProtectionError, OSError, RuntimeError, ValueError):
        print(
            "Receiver startup failed. No other process or port owner was changed.",
            file=sys.stderr,
        )
        return 2
    configuration = uvicorn.Config(
        application,
        host="::1",
        port=settings.port,
        log_level=settings.log_level.lower(),
        access_log=False,
        workers=1,
        lifespan="on",
    )
    server = uvicorn.Server(configuration)
    try:
        server.run(sockets=[listener])
    except OSError:
        listener.close()
        print(
            "Receiver listener failed. No other process or port owner was changed.",
            file=sys.stderr,
        )
        return 2
    return 0


def _inspect(settings: ReceiverSettings, raw_run_id: str) -> int:
    try:
        parsed = uuid.UUID(raw_run_id)
        if str(parsed) != raw_run_id:
            raise ValueError
        store = ReceiverStore(settings.data_root)
        store.initialize()
        report = store.inspect_summary(parsed)
    except ValueError:
        print("Run ID must be a canonical UUID.", file=sys.stderr)
        return 2
    except (OSError, RuntimeError, StorageProtectionError):
        print("Receiver receipt metadata is unavailable.", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
