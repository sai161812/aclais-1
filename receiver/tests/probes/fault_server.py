"""Private child-process HTTP probe for receiver crash-boundary acceptance checks."""

from __future__ import annotations

import argparse
import logging

import uvicorn

from receiver.app import create_app
from receiver.config import ReceiverSettings
from receiver.credentials import read_admin_credential
from receiver.database import InjectedCrash, ReceiverStore
from receiver.listener import create_ipv6_listener

_FAULT_STEPS = (
    "after_reservation",
    "after_stage_flush",
    "after_rename",
    "before_commit",
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("fault_step", choices=_FAULT_STEPS)
    args = parser.parse_args()
    settings = ReceiverSettings.from_env()
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    token = read_admin_credential(settings.data_root)
    injected = False

    def fail_once(step: str) -> None:
        nonlocal injected
        if not injected and step == args.fault_step:
            injected = True
            raise InjectedCrash("private receiver HTTP audit fault")

    store = ReceiverStore(settings.data_root, fault_hook=fail_once)
    application = create_app(settings, store=store, admin_token=token)
    token = ""
    listener = create_ipv6_listener(settings.port)
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
    finally:
        listener.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
