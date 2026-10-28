"""Run the local controller API with its validated loopback configuration."""

from __future__ import annotations

import logging

import uvicorn
from pydantic import ValidationError

from aclais.app import create_app
from aclais.config import Settings
from aclais.logging_config import configure_logging


def main() -> None:
    try:
        settings = Settings.from_env()
    except (ValidationError, ValueError):
        configure_logging()
        logging.getLogger("aclais.startup").error("configuration_invalid")
        raise SystemExit(2) from None

    configure_logging(settings.log_level)
    logging.getLogger("aclais.startup").info(
        "controller_starting",
        extra={"fields": {"host": settings.host, "port": settings.port}},
    )
    uvicorn.run(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        access_log=False,
        log_config=None,
        workers=1,
    )


if __name__ == "__main__":
    main()
