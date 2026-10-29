"""Run the local controller API with its validated loopback configuration."""

from __future__ import annotations

import logging
import threading
import webbrowser

import uvicorn
from pydantic import ValidationError

from aclais.app import create_app
from aclais.config import Settings
from aclais.logging_config import configure_logging
from aclais.runtime import create_a8_runtime


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
    bootstrap_url = None
    if settings.protected_runtime:
        runtime = create_a8_runtime(settings)
        application = runtime.app
        bootstrap_url = runtime.bootstrap_url
    else:
        application = create_app(settings)
    if bootstrap_url is not None:

        def open_owner_bootstrap() -> None:
            try:
                if not webbrowser.open(bootstrap_url, new=1, autoraise=False):
                    logging.getLogger("aclais.startup").warning(
                        "owner_bootstrap_browser_open_failed"
                    )
            except Exception:
                logging.getLogger("aclais.startup").warning("owner_bootstrap_browser_open_failed")

        timer = threading.Timer(1.0, open_owner_bootstrap)
        timer.daemon = True
        timer.start()
    uvicorn.run(
        application,
        host=settings.host,
        port=settings.port,
        access_log=False,
        log_config=None,
        workers=1,
    )


if __name__ == "__main__":
    main()
