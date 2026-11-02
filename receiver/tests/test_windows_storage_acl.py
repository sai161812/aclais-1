from __future__ import annotations

import sys

import pytest

from receiver.config import ReceiverSettings
from receiver.security import audit_store_root

pytestmark = [pytest.mark.windows_runtime_acl]


@pytest.mark.skipif(sys.platform != "win32", reason="requires the demonstration Windows host")
def test_configured_receiver_runtime_acl_is_protected() -> None:
    settings = ReceiverSettings.from_env()
    audit_store_root(settings.data_root)
