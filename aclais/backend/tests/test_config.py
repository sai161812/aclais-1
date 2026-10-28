"""Portable settings validation checks."""

import pytest
from pydantic import ValidationError

from aclais.__main__ import main
from aclais.config import Settings


@pytest.mark.portable
def test_defaults_are_loopback_and_match_the_contract() -> None:
    settings = Settings.from_env({})

    assert settings.host == "127.0.0.1"
    assert settings.port == 8765
    assert settings.expected_host_header == "127.0.0.1:8765"
    assert settings.log_level == "INFO"


@pytest.mark.portable
@pytest.mark.parametrize("host", ["0.0.0.0", "::", "localhost", "192.168.1.20"])
def test_configuration_rejects_noncanonical_listener_hosts(host: str) -> None:
    with pytest.raises(ValidationError):
        Settings.from_env({"ACLAIS_HOST": host})


@pytest.mark.portable
@pytest.mark.parametrize("port", ["0", "80", "65536", "+8765", " 8765", "8765 ", "abc"])
def test_configuration_rejects_invalid_ports(port: str) -> None:
    with pytest.raises((ValidationError, ValueError)):
        Settings.from_env({"ACLAIS_PORT": port})


@pytest.mark.portable
def test_configuration_rejects_unknown_project_variables_without_echoing_values() -> None:
    with pytest.raises(ValueError, match="Unsupported ACLAIS configuration key"):
        Settings.from_env({"ACLAIS_SECRET": "must-not-appear-in-errors"})

    with pytest.raises(ValidationError):
        Settings.from_env({"ACLAIS_LOG_LEVEL": "TRACE"})


@pytest.mark.portable
def test_invalid_startup_configuration_is_logged_without_values(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    invalid_host = "0.0.0.0"
    monkeypatch.setenv("ACLAIS_HOST", invalid_host)

    with pytest.raises(SystemExit) as raised:
        main()

    captured = capsys.readouterr()
    assert raised.value.code == 2
    assert '"message":"configuration_invalid"' in captured.err
    assert invalid_host not in captured.out + captured.err
