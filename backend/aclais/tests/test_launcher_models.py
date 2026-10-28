"""Portable shape and Windows argv quoting checks for A3 launcher configuration."""

import ctypes
from uuid import uuid4

import pytest
from pydantic import ValidationError

from aclais.launcher.models import A3ProbeConfiguration, windows_command_line
from aclais.launcher.windows import _CredentialSecret


@pytest.mark.portable
def test_a3_configuration_is_strict_bounded_and_absolute() -> None:
    config = A3ProbeConfiguration(
        task_id=uuid4(),
        selected_input=r"C:\ACLAIS-Lab\store\selected\Selected_Input.csv",
        temporary_output=r"C:\ACLAIS-Lab\work\temporary-output",
        deadline_seconds=15,
        probe_case="normal",
    )

    assert config.deadline_seconds == 15
    with pytest.raises(ValidationError):
        A3ProbeConfiguration.model_validate({**config.model_dump(), "unexpected": True})
    with pytest.raises(ValidationError):
        A3ProbeConfiguration.model_validate({**config.model_dump(), "deadline_seconds": "15"})
    with pytest.raises(ValidationError):
        A3ProbeConfiguration.model_validate(
            {**config.model_dump(), "selected_input": r"..\outside.csv"}
        )
    with pytest.raises(ValidationError):
        A3ProbeConfiguration.model_validate(
            {
                **config.model_dump(),
                "selected_input": r"C:\ACLAIS-Lab\store\selected\..\private.csv",
            }
        )
    with pytest.raises(ValidationError):
        A3ProbeConfiguration.model_validate(
            {
                **config.model_dump(),
                "selected_input": r"C:\ACLAIS-Lab\store\selected\input.csv:stream",
            }
        )
    with pytest.raises(ValidationError):
        A3ProbeConfiguration.model_validate({**config.model_dump(), "deadline_seconds": 601})


@pytest.mark.portable
def test_windows_argv_quotes_values_without_shell_expansion() -> None:
    argv = (
        "-I",
        r"C:\Program Files\ACLAIS\worker probe.py",
        "space in value",
        'quote"inside',
        "trailing slash\\",
        "& | < > ; ` $()",
    )

    command_line = windows_command_line(r"C:\Program Files\Python\python.exe", argv)

    assert '"C:\\Program Files\\Python\\python.exe"' in command_line
    assert '"C:\\Program Files\\ACLAIS\\worker probe.py"' in command_line
    assert '"space in value"' in command_line
    assert "& | < > ; ` $()" in command_line
    with pytest.raises(ValueError):
        windows_command_line(r"C:\Python\python.exe", ("bad\x00argument",))
    with pytest.raises(ValueError, match="absolute"):
        windows_command_line("python.exe", ("--fixed",))


@pytest.mark.portable
def test_windows_argv_rejects_command_lines_over_the_documented_limit() -> None:
    with pytest.raises(ValueError, match="limit"):
        windows_command_line(r"C:\Python\python.exe", ("x" * 32_760,))


@pytest.mark.portable
def test_mutable_password_buffer_is_zeroed_after_the_native_call() -> None:
    buffer = ctypes.create_unicode_buffer("a3-synthetic-secret-marker")
    address = ctypes.addressof(buffer)
    size = ctypes.sizeof(buffer)
    credential = _CredentialSecret("MACHINE\\AclaisWorker", buffer)

    credential.clear()

    assert credential.password_buffer is None
    assert ctypes.string_at(address, size) == b"\x00" * size
