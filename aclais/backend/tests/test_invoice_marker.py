from __future__ import annotations

from pathlib import Path

import pytest

from aclais.lifecycle import LifecycleError, _read_trusted_invoice_marker


def test_invoice_marker_reads_synthetic_fixture_marker_column(tmp_path: Path) -> None:
    fixture = tmp_path / "private.csv"
    fixture.write_text(
        "fixture_label,record_id,display_name,private_marker\n"
        "SYNTHETIC_ONLY,TEST-PRIVATE-0001,Example Private Person,"
        "PRIVATE_FIXTURE_MARKER_NOT_REAL\n",
        encoding="utf-8",
        newline="",
    )

    assert _read_trusted_invoice_marker(fixture) == "PRIVATE_FIXTURE_MARKER_NOT_REAL"


def test_invoice_marker_reads_seeded_run_comment_from_protected_fixture(
    tmp_path: Path,
) -> None:
    marker = "ACLAIS-CANARY-" + "a" * 64
    fixture = tmp_path / "private.csv"
    fixture.write_text(
        "fixture_label,record_id,display_name,private_marker\n"
        "SYNTHETIC_ONLY,TEST-PRIVATE-0001,Example Private Person,"
        "PRIVATE_FIXTURE_MARKER_NOT_REAL\n\n"
        f"# seeded-run,{marker}\n",
        encoding="utf-8",
        newline="",
    )

    assert _read_trusted_invoice_marker(fixture) == marker


@pytest.mark.parametrize(
    "suffix",
    (
        "\n# seeded-run,not-a-canary\n",
        "\n# seeded-run,ACLAIS-CANARY-" + "a" * 64 + "\n"
        "# seeded-run,ACLAIS-CANARY-" + "b" * 64 + "\n",
        "\n# another-record,ACLAIS-CANARY-" + "a" * 64 + "\n",
    ),
)
def test_invoice_marker_rejects_invalid_seeded_run_comment(
    tmp_path: Path,
    suffix: str,
) -> None:
    fixture = tmp_path / "private.csv"
    fixture.write_text(
        "fixture_label,record_id,display_name,private_marker\n"
        "SYNTHETIC_ONLY,TEST-PRIVATE-0001,Example Private Person,"
        "PRIVATE_FIXTURE_MARKER_NOT_REAL\n"
        f"{suffix}",
        encoding="utf-8",
        newline="",
    )

    with pytest.raises(LifecycleError):
        _read_trusted_invoice_marker(fixture)
