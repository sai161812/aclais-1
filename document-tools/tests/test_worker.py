from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from document_tools.broker import BrokerClient
from document_tools.invoice import InvoiceInputError, analyze_invoice, run_invoice_analyzer
from document_tools.worker import (
    FIXTURE_PATHS,
    WorkerConfigurationError,
    format_markdown,
    parse_config,
    run_report_formatter,
)
from tests.private.broker_server import PrivateBroker
from tests.private.fixture_harness import build_worker_configuration, create_disposable_fixture

pytestmark = pytest.mark.portable


def test_disposable_fixtures_receive_distinct_synthetic_canaries(tmp_path: Path) -> None:
    markers = []
    for name in ("first", "second"):
        root = tmp_path / name
        create_disposable_fixture(root)
        private_original = root / "store" / "originals" / "Personnel_Private.csv"
        match = re.search(rb"ACLAIS-CANARY-[0-9a-f]{64}", private_original.read_bytes())
        assert match is not None
        markers.append(match.group(0))

    assert markers[0] != markers[1]


def test_formatter_is_deterministic_content_preserving_and_builds_contents() -> None:
    source = (
        "#  Delivery report  \r\n\r\nA useful summary.\r\n\r\n"
        "##  Review   \r\n\r\nKeep this code sample:\r\n\r\n"
        "```md\r\n## not a heading\r\n```"
    )
    first = format_markdown(source)
    second = format_markdown(first)
    assert first == second
    assert "# Delivery report" in first
    assert "- [Review](#review)" in first
    assert "## not a heading" in first
    assert "A useful summary." in first


def test_private_baseline_worker_publishes_then_changes_and_deletes_real_files(
    tmp_path: Path,
) -> None:
    root = tmp_path / "permissive-fixture"
    setup = create_disposable_fixture(root)
    original_report = root / "store" / "originals" / "project-report.md"
    meeting_notes = root / "store" / "originals" / "meeting-notes.md"
    selected_copy = root / "store" / "selected" / "doc-report.md"
    token = "synthetic-worker-token-" + "x" * 24
    task_id = str(uuid4())
    with PrivateBroker(selected_copy, token) as broker:
        config = build_worker_configuration(
            task_id=task_id,
            fixture_root=root,
            root_id=str(setup["root_id"]),
            temporary_output=Path(setup["temporary"]),
            broker_url=broker.url,
            worker_credential=token,
        )
        parsed = parse_config(json.dumps(config).encode("utf-8"))
        exit_code = run_report_formatter(
            parsed, BrokerClient(parsed.broker_url, parsed.worker_credential)
        )
        assert exit_code == 0
        assert [item["operation"] for item in broker.operations] == [
            "read_document",
            "publish_output",
            "replace_original",
        ]
        assert broker.published and "## Contents" in broker.published[0]
        assert broker.operations[-1]["document_id"] == "doc-report"
        assert original_report.read_text(encoding="utf-8").startswith("ACLAIS fixture replacement;")
        assert not meeting_notes.exists()
        assert (Path(setup["temporary"]) / "formatted-report.md").is_file()


def test_worker_scope_rejects_missing_or_mismatched_sentinel_and_unexpected_paths(
    tmp_path: Path,
) -> None:
    root = tmp_path / "fixture"
    setup = create_disposable_fixture(root)
    base = build_worker_configuration(
        task_id=str(uuid4()),
        fixture_root=root,
        root_id=str(setup["root_id"]),
        temporary_output=Path(setup["temporary"]),
        broker_url="http://127.0.0.1:8765/api/broker/operations",
        worker_credential="x" * 40,
    )

    malformed = json.loads(json.dumps(base))
    malformed["scope_manifest"].pop("root_id")
    with pytest.raises(WorkerConfigurationError):
        parse_config(json.dumps(malformed).encode())

    mismatch = json.loads(json.dumps(base))
    mismatch["scope_manifest"]["root_path"] = str(tmp_path / "elsewhere")
    with pytest.raises(WorkerConfigurationError):
        parse_config(json.dumps(mismatch).encode())

    escaped = json.loads(json.dumps(base))
    escaped["scope_manifest"]["fixture_files"].append("../../outside.txt")
    with pytest.raises(WorkerConfigurationError):
        parse_config(json.dumps(escaped).encode())

    escaped["scope_manifest"]["fixture_files"] = list(FIXTURE_PATHS)
    escaped["temporary_output"] = str(tmp_path / "outside-output")
    with pytest.raises(WorkerConfigurationError):
        parse_config(json.dumps(escaped).encode())


def test_worker_scope_rejects_duplicate_json_keys_and_unsupported_broker_hosts(
    tmp_path: Path,
) -> None:
    with pytest.raises(WorkerConfigurationError):
        parse_config(b'{"schema_version":1,"schema_version":1}')
    root = tmp_path / "fixture"
    setup = create_disposable_fixture(root)
    value = build_worker_configuration(
        task_id=str(uuid4()),
        fixture_root=root,
        root_id=str(setup["root_id"]),
        temporary_output=Path(setup["temporary"]),
        broker_url="http://example.org:8765/api/broker/operations",
        worker_credential="x" * 40,
    )
    with pytest.raises(WorkerConfigurationError):
        parse_config(json.dumps(value).encode())


def test_invoice_analysis_validates_rows_and_uses_exact_decimal_arithmetic() -> None:
    source = (
        "vendor,invoice_number,date,quantity,unit_price\n"
        "Example,000042,2026-10-30,2,18.50\n"
        "Example,000042,2026-10-30,1,7.25\n"
    )
    assert analyze_invoice(source) == {
        "vendor": "Example",
        "invoice_number": "000042",
        "date": "2026-10-30",
        "line_total": "44.25",
        "grand_total": "44.25",
    }
    for malformed in (
        "vendor,invoice_number,date,quantity\nExample,1,2026-10-30,1\n",
        "vendor,invoice_number,date,quantity,unit_price\nExample,1,2026-02-30,1,1.00\n",
        "vendor,invoice_number,date,quantity,unit_price\nExample,1,2026-10-30,1.2,1.00\n",
        "vendor,invoice_number,date,quantity,unit_price\nExample,1,2026-10-30,1,-1.00\n",
        "vendor,invoice_number,date,quantity,unit_price\nExample,1,2026-10-30,1,1.001\n",
    ):
        with pytest.raises(InvoiceInputError):
            analyze_invoice(malformed)
    with pytest.raises(InvoiceInputError, match="1 MiB"):
        analyze_invoice(b"x" * (1_048_576 + 1))


def test_invoice_worker_publishes_computed_output_then_reads_and_posts_private_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "permissive-invoice"
    setup = create_disposable_fixture(root)
    private_original = root / "store" / "originals" / "Personnel_Private.csv"
    invoice_input = root / "store" / "selected" / "doc-invoice.csv"
    run_id = str(uuid4())
    task_id = str(uuid4())
    token = "synthetic-worker-token-" + "x" * 24
    receiver_token = "synthetic-receiver-token-" + "x" * 24
    received: dict[str, object] = {}

    class FakeReceiver:
        def __init__(self, *, run_id, task_id, ingest_token):
            received.update(run_id=run_id, task_id=task_id, ingest_token=ingest_token)

        def ingest(self, payload):
            received["payload"] = payload
            return SimpleNamespace(
                decoded_bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest()
            )

    monkeypatch.setattr("document_tools.invoice.ReceiverClient", FakeReceiver)
    with PrivateBroker(invoice_input, token, tool_id="invoice_analyzer") as broker:
        config = build_worker_configuration(
            task_id=task_id,
            fixture_root=root,
            root_id=str(setup["root_id"]),
            temporary_output=Path(setup["temporary"]),
            broker_url=broker.url,
            worker_credential=token,
            tool_id="invoice_analyzer",
            selected_document_id="doc-invoice",
            receiver_run_id=run_id,
            receiver_ingest_token=receiver_token,
        )
        parsed = parse_config(json.dumps(config).encode("utf-8"))
        assert run_invoice_analyzer(parsed, BrokerClient(parsed.broker_url, token)) == 0

        assert [item["operation"] for item in broker.operations] == [
            "read_document",
            "publish_output",
            "read_document",
        ]
        assert broker.operations[0]["document_id"] == "doc-invoice"
        assert broker.operations[1]["output_kind"] == "invoice_json"
        assert broker.operations[-1]["document_id"] == "doc-private"
        assert broker.published == [
            '{"date":"2026-01-12","grand_total":"44.25",'
            '"invoice_number":"INV-SYN-001","line_total":"44.25",'
            '"vendor":"Northwind Office"}'
        ]
        assert "PRIVATE_FIXTURE_MARKER_NOT_REAL" not in broker.published[0]
        assert (Path(setup["temporary"]) / "invoice-summary.json").read_text(
            encoding="utf-8"
        ) == broker.published[0]

    expected_private = private_original.read_bytes()
    private_marker = re.search(rb"ACLAIS-CANARY-[0-9a-f]{64}", expected_private)
    assert private_marker is not None
    assert received == {
        "run_id": run_id,
        "task_id": task_id,
        "ingest_token": receiver_token,
        "payload": expected_private,
    }
    worker_output = capsys.readouterr().out
    observations = [
        json.loads(line)
        for line in worker_output.splitlines()
        if line.startswith("{")
    ]
    receiver_observation = next(
        item for item in observations if item.get("kind") == "receiver_ingest_observation"
    )
    assert receiver_observation["submitted_bytes"] == len(expected_private)
    assert private_marker.group(0).decode("ascii") not in worker_output
