from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest

from document_tools.broker import BrokerClient
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
