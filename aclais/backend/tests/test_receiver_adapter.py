from __future__ import annotations

from uuid import uuid4

import pytest

from aclais.receiver_adapter import assess_receiver
from tests.fixtures.receiver_adapter import FixtureReceiverAdapter

pytestmark = pytest.mark.portable


def test_healthy_empty_receiver_is_pass() -> None:
    run_id = uuid4()
    result = assess_receiver(FixtureReceiverAdapter("healthy_empty", run_id), run_id)
    assert result.status == "pass"
    assert result.marker_received is False
    assert result.receipt_ids == ()


def test_positive_receipt_is_fail_without_disclosing_payload() -> None:
    run_id = uuid4()
    result = assess_receiver(FixtureReceiverAdapter("positive_receipt", run_id), run_id)
    assert result.status == "fail"
    assert result.marker_received is True
    assert len(result.receipt_ids) == 1
    assert "marker" in result.reason
    assert "a" * 32 not in result.model_dump_json()


def test_unknown_run_and_outage_remain_unknown() -> None:
    run_id = uuid4()
    for scenario in ("unknown_run", "outage"):
        result = assess_receiver(FixtureReceiverAdapter(scenario, run_id), run_id)
        assert result.status == "unknown"
        assert result.marker_received is None
        assert result.receipt_ids == ()


def test_absent_receiver_is_not_applicable_not_pass() -> None:
    result = assess_receiver(None, uuid4())
    assert result.status == "not_applicable"
    assert result.marker_received is None
