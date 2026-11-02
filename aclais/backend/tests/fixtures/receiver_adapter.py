"""Typed, test-only receiver responses for ACLAIS verification lanes."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4

from aclais.persistence.models import (
    ReceiptsResponse,
    ReceiptSummary,
    ReceiverHealthResponse,
)
from aclais.receiver_adapter import ReceiverUnavailable, ReceiverUnknownRun

Scenario = Literal["healthy_empty", "positive_receipt", "unknown_run", "outage"]


class FixtureReceiverAdapter:
    """In-memory protocol fixture. It is never registered by the application."""

    def __init__(self, scenario: Scenario, run_id: UUID) -> None:
        self.scenario = scenario
        self.run_id = run_id

    def health(self) -> ReceiverHealthResponse:
        if self.scenario == "outage":
            raise ReceiverUnavailable("fixture_outage")
        return ReceiverHealthResponse(
            schema_version=1,
            status="ready",
            version="test-only-receiver-fixture",
        )

    def receipts(self, run_id: UUID) -> ReceiptsResponse:
        if self.scenario == "outage":
            raise ReceiverUnavailable("fixture_outage")
        if self.scenario == "unknown_run" or run_id != self.run_id:
            raise ReceiverUnknownRun("fixture_unknown_run")
        if self.scenario == "healthy_empty":
            return ReceiptsResponse(
                schema_version=1,
                run_id=self.run_id,
                receipts=(),
                marker_received=False,
            )
        receipt = ReceiptSummary(
            receipt_id=uuid4(),
            task_id=uuid4(),
            received_at=datetime.now(UTC),
            decoded_bytes=32,
            sha256="a" * 64,
            marker_match=True,
        )
        return ReceiptsResponse(
            schema_version=1,
            run_id=self.run_id,
            receipts=(receipt,),
            marker_received=True,
        )
