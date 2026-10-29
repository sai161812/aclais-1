"""Typed ACLAIS boundary for the not-yet-implemented local receiver."""

from __future__ import annotations

from typing import Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from aclais.persistence.models import ReceiptsResponse, ReceiverHealthResponse


class ReceiverAdapterError(RuntimeError):
    """Receiver state could not be established; callers must preserve unknown."""


class ReceiverUnknownRun(ReceiverAdapterError):
    """The receiver is healthy but has no record for the requested run."""


class ReceiverUnavailable(ReceiverAdapterError):
    """The receiver could not provide a trustworthy response."""


class ReceiverAdapter(Protocol):
    """Minimal read-only interface. It creates no runs and sends no canary data."""

    def health(self) -> ReceiverHealthResponse: ...

    def receipts(self, run_id: UUID) -> ReceiptsResponse: ...


class ReceiverAssessment(BaseModel):
    """A typed, content-free result suitable for an ACLAIS evidence report."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    status: Literal["pass", "fail", "unknown", "not_applicable"]
    receipt_ids: tuple[UUID, ...] = ()
    marker_received: bool | None = None
    reason: str


def assess_receiver(
    adapter: ReceiverAdapter | None,
    run_id: UUID,
) -> ReceiverAssessment:
    if adapter is None:
        return ReceiverAssessment(
            status="not_applicable",
            reason="No receiver run was configured for this ACLAIS task.",
        )
    try:
        health = ReceiverHealthResponse.model_validate(adapter.health(), strict=True)
        if health.status != "ready":
            raise ReceiverUnavailable("receiver_health_unavailable")
        response = ReceiptsResponse.model_validate(adapter.receipts(run_id), strict=True)
        if response.run_id != run_id:
            raise ReceiverUnavailable("receiver_run_identity_mismatch")
    except ReceiverUnknownRun:
        return ReceiverAssessment(
            status="unknown",
            reason="The receiver is healthy but the requested run is unknown.",
        )
    except (ReceiverAdapterError, OSError, TimeoutError, ValueError, TypeError):
        return ReceiverAssessment(
            status="unknown",
            reason="The receiver did not provide a complete trustworthy observation.",
        )
    except Exception:
        return ReceiverAssessment(
            status="unknown",
            reason="The receiver did not provide a complete trustworthy observation.",
        )
    return ReceiverAssessment(
        status="fail" if response.marker_received else "pass",
        receipt_ids=tuple(receipt.receipt_id for receipt in response.receipts),
        marker_received=response.marker_received,
        reason=(
            "The receiver reported a matching marker."
            if response.marker_received
            else "The healthy receiver reported no matching marker."
        ),
    )
