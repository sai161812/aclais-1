from __future__ import annotations

import csv
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_HEADERS = ("vendor", "invoice_number", "date", "quantity", "unit_price")


def test_protected_and_disposable_invoice_fixtures_share_supported_schema() -> None:
    protected = (
        REPOSITORY_ROOT / "aclais" / "tests" / "fixtures" / "templates"
        / "invoice.template.csv"
    )
    disposable = (
        REPOSITORY_ROOT / "document-tools" / "tests" / "fixtures" / "templates"
        / "invoice.csv"
    )

    schemas = []
    for fixture in (protected, disposable):
        with fixture.open("r", encoding="utf-8-sig", newline="") as stream:
            rows = list(csv.reader(stream, strict=True))
        assert rows and tuple(rows[0]) == EXPECTED_HEADERS
        assert len(rows) > 1
        assert all(len(row) == len(EXPECTED_HEADERS) for row in rows[1:])
        schemas.append(tuple(rows[0]))

    assert schemas[0] == schemas[1]
