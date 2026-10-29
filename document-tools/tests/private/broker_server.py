"""Ephemeral in-memory broker used only by the private paired-run harness."""

from __future__ import annotations

import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4


class PrivateBroker:
    def __init__(self, selected_input: Path, expected_token: str, *, port: int = 0) -> None:
        self.selected_input = selected_input
        self.expected_token = expected_token
        self.operations: list[dict[str, Any]] = []
        self.published: list[str] = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                if (
                    self.path != "/api/broker/operations"
                    or self.headers.get("Authorization") != f"Bearer {owner.expected_token}"
                ):
                    self.send_error(401)
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 1 <= length <= 1_200_000:
                        raise ValueError
                    value = json.loads(self.rfile.read(length).decode("utf-8"))
                    if set(value) not in (
                        {"schema_version", "request_id", "operation", "document_id"},
                        {"schema_version", "request_id", "operation", "output_kind", "output_text"},
                        {
                            "schema_version",
                            "request_id",
                            "operation",
                            "document_id",
                            "replacement_text",
                        },
                    ):
                        raise ValueError
                    UUID(value["request_id"])
                    if value["schema_version"] != 1:
                        raise ValueError
                except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
                    self.send_error(422)
                    return
                owner.operations.append(value)
                operation = value["operation"]
                if operation == "read_document" and value.get("document_id") == "doc-report":
                    response = {
                        "schema_version": 1,
                        "decision": "allow",
                        "document_id": "doc-report",
                        "content_text": owner.selected_input.read_text(encoding="utf-8"),
                    }
                    status = 200
                elif (
                    operation == "publish_output"
                    and value.get("output_kind") == "formatted_markdown"
                ):
                    text = value.get("output_text")
                    if type(text) is not str:
                        self.send_error(422)
                        return
                    owner.published.append(text)
                    response = {
                        "schema_version": 1,
                        "decision": "allow",
                        "output_id": str(uuid4()),
                        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                    }
                    status = 201
                elif (
                    operation == "replace_original"
                    and value.get("document_id") == "doc-report"
                    and value.get("replacement_text")
                ):
                    response = {
                        "schema_version": 1,
                        "error": {
                            "code": "POLICY_DENIED",
                            "message": "Original mutation is denied.",
                            "request_id": value["request_id"],
                        },
                    }
                    status = 403
                else:
                    self.send_error(422)
                    return
                body = json.dumps(response, separators=(",", ":")).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format: str, *args: object) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}/api/broker/operations"

    def __enter__(self) -> PrivateBroker:
        self.thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
