from __future__ import annotations

import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen

import pytest

from document_tools.server import handler_for

pytestmark = pytest.mark.portable


def test_site_host_allowlist_and_no_cookie_or_cors_headers(tmp_path: Path) -> None:
    index = tmp_path / "index.html"
    index.write_text("<main>Document Tools</main>", encoding="utf-8")
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(tmp_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        request = Request(
            f"http://127.0.0.1:{server.server_port}/",
            headers={"Host": "localhost:8766"},
        )
        with urlopen(request, timeout=3) as response:
            assert response.status == 200
            assert response.read() == b"<main>Document Tools</main>"
            assert response.headers.get("Set-Cookie") is None
            assert response.headers.get("Access-Control-Allow-Origin") is None
            assert response.headers.get("Content-Security-Policy")

        blocked = Request(
            f"http://127.0.0.1:{server.server_port}/",
            headers={"Host": "127.0.0.1:8766"},
        )
        with pytest.raises(Exception):
            urlopen(blocked, timeout=3)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_normal_tool_card_links_only_to_trusted_aclais_approval() -> None:
    source = (Path(__file__).resolve().parents[1] / "frontend" / "src" / "main.tsx").read_text(
        encoding="utf-8"
    )
    assert "http://127.0.0.1:8765/approve" in source
    assert 'searchParams.set("launch_source_claim", "document_tools")' in source
    assert 'approvalUrl("report_formatter")' in source
    assert 'disabled aria-disabled="true"' in source
    for prohibited in ("attack button", "protection switch", "demo mode", "payload input"):
        assert prohibited not in source.casefold()
