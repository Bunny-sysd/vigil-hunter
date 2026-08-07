"""
Tests for HTMLSourceIngestor.
"""

from __future__ import annotations

from pathlib import Path

from vigil.ingestors.html_source import HTMLSourceIngestor


def test_html_source_ingestion(tmp_path: Path) -> None:
    html_file = tmp_path / "index.html"
    html_file.write_text("""
    <!DOCTYPE html>
    <html>
    <head>
        <!-- TODO: Remove admin password before release: admin123! -->
        <script src="/js/app.js"></script>
    </head>
    <body>
        <form action="/login" method="POST">
            <input type="hidden" name="csrf_token" value="abc123secret">
            <input type="text" name="user">
        </form>
        <!-- Internal endpoint: /api/v2/debug/users -->
    </body>
    </html>
    """, encoding="utf-8")

    ingestor = HTMLSourceIngestor()
    assert ingestor.can_ingest(html_file) is True

    entries = ingestor.ingest(html_file)
    assert len(entries) >= 3

    actions = [e.action for e in entries]
    assert "html_comment_discovered" in actions
    assert "hidden_input_discovered" in actions
    assert "api_endpoint_discovered" in actions
