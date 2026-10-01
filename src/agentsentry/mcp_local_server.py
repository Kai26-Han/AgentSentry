"""A fixed, synthetic MCP server used to exercise the gateway's MCP egress."""

import os
import re
import sqlite3
import json
import uuid
from pathlib import Path

from mcp.types import CallToolResult, TextContent
from mcp.server.mcpserver import MCPServer


server = MCPServer("AgentSentry local reference server", version="2.1")

CARDS = {
    "public-guide": "The quarterly plan should be reviewed before Friday.",
    "routing-guide": "Use the approved demo-notes notebook for review notes.",
}
from .attack_corpus import cards as research_cards
from .memory_lab import cards as memory_cards
from .calibration_corpus import cards as calibration_cards
from .goal_lab_corpus import cards as goal_cards

CARDS.update(research_cards())
CARDS.update(memory_cards())
CARDS.update(calibration_cards())
CARDS.update(goal_cards())


def _result(payload: dict) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(payload, ensure_ascii=False))],
        structured_content=payload,
    )


@server.tool()
def lookup_card(card_id: str) -> CallToolResult:
    """Look up a synthetic reference card by its ID."""
    if card_id not in CARDS:
        return _result({"error": "card_not_found"})
    return _result({"card_id": card_id, "content": CARDS[card_id]})


@server.tool()
def record_note(note_id: str, text: str, operation_id: str) -> CallToolResult:
    """Record a synthetic review note in the local demo notebook."""
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", note_id) or not 1 <= len(text) <= 500:
        return _result({"error": "invalid_note"})
    try:
        uuid.UUID(operation_id)
    except ValueError:
        return _result({"error": "invalid_operation_id"})
    path = Path(os.environ["MCP_DEMO_DB_PATH"])
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path, timeout=5) as db:
        db.execute("CREATE TABLE IF NOT EXISTS notes (operation_id TEXT PRIMARY KEY, note_id TEXT NOT NULL, text TEXT NOT NULL)")
        db.execute(
            "INSERT OR IGNORE INTO notes (operation_id, note_id, text) VALUES (?, ?, ?)",
            (operation_id, note_id, text),
        )
        db.commit()
    return _result({"note_id": note_id, "recorded": True})


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
