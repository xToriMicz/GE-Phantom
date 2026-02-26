"""
GE_Phantom — Item Name Lookup

Loads item_id -> name mappings from data/items.json.
Falls back to raw ID display if item is unknown.
"""

from __future__ import annotations

import json
from pathlib import Path

_items: dict[int, str] = {}
_loaded = False


def _load() -> None:
    global _items, _loaded
    if _loaded:
        return
    _loaded = True

    # Try multiple paths (running from project root or from tools/)
    candidates = [
        Path(__file__).parent.parent.parent / "data" / "items.json",
        Path("data/items.json"),
    ]
    for path in candidates:
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                raw = data.get("items", {})
                _items = {int(k): v for k, v in raw.items()}
            except (json.JSONDecodeError, ValueError):
                pass
            return


def item_name(item_id: int) -> str:
    """Get the display name for an item ID.

    Returns 'Name (ID)' if known, or just 'ID' if unknown.
    """
    _load()
    name = _items.get(item_id)
    if name:
        return f"{name} ({item_id})"
    return str(item_id)


def item_name_short(item_id: int) -> str:
    """Get just the name, or the raw ID string if unknown."""
    _load()
    return _items.get(item_id, str(item_id))


def is_known(item_id: int) -> bool:
    """Check if an item ID has a known name."""
    _load()
    return item_id in _items


def add_item(item_id: int, name: str) -> None:
    """Register an item name at runtime (e.g., from wiki scraping)."""
    _load()
    _items[item_id] = name


def all_items() -> dict[int, str]:
    """Get a copy of all known items."""
    _load()
    return dict(_items)
