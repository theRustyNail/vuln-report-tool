"""JSON file cache for NVD CVE responses.

Each CVE's raw API response is stored as ``data/cache/<CVE-ID>.json`` so repeat
lookups during development and evaluation do not re-hit the NVD service.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

# This file lives at <repo>/vulnreport/nvd/cache.py, so the repo root is three
# levels up. The cache directory matches the layout in the design notes.
_REPO_ROOT = Path(__file__).resolve().parents[2]
CACHE_DIR = _REPO_ROOT / "data" / "cache"


def cache_path(cve_id: str) -> Path:
    """Return the file path used to cache a given CVE."""
    return CACHE_DIR / f"{cve_id}.json"


def load(cve_id: str) -> Optional[dict]:
    """Return the cached response for a CVE, or None if it is not cached."""
    path = cache_path(cve_id)
    if not path.exists():
        return None
    try:
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        # Treat an unreadable or corrupt cache file as a miss.
        return None


def save(cve_id: str, data: dict) -> None:
    """Write a CVE response to the cache, creating the directory if needed."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    with cache_path(cve_id).open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
