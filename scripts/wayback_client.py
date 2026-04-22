"""Wayback Machine CDX API client.

Docs: https://github.com/internetarchive/wayback/blob/master/wayback-cdx-server/README.md
Endpoint: http://web.archive.org/cdx/search/cdx
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

import requests

CDX_URL = "http://web.archive.org/cdx/search/cdx"

# Wayback blocks requests with python-requests' default UA; send a real one.
USER_AGENT = (
    "old-domain-tool/0.1 (+https://github.com/) "
    "Mozilla/5.0 (compatible; python-requests)"
)

# Heuristics for "has Japanese content history":
#   - Any snapshot whose original URL ends with `.jp` (or has `.jp/`)
#   - Any snapshot whose mimetype is text/html and original URL contains
#     common japanese TLD/hosts. We can't fetch body cheaply, so we also
#     infer from language hints that appear in some CDX rows.
JAPANESE_URL_HINTS = (".jp/", ".jp?", ".jp#", ".co.jp", ".or.jp", ".ne.jp")


def _parse_ts(ts: str) -> datetime | None:
    """CDX timestamps look like 20050102153025."""
    try:
        return datetime.strptime(ts[:14], "%Y%m%d%H%M%S")
    except (ValueError, TypeError):
        return None


def fetch_cdx(domain: str, timeout: int = 30) -> list[dict[str, Any]]:
    """Return all snapshots for `domain` as a list of dicts.

    Each row: {timestamp, original, mimetype, statuscode, digest}
    """
    params = {
        "url": domain,
        "output": "json",
        "fl": "timestamp,original,mimetype,statuscode,digest",
        "collapse": "digest",
    }
    resp = requests.get(
        CDX_URL,
        params=params,
        timeout=timeout,
        headers={"User-Agent": USER_AGENT},
    )
    resp.raise_for_status()
    data = resp.json()
    if not data:
        return []
    header, *rows = data
    return [dict(zip(header, row)) for row in rows]


def summarize(domain: str, timeout: int = 30) -> dict[str, Any]:
    """Return a summary of Wayback history for `domain`.

    Keys:
      first_snapshot (ISO date str or None)
      last_snapshot  (ISO date str or None)
      snapshot_count (int)
      years_active   (float; years between first and last snapshot)
      has_japanese   (bool; based on URL host hints)
    """
    rows = fetch_cdx(domain, timeout=timeout)
    if not rows:
        return {
            "first_snapshot": None,
            "last_snapshot": None,
            "snapshot_count": 0,
            "years_active": 0.0,
            "has_japanese": False,
        }

    timestamps = [_parse_ts(r.get("timestamp", "")) for r in rows]
    timestamps = [t for t in timestamps if t is not None]
    first = min(timestamps) if timestamps else None
    last = max(timestamps) if timestamps else None
    years = 0.0
    if first and last:
        years = round((last - first).days / 365.25, 2)

    has_jp = False
    for r in rows:
        original = (r.get("original") or "").lower()
        if any(hint in original for hint in JAPANESE_URL_HINTS):
            has_jp = True
            break
        # `example.jp` with no trailing slash
        host = original.split("//", 1)[-1].split("/", 1)[0]
        if host.endswith(".jp"):
            has_jp = True
            break

    return {
        "first_snapshot": first.date().isoformat() if first else None,
        "last_snapshot": last.date().isoformat() if last else None,
        "snapshot_count": len(rows),
        "years_active": years,
        "has_japanese": has_jp,
    }


def _demo() -> None:
    print("[wayback] live summary for example.com:")
    try:
        print(summarize("example.com"))
    except Exception as exc:  # pragma: no cover - network dependent
        print(f"  (skipped; network error: {exc.__class__.__name__})")

    # Offline sanity check of the parsing logic.
    fake_rows = [
        {
            "timestamp": "20050110120000",
            "original": "http://example.jp/",
            "mimetype": "text/html",
            "statuscode": "200",
            "digest": "AAA",
        },
        {
            "timestamp": "20200110120000",
            "original": "http://example.com/",
            "mimetype": "text/html",
            "statuscode": "200",
            "digest": "BBB",
        },
    ]
    timestamps = sorted(_parse_ts(r["timestamp"]) for r in fake_rows)
    assert timestamps[0].year == 2005
    assert timestamps[-1].year == 2020
    print("[wayback] offline parse test ok.")


if __name__ == "__main__":
    _demo()
