"""Wayback Machine CDX API client.

Docs: https://github.com/internetarchive/wayback/blob/master/wayback-cdx-server/README.md
Endpoint: http://web.archive.org/cdx/search/cdx
"""
from __future__ import annotations

import re
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

# Unicode ranges used to detect Japanese text in HTML bodies.
_JAPANESE_RANGES = (
    (0x3040, 0x309F),  # Hiragana
    (0x30A0, 0x30FF),  # Katakana
    (0x4E00, 0x9FFF),  # CJK Unified Ideographs
    (0xFF66, 0xFF9F),  # Half-width Katakana
)


def extract_text(html: str, max_chars: int = 5000) -> tuple[str, str]:
    """Return (title, text) extracted from `html`.

    Used by the categoriser in analyze.py; keeps title separate so we
    can weight it higher than body text.
    """
    if not html:
        return "", ""
    title_m = re.search(
        r"<title[^>]*>([^<]{1,400})</title>", html, re.I | re.S
    )
    title = (title_m.group(1) if title_m else "").strip()
    text = re.sub(r"<script[^>]*>.*?</script>", " ", html, flags=re.S | re.I)
    text = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.S | re.I)
    text = re.sub(r"<!--.*?-->", " ", text, flags=re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return title, text[:max_chars]


def _is_japanese_text(html: str, threshold: float = 0.05) -> bool:
    """Return True if `html` looks like Japanese content.

    Heuristics:
      1. <html lang="ja...">
      2. Ratio of Japanese chars / printable chars >= threshold
    """
    if not html:
        return False
    m = re.search(
        r'<html[^>]*\blang\s*=\s*["\']([A-Za-z-]+)',
        html[:4000],
        re.I,
    )
    if m and m.group(1).lower().startswith("ja"):
        return True
    total = 0
    jp = 0
    for c in html:
        cp = ord(c)
        if cp < 0x21:  # whitespace / control
            continue
        total += 1
        for lo, hi in _JAPANESE_RANGES:
            if lo <= cp <= hi:
                jp += 1
                break
    if total < 200:
        return False
    return (jp / total) >= threshold


def fetch_snapshot_html(
    domain: str, timestamp: str, timeout: int = 15, max_bytes: int = 200_000
) -> str:
    """Fetch a specific Wayback snapshot's raw HTML (no toolbar).

    Uses the `id_` flag to get the unrewritten body. Capped at `max_bytes`.
    """
    url = f"http://web.archive.org/web/{timestamp}id_/http://{domain}/"
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
            stream=True,
        )
        if resp.status_code != 200:
            return ""
        content = resp.raw.read(max_bytes, decode_content=True)
        enc = resp.encoding or resp.apparent_encoding or "utf-8"
        return content.decode(enc, errors="replace")
    except Exception:
        return ""


def _pick_latest_html(rows: list[dict]) -> dict | None:
    """Return the snapshot row with the most recent text/html 200 response."""
    cands = [
        r for r in rows
        if (r.get("mimetype") or "").lower().startswith("text/html")
        and (r.get("statuscode") or "") == "200"
    ]
    if not cands:
        return None
    cands.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
    return cands[0]


def _parse_ts(ts: str) -> datetime | None:
    """CDX timestamps look like 20050102153025."""
    try:
        return datetime.strptime(ts[:14], "%Y%m%d%H%M%S")
    except (ValueError, TypeError):
        return None


def fetch_cdx(
    domain: str, timeout: int = 30, retries: int = 3
) -> list[dict[str, Any]]:
    """Return all snapshots for ``domain`` as a list of dicts.

    Each row: ``{timestamp, original, mimetype, statuscode, digest}``.

    Retries on 429 / 5xx / network errors with exponential backoff
    (3s, 6s, 12s) since Wayback intermittently returns those under
    load and the previous bare ``requests.get`` would fail outright.
    """
    import time as _time

    params = {
        "url": domain,
        "output": "json",
        "fl": "timestamp,original,mimetype,statuscode,digest",
        "collapse": "digest",
    }
    last_exc: Exception | None = None
    last_resp: requests.Response | None = None
    for attempt in range(retries):
        try:
            resp = requests.get(
                CDX_URL,
                params=params,
                timeout=timeout,
                headers={"User-Agent": USER_AGENT},
            )
        except requests.RequestException as exc:
            last_exc = exc
            last_resp = None
            if attempt < retries - 1:
                _time.sleep(3 * (2 ** attempt))
                continue
            raise
        last_resp = resp
        if resp.status_code == 429 or resp.status_code >= 500:
            if attempt < retries - 1:
                ra = resp.headers.get("Retry-After")
                wait = float(ra) if ra and ra.isdigit() else 3 * (2 ** attempt)
                _time.sleep(min(wait, 30.0))
                continue
        resp.raise_for_status()
        data = resp.json()
        if not data:
            return []
        header, *rows = data
        return [dict(zip(header, row)) for row in rows]
    # Exhausted retries on transient status — surface the last response.
    if last_resp is not None:
        last_resp.raise_for_status()
    if last_exc is not None:
        raise last_exc
    return []


def summarize(
    domain: str,
    timeout: int = 30,
    check_content: bool = True,
) -> dict[str, Any]:
    """Return a summary of Wayback history for `domain`.

    Japanese detection:
      1. URL heuristic — any snapshot whose host ends in `.jp` etc.
      2. (if check_content) fetch the latest HTML snapshot and look for
         `<html lang="ja">` or a ≥5 % Japanese-character ratio.
    """
    rows = fetch_cdx(domain, timeout=timeout)
    if not rows:
        return {
            "first_snapshot": None,
            "last_snapshot": None,
            "last_snapshot_ts": None,
            "snapshot_count": 0,
            "years_active": 0.0,
            "has_japanese": False,
            "japanese_source": "none",
            "title": "",
            "text_sample": "",
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
        host = original.split("//", 1)[-1].split("/", 1)[0]
        if host.endswith(".jp"):
            has_jp = True
            break

    japanese_source = "url" if has_jp else "none"
    title = ""
    text_sample = ""
    if check_content:
        snap = _pick_latest_html(rows)
        if snap:
            html = fetch_snapshot_html(domain, snap.get("timestamp", ""))
            if html:
                title, text_sample = extract_text(html)
                if not has_jp and _is_japanese_text(html):
                    has_jp = True
                    japanese_source = "content"

    return {
        "first_snapshot": first.date().isoformat() if first else None,
        "last_snapshot": last.date().isoformat() if last else None,
        "last_snapshot_ts": last.strftime("%Y%m%d%H%M%S") if last else None,
        "snapshot_count": len(rows),
        "years_active": years,
        "has_japanese": has_jp,
        "japanese_source": japanese_source,
        "title": title,
        "text_sample": text_sample,
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
