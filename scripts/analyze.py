"""Analyze expireddomains.net CSV and produce docs/data.json.

Flow:
  1. Load the newest CSV in data/input/.
  2. For each domain, call Ahrefs (batch-analysis + top anchors) and
     Wayback CDX. 0.5s sleep between domains for anchors/wayback.
  3. Compute a 0-100 score (plus spam penalty).
  4. Write docs/data.json.

Usage:
  python scripts/analyze.py
  python scripts/analyze.py --dry-run    # uses stub data, no API calls
  python scripts/analyze.py --input path/to.csv
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
from dotenv import load_dotenv

# Make sibling imports work whether run as a module or as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ahrefs_client import AhrefsClient  # noqa: E402
from wayback_client import summarize as wayback_summarize  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
INPUT_DIR = ROOT / "data" / "input"
OUTPUT_DIR = ROOT / "data" / "output"
DOCS_DATA = ROOT / "docs" / "data.json"

SPAM_KEYWORDS = [
    "casino",
    "porn",
    "viagra",
    "cialis",
    "poker",
    "カジノ",
    "アダルト",
    "出会い",
    "副業",
    "出合い",
    "エロ",
]

DOMAIN_COLUMN_CANDIDATES = (
    "Domain",
    "domain",
    "DOMAIN",
    "URL",
    "url",
)


def newest_csv(input_dir: Path) -> Path | None:
    csvs = sorted(input_dir.glob("*.csv"), key=lambda p: p.stat().st_mtime)
    return csvs[-1] if csvs else None


def load_domains(csv_path: Path) -> list[str]:
    """Read a CSV and return a de-duplicated list of domains.

    expireddomains.net exports are usually semicolon-separated; we try
    both separators and pick whichever yields a known domain column.
    """
    last_error: Exception | None = None
    for sep in (",", ";", "\t"):
        try:
            df = pd.read_csv(csv_path, sep=sep, dtype=str, keep_default_na=False)
        except Exception as exc:  # pragma: no cover
            last_error = exc
            continue
        for col in DOMAIN_COLUMN_CANDIDATES:
            if col in df.columns:
                values = [v.strip() for v in df[col].tolist() if v and v.strip()]
                # Preserve order while de-duplicating.
                seen: set[str] = set()
                out: list[str] = []
                for v in values:
                    key = v.lower()
                    if key not in seen:
                        seen.add(key)
                        out.append(v)
                return out
    raise RuntimeError(
        f"Could not find a Domain column in {csv_path}. "
        f"Tried separators , ; \\t and columns {DOMAIN_COLUMN_CANDIDATES}. "
        f"(last error: {last_error})"
    )


def compute_score(
    dr: float,
    refdomains: int,
    years_active: float,
    has_japanese: bool,
    has_spam: bool,
) -> dict[str, Any]:
    """Return score breakdown (0-100, minus spam penalty)."""
    dr_pts = round(min(max(dr, 0), 100) * 0.4, 2)
    ref_pts = round(min(math.log10(max(refdomains, 0) + 1) * 7, 20), 2)
    years_pts = round(min(max(years_active, 0) * 2, 15), 2)
    jp_pts = 15 if has_japanese else 0
    spam_penalty = -50 if has_spam else 0
    total = dr_pts + ref_pts + years_pts + jp_pts + spam_penalty
    return {
        "score": round(total, 2),
        "score_breakdown": {
            "dr": dr_pts,
            "refdomains": ref_pts,
            "years": years_pts,
            "japanese": jp_pts,
            "spam_penalty": spam_penalty,
        },
    }


def detect_spam(anchors: list[dict]) -> tuple[bool, list[str]]:
    hits: list[str] = []
    for a in anchors:
        text = (a.get("anchor") or "").lower()
        for kw in SPAM_KEYWORDS:
            if kw.lower() in text:
                hits.append(kw)
                break
    return (len(hits) > 0, sorted(set(hits)))


def _batch_row_for(domain: str, batch: list[dict]) -> dict:
    """batch-analysis rows may use "url" or "target" as the key."""
    dlow = domain.lower().strip()
    for row in batch:
        for k in ("url", "target"):
            if (row.get(k) or "").lower().strip().rstrip("/") == dlow:
                return row
    return {}


def _count_tld(refdoms: list[dict], suffix: str) -> int:
    """Count referring domains whose host ends with `suffix` (case-insensitive)."""
    n = 0
    for r in refdoms or []:
        host = (r.get("domain") or r.get("hostname") or "").lower().rstrip(".")
        if host.endswith(suffix):
            n += 1
    return n


def _f(row: dict, *keys, default: float = 0.0) -> float:
    for k in keys:
        v = row.get(k)
        if v is not None:
            try:
                return float(v)
            except (TypeError, ValueError):
                continue
    return default


def analyze(
    domains: list[str],
    dry_run: bool = False,
    sleep_between: float = 0.5,
) -> list[dict]:
    rows: list[dict] = []

    if dry_run:
        batch_rows: list[dict] = []
        client: AhrefsClient | None = None
    else:
        client = AhrefsClient()
        try:
            info = client.subscription_info()
            print(f"[ahrefs] subscription info: {info}")
        except Exception as exc:
            print(f"[ahrefs] WARN could not fetch subscription info: {exc}")
        print(f"[ahrefs] batch-analysis for {len(domains)} domains...")
        batch_rows = client.batch_analysis(domains)

    for i, domain in enumerate(domains, start=1):
        print(f"[{i}/{len(domains)}] {domain}")
        if dry_run:
            dr = 42
            refdomains = 123
            org_kw = 50
            org_tr = 100
            refips = 110
            refclass_c = 80
            refdomains_gojp = 0
            refdomains_lgjp = 0
            refdomains_acjp = 2
            anchors = [{"anchor": "example", "refdomains": 5, "backlinks": 10}]
            wayback = {
                "first_snapshot": "2001-06-01",
                "last_snapshot": "2023-06-01",
                "last_snapshot_ts": "20230601000000",
                "snapshot_count": 42,
                "years_active": 22.0,
                "has_japanese": False,
            }
        else:
            row = _batch_row_for(domain, batch_rows)
            dr = _f(row, "domain_rating")
            refdomains = int(_f(row, "refdomains"))
            org_kw = int(_f(row, "org_keywords"))
            org_tr = int(_f(row, "org_traffic"))
            refips = int(_f(row, "refips"))
            refclass_c = int(_f(row, "refclass_c"))
            try:
                refdoms = client.site_explorer_refdomains(domain, limit=1000)
            except Exception as exc:
                print(f"  refdomains fetch failed: {exc}")
                refdoms = []
            refdomains_gojp = _count_tld(refdoms, ".go.jp")
            refdomains_lgjp = _count_tld(refdoms, ".lg.jp")
            refdomains_acjp = _count_tld(refdoms, ".ac.jp")
            try:
                anchors = client.site_explorer_anchors(domain, limit=20)
            except Exception as exc:
                print(f"  anchors fetch failed: {exc}")
                anchors = []
            try:
                wayback = wayback_summarize(domain)
            except Exception as exc:
                print(f"  wayback fetch failed: {exc}")
                wayback = {
                    "first_snapshot": None,
                    "last_snapshot": None,
                    "last_snapshot_ts": None,
                    "snapshot_count": 0,
                    "years_active": 0.0,
                    "has_japanese": False,
                }
            time.sleep(sleep_between)

        has_spam, spam_hits = detect_spam(anchors)
        score = compute_score(
            dr=dr,
            refdomains=refdomains,
            years_active=wayback.get("years_active", 0.0),
            has_japanese=wayback.get("has_japanese", False),
            has_spam=has_spam,
        )

        rows.append(
            {
                "domain": domain,
                "dr": round(float(dr), 2),
                "refdomains": refdomains,
                "org_keywords": org_kw,
                "org_traffic": org_tr,
                "refips": refips,
                "refclass_c": refclass_c,
                "refdomains_gojp": refdomains_gojp,
                "refdomains_lgjp": refdomains_lgjp,
                "refdomains_acjp": refdomains_acjp,
                "first_snapshot": wayback.get("first_snapshot"),
                "last_snapshot": wayback.get("last_snapshot"),
                "last_snapshot_ts": wayback.get("last_snapshot_ts"),
                "snapshot_count": wayback.get("snapshot_count", 0),
                "years_active": wayback.get("years_active", 0.0),
                "has_japanese": bool(wayback.get("has_japanese", False)),
                "has_spam": has_spam,
                "spam_hits": spam_hits,
                "top_anchors": [
                    (a.get("anchor") or "")[:60] for a in anchors[:5]
                ],
                **score,
            }
        )

    rows.sort(key=lambda r: r["score"], reverse=True)
    return rows


def write_output(rows: list[dict]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    snapshot_path = OUTPUT_DIR / f"data-{timestamp}.json"
    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "count": len(rows),
        "rows": rows,
    }
    snapshot_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    # The dashboard reads a plain array for simplicity.
    DOCS_DATA.write_text(
        json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"[write] {len(rows)} rows -> {DOCS_DATA.relative_to(ROOT)}")
    print(f"[write] snapshot -> {snapshot_path.relative_to(ROOT)}")


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Analyze expired domains.")
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Path to a CSV file (default: newest file under data/input/).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Use stub data instead of calling Ahrefs/Wayback.",
    )
    args = parser.parse_args(argv)

    csv_path = args.input or newest_csv(INPUT_DIR)
    if csv_path is None:
        print(f"No CSV found under {INPUT_DIR}. Put an export there first.")
        return 1
    print(f"[input] {csv_path}")

    domains = load_domains(csv_path)
    if not domains:
        print("CSV contains no domains.")
        return 1
    print(f"[input] {len(domains)} domain(s)")

    rows = analyze(domains, dry_run=args.dry_run)
    write_output(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
