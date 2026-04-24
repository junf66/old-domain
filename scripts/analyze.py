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

CATEGORY_KEYWORDS: dict[str, list[str]] = {
    "SEO・アフィリ": [
        "seo", "アフィリ", "アフィリエイト", "副業", "稼ぐ", "月収",
        "在宅", "ネットビジネス", "物販", "転売",
    ],
    "金融・投資": [
        "fx", "株式", "株価", "投資", "仮想通貨", "暗号資産", "ビットコイン",
        "nft", "ローン", "クレジット", "保険", "資産運用", "ファイナンス",
    ],
    "美容・健康": [
        "美容", "ダイエット", "スキンケア", "コスメ", "化粧品", "サプリ",
        "育毛", "脱毛", "痩身", "エステ", "健康食品", "サプリメント",
    ],
    "医療・クリニック": [
        "クリニック", "病院", "診療", "治療", "医師", "メディカル",
        "歯科", "眼科", "皮膚科",
    ],
    "IT・開発": [
        "プログラミング", "エンジニア", "python", "javascript", "typescript",
        "php", "ruby", "java", "api", "devops", "クラウド", "aws",
        "github", "フロントエンド", "バックエンド",
    ],
    "メディア・ブログ": [
        "ニュース", "news", "ブログ", "blog", "メディア", "magazine",
        "記事", "まとめ", "コラム",
    ],
    "EC・通販": [
        "通販", "販売", "購入", "カート", "ec", "楽天", "amazon",
        "ショップ", "shop", "store", "オンラインストア",
    ],
    "不動産": [
        "不動産", "賃貸", "物件", "マンション", "戸建て", "中古住宅",
        "土地", "売買", "リフォーム",
    ],
    "旅行・ホテル": [
        "旅行", "観光", "ホテル", "旅館", "宿泊", "travel", "航空券",
        "ツアー",
    ],
    "教育・学習": [
        "教育", "学習", "スクール", "塾", "英会話", "eラーニング",
        "オンライン学習", "通信講座", "資格",
    ],
    "求人・転職": [
        "求人", "転職", "就職", "career", "キャリア", "job",
        "エージェント", "採用", "アルバイト", "indeed",
    ],
    "エンタメ・ゲーム": [
        "ゲーム", "game", "アニメ", "漫画", "マンガ", "映画", "音楽",
        "アイドル", "芸能", "エンタメ",
    ],
    "スポーツ": [
        "スポーツ", "野球", "サッカー", "ゴルフ", "テニス",
        "フィットネス", "ジム", "ヨガ",
    ],
    "グルメ・食": [
        "レシピ", "料理", "グルメ", "レストラン", "カフェ", "食べログ",
        "食材", "お取り寄せ", "弁当",
    ],
    "自動車・バイク": [
        "自動車", "中古車", "新車", "車検", "バイク", "整備",
        "オートバイ",
    ],
    "結婚・出会い": [
        "結婚", "婚活", "ウェディング", "出会い", "マッチング", "恋愛",
    ],
    "ビジネス・B2B": [
        "法人", "ビジネス", "マーケティング", "経営", "コンサル",
        "bpo", "saas", "営業支援",
    ],
    "公的・団体": [
        "行政", "自治体", "市役所", "区役所", "協会", "財団", "学会",
    ],
}


def _clean_category_hit(s: str, kw: str) -> int:
    """Count occurrences of `kw` in `s` (case-insensitive)."""
    if not s or not kw:
        return 0
    return s.lower().count(kw.lower())


def categorize(
    domain: str,
    title: str,
    text_sample: str,
    anchors: list[dict],
    org_keywords: int = 0,
) -> tuple[str, dict[str, int]]:
    """Return (best_category, score_by_category).

    The title and domain name are weighted 3x, anchors 2x, body 1x.
    """
    title_s = (title or "").lower()
    text_s = (text_sample or "").lower()
    domain_s = (domain or "").lower().replace(".", " ")
    anchor_s = " ".join((a.get("anchor") or "") for a in anchors or []).lower()

    scores: dict[str, int] = {}
    for cat, kws in CATEGORY_KEYWORDS.items():
        s = 0
        for kw in kws:
            s += _clean_category_hit(title_s, kw) * 3
            s += _clean_category_hit(domain_s, kw) * 3
            s += _clean_category_hit(anchor_s, kw) * 2
            s += _clean_category_hit(text_s, kw)
        if s:
            scores[cat] = s

    if not scores:
        return "その他", {}
    best = max(scores.items(), key=lambda kv: kv[1])[0]
    return best, scores


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
    refips: int,
    refclass_c: int,
    years_active: float,
    has_japanese: bool,
    refdomains_gojp: int,
    refdomains_lgjp: int,
    refdomains_acjp: int,
    category: str,
    has_spam: bool,
) -> dict[str, Any]:
    """Compute the composite 0-∞ score.

    Positive-capped components (total 80pt):
      DR 30 / refdomains 15 / refips 5 / refclass_c 5 /
      years 10 / japanese 10

    Uncapped additive:
      .go.jp × 30 + .lg.jp × 25 + .ac.jp × 20

    Bonuses:
      Distribution bonus (+5 if Cクラス/refips ≥ 0.7)
      Category bonus (+5 if category == 公的・団体)

    Penalties:
      Spam -50 / PBN -20
    """
    dr_pts = min(max(dr, 0), 100) * 0.3
    ref_pts = min(math.log10(max(refdomains, 0) + 1) * 5, 15)
    refips_pts = min(math.log10(max(refips, 0) + 1) * 2, 5)
    refclass_pts = min(math.log10(max(refclass_c, 0) + 1) * 2, 5)
    years_pts = min(max(years_active, 0) * 1.25, 10)
    jp_pts = 10 if has_japanese else 0
    gov_pts = (
        max(refdomains_gojp, 0) * 30
        + max(refdomains_lgjp, 0) * 25
        + max(refdomains_acjp, 0) * 20
    )

    ratio = (refclass_c / refips) if refips else 0.0
    distribution_bonus = 5 if refips >= 1 and ratio >= 0.7 else 0
    category_bonus = 5 if category == "公的・団体" else 0

    spam_penalty = -50 if has_spam else 0
    pbn_penalty = -20 if (refips >= 30 and ratio < 0.3) else 0

    total = (
        dr_pts + ref_pts + refips_pts + refclass_pts
        + years_pts + jp_pts + gov_pts
        + distribution_bonus + category_bonus
        + spam_penalty + pbn_penalty
    )
    return {
        "score": round(total, 2),
        "score_breakdown": {
            "dr": round(dr_pts, 2),
            "refdomains": round(ref_pts, 2),
            "refips": round(refips_pts, 2),
            "refclass_c": round(refclass_pts, 2),
            "years": round(years_pts, 2),
            "japanese": jp_pts,
            "gov_edu": gov_pts,
            "distribution_bonus": distribution_bonus,
            "category_bonus": category_bonus,
            "spam_penalty": spam_penalty,
            "pbn_penalty": pbn_penalty,
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
                "title": "Example blog about investment",
                "text_sample": "投資 株式 fx",
            }
        else:
            row = _batch_row_for(domain, batch_rows)
            dr = _f(row, "domain_rating")
            refdomains = int(_f(row, "refdomains"))
            org_kw = int(_f(row, "org_keywords"))
            org_tr = int(_f(row, "org_traffic"))
            refips = int(_f(row, "refips"))
            refclass_c = int(_f(row, "refips_subnets", "refclass_c"))
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
                    "title": "",
                    "text_sample": "",
                    "has_japanese": False,
                }
            time.sleep(sleep_between)

        category, _cat_scores = categorize(
            domain=domain,
            title=wayback.get("title", ""),
            text_sample=wayback.get("text_sample", ""),
            anchors=anchors,
            org_keywords=org_kw,
        )

        has_spam, spam_hits = detect_spam(anchors)
        score = compute_score(
            dr=dr,
            refdomains=refdomains,
            refips=refips,
            refclass_c=refclass_c,
            years_active=wayback.get("years_active", 0.0),
            has_japanese=wayback.get("has_japanese", False),
            refdomains_gojp=refdomains_gojp,
            refdomains_lgjp=refdomains_lgjp,
            refdomains_acjp=refdomains_acjp,
            category=category,
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
                "category": category,
                "title": wayback.get("title", ""),
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
