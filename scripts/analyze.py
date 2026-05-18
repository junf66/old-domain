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


class QuotaInsufficientError(RuntimeError):
    """Raised when the Ahrefs subscription does not have enough units to
    safely run the requested work. Inherits ``RuntimeError`` so callers
    that only catch the base class still see the abort, but ``main()``
    can match on this specific type to format a friendly message and
    return a distinct exit code instead of dumping a stacktrace.
    """


# Conservative units-per-domain estimate for the batch-analysis call.
# Ahrefs documents 22 units/row for batch-analysis when selecting the
# fields this tool requests; round up to leave headroom for the
# select-list growing later.
BATCH_UNITS_PER_DOMAIN = 22


def _ahrefs_units_left(info: dict) -> tuple[int, str]:
    """Return ``(units_left, reset_date)`` from ``subscription_info()``.

    Workspace and per-key limits are tracked separately on Ahrefs Lite;
    the effective ceiling is the smaller of the two remainders. Returns
    ``(-1, "unknown")`` when the payload shape is unexpected so the
    caller can decide to fall through rather than abort on a parse
    glitch.
    """
    limits = (info or {}).get("limits_and_usage") or {}
    if not isinstance(limits, dict):
        return -1, "unknown"
    try:
        ws_left = int(limits.get("units_limit_workspace", 0)) - int(
            limits.get("units_usage_workspace", 0)
        )
        key_left = int(limits.get("units_limit_api_key", 0)) - int(
            limits.get("units_usage_api_key", 0)
        )
    except (TypeError, ValueError):
        return -1, "unknown"
    reset = str(limits.get("usage_reset_date") or "unknown")
    return min(ws_left, key_left), reset


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
    "Domain Name",
    "DomainName",
    "URL",
    "url",
    "ドメイン",
    "ドメイン名",
)

# Literal cell values that must never be treated as a domain even if they
# slip through the heuristics (typically header rows or sentinel labels).
_HEADER_LITERALS = {
    "domain", "domain name", "domainname", "domains",
    "url", "urls", "host", "hostname",
    "ドメイン", "ドメイン名",
}


def normalize_domain(value: object) -> str | None:
    """Return a canonical lowercase domain, or ``None`` if not a domain.

    Strips URL scheme, leading ``www.``, path/query, and surrounding
    whitespace. Returns ``None`` for header strings ("Domain", "URL", …),
    empty cells, and obvious non-domains (no dot, contains whitespace, …).
    """
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    # Drop the scheme and anything after the first path/query/fragment char.
    low = s.lower()
    for proto in ("https://", "http://", "//"):
        if low.startswith(proto):
            low = low[len(proto):]
            break
    for sep in ("/", "?", "#", " ", "\t"):
        idx = low.find(sep)
        if idx >= 0:
            low = low[:idx]
    low = low.rstrip(".")
    if low.startswith("www."):
        low = low[4:]
    if not low or low in _HEADER_LITERALS:
        return None
    if "." not in low:
        return None
    parts = low.split(".")
    if len(parts) < 2 or not all(parts):
        return None
    # Reject values with characters that can't appear in a hostname.
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.")
    if any(ch not in allowed for ch in low):
        return None
    return low


def _looks_like_domain(value: str) -> bool:
    return normalize_domain(value) is not None


def newest_csv(input_dir: Path) -> Path | None:
    """Pick the best single CSV under `input_dir`.

    Priority order:
      1. Files whose name starts with `upload-` (dashboard uploads include
         a timestamp in the filename), sorted desc by filename.
      2. Any other CSV, sorted desc by filename.
    """
    csvs = list(input_dir.glob("*.csv"))
    if not csvs:
        return None
    uploaded = [p for p in csvs if p.name.startswith("upload-")]
    if uploaded:
        return sorted(uploaded, key=lambda p: p.name)[-1]
    return sorted(csvs, key=lambda p: p.name)[-1]


def load_all_domains(input_dir: Path) -> list[str]:
    """Merge domains from every CSV under `input_dir` (de-duplicated).

    Useful when the user accumulates several exports; we still honour
    `--input` if a specific path is given elsewhere.
    """
    seen: set[str] = set()
    out: list[str] = []
    for csv in sorted(input_dir.glob("*.csv"), key=lambda p: p.name):
        try:
            values = load_domains(csv)
        except Exception as exc:
            print(f"[input] SKIP {csv.name}: {exc}")
            continue
        print(f"[input] {csv.name}: {len(values)} domain(s)")
        for v in values:
            k = v.lower()
            if k not in seen:
                seen.add(k)
                out.append(v)
    return out


def _dedupe(values: list[object], source: str | None = None) -> list[str]:
    """Normalize each value and return de-duplicated canonical domains.

    Logs how many rows were dropped because they did not look like domains
    so that ``Domain`` / ``URL`` header strings (and other noise) are
    visible rather than silently passed through to Ahrefs.
    """
    seen: set[str] = set()
    out: list[str] = []
    dropped = 0
    for v in values:
        dom = normalize_domain(v)
        if not dom:
            if (v is not None) and str(v).strip():
                dropped += 1
            continue
        if dom not in seen:
            seen.add(dom)
            out.append(dom)
    if dropped:
        label = f" ({source})" if source else ""
        print(f"[input] dropped {dropped} non-domain row(s){label}")
    return out


def load_domains(csv_path: Path) -> list[str]:
    """Read a CSV and return a list of canonical, de-duplicated domains.

    Accepts several shapes:
      1. Header row containing one of DOMAIN_COLUMN_CANDIDATES
      2. No header — first column already looks like domains
      3. Single-column file with one domain per line

    All returned values pass through ``normalize_domain`` so callers can
    rely on them being scheme-less, ``www.``-less, lowercase domains.
    """
    last_error: Exception | None = None
    for sep in (",", ";", "\t"):
        # --- with header ---
        try:
            df = pd.read_csv(csv_path, sep=sep, dtype=str, keep_default_na=False)
        except Exception as exc:  # pragma: no cover
            last_error = exc
            df = None
        if df is not None and len(df.columns) > 0:
            for col in DOMAIN_COLUMN_CANDIDATES:
                if col in df.columns:
                    return _dedupe(df[col].tolist(), source=csv_path.name)
            # Heuristic A: the "header" is itself a domain → no header
            first_header = str(df.columns[0])
            if _looks_like_domain(first_header):
                df_nh = pd.read_csv(
                    csv_path, sep=sep, dtype=str,
                    keep_default_na=False, header=None,
                )
                return _dedupe(df_nh.iloc[:, 0].tolist(), source=csv_path.name)
            # Heuristic B: first column values look like domains
            first_vals = df.iloc[:, 0].tolist()
            domainish = sum(1 for v in first_vals if _looks_like_domain(v))
            if domainish >= max(1, len(first_vals) // 2):
                return _dedupe(first_vals, source=csv_path.name)

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
    """Find the batch-analysis row that matches ``domain``.

    Ahrefs returns the target URL with the scheme prefix and a trailing
    slash (e.g. ``"https://example.com/"``) and may emit multiple rows for
    a single target when ``protocol=both`` was requested. Normalize both
    sides through :func:`normalize_domain` so the comparison succeeds and
    pick the row with the strongest signal (highest ``domain_rating``).
    """
    target = normalize_domain(domain)
    if not target:
        return {}
    candidates: list[dict] = []
    for row in batch:
        for k in ("url", "target"):
            v = row.get(k) if isinstance(row, dict) else None
            if v and normalize_domain(v) == target:
                candidates.append(row)
                break
    if not candidates:
        return {}
    candidates.sort(
        key=lambda r: (
            _f(r, "domain_rating"),
            _f(r, "refdomains"),
            _f(r, "refips"),
        ),
        reverse=True,
    )
    return candidates[0]


ACTIVE_TRUST_WHERE = (
    '{"and":['
    '{"field":"is_lost","is":["eq",false]},'
    '{"or":['
    '{"field":"url_from","is":["substring","ac.jp"]},'
    '{"field":"url_from","is":["substring","lg.jp"]},'
    '{"field":"url_from","is":["substring","go.jp"]}'
    ']}'
    ']}'
)

ACTIVE_TRUST_SELECT = "url_from,anchor,first_seen,is_dofollow"

# .ac.jp / .lg.jp / .go.jp screening weights — see compute_active_trust_score.
ACTIVE_TRUST_WEIGHTS = {"go": 10, "lg": 6, "ac": 5}


def _classify_active_trust_link(url_from: str) -> str | None:
    """Return ``'go'`` / ``'lg'`` / ``'ac'`` for a referring page URL, else None.

    Ahrefs' ``substring`` where filter matches anywhere in the URL, so
    we re-check the host part here to avoid counting noise like
    ``example.com/?ref=ac.jp``.
    """
    if not url_from:
        return None
    s = str(url_from).strip().lower()
    for proto in ("https://", "http://"):
        if s.startswith(proto):
            s = s[len(proto):]
            break
    host = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].rstrip(".")
    if not host:
        return None
    if host.endswith(".go.jp") or host == "go.jp":
        return "go"
    if host.endswith(".lg.jp") or host == "lg.jp":
        return "lg"
    if host.endswith(".ac.jp") or host == "ac.jp":
        return "ac"
    return None


def count_active_trust_links(
    backlinks: list[dict],
) -> tuple[int, int, int]:
    """Return ``(go_count, lg_count, ac_count)`` from active-trust backlinks.

    Counts unique referring root domains per TLD (the all-backlinks
    request runs with ``aggregation=1_per_domain``, so each row already
    represents one referring domain — we just bucket them).
    """
    seen: dict[str, set[str]] = {"go": set(), "lg": set(), "ac": set()}
    for row in backlinks or []:
        url = row.get("url_from") if isinstance(row, dict) else None
        cls = _classify_active_trust_link(url or "")
        if not cls:
            continue
        host = str(url).split("//", 1)[-1].split("/", 1)[0].lower()
        # Reduce to the root e.g. ``shu-lab.shudo-u.ac.jp`` -> ``shudo-u.ac.jp``
        parts = host.split(".")
        if len(parts) >= 3:
            root = ".".join(parts[-3:])
        else:
            root = host
        seen[cls].add(root)
    return len(seen["go"]), len(seen["lg"]), len(seen["ac"])


def compute_active_trust_score(go: int, lg: int, ac: int) -> int:
    """Weighted screening score: go×10 + lg×6 + ac×5."""
    return (
        max(go, 0) * ACTIVE_TRUST_WEIGHTS["go"]
        + max(lg, 0) * ACTIVE_TRUST_WEIGHTS["lg"]
        + max(ac, 0) * ACTIVE_TRUST_WEIGHTS["ac"]
    )


def _count_tld(refdoms: list[dict], suffix: str) -> int:
    """Count referring domains whose host ends with `suffix` (case-insensitive).

    Tries several possible response field names because Ahrefs' field
    layout has shifted historically. Also strips scheme/path when the
    API hands us a full URL instead of a bare hostname.
    """
    n = 0
    for r in refdoms or []:
        host = ""
        for k in ("domain", "refdomain", "hostname", "host", "url_from",
                  "ref_domain", "domain_name"):
            v = r.get(k) if isinstance(r, dict) else None
            if v:
                host = str(v).strip().lower()
                break
        if not host and isinstance(r, str):
            host = r.lower().strip()
        # Drop scheme and path if it's actually a URL.
        for proto in ("https://", "http://"):
            if host.startswith(proto):
                host = host[len(proto):]
                break
        host = host.split("/", 1)[0].rstrip(".")
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


def _row_has_real_data(row: dict) -> bool:
    """Return True if a cached row carries enough Ahrefs signal to reuse.

    A row is treated as cache-worthy when batch-analysis returned real
    numbers (DR / refdomains / org_*) for it. Sub-fetch failures
    (refdomains list, anchors, Wayback) do **not** disqualify the row —
    those failures are already recorded in ``row["errors"]`` for the UI
    and re-running just to retry them would waste Ahrefs credits without
    fixing the underlying upstream issue (typically rate-limiting).

    We do still re-fetch when the batch row itself was missing
    (``ahrefs_batch_unmatched`` in errors), since that's the case where
    an actual API failure poisoned the data.
    """
    if not isinstance(row, dict):
        return False
    errs = row.get("errors") or []
    if any(e == "ahrefs_batch_unmatched" or str(e).startswith("batch-analysis")
           for e in errs):
        return False
    if (row.get("dr") or 0) > 0:
        return True
    if (row.get("refdomains") or 0) > 0:
        return True
    if (row.get("org_keywords") or 0) > 0:
        return True
    if (row.get("org_traffic") or 0) > 0:
        return True
    if (row.get("snapshot_count") or 0) > 0:
        return True
    return False


def analyze(
    domains: list[str],
    dry_run: bool = False,
    sleep_between: float = 0.5,
    skip_existing: bool = True,
) -> tuple[list[dict], dict]:
    """Analyse ``domains`` and return ``(rows, quality)``.

    ``quality`` is an aggregate summary describing how many domains
    succeeded, hit cached data, or failed against each upstream
    (Ahrefs batch / refdomains / anchors, Wayback). It is also written
    to ``docs/quality.json`` so the dashboard can render it.
    """
    rows: list[dict] = []

    # ---- skip already-analysed domains so we don't burn credits again ----
    existing_by_domain: dict[str, dict] = {}
    if skip_existing and DOCS_DATA.exists():
        try:
            prior = json.loads(DOCS_DATA.read_text(encoding="utf-8"))
            if isinstance(prior, list):
                for r in prior:
                    d = normalize_domain(r.get("domain"))
                    if d:
                        existing_by_domain[d] = r
        except Exception:
            existing_by_domain = {}

    fresh_domains: list[str] = []
    cached_count = 0
    stale_cached_count = 0
    for d in domains:
        key = (normalize_domain(d) or d.lower())
        prior_row = existing_by_domain.get(key)
        if prior_row and _row_has_real_data(prior_row):
            cached_count += 1
        else:
            if prior_row:
                stale_cached_count += 1
            fresh_domains.append(d)
    if cached_count:
        print(
            f"[cache] {cached_count} domain(s) already analysed — reusing existing scores"
        )
    if stale_cached_count:
        print(
            f"[cache] {stale_cached_count} domain(s) had zero-data cache — re-fetching"
        )
    domains_to_fetch = fresh_domains

    # Per-domain error / quality counters.
    quality = {
        "total": len(domains),
        "fresh": len(fresh_domains),
        "cached": cached_count,
        "stale_refetched": stale_cached_count,
        "ahrefs_batch_unmatched": 0,
        "refdomains_errors": 0,
        "anchors_errors": 0,
        "wayback_errors": 0,
        "wayback_disabled": False,
        "batch_chunks_failed": 0,
        "all_backlinks_errors": 0,
        "filtered_no_active_trust": 0,
        "active_trust_filter_failures": 0,
        "errors": [],
    }

    if dry_run:
        batch_rows: list[dict] = []
        client: AhrefsClient | None = None
    else:
        client = AhrefsClient()
        units_left = -1
        reset_date = "unknown"
        try:
            info = client.subscription_info()
            print(f"[ahrefs] subscription info: {info}")
            units_left, reset_date = _ahrefs_units_left(info)
        except Exception as exc:
            print(f"[ahrefs] WARN could not fetch subscription info: {exc}")
            quality["errors"].append(f"subscription-info: {exc}")
        if domains_to_fetch:
            # Pre-flight: refuse to start a CSV run when batch-analysis
            # alone wouldn't fit in the remaining quota. Bailing out
            # *before* the API call gives the user a clean message
            # instead of a stacktrace, and saves one wasted unit lookup.
            need = len(domains_to_fetch) * BATCH_UNITS_PER_DOMAIN
            if 0 <= units_left < need:
                quality["ahrefs_quota_exhausted"] = True
                quality["errors"].append(
                    f"quota_insufficient: need {need}, left {units_left}, "
                    f"resets {reset_date}"
                )
                raise QuotaInsufficientError(
                    f"Need ~{need} units for batch-analysis on "
                    f"{len(domains_to_fetch)} domain(s), but only "
                    f"{units_left} units left. Resets {reset_date}. "
                    "Aborting without touching docs/data.json — upgrade "
                    "the Ahrefs plan or wait for the next reset, then "
                    "re-run."
                )
            print(f"[ahrefs] batch-analysis for {len(domains_to_fetch)} domains...")
            try:
                batch_rows = client.batch_analysis(domains_to_fetch)
            except Exception as exc:
                quality["errors"].append(f"batch-analysis: {exc}")
                raise
            quality["batch_chunks_failed"] = getattr(
                client, "last_batch_failures", 0
            )
            # Detect the case where Ahrefs returned nothing meaningful at
            # all (auth/credits/etc.). Refuse to clobber the dashboard.
            if not batch_rows and domains_to_fetch:
                raise RuntimeError(
                    "Ahrefs batch-analysis returned no rows for "
                    f"{len(domains_to_fetch)} domain(s). Refusing to write "
                    "zero-only data to docs/data.json. "
                    "Check API key / credits / rate limit and retry."
                )
        else:
            batch_rows = []

    # Wayback is flaky (web.archive.org occasionally 429s/timeouts under
    # load). Be generous before disabling it for the rest of the run.
    wayback_skip_after = 15
    wayback_failures = 0
    wayback_disabled = False
    for i, domain in enumerate(domains, start=1):
        key = normalize_domain(domain) or domain.lower()
        cached = existing_by_domain.get(key)
        if cached and _row_has_real_data(cached):
            print(f"[{i}/{len(domains)}] {domain}  (cached)")
            rows.append(cached)
            continue
        print(f"[{i}/{len(domains)}] {domain}")
        row_errors: list[str] = []
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
            active_go = 1
            active_lg = 0
            active_ac = 2
            active_score = compute_active_trust_score(active_go, active_lg, active_ac)
            active_filter_failed = False
        else:
            row = _batch_row_for(domain, batch_rows)
            if not row:
                quality["ahrefs_batch_unmatched"] += 1
                row_errors.append("ahrefs_batch_unmatched")
                print(f"  [batch] no matching row for {domain}")
            dr = _f(row, "domain_rating")
            refdomains = int(_f(row, "refdomains"))
            org_kw = int(_f(row, "org_keywords"))
            org_tr = int(_f(row, "org_traffic"))
            refips = int(_f(row, "refips"))
            refclass_c = int(_f(row, "refips_subnets", "refclass_c"))
            ahrefs_dead = getattr(client, "quota_exhausted", False)

            # ----- Step 1: active .go/.lg/.ac.jp screening filter ---------
            # Drop the domain entirely when it has zero ACTIVE high-trust
            # links. We do this BEFORE refdomains / anchors so a 0-hit
            # domain only costs one all-backlinks call (≈50 units) instead
            # of ~250 units of extra site-explorer work.
            active_go = active_lg = active_ac = 0
            active_score = 0
            active_filter_failed = False
            active_backlinks: list[dict] = []
            if ahrefs_dead:
                active_filter_failed = True
                row_errors.append(
                    "all_backlinks: skipped (ahrefs quota exhausted)"
                )
                quality["active_trust_filter_failures"] += 1
            else:
                try:
                    active_backlinks = client.site_explorer_all_backlinks(
                        domain,
                        select=ACTIVE_TRUST_SELECT,
                        where=ACTIVE_TRUST_WHERE,
                    )
                    active_go, active_lg, active_ac = count_active_trust_links(
                        active_backlinks
                    )
                    active_score = compute_active_trust_score(
                        active_go, active_lg, active_ac
                    )
                except Exception as exc:
                    print(f"  all-backlinks filter failed: {exc}")
                    active_filter_failed = True
                    quality["all_backlinks_errors"] += 1
                    quality["active_trust_filter_failures"] += 1
                    row_errors.append(f"all_backlinks: {exc}")
                    if getattr(client, "quota_exhausted", False):
                        ahrefs_dead = True
            if (
                not active_filter_failed
                and active_go == 0
                and active_lg == 0
                and active_ac == 0
            ):
                # Spec: 0-hit domains are excluded from the candidate list
                # entirely, AND we early-return to skip the expensive
                # refdomains / anchors / wayback calls.
                quality["filtered_no_active_trust"] += 1
                print(
                    f"  [filter] no active .go/.lg/.ac.jp backlink — "
                    f"excluding from output"
                )
                continue

            if ahrefs_dead:
                refdoms = []
                row_errors.append("refdomains: skipped (ahrefs quota exhausted)")
                quality["refdomains_errors"] += 1
            else:
                try:
                    refdoms = client.site_explorer_refdomains(domain, limit=100)
                except Exception as exc:
                    print(f"  refdomains fetch failed: {exc}")
                    refdoms = []
                    quality["refdomains_errors"] += 1
                    row_errors.append(f"refdomains: {exc}")
                    if getattr(client, "quota_exhausted", False):
                        print(
                            "  [ahrefs] quota exhausted — skipping all "
                            "further Ahrefs calls in this run."
                        )
                        ahrefs_dead = True
            if i == 1:
                # One-shot debug so we can verify the actual response shape.
                preview = refdoms[:3] if isinstance(refdoms, list) else refdoms
                print(f"  [debug] refdomains sample for {domain}: {preview}")
            refdomains_gojp = _count_tld(refdoms, ".go.jp")
            refdomains_lgjp = _count_tld(refdoms, ".lg.jp")
            refdomains_acjp = _count_tld(refdoms, ".ac.jp")
            if ahrefs_dead:
                anchors = []
                row_errors.append("anchors: skipped (ahrefs quota exhausted)")
                quality["anchors_errors"] += 1
            else:
                try:
                    anchors = client.site_explorer_anchors(domain, limit=5)
                except Exception as exc:
                    print(f"  anchors fetch failed: {exc}")
                    anchors = []
                    quality["anchors_errors"] += 1
                    row_errors.append(f"anchors: {exc}")
                    if getattr(client, "quota_exhausted", False):
                        ahrefs_dead = True
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
            if not wayback_disabled:
                try:
                    wayback = wayback_summarize(domain, timeout=12)
                    wayback_failures = 0
                except Exception as exc:
                    wayback_failures += 1
                    print(f"  wayback fetch failed ({wayback_failures}): {exc}")
                    quality["wayback_errors"] += 1
                    row_errors.append(f"wayback: {exc}")
                    if wayback_failures >= wayback_skip_after:
                        wayback_disabled = True
                        quality["wayback_disabled"] = True
                        print(
                            f"  [wayback] {wayback_skip_after} consecutive failures — "
                            f"skipping Wayback for the remaining domains in this run."
                        )
            else:
                row_errors.append("wayback: disabled (too many failures)")
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
                "active_go_jp_count": active_go,
                "active_lg_jp_count": active_lg,
                "active_ac_jp_count": active_ac,
                "active_high_trust_score": active_score,
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
                "errors": row_errors,
                **score,
            }
        )

    # ---- Abort the run if Ahrefs returned no usable data at all. ------
    # Without this guard, a single bad run (auth/credits/rate-limit)
    # would silently overwrite docs/data.json with all-zero rows and
    # poison the cache. We tolerate up to 50% unmatched, which already
    # signals a serious upstream issue but might still be salvageable.
    if not dry_run and len(fresh_domains) > 0:
        unmatched = quality["ahrefs_batch_unmatched"]
        if unmatched / max(len(fresh_domains), 1) > 0.5:
            raise RuntimeError(
                "Ahrefs batch-analysis returned no matching row for "
                f"{unmatched}/{len(fresh_domains)} fresh domains. "
                "Refusing to write mostly-zero data to docs/data.json."
            )

    # Default sort: high-trust screening score first, then composite score.
    rows.sort(
        key=lambda r: (
            r.get("active_high_trust_score", 0),
            r.get("score", 0),
        ),
        reverse=True,
    )
    quality["written_rows"] = len(rows)
    quality["zero_rows"] = sum(1 for r in rows if not _row_has_real_data(r))
    return rows, quality


def write_output(rows: list[dict], quality: dict | None = None) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    snapshot_path = OUTPUT_DIR / f"data-{timestamp}.json"
    payload: dict[str, Any] = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "count": len(rows),
        "rows": rows,
    }
    if quality is not None:
        payload["quality"] = quality
    snapshot_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    # The dashboard reads a plain array for simplicity.
    DOCS_DATA.write_text(
        json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"[write] {len(rows)} rows -> {DOCS_DATA.relative_to(ROOT)}")
    print(f"[write] snapshot -> {snapshot_path.relative_to(ROOT)}")

    if quality is not None:
        quality_path = ROOT / "docs" / "quality.json"
        quality_payload = {
            "generated_at": payload["generated_at"],
            **quality,
        }
        quality_path.write_text(
            json.dumps(quality_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"[write] quality -> {quality_path.relative_to(ROOT)}")


def retry_failed_rows(
    sleep_between: float = 0.5,
) -> tuple[list[dict], dict]:
    """Re-attempt failed sub-fetches on existing rows in ``docs/data.json``.

    For each row whose ``errors`` list contains a ``wayback:`` /
    ``refdomains:`` / ``anchors:`` entry, re-call just that upstream and
    update the row in place. Successful retries clear the matching error
    entry; persistent failures keep it. The cached batch-analysis fields
    (``dr`` / ``refdomains`` / ``org_*``) are **never** re-fetched, so
    this mode does not consume Ahrefs batch credits — only site-explorer
    credits for the rows that need refdomains/anchors retried.

    Wayback retries are free.
    """
    if not DOCS_DATA.exists():
        raise RuntimeError(
            f"{DOCS_DATA} does not exist. Run a normal analyse first."
        )
    rows: list[dict] = json.loads(DOCS_DATA.read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        raise RuntimeError(
            f"{DOCS_DATA} is not a JSON array of rows."
        )

    needs_refdomains: list[int] = []
    needs_anchors: list[int] = []
    needs_wayback: list[int] = []
    for idx, row in enumerate(rows):
        errs = row.get("errors") or []
        if any(str(e).startswith("refdomains:") for e in errs):
            needs_refdomains.append(idx)
        if any(str(e).startswith("anchors:") for e in errs):
            needs_anchors.append(idx)
        if any(
            str(e).startswith("wayback:") or str(e) == "wayback: disabled (too many failures)"
            for e in errs
        ):
            needs_wayback.append(idx)

    quality: dict[str, Any] = {
        "mode": "retry-failed",
        "total": len(rows),
        "rows_needing_refdomains": len(needs_refdomains),
        "rows_needing_anchors": len(needs_anchors),
        "rows_needing_wayback": len(needs_wayback),
        "refdomains_recovered": 0,
        "anchors_recovered": 0,
        "wayback_recovered": 0,
        "refdomains_still_failing": 0,
        "anchors_still_failing": 0,
        "wayback_still_failing": 0,
        "ahrefs_skipped_quota": 0,
        "wayback_skipped_disabled": 0,
        "ahrefs_quota_exhausted": False,
        "wayback_disabled": False,
        "errors": [],
    }
    print(
        f"[retry] needs_refdomains={len(needs_refdomains)} "
        f"needs_anchors={len(needs_anchors)} "
        f"needs_wayback={len(needs_wayback)}"
    )
    if not (needs_refdomains or needs_anchors or needs_wayback):
        print("[retry] no rows have failed sub-fetches — nothing to do.")
        quality["written_rows"] = len(rows)
        quality["zero_rows"] = sum(1 for r in rows if not _row_has_real_data(r))
        return rows, quality

    needs_ahrefs = bool(needs_refdomains or needs_anchors)
    client = AhrefsClient() if needs_ahrefs else None
    if client is not None:
        try:
            info = client.subscription_info()
            print(f"[ahrefs] subscription info: {info}")
        except Exception as exc:
            print(f"[ahrefs] WARN could not fetch subscription info: {exc}")
            quality["errors"].append(f"subscription-info: {exc}")

    # Process each row that needs *any* retry. We touch a row at most
    # once per upstream so the script stays linear in ``len(rows)``.
    affected = sorted(set(needs_refdomains) | set(needs_anchors) | set(needs_wayback))
    # Wayback retry mode also gets the consecutive-failure circuit
    # breaker; without it a 503/timeout storm on web.archive.org makes
    # the workflow run for hours (~30 s per failed row).
    wayback_skip_after = 15
    wayback_consecutive_failures = 0
    wayback_disabled = False
    for n, idx in enumerate(affected, start=1):
        row = rows[idx]
        domain = row.get("domain") or ""
        if not domain:
            continue
        # Drop the old errors that we are about to retry; keep anything
        # else (e.g. ``ahrefs_batch_unmatched``) untouched.
        prev_errs = row.get("errors") or []
        kept_errs = [
            e for e in prev_errs
            if not (
                str(e).startswith("refdomains:")
                or str(e).startswith("anchors:")
                or str(e).startswith("wayback:")
            )
        ]
        new_errs: list[str] = list(kept_errs)
        print(f"[{n}/{len(affected)}] {domain}")

        ahrefs_dead = client is None or client.quota_exhausted

        if idx in needs_refdomains:
            if ahrefs_dead:
                new_errs.append("refdomains: skipped (ahrefs quota exhausted)")
                quality["ahrefs_skipped_quota"] += 1
                quality["refdomains_still_failing"] += 1
            else:
                try:
                    refdoms = client.site_explorer_refdomains(domain, limit=100)
                    row["refdomains_gojp"] = _count_tld(refdoms, ".go.jp")
                    row["refdomains_lgjp"] = _count_tld(refdoms, ".lg.jp")
                    row["refdomains_acjp"] = _count_tld(refdoms, ".ac.jp")
                    quality["refdomains_recovered"] += 1
                except Exception as exc:
                    print(f"  refdomains retry failed: {exc}")
                    new_errs.append(f"refdomains: {exc}")
                    quality["refdomains_still_failing"] += 1
                    if client is not None and client.quota_exhausted:
                        print(
                            "  [ahrefs] quota exhausted — skipping all "
                            "further Ahrefs calls in this run."
                        )
                        ahrefs_dead = True
                        quality["ahrefs_quota_exhausted"] = True

        if idx in needs_anchors:
            if ahrefs_dead:
                new_errs.append("anchors: skipped (ahrefs quota exhausted)")
                quality["ahrefs_skipped_quota"] += 1
                quality["anchors_still_failing"] += 1
            else:
                try:
                    anchors = client.site_explorer_anchors(domain, limit=5)
                    has_spam, spam_hits = detect_spam(anchors)
                    row["has_spam"] = has_spam
                    row["spam_hits"] = spam_hits
                    row["top_anchors"] = [
                        (a.get("anchor") or "")[:60] for a in anchors[:5]
                    ]
                    quality["anchors_recovered"] += 1
                except Exception as exc:
                    print(f"  anchors retry failed: {exc}")
                    new_errs.append(f"anchors: {exc}")
                    quality["anchors_still_failing"] += 1
                    if client is not None and client.quota_exhausted:
                        ahrefs_dead = True
                        quality["ahrefs_quota_exhausted"] = True

        if idx in needs_wayback:
            if wayback_disabled:
                new_errs.append("wayback: skipped (disabled this run)")
                quality["wayback_skipped_disabled"] += 1
                quality["wayback_still_failing"] += 1
            else:
                try:
                    wb = wayback_summarize(domain, timeout=12)
                    row["first_snapshot"] = wb.get("first_snapshot")
                    row["last_snapshot"] = wb.get("last_snapshot")
                    row["last_snapshot_ts"] = wb.get("last_snapshot_ts")
                    row["snapshot_count"] = wb.get("snapshot_count", 0)
                    row["years_active"] = wb.get("years_active", 0.0)
                    row["has_japanese"] = bool(wb.get("has_japanese", False))
                    if wb.get("title"):
                        row["title"] = wb.get("title", "")
                    quality["wayback_recovered"] += 1
                    wayback_consecutive_failures = 0
                except Exception as exc:
                    print(f"  wayback retry failed: {exc}")
                    new_errs.append(f"wayback: {exc}")
                    quality["wayback_still_failing"] += 1
                    wayback_consecutive_failures += 1
                    if wayback_consecutive_failures >= wayback_skip_after:
                        wayback_disabled = True
                        quality["wayback_disabled"] = True
                        print(
                            f"  [wayback] {wayback_skip_after} consecutive "
                            "failures — skipping Wayback for the rest of "
                            "this run."
                        )

        # Recompute score with the (possibly) refreshed inputs.
        category, _ = categorize(
            domain=domain,
            title=row.get("title", ""),
            text_sample="",
            anchors=[{"anchor": a} for a in (row.get("top_anchors") or [])],
            org_keywords=row.get("org_keywords", 0),
        )
        row["category"] = category
        score = compute_score(
            dr=row.get("dr", 0.0),
            refdomains=row.get("refdomains", 0),
            refips=row.get("refips", 0),
            refclass_c=row.get("refclass_c", 0),
            years_active=row.get("years_active", 0.0),
            has_japanese=bool(row.get("has_japanese", False)),
            refdomains_gojp=row.get("refdomains_gojp", 0),
            refdomains_lgjp=row.get("refdomains_lgjp", 0),
            refdomains_acjp=row.get("refdomains_acjp", 0),
            category=category,
            has_spam=bool(row.get("has_spam", False)),
        )
        row["score"] = score["score"]
        row["score_breakdown"] = score["score_breakdown"]
        row["errors"] = new_errs
        time.sleep(sleep_between)

    rows.sort(
        key=lambda r: (
            r.get("active_high_trust_score", 0),
            r.get("score", 0),
        ),
        reverse=True,
    )
    quality["written_rows"] = len(rows)
    quality["zero_rows"] = sum(1 for r in rows if not _row_has_real_data(r))
    return rows, quality


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
    parser.add_argument(
        "--merge",
        action="store_true",
        help="Merge every CSV under data/input/ instead of only the newest.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Only process the first N domains (useful for debug runs).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-analyse every domain even if already in docs/data.json.",
    )
    parser.add_argument(
        "--retry-failed",
        action="store_true",
        help=(
            "Skip CSV input entirely. Re-attempt only the previously-failed "
            "sub-fetches (Wayback / refdomains / anchors) on rows already in "
            "docs/data.json. Does not consume Ahrefs batch-analysis credits."
        ),
    )
    args = parser.parse_args(argv)

    if args.retry_failed:
        rows, quality = retry_failed_rows()
        write_output(rows, quality=quality)
        print(
            "[quality] retry-failed: "
            f"refdomains_recovered={quality['refdomains_recovered']}/"
            f"{quality['rows_needing_refdomains']} "
            f"anchors_recovered={quality['anchors_recovered']}/"
            f"{quality['rows_needing_anchors']} "
            f"wayback_recovered={quality['wayback_recovered']}/"
            f"{quality['rows_needing_wayback']} "
            f"ahrefs_skipped_quota={quality['ahrefs_skipped_quota']} "
            f"wayback_skipped_disabled={quality['wayback_skipped_disabled']} "
            f"zero_rows={quality.get('zero_rows', 0)}"
        )
        if quality.get("ahrefs_quota_exhausted"):
            print(
                "[quality] WARN: Ahrefs API units limit was reached — "
                "raise the limit and re-run with retry_failed=true to "
                "fill the remaining refdomains / anchors rows."
            )
        if quality.get("wayback_disabled"):
            print(
                "[quality] WARN: Wayback was disabled after consecutive "
                "failures — re-run with retry_failed=true later to fill "
                "the remaining wayback rows."
            )
        return 0

    if args.input is not None:
        print(f"[input] {args.input}")
        domains = load_domains(args.input)
    elif args.merge:
        if not any(INPUT_DIR.glob("*.csv")):
            print(f"No CSV found under {INPUT_DIR}. Put an export there first.")
            return 1
        domains = load_all_domains(INPUT_DIR)
    else:
        csv_path = newest_csv(INPUT_DIR)
        if csv_path is None:
            print(f"No CSV found under {INPUT_DIR}. Put an export there first.")
            return 1
        print(f"[input] {csv_path}")
        domains = load_domains(csv_path)

    if not domains:
        print("CSV contains no domains.")
        return 1
    if args.limit and args.limit > 0:
        domains = domains[: args.limit]
        print(f"[input] --limit {args.limit} applied")
    print(f"[input] total unique: {len(domains)} domain(s)")

    try:
        rows, quality = analyze(
            domains,
            dry_run=args.dry_run,
            skip_existing=not args.force,
        )
    except QuotaInsufficientError as exc:
        # No stacktrace — pre-flight already explained the situation.
        # Exit code 2 distinguishes "ran out of quota" from other failure
        # modes so a future workflow step can branch on it if needed.
        print(f"[ahrefs] QUOTA INSUFFICIENT: {exc}")
        return 2
    write_output(rows, quality=quality)
    print(
        f"[quality] cached={quality['cached']} fresh={quality['fresh']} "
        f"stale_refetched={quality['stale_refetched']} "
        f"unmatched={quality['ahrefs_batch_unmatched']} "
        f"refdomains_err={quality['refdomains_errors']} "
        f"anchors_err={quality['anchors_errors']} "
        f"wayback_err={quality['wayback_errors']} "
        f"zero_rows={quality.get('zero_rows', 0)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
