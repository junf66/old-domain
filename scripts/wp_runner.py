"""WordPress queue runner (status-check only).

The dashboard writes domains it wants to process into
`data/wp-install-queue.json`. This script handles the **status-check**
action server-side (in GitHub Actions) and appends results to
`data/wp-install-results.json`.

The **install** action is intentionally NOT handled here — it is meant
to be processed by an AI agent that has access to the **XServer MCP
Server**. The agent reads the same queue file, calls the MCP tools to
add the domain / enable SSL / install WordPress, and writes the result
back into `data/wp-install-results.json` using the same schema as
below. See README for the recommended workflow.

Queue item schema:
  {
    "action": "install" | "check_status",
    "domain": "example.com",
    "requested_at": "<iso8601>",
    "id":   "<dashboard-side site id, optional>"
  }

Result item schema (status-check):
  {
    "action": "check_status",
    "domain": ...,
    "ok": bool,
    "wp_detected": bool,
    "homepage_status": int|null,
    "wp_json_status":  int|null,
    "front_page_id":   int|null,
    "suggested_edit_url": str|null,
    "checked_at": "<iso8601>"
  }

Result item schema (install, written by the agent):
  {
    "action": "install",
    "domain": ...,
    "ok": bool,
    "login_url": str,
    "edit_url":  str,
    "admin_user": str,
    "admin_password": str,
    "front_page_id": int,
    "finished_at": "<iso8601>",
    "error": str (when ok is false)
  }
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import requests

ROOT = Path(__file__).resolve().parent.parent
QUEUE_PATH = ROOT / "data" / "wp-install-queue.json"
RESULTS_PATH = ROOT / "data" / "wp-install-results.json"

USER_AGENT = (
    "old-domain-tool/0.1 wp-runner "
    "Mozilla/5.0 (compatible; python-requests)"
)


def _load(path: Path, default: dict) -> dict:
    if not path.exists():
        return dict(default)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return dict(default)


def _save(path: Path, data: dict) -> None:
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _bool_wp_signature(html: str) -> bool:
    if not html:
        return False
    low = html.lower()
    if 'name="generator"' in low and "wordpress" in low:
        return True
    if "/wp-content/" in low or "/wp-includes/" in low:
        return True
    if "wp-emoji-release" in low or "/wp-json/" in low:
        return True
    return False


def _front_page_id(domain: str, timeout: int = 15) -> int | None:
    """Return the WordPress front-page ID (best-effort, no auth)."""
    headers = {"User-Agent": USER_AGENT}

    # Cheapest path: look at body class on the homepage.
    try:
        r = requests.get(
            f"https://{domain}/",
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
        )
        m = re.search(r'class="[^"]*\bpage-id-(\d+)\b', r.text or "")
        if m:
            return int(m.group(1))
        m = re.search(r'class="[^"]*\bpostid-(\d+)\b', r.text or "")
        if m:
            return int(m.group(1))
    except Exception:
        pass

    # Fallback: REST API page list.
    try:
        r = requests.get(
            f"https://{domain}/wp-json/wp/v2/pages",
            params={"per_page": 20},
            headers=headers,
            timeout=timeout,
        )
        if r.status_code == 200:
            pages = r.json()
            origin = f"https://{domain}/".rstrip("/")
            for p in pages:
                link = (p.get("link") or "").rstrip("/")
                if link == origin:
                    return int(p.get("id"))
            if pages:
                return int(pages[0].get("id"))
    except Exception:
        pass

    return None


def check_status(domain: str) -> dict[str, Any]:
    """Probe `domain` and return a small summary suitable for the results file."""
    headers = {"User-Agent": USER_AGENT}
    out: dict[str, Any] = {
        "action": "check_status",
        "domain": domain,
        "ok": False,
        "wp_detected": False,
        "homepage_status": None,
        "wp_json_status": None,
        "front_page_id": None,
        "suggested_edit_url": None,
        "checked_at": datetime.utcnow().isoformat() + "Z",
    }
    try:
        r = requests.get(
            f"https://{domain}/",
            headers=headers,
            timeout=15,
            allow_redirects=True,
        )
        out["homepage_status"] = r.status_code
        out["wp_detected"] = _bool_wp_signature(r.text or "")
    except Exception as exc:
        out["error"] = f"homepage: {exc.__class__.__name__}"

    try:
        r = requests.get(
            f"https://{domain}/wp-json/",
            headers=headers,
            timeout=15,
        )
        out["wp_json_status"] = r.status_code
        if r.status_code == 200:
            out["wp_detected"] = True
    except Exception:
        pass

    if out["wp_detected"]:
        pid = _front_page_id(domain)
        if pid is not None:
            out["front_page_id"] = pid
            out["suggested_edit_url"] = (
                f"https://{domain}/wp-admin/post.php?post={pid}&action=edit"
            )
    out["ok"] = bool(out["wp_detected"])
    return out


def process_queue() -> int:
    """Process every `check_status` item; leave `install` items in the
    queue so an MCP-enabled agent can pick them up."""
    queue = _load(QUEUE_PATH, {"version": 1, "items": []})
    results_blob = _load(RESULTS_PATH, {"version": 1, "results": []})

    items = list(queue.get("items") or [])
    if not items:
        print("[wp-runner] queue is empty; nothing to do.")
        return 0

    handled: list[dict] = []
    remaining: list[dict] = []
    for item in items:
        action = (item.get("action") or "check_status").lower()
        domain = (item.get("domain") or "").strip()
        if not domain:
            continue
        if action != "check_status":
            # Install is handled out-of-band by the agent + XServer MCP.
            remaining.append(item)
            continue
        print(f"[wp-runner] check_status :: {domain}")
        try:
            r = check_status(domain)
        except Exception as exc:
            r = {
                "action": "check_status",
                "domain": domain,
                "ok": False,
                "error": f"{exc.__class__.__name__}: {exc}",
                "checked_at": datetime.utcnow().isoformat() + "Z",
            }
        r["requested_at"] = item.get("requested_at")
        handled.append(r)

    if not handled and not remaining:
        return 0

    results_blob.setdefault("results", []).extend(handled)
    results_blob["last_run_at"] = datetime.utcnow().isoformat() + "Z"
    _save(RESULTS_PATH, results_blob)

    _save(
        QUEUE_PATH,
        {
            "version": 1,
            "items": remaining,
            "last_processed_at": datetime.utcnow().isoformat() + "Z",
        },
    )

    print(
        f"[wp-runner] done. wrote {len(handled)} status result(s); "
        f"{len(remaining)} install item(s) left for the MCP agent."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(process_queue())
