"""WordPress queue runner.

Reads `data/wp-install-queue.json`, processes each item, appends results to
`data/wp-install-results.json`, and clears the processed items from the queue.

Two actions are supported:

  - check_status  (fully implemented; no XServer needed)
      Probes the live domain to determine:
        * is WordPress installed?
        * does the homepage respond 200?
        * the front-page ID (used to build the correct edit URL)

  - install       (XServer-specific bits are TODO)
      Adds the domain to XServer, enables SSL, installs WordPress, creates
      a front page, returns admin credentials and the page-edit URL.
      Currently raises NotImplementedError; fill in the marked sections
      with calls to the XServer MCP Server / XServer CLI you intend to use.

The queue / results files use the schema documented in the dashboard's
"WordPress投稿モード" implementation. External runners (a separate process
that drives XServer MCP / CLI) can consume the same queue file directly.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

ROOT = Path(__file__).resolve().parent.parent
QUEUE_PATH = ROOT / "data" / "wp-install-queue.json"
RESULTS_PATH = ROOT / "data" / "wp-install-results.json"

USER_AGENT = (
    "old-domain-tool/0.1 wp-runner "
    "Mozilla/5.0 (compatible; python-requests)"
)


# ---------- file helpers ----------

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


# ---------- check_status ----------

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
    """Return the WordPress front-page ID (best-effort).

    Strategy:
      1. GET https://{domain}/wp-json/             — discover the API root
      2. GET /wp-json/wp/v2/pages?per_page=20
      3. GET https://{domain}/                     — find body class "page-id-N"
    """
    headers = {"User-Agent": USER_AGENT}

    # 3rd-strategy first since it's the cheapest and most reliable.
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

    # Fallback: list pages and pick the one whose URL is the site root.
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
    """Probe `domain` and return a small summary."""
    headers = {"User-Agent": USER_AGENT}
    out: dict[str, Any] = {
        "domain": domain,
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
    return out


# ---------- install ----------

def install_wordpress(item: dict[str, Any]) -> dict[str, Any]:
    """Install WordPress on `item['domain']` via XServer MCP / CLI.

    Required env vars (configure in GitHub Secrets):
      - XSERVER_CLI_BIN          : path or name of the xserver-cli binary
      - XSERVER_API_KEY          : your XServer API key
      - XSERVER_SERVER_ID        : target server identifier (e.g. "sv1234")
      - WP_ADMIN_USER  (optional): default admin username for new installs
      - WP_ADMIN_EMAIL (optional): default admin email
    """
    domain = item["domain"]
    out: dict[str, Any] = {
        "domain": domain,
        "action": "install",
        "ok": False,
        "started_at": datetime.utcnow().isoformat() + "Z",
    }

    cli = os.environ.get("XSERVER_CLI_BIN") or "xserver-cli"
    api_key = os.environ.get("XSERVER_API_KEY", "")
    server_id = os.environ.get("XSERVER_SERVER_ID", "")
    if not api_key or not server_id:
        out["error"] = (
            "XSERVER_API_KEY / XSERVER_SERVER_ID is not set. "
            "Add them to GitHub Secrets to enable installs."
        )
        return out

    admin_user = os.environ.get("WP_ADMIN_USER") or "admin"
    admin_email = os.environ.get("WP_ADMIN_EMAIL") or f"admin@{domain}"

    # NOTE: XServer CLI subcommand names below are placeholders.
    # Replace each subprocess call with the actual command from your
    # XServer CLI / MCP Server reference once those names are known.
    try:
        # 1) Add domain to XServer.
        _run_xs(cli, ["domain", "add", "--server", server_id, "--domain", domain])
        # 2) Enable Let's Encrypt SSL.
        _run_xs(cli, ["ssl", "enable", "--server", server_id, "--domain", domain])
        # 3) Install WordPress via "簡単インストール".
        creds = _run_xs(
            cli,
            [
                "wp", "install",
                "--server", server_id,
                "--domain", domain,
                "--admin-user", admin_user,
                "--admin-email", admin_email,
            ],
            capture_json=True,
        )
        # `creds` is expected to contain at least
        # { admin_user, admin_password, login_url }.
        out.update({
            "ok": True,
            "admin_user": creds.get("admin_user") or admin_user,
            "admin_password": creds.get("admin_password"),
            "login_url": creds.get("login_url")
                or f"https://{domain}/wp-admin/",
        })

        # 4) Detect / create front page and compute the edit URL.
        time.sleep(8)  # give the new site a moment to come online
        status = check_status(domain)
        out["front_page_id"] = status.get("front_page_id")
        out["edit_url"] = status.get("suggested_edit_url")
    except subprocess.CalledProcessError as exc:
        out["error"] = (
            f"{exc.cmd[1:3]} failed (rc={exc.returncode}): "
            f"{(exc.stderr or '').strip()[:400]}"
        )
    except FileNotFoundError as exc:
        out["error"] = (
            f"XServer CLI not found ({exc}). "
            f"Install it on the runner or set XSERVER_CLI_BIN."
        )
    except NotImplementedError as exc:
        out["error"] = str(exc)

    out["finished_at"] = datetime.utcnow().isoformat() + "Z"
    return out


def _run_xs(cli: str, args: list[str], capture_json: bool = False) -> dict:
    """Run an XServer CLI subcommand. Returns parsed JSON if requested."""
    env = os.environ.copy()
    api_key = env.get("XSERVER_API_KEY", "")
    if api_key:
        env["XSERVER_API_KEY"] = api_key  # passthrough
    cmd = [cli] + list(args)
    print(f"[xs] $ {' '.join(cmd)}")
    proc = subprocess.run(
        cmd, env=env, capture_output=True, text=True, timeout=300
    )
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(
            proc.returncode, cmd, output=proc.stdout, stderr=proc.stderr
        )
    if capture_json:
        try:
            return json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            return {}
    return {}


# ---------- main ----------

def process_queue() -> int:
    queue = _load(QUEUE_PATH, {"version": 1, "items": []})
    results_blob = _load(RESULTS_PATH, {"version": 1, "results": []})

    items = queue.get("items") or []
    if not items:
        print("[wp-runner] queue is empty; nothing to do.")
        return 0

    print(f"[wp-runner] processing {len(items)} item(s)")
    new_results: list[dict] = []
    for i, item in enumerate(items, 1):
        action = (item.get("action") or "check_status").lower()
        domain = (item.get("domain") or "").strip()
        if not domain:
            continue
        print(f"[{i}/{len(items)}] {action} :: {domain}")
        try:
            if action == "install":
                r = install_wordpress(item)
            else:
                r = check_status(domain)
                r["action"] = "check_status"
                r["ok"] = bool(r.get("wp_detected"))
            r.setdefault("requested_at", item.get("requested_at"))
        except Exception as exc:
            r = {
                "domain": domain,
                "action": action,
                "ok": False,
                "error": f"{exc.__class__.__name__}: {exc}",
            }
        new_results.append(r)

    # Append to results and clear the queue.
    results_blob.setdefault("results", []).extend(new_results)
    results_blob["last_run_at"] = datetime.utcnow().isoformat() + "Z"
    _save(RESULTS_PATH, results_blob)

    _save(QUEUE_PATH, {"version": 1, "items": [], "last_processed_at":
        datetime.utcnow().isoformat() + "Z"})

    print(
        f"[wp-runner] done. wrote {len(new_results)} result(s); "
        f"queue cleared."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(process_queue())
