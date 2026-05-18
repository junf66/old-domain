"""Ahrefs API v3 client.

Docs: https://docs.ahrefs.com/docs/api/reference
"""
from __future__ import annotations

import os
import time
from typing import Iterable

import requests

API_BASE = "https://api.ahrefs.com/v3"

# Ahrefs sits behind Cloudflare, which 429-rejects the bare
# python-requests UA with a "Just a moment..." challenge page. Send a
# real-looking UA so the requests reach the API.
USER_AGENT = (
    "old-domain-tool/0.1 "
    "Mozilla/5.0 (compatible; +https://github.com/junf66/old-domain)"
)


class AhrefsClient:
    def __init__(self, api_key: str | None = None, timeout: int = 30):
        self.api_key = api_key or os.environ.get("AHREFS_API_KEY", "")
        if not self.api_key:
            raise RuntimeError(
                "AHREFS_API_KEY is not set. Put it in .env or export it."
            )
        self.timeout = timeout
        # Flips to True the first time the API returns "units limit reached".
        # Callers should consult this before queueing another expensive call
        # so we don't burn time on requests that will 403 outright.
        self.quota_exhausted = False
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.api_key}",
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            }
        )

    @staticmethod
    def _retry_wait(resp: requests.Response | None, attempt: int) -> float:
        """Compute backoff for a transient failure.

        Honours the upstream ``Retry-After`` header when present (Ahrefs /
        Cloudflare set it on 429s), otherwise falls back to exponential
        backoff capped at 30s.
        """
        if resp is not None:
            ra = resp.headers.get("Retry-After")
            if ra:
                try:
                    return min(float(ra), 60.0)
                except ValueError:
                    pass
        return min(2 ** attempt * 2.0, 30.0)

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        json_body: dict | None = None,
        retries: int = 4,
    ) -> dict:
        """HTTP call with retry on transient errors (5xx, 429, network).

        Raises ``RuntimeError`` on a non-recoverable HTTP error or after
        exhausting retries on a transient one. Successful responses are
        returned as parsed JSON.
        """
        url = f"{API_BASE}/{path.lstrip('/')}"
        last_exc: Exception | None = None
        last_resp: requests.Response | None = None
        for attempt in range(retries):
            try:
                resp = self.session.request(
                    method, url,
                    params=params,
                    json=json_body,
                    timeout=self.timeout,
                )
            except requests.RequestException as exc:
                last_exc = exc
                last_resp = None
                if attempt < retries - 1:
                    wait = self._retry_wait(None, attempt)
                    print(
                        f"  [http] {path} network error (attempt {attempt+1}): "
                        f"{exc}; retry in {wait:.1f}s"
                    )
                    time.sleep(wait)
                    continue
                break
            last_resp = resp
            status = resp.status_code
            if status < 400:
                try:
                    return resp.json()
                except ValueError as exc:
                    raise RuntimeError(
                        f"Ahrefs API returned non-JSON on {path}: "
                        f"{resp.text[:200]}"
                    ) from exc
            # Detect Ahrefs' "API units limit reached" so callers can stop
            # queueing more requests. The 403 itself is non-transient, but
            # the global flag lets the analyser skip future Ahrefs calls
            # entirely instead of paying ~30 s per request to find out
            # they'll all 403.
            if status == 403 and "units limit reached" in resp.text.lower():
                self.quota_exhausted = True
            transient = status == 429 or status >= 500
            if transient and attempt < retries - 1:
                wait = self._retry_wait(resp, attempt)
                print(
                    f"  [http] {path} HTTP {status} (attempt {attempt+1}); "
                    f"retry in {wait:.1f}s"
                )
                time.sleep(wait)
                continue
            break
        if last_resp is not None:
            raise RuntimeError(
                f"Ahrefs API error {last_resp.status_code} on {path}: "
                f"{last_resp.text[:400]}"
            )
        raise RuntimeError(
            f"Ahrefs API request failed on {path}: {last_exc}"
        )

    def _get(self, path: str, params: dict) -> dict:
        return self._request("GET", path, params=params)

    def _post(self, path: str, body: dict) -> dict:
        return self._request("POST", path, json_body=body)

    def subscription_info(self) -> dict:
        """Return remaining credits / limits for the account."""
        return self._get("subscription-info/limits-and-usage", params={})

    def batch_analysis(
        self, domains: Iterable[str], chunk_size: int = 50
    ) -> list[dict]:
        """Run batch-analysis for up to ``chunk_size`` domains at a time.

        Per-request 429/5xx retries are handled inside :meth:`_request`,
        so a chunk only ends up here as a hard failure if every retry
        was exhausted. We still record per-chunk failure counts on
        ``self.last_batch_failures`` and raise when *every* chunk
        failed (otherwise the analyser would happily overwrite
        ``docs/data.json`` with all-zero rows).
        """
        domains = [d.strip() for d in domains if d and d.strip()]
        results: list[dict] = []
        select = [
            "url",
            "domain_rating",
            "refdomains",
            "org_keywords",
            "org_traffic",
            "refips",
            "refips_subnets",
        ]
        chunk_failures = 0
        last_exc: Exception | None = None
        total_chunks = 0
        for i in range(0, len(domains), chunk_size):
            total_chunks += 1
            chunk = domains[i : i + chunk_size]
            body = {
                "select": select,
                "targets": [
                    {"url": d, "protocol": "both", "mode": "domain"}
                    for d in chunk
                ],
            }
            try:
                data = self._post("batch-analysis/batch-analysis", body=body)
            except RuntimeError as exc:
                chunk_failures += 1
                last_exc = exc
                print(
                    f"  [batch] giving up on chunk {i}-{i+len(chunk)-1}: {exc}"
                )
                time.sleep(0.3)
                continue
            rows = data.get("targets") or data.get("results") or []
            results.extend(rows)
            time.sleep(0.3)
        self.last_batch_failures = chunk_failures
        if total_chunks and chunk_failures == total_chunks:
            raise RuntimeError(
                "Ahrefs batch-analysis failed for every chunk "
                f"({chunk_failures}/{total_chunks}). Last error: {last_exc}"
            )
        return results

    def site_explorer_refdomains(
        self, target: str, limit: int = 100
    ) -> list[dict]:
        """Top referring domains by DR.

        Used to count specific TLDs (.go.jp, .lg.jp, .ac.jp, …) locally
        without burning one API call per TLD.
        """
        params = {
            "target": target,
            "mode": "domain",
            "limit": limit,
            "order_by": "domain_rating:desc",
            "select": "domain,domain_rating",
        }
        data = self._get("site-explorer/refdomains", params=params)
        # Ahrefs has historically wrapped the array under several names —
        # accept whichever appears.
        for k in ("refdomains", "results", "data", "rows", "items"):
            v = data.get(k) if isinstance(data, dict) else None
            if isinstance(v, list):
                return v
        return []

    def site_explorer_anchors(
        self, target: str, limit: int = 5
    ) -> list[dict]:
        """Top anchor texts for a domain (by referring domains desc)."""
        params = {
            "target": target,
            "mode": "domain",
            "limit": limit,
            "order_by": "refdomains:desc",
            "select": "anchor,refdomains",
        }
        data = self._get("site-explorer/anchors", params=params)
        return data.get("anchors") or data.get("results") or []

    def site_explorer_all_backlinks(
        self,
        target: str,
        *,
        select: str,
        where: str,
        mode: str = "subdomains",
        aggregation: str = "1_per_domain",
        history: str = "live",
        limit: int = 200,
    ) -> list[dict]:
        """Fetch backlinks matching a ``where`` filter.

        Defaults are tuned for the "active trust links" screening step:

        - ``aggregation='1_per_domain'`` returns one row per referring
          domain so counts reflect unique domains rather than every
          backlink page (cheaper and matches the spec).
        - ``history='live'`` excludes ``is_lost=true`` links by default
          at the API level; callers can still add ``is_lost`` filters
          inside ``where`` for belt-and-braces safety.
        - ``mode='subdomains'`` matches Ahrefs' own recommendation for
          domain-level queries.

        ``where`` must be the JSON-encoded filter expression (Ahrefs
        accepts it as a query-string parameter).
        """
        params = {
            "target": target,
            "mode": mode,
            "aggregation": aggregation,
            "history": history,
            "limit": limit,
            "select": select,
            "where": where,
        }
        data = self._get("site-explorer/all-backlinks", params=params)
        for k in ("backlinks", "results", "data", "rows", "items"):
            v = data.get(k) if isinstance(data, dict) else None
            if isinstance(v, list):
                return v
        return []


def _demo() -> None:
    """Quick smoke test against example.com.

    Skipped automatically if AHREFS_API_KEY is not set.
    """
    from dotenv import load_dotenv

    load_dotenv()
    if not os.environ.get("AHREFS_API_KEY"):
        print("[ahrefs] AHREFS_API_KEY is not set; skipping live demo.")
        return
    client = AhrefsClient()
    print("[ahrefs] subscription info:")
    print(client.subscription_info())
    print("[ahrefs] batch-analysis example.com:")
    print(client.batch_analysis(["example.com"]))
    print("[ahrefs] top anchors example.com:")
    print(client.site_explorer_anchors("example.com", limit=5))


if __name__ == "__main__":
    _demo()
