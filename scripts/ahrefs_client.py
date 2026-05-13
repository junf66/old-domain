"""Ahrefs API v3 client.

Docs: https://docs.ahrefs.com/docs/api/reference
"""
from __future__ import annotations

import os
import time
from typing import Iterable

import requests

API_BASE = "https://api.ahrefs.com/v3"


class AhrefsClient:
    def __init__(self, api_key: str | None = None, timeout: int = 30):
        self.api_key = api_key or os.environ.get("AHREFS_API_KEY", "")
        if not self.api_key:
            raise RuntimeError(
                "AHREFS_API_KEY is not set. Put it in .env or export it."
            )
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.api_key}",
                "Accept": "application/json",
            }
        )

    def _get(self, path: str, params: dict) -> dict:
        url = f"{API_BASE}/{path.lstrip('/')}"
        resp = self.session.get(url, params=params, timeout=self.timeout)
        if resp.status_code >= 400:
            raise RuntimeError(
                f"Ahrefs API error {resp.status_code} on {path}: {resp.text[:400]}"
            )
        return resp.json()

    def _post(self, path: str, body: dict) -> dict:
        url = f"{API_BASE}/{path.lstrip('/')}"
        resp = self.session.post(url, json=body, timeout=self.timeout)
        if resp.status_code >= 400:
            raise RuntimeError(
                f"Ahrefs API error {resp.status_code} on {path}: {resp.text[:400]}"
            )
        return resp.json()

    def subscription_info(self) -> dict:
        """Return remaining credits / limits for the account."""
        return self._get("subscription-info/limits-and-usage", params={})

    def batch_analysis(
        self, domains: Iterable[str], chunk_size: int = 50, retries: int = 3
    ) -> list[dict]:
        """Run batch-analysis for up to `chunk_size` domains at a time.

        On transient Ahrefs errors (HTTP 5xx) we retry with exponential
        backoff. If a chunk still fails, we skip it and continue so a
        single bad batch can't kill an otherwise good run.
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
        for i in range(0, len(domains), chunk_size):
            chunk = domains[i : i + chunk_size]
            body = {
                "select": select,
                "targets": [
                    {"url": d, "protocol": "both", "mode": "domain"}
                    for d in chunk
                ],
            }
            last_exc: Exception | None = None
            for attempt in range(retries):
                try:
                    data = self._post("batch-analysis/batch-analysis", body=body)
                    rows = data.get("targets") or data.get("results") or []
                    results.extend(rows)
                    last_exc = None
                    break
                except RuntimeError as exc:
                    msg = str(exc)
                    last_exc = exc
                    # Only retry on Ahrefs-side transient errors (5xx).
                    if " 5" in msg and "Ahrefs API error" in msg and attempt < retries - 1:
                        wait = 2 ** attempt
                        print(
                            f"  [batch] attempt {attempt+1} failed (5xx). "
                            f"Retrying in {wait}s..."
                        )
                        time.sleep(wait)
                        continue
                    break
            if last_exc is not None:
                print(
                    f"  [batch] giving up on chunk {i}-{i+len(chunk)-1}: "
                    f"{last_exc}"
                )
            time.sleep(0.3)
        return results

    def site_explorer_refdomains(
        self, target: str, limit: int = 1000
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
        return data.get("refdomains") or data.get("results") or []

    def site_explorer_anchors(
        self, target: str, limit: int = 20
    ) -> list[dict]:
        """Top anchor texts for a domain (by referring domains desc)."""
        params = {
            "target": target,
            "mode": "domain",
            "limit": limit,
            "order_by": "refdomains:desc",
            "select": "anchor,refdomains,backlinks",
        }
        data = self._get("site-explorer/anchors", params=params)
        return data.get("anchors") or data.get("results") or []


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
