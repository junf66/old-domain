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

    def batch_analysis(self, domains: Iterable[str]) -> list[dict]:
        """Run batch-analysis for up to 100 domains at a time.

        Returns a list of per-domain dicts with DR, refdomains,
        organic keywords, and organic traffic.
        """
        domains = [d.strip() for d in domains if d and d.strip()]
        results: list[dict] = []
        select = [
            "url",
            "domain_rating",
            "refdomains",
            "org_keywords",
            "org_traffic",
            "ahrefs_rank",
            "refips",
            "refclass_c",
        ]
        for i in range(0, len(domains), 100):
            chunk = domains[i : i + 100]
            body = {
                "select": select,
                "targets": [
                    {"url": d, "protocol": "both", "mode": "domain"}
                    for d in chunk
                ],
            }
            data = self._post("batch-analysis/batch-analysis", body=body)
            rows = data.get("targets") or data.get("results") or []
            for row in rows:
                results.append(row)
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
