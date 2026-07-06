"""urlscan.io client.

Three primitives, mirroring urlscan's own model:
  * submit a scan            -> POST /api/v1/scan/
  * poll for the result      -> GET  /api/v1/result/{uuid}/
  * search historical scans  -> GET  /api/v1/search/?q=<ES query>

As with the VT client, responses are projected down to compact summaries; a full
urlscan result document is large (full DOM, every request/response, screenshots
metadata, ...) and we keep only the pivot-worthy fields.
"""

from __future__ import annotations

from typing import Any

import httpx

from . import config
from .errors import error, from_http_status
from .ratelimit import SlidingWindowLimiter

_BASE_URL = "https://urlscan.io/api/v1"

_limiter = SlidingWindowLimiter(
    api="urlscan.io",
    max_calls=config.URLSCAN_RATE_MAX_CALLS,
    period=config.URLSCAN_RATE_PERIOD_SECONDS,
)


def _headers(api_key: str | None) -> dict[str, str]:
    headers = {"accept": "application/json"}
    if api_key:
        headers["API-Key"] = api_key
    return headers


def summarize_submission(data: dict[str, Any]) -> dict[str, Any]:
    """The POST /scan/ response is small already; keep the useful handles."""
    return {
        "uuid": data.get("uuid"),
        "scan_url": data.get("url"),
        "result_api": data.get("api"),
        "result_ui": data.get("result"),
        "visibility": data.get("visibility"),
        "message": data.get("message"),
        "note": "Poll get_url_result with this uuid; results take ~10-30s to finish.",
    }


def summarize_result(data: dict[str, Any]) -> dict[str, Any]:
    """Project a completed urlscan result to the fields an analyst pivots on."""
    page = data.get("page", {}) or {}
    verdicts = data.get("verdicts", {}) or {}
    overall = verdicts.get("overall", {}) or {}
    lists = data.get("lists", {}) or {}
    task = data.get("task", {}) or {}
    stats = data.get("stats", {}) or {}

    return {
        "uuid": task.get("uuid"),
        "submitted_url": task.get("url"),
        "final_url": page.get("url"),
        "malicious": overall.get("malicious"),
        "score": overall.get("score"),
        "categories": overall.get("categories"),
        "brands": [b.get("name") for b in overall.get("brands", []) if isinstance(b, dict)],
        "page_domain": page.get("domain"),
        "page_ip": page.get("ip"),
        "page_asn": page.get("asn"),
        "page_asnname": page.get("asnname"),
        "page_country": page.get("country"),
        "page_server": page.get("server"),
        "page_title": page.get("title"),
        "tls_issuer": page.get("tlsIssuer"),
        # Contacted infrastructure — the highest-value pivot set.
        "contacted_domains": (lists.get("domains") or [])[:25],
        "contacted_ips": (lists.get("ips") or [])[:25],
        "unique_countries": stats.get("uniqCountries"),
        "screenshot": task.get("screenshotURL"),
        "result_ui": f"https://urlscan.io/result/{task.get('uuid')}/" if task.get("uuid") else None,
    }


def summarize_search(data: dict[str, Any]) -> dict[str, Any]:
    """Reduce a search response to a short list of hits."""
    results = data.get("results", []) or []
    hits = []
    for r in results:
        page = r.get("page", {}) or {}
        task = r.get("task", {}) or {}
        hits.append(
            {
                "uuid": r.get("_id") or task.get("uuid"),
                "url": page.get("url") or task.get("url"),
                "domain": page.get("domain"),
                "ip": page.get("ip"),
                "asn": page.get("asnname"),
                "country": page.get("country"),
                "scanned_at": task.get("time"),
                "result_ui": r.get("result"),
            }
        )
    return {
        "total": data.get("total"),
        "returned": len(hits),
        "has_more": bool(data.get("has_more")),
        "results": hits,
    }


async def submit_scan(
    url: str, api_key: str, *, visibility: str = "unlisted", tags: list[str] | None = None
) -> dict[str, Any]:
    await _limiter.acquire()
    payload: dict[str, Any] = {"url": url, "visibility": visibility}
    if tags:
        payload["tags"] = tags
    async with httpx.AsyncClient(timeout=config.HTTP_TIMEOUT_SECONDS) as client:
        resp = await client.post(
            f"{_BASE_URL}/scan/", headers=_headers(api_key), json=payload
        )
    if resp.is_error:
        return from_http_status("urlscan.io", resp)
    return summarize_submission(resp.json())


async def get_result(uuid: str, api_key: str | None) -> dict[str, Any]:
    await _limiter.acquire()
    async with httpx.AsyncClient(timeout=config.HTTP_TIMEOUT_SECONDS) as client:
        resp = await client.get(
            f"{_BASE_URL}/result/{uuid}/", headers=_headers(api_key)
        )
    if resp.status_code == 404:
        # urlscan returns 404 while a scan is still processing; make that
        # explicit so the agent knows to keep polling rather than give up.
        return error(
            "pending",
            "Scan not ready yet (HTTP 404). Wait a few seconds and poll again.",
            api="urlscan.io",
            uuid=uuid,
        )
    if resp.is_error:
        return from_http_status("urlscan.io", resp)
    return summarize_result(resp.json())


async def search(query: str, api_key: str | None, *, size: int = 10) -> dict[str, Any]:
    await _limiter.acquire()
    params = {"q": query, "size": str(size)}
    async with httpx.AsyncClient(timeout=config.HTTP_TIMEOUT_SECONDS) as client:
        resp = await client.get(
            f"{_BASE_URL}/search/", headers=_headers(api_key), params=params
        )
    if resp.is_error:
        return from_http_status("urlscan.io", resp)
    return summarize_search(resp.json())
