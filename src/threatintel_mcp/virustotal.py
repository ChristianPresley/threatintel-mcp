"""VirusTotal v3 client.

Responsibility split:
  * this module talks to the API and *summarizes* the response;
  * it does NOT defang (that happens once, centrally, in server.py) so the
    summaries stay easy to unit-test against real field names.

Compact-output design decision
------------------------------
A single VT v3 file report can be several hundred KB of JSON (every AV engine's
verdict, full behavioral traces, embedded resources, ...). Dumping that into an
LLM's context is wasteful and drowns the signal. Each ``summarize_*`` function
below deliberately projects the response down to the handful of fields an
investigator actually pivots on: the detection ratio, reputation, key hashes,
notable names, and first/last-seen timestamps.
"""

from __future__ import annotations

from typing import Any

import httpx

from . import config
from .errors import from_http_status
from .ratelimit import SlidingWindowLimiter

_BASE_URL = "https://www.virustotal.com/api/v3"

# One shared limiter instance per process, sized to the public tier by default.
_limiter = SlidingWindowLimiter(
    api="VirusTotal",
    max_calls=config.VT_RATE_MAX_CALLS,
    period=config.VT_RATE_PERIOD_SECONDS,
    daily_cap=config.VT_DAILY_CAP,
)


def _headers(api_key: str) -> dict[str, str]:
    return {"x-apikey": api_key, "accept": "application/json"}


def _iso(ts: int | None) -> str | None:
    """VT returns UNIX epochs; render them as ISO-8601 UTC for readability."""
    if not ts:
        return None
    import datetime as _dt

    return _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc).isoformat()


def _analysis_verdict(stats: dict[str, int]) -> str:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    if malicious > 0:
        return "malicious"
    if suspicious > 0:
        return "suspicious"
    return "clean"


def summarize_file(data: dict[str, Any]) -> dict[str, Any]:
    """Project a VT file object down to the investigator-relevant fields."""
    attr = data.get("data", {}).get("attributes", {})
    stats = attr.get("last_analysis_stats", {}) or {}
    total = sum(v for v in stats.values() if isinstance(v, int))
    detections = stats.get("malicious", 0) + stats.get("suspicious", 0)

    # Surface the most-agreed-upon threat label, if VT computed one.
    suggested = attr.get("popular_threat_classification", {}) or {}
    threat_label = suggested.get("suggested_threat_label")

    return {
        "indicator_type": "file",
        "sha256": attr.get("sha256") or data.get("data", {}).get("id"),
        "md5": attr.get("md5"),
        "verdict": _analysis_verdict(stats),
        "detection_ratio": f"{detections}/{total}" if total else "0/0",
        "detection_stats": stats,
        "reputation": attr.get("reputation"),
        "type_description": attr.get("type_description"),
        "size_bytes": attr.get("size"),
        "threat_label": threat_label,
        "meaningful_name": attr.get("meaningful_name"),
        "times_submitted": attr.get("times_submitted"),
        "first_seen": _iso(attr.get("first_submission_date")),
        "last_seen": _iso(attr.get("last_analysis_date")),
        "vt_link": f"https://www.virustotal.com/gui/file/{attr.get('sha256', '')}",
    }


def summarize_domain(data: dict[str, Any]) -> dict[str, Any]:
    attr = data.get("data", {}).get("attributes", {})
    stats = attr.get("last_analysis_stats", {}) or {}
    total = sum(v for v in stats.values() if isinstance(v, int))
    detections = stats.get("malicious", 0) + stats.get("suspicious", 0)
    domain = data.get("data", {}).get("id")

    # Registrar + creation date are strong pivots for newly-registered-domain
    # (NRD) tradecraft; categories hint at what the site claims to be.
    return {
        "indicator_type": "domain",
        "domain": domain,
        "verdict": _analysis_verdict(stats),
        "detection_ratio": f"{detections}/{total}" if total else "0/0",
        "detection_stats": stats,
        "reputation": attr.get("reputation"),
        "registrar": attr.get("registrar"),
        "creation_date": _iso(attr.get("creation_date")),
        "categories": attr.get("categories"),
        "last_analysis_date": _iso(attr.get("last_analysis_date")),
        "vt_link": f"https://www.virustotal.com/gui/domain/{domain}",
    }


def summarize_ip(data: dict[str, Any]) -> dict[str, Any]:
    attr = data.get("data", {}).get("attributes", {})
    stats = attr.get("last_analysis_stats", {}) or {}
    total = sum(v for v in stats.values() if isinstance(v, int))
    detections = stats.get("malicious", 0) + stats.get("suspicious", 0)
    ip = data.get("data", {}).get("id")

    # ASN / owner / country are the classic hosting-context pivots.
    return {
        "indicator_type": "ip",
        "ip": ip,
        "verdict": _analysis_verdict(stats),
        "detection_ratio": f"{detections}/{total}" if total else "0/0",
        "detection_stats": stats,
        "reputation": attr.get("reputation"),
        "asn": attr.get("asn"),
        "as_owner": attr.get("as_owner"),
        "country": attr.get("country"),
        "network": attr.get("network"),
        "last_analysis_date": _iso(attr.get("last_analysis_date")),
        "vt_link": f"https://www.virustotal.com/gui/ip-address/{ip}",
    }


async def _get(path: str, api_key: str) -> dict[str, Any]:
    """Shared GET with local throttle + structured error handling."""
    await _limiter.acquire()
    async with httpx.AsyncClient(timeout=config.HTTP_TIMEOUT_SECONDS) as client:
        resp = await client.get(
            f"{_BASE_URL}{path}", headers=_headers(api_key)
        )
    if resp.is_error:
        return from_http_status("VirusTotal", resp)
    return {"ok": resp.json()}


async def get_file(file_hash: str, api_key: str) -> dict[str, Any]:
    result = await _get(f"/files/{file_hash}", api_key)
    if "ok" not in result:
        return result
    return summarize_file(result["ok"])


async def get_domain(domain: str, api_key: str) -> dict[str, Any]:
    result = await _get(f"/domains/{domain}", api_key)
    if "ok" not in result:
        return result
    return summarize_domain(result["ok"])


async def get_ip(ip: str, api_key: str) -> dict[str, Any]:
    result = await _get(f"/ip_addresses/{ip}", api_key)
    if "ok" not in result:
        return result
    return summarize_ip(result["ok"])
