"""Tests for the urlscan.io tools — happy path + error paths, fully mocked."""

import httpx
import pytest
import respx

from threatintel_mcp import server

from ._helpers import tool_error

US_BASE = "https://urlscan.io/api/v1"


@respx.mock
@pytest.mark.asyncio
async def test_scan_url_defaults_to_unlisted():
    route = respx.post(f"{US_BASE}/scan/").mock(
        return_value=httpx.Response(
            200,
            json={
                "uuid": "1111-2222",
                "url": "http://phish.test/login",
                "api": "https://urlscan.io/api/v1/result/1111-2222/",
                "result": "https://urlscan.io/result/1111-2222/",
                "visibility": "unlisted",
                "message": "Submission successful",
            },
        )
    )
    result = await server.scan_url("http://phish.test/login")

    # The request we sent must carry visibility=unlisted (OPSEC default).
    sent = route.calls.last.request
    import json

    assert json.loads(sent.content)["visibility"] == "unlisted"

    assert result["uuid"] == "1111-2222"
    assert result["visibility"] == "unlisted"
    # Output defanged.
    assert result["scan_url"] == "hxxp://phish[.]test/login"


@respx.mock
@pytest.mark.asyncio
async def test_scan_url_rejects_bad_visibility():
    result = await tool_error(server.scan_url("http://x.test", visibility="semi-public"))
    assert result["error"] == "bad_request"


@respx.mock
@pytest.mark.asyncio
async def test_get_url_result_pending_when_404():
    respx.get(f"{US_BASE}/result/abc/").mock(return_value=httpx.Response(404))
    result = await tool_error(server.get_url_result("abc"))
    assert result["error"] == "pending"


@respx.mock
@pytest.mark.asyncio
async def test_get_url_result_happy_path():
    respx.get(f"{US_BASE}/result/abc/").mock(
        return_value=httpx.Response(
            200,
            json={
                "task": {
                    "uuid": "abc",
                    "url": "http://phish.test/login",
                    "screenshotURL": "https://urlscan.io/screenshots/abc.png",
                },
                "page": {
                    "url": "http://phish.test/login",
                    "domain": "phish.test",
                    "ip": "203.0.113.9",
                    "asn": "AS64500",
                    "asnname": "EVIL-HOST",
                    "country": "RU",
                    "server": "nginx",
                    "title": "Sign in",
                },
                "verdicts": {"overall": {"malicious": True, "score": 80, "categories": ["phishing"], "brands": [{"name": "Microsoft"}]}},
                "lists": {"domains": ["phish.test", "cdn.evil.test"], "ips": ["203.0.113.9"]},
                "stats": {"uniqCountries": 2},
            },
        )
    )
    result = await server.get_url_result("abc")
    assert result["malicious"] is True
    assert result["brands"] == ["Microsoft"]
    # Contacted infra is present and defanged.
    assert "phish[.]test" in result["contacted_domains"]
    assert result["page_ip"] == "203[.]0[.]113[.]9"


@respx.mock
@pytest.mark.asyncio
async def test_search_urlscan_happy_path():
    respx.get(f"{US_BASE}/search/").mock(
        return_value=httpx.Response(
            200,
            json={
                "total": 1,
                "has_more": False,
                "results": [
                    {
                        "_id": "res-1",
                        "task": {"url": "http://phish.test/", "time": "2026-01-01T00:00:00Z"},
                        "page": {
                            "url": "http://phish.test/",
                            "domain": "phish.test",
                            "ip": "203.0.113.9",
                            "asnname": "EVIL-HOST",
                            "country": "RU",
                        },
                        "result": "https://urlscan.io/result/res-1/",
                    }
                ],
            },
        )
    )
    result = await server.search_urlscan("domain:phish.test")
    assert result["total"] == 1
    assert result["returned"] == 1
    assert result["results"][0]["domain"] == "phish[.]test"
