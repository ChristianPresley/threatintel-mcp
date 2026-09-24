"""Tests for the VirusTotal tools — happy path + error paths, fully mocked."""

import httpx
import pytest
import respx

from threatintel_mcp import server

from ._helpers import tool_error

VT_BASE = "https://www.virustotal.com/api/v3"

_FILE_RESPONSE = {
    "data": {
        "id": "a" * 64,
        "type": "file",
        "attributes": {
            "sha256": "a" * 64,
            "md5": "b" * 32,
            "size": 12345,
            "type_description": "Win32 EXE",
            "meaningful_name": "invoice.exe",
            "reputation": -50,
            "times_submitted": 42,
            "first_submission_date": 1_600_000_000,
            "last_analysis_date": 1_700_000_000,
            "last_analysis_stats": {
                "malicious": 55,
                "suspicious": 2,
                "harmless": 10,
                "undetected": 5,
            },
            "popular_threat_classification": {
                "suggested_threat_label": "trojan.emotet/foo"
            },
        },
    }
}


@respx.mock
@pytest.mark.asyncio
async def test_lookup_hash_happy_path():
    respx.get(f"{VT_BASE}/files/{'a' * 64}").mock(
        return_value=httpx.Response(200, json=_FILE_RESPONSE)
    )
    result = await server.lookup_hash("a" * 64)

    assert result["verdict"] == "malicious"
    assert result["detection_ratio"] == "57/72"  # 55 malicious + 2 suspicious of 72
    # Defanged: the dot in the threat label is neutralized on output.
    assert result["threat_label"] == "trojan[.]emotet/foo"
    # Output must be defanged: the meaningful_name domain-like dot is neutralized.
    assert result["meaningful_name"] == "invoice[.]exe"


@respx.mock
@pytest.mark.asyncio
async def test_lookup_hash_not_found():
    respx.get(f"{VT_BASE}/files/deadbeef").mock(return_value=httpx.Response(404))
    result = await tool_error(server.lookup_hash("deadbeef"))
    assert result["error"] == "not_found"
    assert result["status"] == 404


@respx.mock
@pytest.mark.asyncio
async def test_lookup_hash_auth_error():
    respx.get(f"{VT_BASE}/files/xyz").mock(return_value=httpx.Response(401))
    result = await tool_error(server.lookup_hash("xyz"))
    assert result["error"] == "auth_error"


@respx.mock
@pytest.mark.asyncio
async def test_lookup_domain_happy_path():
    domain = "example.com"
    respx.get(f"{VT_BASE}/domains/{domain}").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "id": domain,
                    "attributes": {
                        "registrar": "NameCheap",
                        "creation_date": 1_650_000_000,
                        "reputation": 0,
                        "categories": {"engineX": "phishing"},
                        "last_analysis_stats": {
                            "malicious": 3,
                            "suspicious": 0,
                            "harmless": 60,
                            "undetected": 5,
                        },
                    },
                }
            },
        )
    )
    result = await server.lookup_domain(domain)
    assert result["verdict"] == "malicious"
    assert result["detection_ratio"] == "3/68"
    assert result["registrar"] == "NameCheap"
    # Defanged domain in output.
    assert result["domain"] == "example[.]com"


@respx.mock
@pytest.mark.asyncio
async def test_lookup_ip_rate_limited_upstream():
    respx.get(f"{VT_BASE}/ip_addresses/1.2.3.4").mock(
        return_value=httpx.Response(429, headers={"Retry-After": "30"})
    )
    result = await tool_error(server.lookup_ip("1.2.3.4"))
    assert result["error"] == "rate_limited"
    assert result["retry_after"] == "30"
