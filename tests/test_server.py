"""Protocol-level tests: drive the server through a real MCP client in-process.

These catch SDK/protocol regressions the per-tool tests can't — e.g. the server
failing to import against a new SDK, or tool failures not being flagged with
``isError``.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from mcp import Client

from threatintel_mcp import __version__, server

VT_BASE = "https://www.virustotal.com/api/v3"

_TOOLS = [
    "scan_url",
    "get_url_result",
    "search_urlscan",
    "lookup_hash",
    "lookup_domain",
    "lookup_ip",
]


@pytest.mark.asyncio
async def test_negotiates_latest_protocol_and_identifies_itself():
    async with Client(server.mcp) as client:
        assert client.protocol_version == "2026-07-28"
        assert client.server_info.name == "threatintel-mcp"
        assert client.server_info.version == __version__


@pytest.mark.asyncio
async def test_tools_list_is_deterministic_and_annotated():
    async with Client(server.mcp) as client:
        result = await client.list_tools()
    assert [t.name for t in result.tools] == _TOOLS
    assert result.ttl_ms and result.ttl_ms > 0
    by_name = {t.name: t for t in result.tools}
    for name, tool in by_name.items():
        assert tool.title, name
        assert tool.annotations is not None, name
        assert tool.annotations.open_world_hint is True
    # Only scan_url has a side effect (it submits a new scan).
    assert by_name["scan_url"].annotations.read_only_hint is False
    for name in _TOOLS[1:]:
        assert by_name[name].annotations.read_only_hint is True
    visibility = by_name["scan_url"].input_schema["properties"]["visibility"]
    assert visibility["enum"] == ["unlisted", "private", "public"]


@respx.mock
@pytest.mark.asyncio
async def test_failed_lookup_is_flagged_is_error():
    respx.get(f"{VT_BASE}/files/deadbeef").mock(return_value=httpx.Response(404))
    async with Client(server.mcp) as client:
        result = await client.call_tool("lookup_hash", {"file_hash": "deadbeef"})
    assert result.is_error is True
    # The SDK prefixes the ToolError message with "Error executing tool <name>: ".
    text = result.content[0].text
    envelope = json.loads(text[text.index("{") :])
    assert envelope["error"] == "not_found"


@respx.mock
@pytest.mark.asyncio
async def test_successful_lookup_returns_structured_content():
    respx.get(f"{VT_BASE}/ip_addresses/1.2.3.4").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "id": "1.2.3.4",
                    "attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 70}},
                }
            },
        )
    )
    async with Client(server.mcp) as client:
        result = await client.call_tool("lookup_ip", {"ip": "1.2.3.4"})
    assert result.is_error is False
    assert result.structured_content["ip"] == "1[.]2[.]3[.]4"


def test_http_security_defaults_to_sdk_loopback_protection():
    assert server.http_security("127.0.0.1", [], []) is None


def test_http_security_allows_named_host_on_wide_bind():
    settings = server.http_security("0.0.0.0", ["ti.corp.example:*"], ["https://ti.corp.example"])
    assert settings.enable_dns_rebinding_protection is True
    assert "ti.corp.example:*" in settings.allowed_hosts
    assert "localhost:*" in settings.allowed_hosts
    assert "0.0.0.0:*" not in settings.allowed_hosts
    assert "https://ti.corp.example" in settings.allowed_origins
