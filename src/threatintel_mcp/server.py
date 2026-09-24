"""FastMCP server exposing threat-intelligence lookups as MCP tools.

Design overview
---------------
* Six tools spanning two providers (urlscan.io + VirusTotal v3), grouped around
  three urlscan primitives (submit / poll / search) and three VT lookups
  (hash / domain / ip).
* Every tool returns a COMPACT, structured summary (see ``virustotal.py`` and
  ``urlscan.py``) rather than raw API JSON — this keeps the model's context lean
  and the signal high.
* Every tool's output is passed through :func:`sanitize.defang_deep` before it
  leaves the process, because tool output is an untrusted-content / prompt-
  injection surface (see ``sanitize.py``).
* Failures are raised as :class:`ToolError` so the client receives a result with
  ``isError: true``; the message is the same structured error envelope as JSON
  (see ``errors.py``), so the agent can still tell *why* a lookup failed.
* Each tool's docstring is written as a "when to call me" prompt — MCPServer turns
  the type hints + docstring into the tool's JSON Schema and description that the
  model sees, so these read like guidance to an investigating agent.

Transports
----------
Selectable at launch:  ``--transport stdio`` (default, one local analyst) or
``--transport http`` (Streamable HTTP, for a shared team deployment). See README.

Protocol
--------
Built on the MCP Python SDK 2.x, which implements the 2026-07-28 specification
(stateless core, ``server/discover``, ``resultType``, cacheable list results)
and still negotiates earlier revisions with older clients.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Awaitable
from typing import Annotated, Any, Literal

from mcp.server.caching import CacheHint
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from pydantic import Field

from . import __version__, config, urlscan, virustotal
from .errors import RateLimitError, error
from .sanitize import defang_deep

# The tool list is fixed at import time and identical for every caller, so
# clients (and shared intermediaries) may cache it.
_STATIC_LIST_HINT = CacheHint(ttl_ms=3_600_000, scope="public")

mcp = MCPServer(
    name="threatintel-mcp",
    title="Threat Intel Lookups",
    version=__version__,
    instructions=(
        "Threat-intelligence lookup tools for pivoting on indicators during an "
        "investigation (urlscan.io + VirusTotal). All indicators in tool output "
        "are DEFANGED (hxxp, [.]) because they may be attacker-controlled; refang "
        "them before use. Prefer 'unlisted' urlscan visibility to avoid tipping "
        "off targets. Respect rate limits — space out VirusTotal calls."
    ),
    cache_hints={"tools/list": _STATIC_LIST_HINT},
)

# Passive lookups: they only read from the provider's database.
_LOOKUP = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=True,
)


def _fail(payload: dict[str, Any]) -> ToolError:
    """Wrap an error envelope in a ToolError so the result carries ``isError``."""
    return ToolError(json.dumps(defang_deep(payload), indent=2))


def _require_key(key: str | None, env_var: str) -> None:
    if not key:
        raise _fail(
            error(
                "config_error",
                f"Missing {env_var}. Set it in the environment or a .env file.",
                env_var=env_var,
            )
        )


async def _run(api: str, call: Awaitable[dict[str, Any]]) -> dict[str, Any]:
    """Await a provider call, defang its output, and raise on any failure.

    Central choke point: every summary is defanged on the way out, and every
    error envelope (HTTP error, local throttle, network failure) becomes a
    ToolError instead of a normal-looking result.
    """
    try:
        result = await call
    except RateLimitError as exc:
        raise _fail(
            error("rate_limited", str(exc), api=exc.api, retry_after=exc.retry_after)
        ) from exc
    except Exception as exc:  # network/timeout/parse — never leak a raw traceback
        raise _fail(error("network_error", f"{api} request failed: {exc}")) from exc
    if "error" in result:
        raise _fail(result)
    return defang_deep(result)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# urlscan.io tools
# ---------------------------------------------------------------------------


@mcp.tool(
    title="Submit URL to urlscan.io",
    annotations=ToolAnnotations(
        # Submits a new scan (a side effect on urlscan, and urlscan fetches the
        # target), so it is neither read-only nor idempotent.
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=False,
        open_world_hint=True,
    ),
)
async def scan_url(
    url: Annotated[str, Field(description="The URL to submit for scanning.")],
    visibility: Annotated[
        Literal["unlisted", "private", "public"],
        Field(
            description="Scan visibility: 'unlisted' (default), 'private', or 'public'.",
        ),
    ] = "unlisted",
) -> dict[str, Any]:
    """Submit a URL to urlscan.io for a fresh sandbox scan.

    Call this when you have a *suspicious or unknown URL* and want live analysis:
    what it loads, where it redirects, what infrastructure it contacts, and
    whether urlscan flags it as malicious. Returns a scan ``uuid`` — then poll
    ``get_url_result`` with that uuid to fetch findings.

    OPSEC — visibility defaults to 'unlisted' on purpose. A **public** scan is
    indexed and browsable by anyone, including the adversary, who may be watching
    urlscan for scans of their own infrastructure. Scanning their URL publicly
    tips them off that they are under investigation and can burn the operation.
    Use 'public' only when you deliberately want the result shared; use 'private'
    for the most sensitive cases.
    """
    _require_key(config.urlscan_api_key(), "URLSCAN_API_KEY")
    if visibility not in {"unlisted", "private", "public"}:
        raise _fail(error("bad_request", "visibility must be unlisted, private, or public."))
    return await _run(
        "urlscan.io",
        urlscan.submit_scan(url, config.urlscan_api_key(), visibility=visibility),
    )


@mcp.tool(title="Get urlscan.io result", annotations=_LOOKUP)
async def get_url_result(
    uuid: Annotated[str, Field(description="The scan uuid returned by scan_url.")],
) -> dict[str, Any]:
    """Fetch the results of a urlscan.io scan by its uuid.

    Call this after ``scan_url`` to retrieve the verdict and the contacted
    infrastructure (domains, IPs, ASN, hosting country, page title, TLS issuer).
    Scans take roughly 10-30 seconds; if this fails with an ``error`` of kind
    'pending', wait a few seconds and call again.
    """
    return await _run("urlscan.io", urlscan.get_result(uuid, config.urlscan_api_key()))


@mcp.tool(title="Search urlscan.io history", annotations=_LOOKUP)
async def search_urlscan(
    query: Annotated[
        str,
        Field(
            description=(
                "urlscan Elasticsearch query, e.g. "
                "'domain:example.com', 'page.ip:1.2.3.4', "
                "'hash:<sha256>', 'filename:invoice.exe'."
            )
        ),
    ],
    size: Annotated[int, Field(description="Max results to return (1-100).", ge=1, le=100)] = 10,
) -> dict[str, Any]:
    """Search urlscan.io's historical scan database (Elasticsearch query syntax).

    Call this to find *existing* scans instead of running a new one — e.g. to see
    every scan that touched a domain/IP, hunt for a favicon or TLS-cert hash
    across sites, or discover other pages hosted on the same infrastructure. This
    is passive: it does not touch the target, so it's safe to use freely during
    an investigation. Returns a short list of matching scans with their domains,
    IPs, ASN and result links to pivot from.
    """
    return await _run("urlscan.io", urlscan.search(query, config.urlscan_api_key(), size=size))


# ---------------------------------------------------------------------------
# VirusTotal tools
# ---------------------------------------------------------------------------


@mcp.tool(title="VirusTotal file hash lookup", annotations=_LOOKUP)
async def lookup_hash(
    file_hash: Annotated[
        str,
        Field(description="A file hash: MD5, SHA-1, or SHA-256."),
    ],
) -> dict[str, Any]:
    """Look up a file hash on VirusTotal.

    Call this when you have a *file hash* (from a sample, an email attachment, an
    EDR alert, a sandbox report) and want to know whether it's known-malicious:
    the multi-engine detection ratio, the suggested threat label/family, file
    type and size, and first/last-seen dates. Accepts MD5, SHA-1 or SHA-256.
    Returns a compact summary, not the full per-engine report.
    """
    _require_key(config.vt_api_key(), "VT_API_KEY")
    return await _run("VirusTotal", virustotal.get_file(file_hash, config.vt_api_key()))


@mcp.tool(title="VirusTotal domain lookup", annotations=_LOOKUP)
async def lookup_domain(
    domain: Annotated[str, Field(description="A domain name, e.g. example.com.")],
) -> dict[str, Any]:
    """Look up a domain on VirusTotal.

    Call this to assess a *domain* indicator: its detection ratio across
    URL/domain engines, reputation score, registrar and creation date (a recent
    creation date is a strong newly-registered-domain signal), and category
    tags. Useful when pivoting from a URL or email sender to the domain behind
    it. Returns a compact summary.
    """
    _require_key(config.vt_api_key(), "VT_API_KEY")
    return await _run("VirusTotal", virustotal.get_domain(domain, config.vt_api_key()))


@mcp.tool(title="VirusTotal IP lookup", annotations=_LOOKUP)
async def lookup_ip(
    ip: Annotated[str, Field(description="An IPv4 or IPv6 address.")],
) -> dict[str, Any]:
    """Look up an IP address on VirusTotal.

    Call this to get hosting context and reputation for an *IP indicator*: the
    detection ratio, reputation score, ASN, owning organization, network range
    and country. Useful when pivoting from a domain's resolved IP or a
    urlscan-reported ``page_ip`` to understand who hosts the infrastructure.
    Returns a compact summary.
    """
    _require_key(config.vt_api_key(), "VT_API_KEY")
    return await _run("VirusTotal", virustotal.get_ip(ip, config.vt_api_key()))


# ---------------------------------------------------------------------------
# Entry point / transport selection
# ---------------------------------------------------------------------------

_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


def http_security(
    host: str, allowed_hosts: list[str], allowed_origins: list[str]
) -> TransportSecuritySettings | None:
    """Host/Origin validation for the Streamable HTTP transport.

    The spec requires servers to validate ``Origin`` (DNS-rebinding defence).
    The SDK only turns that on by itself for a loopback bind, so for any other
    bind we build the settings explicitly: loopback names stay allowed, plus the
    hostnames/origins the operator lists (e.g. ``ti.corp.example:8000``).
    """
    if host in _LOOPBACK_HOSTS and not allowed_hosts and not allowed_origins:
        return None  # SDK default: loopback-only protection.
    hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
    if host not in ("0.0.0.0", "::", *_LOOPBACK_HOSTS):
        hosts.append(f"{host}:*")
    origins = ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=hosts + allowed_hosts,
        allowed_origins=origins + allowed_origins,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="threatintel-mcp server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="stdio (default, local single-analyst) or http (Streamable HTTP, shared team).",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host for HTTP transport.")
    parser.add_argument("--port", type=int, default=8000, help="Port for HTTP transport.")
    parser.add_argument(
        "--allowed-host",
        action="append",
        default=[],
        metavar="HOST[:PORT]",
        help=(
            "Host header clients may use to reach the HTTP server, e.g. "
            "'ti.corp.example:*'. Repeatable. Loopback names are always allowed."
        ),
    )
    parser.add_argument(
        "--allowed-origin",
        action="append",
        default=[],
        metavar="ORIGIN",
        help="Browser Origin allowed to call the HTTP server, e.g. 'https://ti.corp.example'. Repeatable.",
    )
    args = parser.parse_args()

    if args.transport == "http":
        # Streamable HTTP transport — one server, many networked clients.
        if args.host not in _LOOPBACK_HOSTS:
            print(
                "threatintel-mcp: WARNING: the HTTP transport has no built-in "
                "authentication. Put it behind an authenticating reverse proxy "
                "before exposing it beyond this machine.",
                file=sys.stderr,
            )
        mcp.run(
            transport="streamable-http",
            host=args.host,
            port=args.port,
            transport_security=http_security(args.host, args.allowed_host, args.allowed_origin),
        )
    else:
        # stdio — the client (e.g. Claude Desktop) spawns us as a subprocess.
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
