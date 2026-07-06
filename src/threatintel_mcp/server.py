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
* Each tool's docstring is written as a "when to call me" prompt — FastMCP turns
  the type hints + docstring into the tool's JSON Schema and description that the
  model sees, so these read like guidance to an investigating agent.

Transports
----------
Selectable at launch:  ``--transport stdio`` (default, one local analyst) or
``--transport http`` (Streamable HTTP, for a shared team deployment). See README.
"""

from __future__ import annotations

import argparse
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from . import config, urlscan, virustotal
from .errors import RateLimitError, error
from .sanitize import defang_deep

mcp = FastMCP(
    name="threatintel-mcp",
    instructions=(
        "Threat-intelligence lookup tools for pivoting on indicators during an "
        "investigation (urlscan.io + VirusTotal). All indicators in tool output "
        "are DEFANGED (hxxp, [.]) because they may be attacker-controlled; refang "
        "them before use. Prefer 'unlisted' urlscan visibility to avoid tipping "
        "off targets. Respect rate limits — space out VirusTotal calls."
    ),
)


def _require_key(key: str | None, env_var: str) -> dict[str, Any] | None:
    if not key:
        return error(
            "config_error",
            f"Missing {env_var}. Set it in the environment or a .env file.",
            env_var=env_var,
        )
    return None


def _guard(coro_result: dict[str, Any]) -> dict[str, Any]:
    """Defang every summary on the way out. Central choke point."""
    return defang_deep(coro_result)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# urlscan.io tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def scan_url(
    url: Annotated[str, Field(description="The URL to submit for scanning.")],
    visibility: Annotated[
        str,
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
    cfg_err = _require_key(config.urlscan_api_key(), "URLSCAN_API_KEY")
    if cfg_err:
        return cfg_err
    if visibility not in {"unlisted", "private", "public"}:
        return error("bad_request", "visibility must be unlisted, private, or public.")
    try:
        return _guard(
            await urlscan.submit_scan(url, config.urlscan_api_key(), visibility=visibility)
        )
    except RateLimitError as exc:
        return error("rate_limited", str(exc), api=exc.api, retry_after=exc.retry_after)
    except Exception as exc:  # network/timeout/parse — never leak a raw traceback
        return error("network_error", f"urlscan.io request failed: {exc}")


@mcp.tool()
async def get_url_result(
    uuid: Annotated[str, Field(description="The scan uuid returned by scan_url.")],
) -> dict[str, Any]:
    """Fetch the results of a urlscan.io scan by its uuid.

    Call this after ``scan_url`` to retrieve the verdict and the contacted
    infrastructure (domains, IPs, ASN, hosting country, page title, TLS issuer).
    Scans take roughly 10-30 seconds; if this returns an ``error`` of kind
    'pending', wait a few seconds and call again.
    """
    try:
        return _guard(await urlscan.get_result(uuid, config.urlscan_api_key()))
    except RateLimitError as exc:
        return error("rate_limited", str(exc), api=exc.api, retry_after=exc.retry_after)
    except Exception as exc:
        return error("network_error", f"urlscan.io request failed: {exc}")


@mcp.tool()
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
    try:
        return _guard(await urlscan.search(query, config.urlscan_api_key(), size=size))
    except RateLimitError as exc:
        return error("rate_limited", str(exc), api=exc.api, retry_after=exc.retry_after)
    except Exception as exc:
        return error("network_error", f"urlscan.io request failed: {exc}")


# ---------------------------------------------------------------------------
# VirusTotal tools
# ---------------------------------------------------------------------------


@mcp.tool()
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
    cfg_err = _require_key(config.vt_api_key(), "VT_API_KEY")
    if cfg_err:
        return cfg_err
    try:
        return _guard(await virustotal.get_file(file_hash, config.vt_api_key()))
    except RateLimitError as exc:
        return error("rate_limited", str(exc), api=exc.api, retry_after=exc.retry_after)
    except Exception as exc:
        return error("network_error", f"VirusTotal request failed: {exc}")


@mcp.tool()
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
    cfg_err = _require_key(config.vt_api_key(), "VT_API_KEY")
    if cfg_err:
        return cfg_err
    try:
        return _guard(await virustotal.get_domain(domain, config.vt_api_key()))
    except RateLimitError as exc:
        return error("rate_limited", str(exc), api=exc.api, retry_after=exc.retry_after)
    except Exception as exc:
        return error("network_error", f"VirusTotal request failed: {exc}")


@mcp.tool()
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
    cfg_err = _require_key(config.vt_api_key(), "VT_API_KEY")
    if cfg_err:
        return cfg_err
    try:
        return _guard(await virustotal.get_ip(ip, config.vt_api_key()))
    except RateLimitError as exc:
        return error("rate_limited", str(exc), api=exc.api, retry_after=exc.retry_after)
    except Exception as exc:
        return error("network_error", f"VirusTotal request failed: {exc}")


# ---------------------------------------------------------------------------
# Entry point / transport selection
# ---------------------------------------------------------------------------


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
    args = parser.parse_args()

    if args.transport == "http":
        # Streamable HTTP transport — one server, many networked clients.
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        mcp.run(transport="streamable-http")
    else:
        # stdio — the client (e.g. Claude Desktop) spawns us as a subprocess.
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
