"""Structured error shaping.

Tools never raise raw exceptions out to the model. Instead every failure is
converted into a small, predictable dict so the calling agent can reason about
*why* a lookup failed (auth vs. rate-limit vs. not-found vs. network) and decide
whether to retry, back off, or ask the user for a key.
"""

from __future__ import annotations

from typing import Any

import httpx


class RateLimitError(Exception):
    """Raised locally by the throttle before we ever hit the network."""

    def __init__(self, api: str, retry_after: float):
        self.api = api
        self.retry_after = retry_after
        super().__init__(
            f"{api} local rate limit reached; retry in ~{retry_after:.1f}s"
        )


def error(kind: str, message: str, **extra: Any) -> dict[str, Any]:
    """Build a consistent error envelope."""
    payload: dict[str, Any] = {"error": kind, "message": message}
    payload.update(extra)
    return payload


def from_http_status(api: str, resp: httpx.Response) -> dict[str, Any]:
    """Map an HTTP error response to a clean, categorized error dict."""
    status = resp.status_code
    if status in (401, 403):
        return error(
            "auth_error",
            f"{api} rejected the request (HTTP {status}). Check the API key.",
            api=api,
            status=status,
        )
    if status == 404:
        return error(
            "not_found",
            f"{api} has no record for that indicator (HTTP 404).",
            api=api,
            status=status,
        )
    if status == 429:
        # Upstream throttle — surface any Retry-After the server gave us.
        retry_after = resp.headers.get("Retry-After")
        return error(
            "rate_limited",
            f"{api} rate limit hit (HTTP 429).",
            api=api,
            status=status,
            retry_after=retry_after,
        )
    return error(
        "api_error",
        f"{api} returned HTTP {status}.",
        api=api,
        status=status,
    )
