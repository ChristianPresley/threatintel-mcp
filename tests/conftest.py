"""Shared test fixtures.

Note: no test ever makes a real network call. Every HTTP interaction is mocked
with ``respx``. We also fake the API keys and reset the module-level rate
limiters between tests so throttle state doesn't leak across cases.
"""

from __future__ import annotations

import os

import pytest

# Set fake keys before any module reads them.
os.environ.setdefault("VT_API_KEY", "test-vt-key")
os.environ.setdefault("URLSCAN_API_KEY", "test-urlscan-key")

from threatintel_mcp import urlscan, virustotal  # noqa: E402
from threatintel_mcp.ratelimit import SlidingWindowLimiter  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh_limiters():
    """Give each test generous, empty limiters so throttling never interferes."""
    virustotal._limiter = SlidingWindowLimiter("VirusTotal", 1000, 60, daily_cap=100000)
    urlscan._limiter = SlidingWindowLimiter("urlscan.io", 1000, 60)
    yield
