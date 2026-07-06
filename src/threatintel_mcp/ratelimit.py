"""Per-API client-side rate limiting.

The VirusTotal public tier allows 4 requests/minute and 500/day. urlscan has its
own (looser) budget. Rather than let the remote API 429 us — which wastes a
round-trip and, on some tiers, counts against quota — we throttle locally with a
sliding-window token bucket per API.

This is intentionally a *self-imposed* guard: it keeps a well-behaved server
from ever tripping the upstream limit under normal single-analyst use.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque

from .errors import RateLimitError


class SlidingWindowLimiter:
    """Allow at most ``max_calls`` within any ``period`` seconds.

    Also enforces an optional hard daily cap. Async-safe via an internal lock so
    concurrent tool calls can't race past the limit.
    """

    def __init__(
        self,
        api: str,
        max_calls: int,
        period: float,
        daily_cap: int | None = None,
    ):
        self.api = api
        self.max_calls = max_calls
        self.period = period
        self.daily_cap = daily_cap
        self._calls: deque[float] = deque()
        self._day_start = time.monotonic()
        self._day_count = 0
        self._lock = asyncio.Lock()

    def _prune(self, now: float) -> None:
        window_start = now - self.period
        while self._calls and self._calls[0] < window_start:
            self._calls.popleft()
        # Roll the daily counter over every 24h.
        if now - self._day_start >= 86_400:
            self._day_start = now
            self._day_count = 0

    async def acquire(self, *, block: bool = True) -> None:
        """Reserve one slot.

        With ``block=True`` (default) this sleeps until a slot frees up. With
        ``block=False`` it raises :class:`RateLimitError` immediately if none is
        available — useful for tests and for fail-fast callers.
        """
        async with self._lock:
            now = time.monotonic()
            self._prune(now)

            if self.daily_cap is not None and self._day_count >= self.daily_cap:
                # Daily budget is exhausted; blocking wouldn't help within a
                # reasonable horizon, so we always fail fast here.
                raise RateLimitError(self.api, retry_after=86_400 - (now - self._day_start))

            if len(self._calls) >= self.max_calls:
                retry_after = self.period - (now - self._calls[0])
                if not block:
                    raise RateLimitError(self.api, retry_after=max(retry_after, 0.0))
                await asyncio.sleep(max(retry_after, 0.0))
                now = time.monotonic()
                self._prune(now)

            self._calls.append(now)
            self._day_count += 1
