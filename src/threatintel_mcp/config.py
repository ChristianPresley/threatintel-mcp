"""Runtime configuration loaded from the environment.

API keys are read from environment variables only — never hardcoded, never
committed. See ``.env.example``. We do a best-effort load of a local ``.env``
file if one exists, but the environment always wins.
"""

from __future__ import annotations

import os
from pathlib import Path

# Public-tier defaults. Overridable via env for paid tiers.
VT_RATE_MAX_CALLS = int(os.getenv("VT_RATE_MAX_CALLS", "4"))
VT_RATE_PERIOD_SECONDS = float(os.getenv("VT_RATE_PERIOD_SECONDS", "60"))
VT_DAILY_CAP = int(os.getenv("VT_DAILY_CAP", "500"))

URLSCAN_RATE_MAX_CALLS = int(os.getenv("URLSCAN_RATE_MAX_CALLS", "60"))
URLSCAN_RATE_PERIOD_SECONDS = float(os.getenv("URLSCAN_RATE_PERIOD_SECONDS", "60"))

HTTP_TIMEOUT_SECONDS = float(os.getenv("THREATINTEL_HTTP_TIMEOUT", "30"))


def _load_dotenv() -> None:
    """Minimal .env loader (no dependency on python-dotenv).

    Only sets variables that are not already present in the environment.
    """
    env_path = Path.cwd() / ".env"
    if not env_path.is_file():
        return
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv()


def vt_api_key() -> str | None:
    return os.getenv("VT_API_KEY") or None


def urlscan_api_key() -> str | None:
    return os.getenv("URLSCAN_API_KEY") or None
