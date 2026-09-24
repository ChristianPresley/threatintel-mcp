"""Test helpers shared across modules."""

from __future__ import annotations

import json

import pytest
from mcp.server.mcpserver.exceptions import ToolError


async def tool_error(call) -> dict:
    """Await a tool call that must fail; return its decoded error envelope.

    Tools raise ``ToolError`` (surfaced to clients as ``isError: true``) whose
    message is the JSON error envelope from ``errors.py``.
    """
    with pytest.raises(ToolError) as excinfo:
        await call
    return json.loads(str(excinfo.value))
