"""Agent-driven MCP test: open Terminal, run `ls ~`, capture the result.

Simulates an AI agent (Hermes) using the MCP tools:
  launch_app -> type_text -> key_press -> screenshot
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import pathlib
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HOME = pathlib.Path.home()
TOKEN = json.loads((HOME / ".hermes_mac_agent/config.json").read_text())["token"]
OUT = pathlib.Path("/tmp/hermes_mac_test")
OUT.mkdir(parents=True, exist_ok=True)

ENV = {
    **os.environ,
    "HERMES_MAC_HOST": "127.0.0.1",
    "HERMES_MAC_PORT": "8765",
    "HERMES_MAC_TOKEN": TOKEN,
    "HERMES_MAC_CA_CERT": str(HOME / ".hermes_mac_agent/ca.pem"),
}


async def call(session: ClientSession, name: str, args: dict | None = None):
    res = await session.call_tool(name, args or {})
    text = "".join(c.text for c in res.content if getattr(c, "text", None))
    is_error = getattr(res, "is_error", None)
    if is_error is None:
        is_error = getattr(res, "isError", False)
    return (not is_error), text


async def main() -> int:
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "hermes_mac_agent.mcp_adapter"],
        env=ENV,
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # 1. Launch Terminal
            ok, text = await call(session, "launch_app", {"app": "Terminal"})
            print(f"launch_app(Terminal): ok={ok} {text[:100]}")
            if not ok:
                return 1
            await asyncio.sleep(3)  # let the window open

            # 2. Type the command and press Enter
            ok, text = await call(session, "type_text", {"text": "ls ~"})
            print(f"type_text('ls ~'): ok={ok} {text[:100]}")
            await asyncio.sleep(0.5)
            ok, text = await call(session, "key_press", {"keys": ["return"]})
            print(f"key_press(return): ok={ok} {text[:100]}")
            await asyncio.sleep(2)  # let the output render

            # 3. Capture the screen
            ok, text = await call(session, "screenshot", {"monitor": 1})
            print(f"screenshot: ok={ok} {len(text)} chars")
            if not ok:
                return 1
            png = base64.b64decode(text)
            (OUT / "ls_home.png").write_bytes(png)
            print(f"saved: {OUT / 'ls_home.png'} ({len(png)} bytes)")
            return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
