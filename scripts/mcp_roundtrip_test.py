"""End-to-end MCP round-trip test.

Drives the REAL MCP server (hermes_mac_agent.mcp_adapter) over the stdio
transport — the same path an MCP client (Hermes) uses — and prints the raw
tool results. This proves the system works via MCP, independent of what any
particular command outputs.

Tools exercised:
  1. health        -> daemon reachable over TLS + TCC permission status
  2. run_command   -> clean text round-trip (exit code + stdout + stderr)
  3. list_processes-> another text tool, filtered
  4. launch_app    -> GUI control (launches Terminal)
  5. type_text     -> GUI input
  6. key_press     -> GUI input
  7. screenshot    -> screen capture (PNG bytes back over MCP)

run_command is gated behind HERMES_MAC_ALLOW_RUN_COMMAND=1, so we set it in
the MCP server's environment for this test.
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
    "HERMES_MAC_ALLOW_RUN_COMMAND": "1",
}

PASS = 0
FAIL = 0


def report(name: str, ok: bool, detail: str) -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {name}")
    for line in detail.strip().splitlines():
        print(f"        {line}")


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
            print("MCP session initialized over stdio.\n")

            # 1. health ---------------------------------------------------
            ok, text = await call(session, "health")
            report("health (daemon reachable over TLS + TCC)", ok, text)

            # 2. run_command ---------------------------------------------
            ok, text = await call(
                session, "run_command", {"cmd": "echo mcp-roundtrip-ok && pwd"}
            )
            report("run_command (clean text round-trip)", ok, text)

            # 3. list_processes ------------------------------------------
            ok, text = await call(session, "list_processes", {"filter": "HermesMac"})
            report("list_processes (filter=HermesMac)", ok, text)

            # 4. launch_app ----------------------------------------------
            ok, text = await call(session, "launch_app", {"app": "Terminal"})
            report("launch_app (Terminal)", ok, text)
            await asyncio.sleep(3)

            # 5. type_text -----------------------------------------------
            ok, text = await call(session, "type_text", {"text": "echo typed-via-mcp"})
            report("type_text", ok, text)
            await asyncio.sleep(0.5)

            # 6. key_press -----------------------------------------------
            ok, text = await call(session, "key_press", {"keys": ["return"]})
            report("key_press (return)", ok, text)
            await asyncio.sleep(1.5)

            # 7. screenshot ----------------------------------------------
            ok, text = await call(session, "screenshot", {"monitor": 1})
            png = base64.b64decode(text) if ok else b""
            shot = OUT / "mcp_roundtrip.png"
            if ok:
                shot.write_bytes(png)
            report(
                "screenshot (PNG bytes returned over MCP)",
                ok and len(png) > 1000,
                f"{len(png)} bytes -> {shot}",
            )

    print(f"\n=== RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
