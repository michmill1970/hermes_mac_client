"""Live end-to-end test: drive the real daemon (owned by the menubar app)
through the real MCP stdio server, simulating an AI agent (Hermes).

Requires: menubar app running on 127.0.0.1:8765 with a test allowlist.
"""
from __future__ import annotations

import ast
import asyncio
import base64
import json
import os
import pathlib
import subprocess
import sys
import time

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HOME = pathlib.Path.home()
TOKEN = json.loads((HOME / ".hermes_mac_agent/config.json").read_text())["token"]
OUT = pathlib.Path("/tmp/hermes_mac_test")
OUT.mkdir(parents=True, exist_ok=True)

BASE_ENV = {
    **os.environ,
    "HERMES_MAC_HOST": "127.0.0.1",
    "HERMES_MAC_PORT": "8765",
    "HERMES_MAC_TOKEN": TOKEN,
    "HERMES_MAC_CA_CERT": str(HOME / ".hermes_mac_agent/ca.pem"),
}

PASS, FAIL, SKIP = 0, 0, 0
failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  PASS  {name}  {detail}")
    else:
        FAIL += 1
        failures.append(name)
        print(f"  FAIL  {name}  {detail}")


def skip(name: str, detail: str = "") -> None:
    global SKIP
    SKIP += 1
    print(f"  SKIP  {name}  {detail}")


async def call(session: ClientSession, name: str, args: dict | None = None):
    """Call a tool; return (ok, text, error_text)."""
    try:
        res = await session.call_tool(name, args or {})
    except Exception as exc:  # transport-level error
        return False, "", f"exception: {exc!r}"
    text = "".join(c.text for c in res.content if getattr(c, "text", None))
    is_error = getattr(res, "is_error", None)
    if is_error is None:  # mcp 1.x uses camelCase
        is_error = getattr(res, "isError", False)
    if is_error:
        return False, text, text
    return True, text, ""


async def run_suite(env_extra: dict, label: str) -> None:
    env = {**BASE_ENV, **env_extra}
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "hermes_mac_agent.mcp_adapter"],
        env=env,
    )
    print(f"\n=== {label} ===")
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            tools = await session.list_tools()
            names = sorted(t.name for t in tools.tools)
            print(f"  server: {init.server_info.name} v{init.server_info.version}")
            print(f"  tools ({len(names)}): {', '.join(names)}")

            # 1. health -------------------------------------------------
            ok, text, err = await call(session, "health")
            check("health", ok and "ok" in text.lower(), text[:120] or err)
            # The MCP health tool returns str(dict) — a Python repr, not JSON.
            # Try JSON first, then ast.literal_eval for the dict repr.
            health = {}
            for _parse in (json.loads, ast.literal_eval):
                try:
                    health = _parse(text)
                    break
                except Exception:
                    continue
            perms = health.get("perms", {})
            screen_ok = bool(perms.get("screen"))
            a11y_ok = bool(perms.get("accessibility"))
            if not (screen_ok and a11y_ok):
                print(f"  NOTE  TCC state: screen={screen_ok} accessibility={a11y_ok} "
                      f"— GUI-input features will be SKIPped")

            # 2. screenshot ---------------------------------------------
            if not screen_ok:
                skip("screenshot", "Screen Recording not granted to the app")
            else:
                ok, text, err = await call(session, "screenshot", {"monitor": 1})
                if ok:
                    png = base64.b64decode(text)
                    (OUT / "screen.png").write_bytes(png)
                    check("screenshot", png[:8] == b"\x89PNG\r\n\x1a\n" and len(png) > 10_000,
                          f"{len(png)} bytes PNG")
                else:
                    check("screenshot", False, err[:200])

            # 3. mouse_move + click (Apple menu, then Escape) -----------
            if not a11y_ok:
                skip("mouse_move", "Accessibility not granted to the app")
                skip("mouse_click", "Accessibility not granted to the app")
                skip("key_press (single key: escape)", "Accessibility not granted to the app")
            else:
                ok, _, err = await call(session, "mouse_move", {"x": 12, "y": 12})
                check("mouse_move", ok, err[:120])
                ok, _, err = await call(session, "mouse_click", {"button": "left", "clicks": 1})
                check("mouse_click", ok, err[:120])
                await asyncio.sleep(0.5)
                if screen_ok:
                    ok, text, err = await call(session, "screenshot")
                    if ok:
                        (OUT / "screen_apple_menu.png").write_bytes(base64.b64decode(text))
                ok, _, err = await call(session, "key_press", {"keys": ["escape"]})
                check("key_press (single key: escape)", ok, err[:120])

            # 4. mouse_drag + scroll -------------------------------------
            if not a11y_ok:
                skip("mouse_drag", "Accessibility not granted to the app")
                skip("mouse_scroll", "Accessibility not granted to the app")
            else:
                ok, _, err = await call(session, "mouse_drag",
                                        {"x1": 120, "y1": 120, "x2": 200, "y2": 180})
                check("mouse_drag", ok, err[:120])
                ok, _, err = await call(session, "mouse_scroll", {"dx": 0, "dy": -3})
                check("mouse_scroll", ok, err[:120])

            # 5. launch_app Calculator + type_text -----------------------
            ok, text, err = await call(session, "launch_app", {"app": "Calculator"})
            check("launch_app (Calculator)", ok, text[:120] or err[:120])
            await asyncio.sleep(1.5)
            if not a11y_ok:
                skip("type_text (12+34= into Calculator)", "Accessibility not granted to the app")
            else:
                ok, _, err = await call(session, "type_text", {"text": "12+34="})
                check("type_text (12+34= into Calculator)", ok, err[:120])
                await asyncio.sleep(0.5)
                if screen_ok:
                    ok, text, err = await call(session, "screenshot")
                    if ok:
                        (OUT / "screen_calculator.png").write_bytes(base64.b64decode(text))
                        check("screenshot (Calculator result)", True, "saved screen_calculator.png")

            # 6. run_command (gated on) ----------------------------------
            if "HERMES_MAC_ALLOW_RUN_COMMAND" in env:
                ok, text, err = await call(session, "run_command", {"cmd": "echo hello-from-mcp"})
                check("run_command (echo)", ok and "hello-from-mcp" in text, text[:120] or err[:120])
                ok, text, err = await call(session, "run_command", {"cmd": "uname -a"})
                check("run_command (uname -a)", ok and "Darwin" in text, text[:120] or err[:120])
                ok, text, err = await call(session, "run_command", {"cmd": "date +%Y"})
                check("run_command (date +%Y)", ok and "2026" in text, text[:120] or err[:120])
                # policy: denylist must still block sudo
                ok, text, err = await call(session, "run_command", {"cmd": "sudo ls"})
                check("run_command (sudo) BLOCKED by denylist",
                      not ok and ("blocked" in (text + err).lower()), (text + err)[:160])
                # policy: allowlist must block unlisted commands
                ok, text, err = await call(session, "run_command", {"cmd": "curl example.com"})
                check("run_command (curl) BLOCKED by allowlist",
                      not ok and ("blocked" in (text + err).lower()), (text + err)[:160])
            else:
                ok, text, err = await call(session, "run_command", {"cmd": "echo hi"})
                check("run_command GATED (no env var)",
                      not ok and "HERMES_MAC_ALLOW_RUN_COMMAND" in (text + err), (text + err)[:160])

            # 7. list_processes ------------------------------------------
            ok, text, err = await call(session, "list_processes", {"filter": "python"})
            check("list_processes (filter=python)", ok and "python" in text.lower(),
                  text[:120] or err[:120])

            # 8. stop_process --------------------------------------------
            sleeper = subprocess.Popen(["sleep", "300"])
            await asyncio.sleep(0.2)
            ok, text, err = await call(session, "stop_process", {"pid": sleeper.pid})
            await asyncio.sleep(0.3)
            gone = sleeper.poll() is not None
            check("stop_process (sleep pid)", ok and gone,
                  f"pid={sleeper.pid} exit={sleeper.returncode} {err[:80]}")

            # 9. file transfer (gated on) --------------------------------
            if "HERMES_MAC_ALLOW_FILE_TRANSFER" in env:
                payload = "hello from the AI agent\n"
                b64 = base64.b64encode(payload.encode()).decode()
                ok, text, err = await call(session, "write_file",
                                           {"path": "/tmp/hermes_mac_test/hello.txt",
                                            "data_base64": b64})
                check("write_file", ok, text[:120] or err[:120])
                ok, text, err = await call(session, "read_file",
                                           {"path": "/tmp/hermes_mac_test/hello.txt"})
                roundtrip = base64.b64decode(text).decode() if ok else ""
                check("read_file (roundtrip)", ok and roundtrip == payload,
                      repr(roundtrip[:60]) or err[:120])
                # policy: file_denylist/allowlist must block /etc/passwd
                ok, text, err = await call(session, "read_file", {"path": "/etc/passwd"})
                check("read_file (/etc/passwd) BLOCKED",
                      not ok and "blocked" in (text + err).lower(), (text + err)[:160])
            else:
                ok, text, err = await call(session, "read_file", {"path": "/tmp/x"})
                check("read_file GATED (no env var)",
                      not ok and "HERMES_MAC_ALLOW_FILE_TRANSFER" in (text + err), (text + err)[:160])

            # 10. final health -------------------------------------------
            ok, text, err = await call(session, "health")
            check("health (final)", ok, text[:120] or err)


async def main() -> None:
    t0 = time.time()
    # Suite 1: full agent experience (gates open, like a configured Hermes)
    await run_suite(
        {"HERMES_MAC_ALLOW_RUN_COMMAND": "1", "HERMES_MAC_ALLOW_FILE_TRANSFER": "1"},
        "Suite 1: full agent (run_command + file transfer enabled)",
    )
    # Suite 2: secure defaults (gates closed)
    await run_suite({}, "Suite 2: secure defaults (gates closed)")
    print(f"\n=== RESULT: {PASS} passed, {FAIL} failed, {SKIP} skipped in {time.time()-t0:.1f}s ===")
    if failures:
        print("failures:", *failures, sep="\n  - ")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
