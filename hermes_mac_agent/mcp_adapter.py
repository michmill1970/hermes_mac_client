"""Optional MCP server adapter for the Hermes Mac agent.

Secondary integration (the Python client is the default). This wraps the
daemon — reached over the TLS WebSocket via :class:`MacAgent` — as MCP tools
so Hermes can also consume the Mac through Model Context Protocol.

Run with ``hermes-mac-mcp`` (stdio transport). Configuration comes from
environment variables:

    HERMES_MAC_HOST      (required)
    HERMES_MAC_PORT      (default 8765)
    HERMES_MAC_TOKEN     (required)
    HERMES_MAC_CA_CERT   (path to the local CA cert, ca.pem, that signed the
                          daemon's leaf cert — needed for real TLS verification)
    HERMES_MAC_NO_VERIFY (set to "1" to skip TLS verification — NOT recommended)
    HERMES_MAC_ALLOW_RUN_COMMAND (set to "1" to expose the run_command tool;
                          off by default because it is an LLM → RCE path)

Example MCP client config (e.g. in an MCP client's mcp.json):

    {
      "mcpServers": {
        "hermes-mac": {
          "command": "hermes-mac-mcp",
          "env": {
            "HERMES_MAC_HOST": "192.168.1.50",
            "HERMES_MAC_TOKEN": "...",
            "HERMES_MAC_CA_CERT": "/path/to/ca.pem"
          }
        }
      }
    }
"""

from __future__ import annotations

import base64
import io
import logging
import os
from typing import Any

from hermes_mac_agent.client.mac_agent import MacAgent

log = logging.getLogger("hermes_mac_agent.mcp")

__all__ = ["build_mcp_server", "main"]


def _agent() -> MacAgent:
    host = os.environ.get("HERMES_MAC_HOST")
    if not host:
        raise RuntimeError("HERMES_MAC_HOST is not set")
    no_verify = os.environ.get("HERMES_MAC_NO_VERIFY") == "1"
    if no_verify:
        log.warning(
            "HERMES_MAC_NO_VERIFY=1 disables TLS certificate verification. "
            "An on-path attacker can MITM the connection and steal the shared "
            "token (full control of the Mac). Only use on a trusted network."
        )
    return MacAgent(
        host=host,
        port=int(os.environ.get("HERMES_MAC_PORT", "8765")),
        token=os.environ.get("HERMES_MAC_TOKEN", ""),
        ca_cert=os.environ.get("HERMES_MAC_CA_CERT"),
        verify=not no_verify,
    )


def build_mcp_server():
    """Build an MCP server exposing the Mac control tools.

    Works with both ``mcp`` 2.x (``mcp.server.MCPServer``) and 1.x
    (``mcp.server.fastmcp.FastMCP``). The tool-registration API
    (``@server.tool()`` + ``server.run()``) is the same in both, so only the
    import differs.
    """
    try:
        from mcp.server import MCPServer as _Server  # mcp >= 2.0
    except ImportError:
        try:
            from mcp.server.fastmcp import FastMCP as _Server  # mcp 1.x
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "the 'mcp' package is required for the MCP adapter: pip install hermes-mac-agent[mcp]"
            ) from exc

    mcp = _Server("hermes-mac")
    agent = _agent()

    @mcp.tool()
    def screenshot(monitor: int = 1) -> str:
        """Capture the Mac screen. Returns PNG bytes as base64.

        monitor=1 is the primary display, monitor=2/3/... are the other
        displays, monitor=0 captures all displays stitched into one image.
        """
        img = agent.screenshot(monitor=monitor)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode("ascii")

    @mcp.tool()
    def mouse_move(x: int, y: int, duration: float = 0.0) -> str:
        """Move the mouse to absolute screen coordinates.

        Coordinates are in the global virtual-screen space: origin (0, 0) is
        the top-left of the PRIMARY display. Monitors positioned to the left
        or above the primary have NEGATIVE coordinates. To click a pixel in a
        single monitor's screenshot, add that monitor's offset (e.g. a
        monitor whose left edge is at x=-5120: image pixel (100, 100) ->
        global (-5020, 100)).
        """
        agent.mouse_move(x, y, duration=duration)
        return "ok"

    @mcp.tool()
    def mouse_click(x: int | None = None, y: int | None = None, button: str = "left", clicks: int = 1) -> str:
        """Click the mouse, optionally at absolute global screen coordinates
        (see mouse_move for the multi-monitor coordinate space)."""
        agent.mouse_click(x=x, y=y, button=button, clicks=clicks)
        return "ok"

    @mcp.tool()
    def mouse_drag(x1: int, y1: int, x2: int, y2: int, button: str = "left") -> str:
        """Drag the mouse from (x1, y1) to (x2, y2) in global screen
        coordinates (see mouse_move for the multi-monitor coordinate space)."""
        agent.mouse_drag(x1, y1, x2, y2, button=button)
        return "ok"

    @mcp.tool()
    def mouse_scroll(dx: int = 0, dy: int = 0) -> str:
        """Scroll the mouse wheel."""
        agent.mouse_scroll(dx=dx, dy=dy)
        return "ok"

    @mcp.tool()
    def type_text(text: str, interval: float = 0.0) -> str:
        """Type text into the focused application."""
        agent.type_text(text, interval=interval)
        return "ok"

    @mcp.tool()
    def key_press(keys: list[str]) -> str:
        """Press a hotkey combination, e.g. ["command", "t"]."""
        agent.key_press(keys)
        return "ok"

    @mcp.tool()
    def launch_app(app: str, url: str | None = None) -> str:
        """Launch a GUI app by name (e.g. 'Safari') or .app path, optionally opening a URL."""
        pid = agent.launch_app(app, url=url)
        return f"launched {app} (pid={pid})"

    @mcp.tool()
    def run_command(cmd: str, cwd: str | None = None, timeout: float = 60.0) -> str:
        """Run a shell command on the Mac. Returns exit code, stdout and stderr.

        Gated: only available when HERMES_MAC_ALLOW_RUN_COMMAND=1 is set. An
        LLM-facing tool that can run arbitrary shell commands is a prompt-
        injection → RCE path, so it is off by default.
        """
        if os.environ.get("HERMES_MAC_ALLOW_RUN_COMMAND") != "1":
            raise RuntimeError(
                "run_command is disabled for the MCP adapter. Set "
                "HERMES_MAC_ALLOW_RUN_COMMAND=1 to enable it. This exposes "
                "arbitrary shell execution to the LLM, so it is off by default."
            )
        result: dict[str, Any] = agent.run_command(cmd, cwd=cwd, timeout=timeout)
        return f"exit_code={result['exit_code']}\nstdout:\n{result['stdout']}\nstderr:\n{result['stderr']}"

    @mcp.tool()
    def list_processes(filter: str | None = None) -> str:
        """List running processes, optionally filtered by name substring."""
        procs = agent.list_processes(filter=filter)
        return "\n".join(f"{p['pid']}\t{p['name']}\tcpu={p['cpu']}%\tmem={p['mem']}%" for p in procs)

    @mcp.tool()
    def stop_process(pid: int, sig: str = "TERM") -> str:
        """Stop a process by pid."""
        agent.stop_process(pid, sig=sig)
        return f"stopped {pid}"

    @mcp.tool()
    def read_file(path: str) -> str:
        """Read a file from the Mac and return its contents as base64.

        Gated: only available when HERMES_MAC_ALLOW_FILE_TRANSFER=1 is set. An
        LLM-facing file reader is a data-exfiltration path, so it is off by
        default. The daemon's file_allowlist/file_denylist still apply.
        """
        if os.environ.get("HERMES_MAC_ALLOW_FILE_TRANSFER") != "1":
            raise RuntimeError(
                "read_file is disabled for the MCP adapter. Set "
                "HERMES_MAC_ALLOW_FILE_TRANSFER=1 to enable it. This exposes "
                "file reads to the LLM, so it is off by default."
            )
        return base64.b64encode(agent.read_file(path)).decode("ascii")

    @mcp.tool()
    def write_file(path: str, data_base64: str) -> str:
        """Write base64-encoded bytes to a file on the Mac.

        Gated: only available when HERMES_MAC_ALLOW_FILE_TRANSFER=1 is set. An
        LLM-facing file writer is an arbitrary-write path, so it is off by
        default. The daemon's file_allowlist/file_denylist still apply.
        """
        if os.environ.get("HERMES_MAC_ALLOW_FILE_TRANSFER") != "1":
            raise RuntimeError(
                "write_file is disabled for the MCP adapter. Set "
                "HERMES_MAC_ALLOW_FILE_TRANSFER=1 to enable it. This exposes "
                "file writes to the LLM, so it is off by default."
            )
        agent.write_file(path, base64.b64decode(data_base64))
        return "ok"

    @mcp.tool()
    def health() -> str:
        """Daemon health and TCC permission status."""
        return str(agent.health())

    return mcp


def main() -> None:
    server = build_mcp_server()
    server.run()  # stdio transport


if __name__ == "__main__":
    main()
