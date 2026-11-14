"""Hermes-facing Python client for the Hermes Mac agent daemon.

Default integration for Hermes (a Python agent):

    from hermes_mac_agent import MacAgent

    agent = MacAgent(
        host="192.168.1.50",
        port=8765,
        token="...",
        ca_cert="~/.hermes_mac_agent/ca.pem",   # or the self-signed cert itself
    )

    with agent:
        img = agent.screenshot()          # PIL.Image
        agent.launch_app("Safari", url="https://www.linkedin.com")
        agent.type_text("hello")
        agent.key_press(["command", "t"])
        agent.run_command("echo ok")
        agent.stop_process(pid)

The client is a thin JSON-RPC layer over a TLS WebSocket. It authenticates
lazily on first use and transparently reconnects if the connection is
dropped: read-only calls are re-sent automatically; a state-changing call
that dies in flight raises (its outcome is unknown) rather than risking a
duplicated click/keypress/command.
"""

from __future__ import annotations

import asyncio
import base64
import io
import json
import logging
import os
import ssl
import threading
from pathlib import Path
from typing import Any

import websockets
from websockets.exceptions import ConnectionClosed

log = logging.getLogger("hermes_mac_agent.client")

from hermes_mac_agent.protocol import (
    AUTH_FAILED,
    AUTH_REQUIRED,
    BLOCKED_BY_POLICY,
    FILE_CHUNK_SIZE,
    INTERNAL_ERROR,
    INVALID_PARAMS,
    MAX_COMMAND_TIMEOUT,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    PROCESS_NOT_FOUND,
    TCC_PERMISSION_DENIED,
    WS_MAX_MESSAGE_SIZE,
)

__all__ = ["MacAgent", "MacAgentError", "BlockedByPolicyError", "TccPermissionError"]


class MacAgentError(Exception):
    """Base error for MacAgent failures. Carries the JSON-RPC error code."""

    def __init__(self, code: int, message: str) -> None:
        self.code = code
        super().__init__(message)


class BlockedByPolicyError(MacAgentError):
    """The daemon's allow/deny policy blocked the request."""


class TccPermissionError(MacAgentError):
    """A macOS TCC permission (Screen Recording / Accessibility) is missing."""


def _error_for(code: int, message: str) -> MacAgentError:
    if code == BLOCKED_BY_POLICY:
        return BlockedByPolicyError(code, message)
    if code == TCC_PERMISSION_DENIED:
        return TccPermissionError(code, message)
    return MacAgentError(code, message)


class MacAgent:
    """Synchronous client for the Hermes Mac agent daemon.

    Thread-safe for a single connection; use one instance per daemon.
    """

    def __init__(
        self,
        host: str,
        port: int = 8765,
        token: str = "",
        ca_cert: str | None = None,
        verify: bool = True,
        timeout: float = 130.0,
    ) -> None:
        self.host = host
        self.port = port
        self.token = token
        self.verify = verify
        self.timeout = timeout
        self.ca_cert = str(Path(ca_cert).expanduser()) if ca_cert else None

        if not verify:
            log.warning(
                "MacAgent(%s:%s) has TLS certificate verification DISABLED "
                "(verify=False). An on-path attacker can MITM this connection "
                "and steal the shared token, which grants full control of the "
                "Mac. Only use this for debugging on a trusted network.",
                host,
                port,
            )
        elif self.ca_cert is None:
            log.warning(
                "MacAgent(%s:%s) will verify the daemon's TLS certificate but "
                "no ca_cert was supplied, so it will be checked against the "
                "system trust store. The daemon's self-signed certificate is "
                "NOT in that store, so the handshake will fail. Pass "
                "ca_cert=<path to the daemon's cert.pem or its CA> to verify "
                "correctly — do not fall back to verify=False.",
                host,
                port,
            )

        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ws: Any = None
        self._authed = False
        self._next_id = 0
        #: True once the current request's frame has been handed to the
        #: socket; distinguishes "daemon may have acted" from "not sent".
        self._request_sent = False
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def __enter__(self) -> "MacAgent":
        self.connect()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _ensure_loop(self) -> None:
        """Start the background event loop if it is not running."""
        if self._loop is None:
            self._loop = asyncio.new_event_loop()
            self._thread = threading.Thread(target=self._run_loop, daemon=True)
            self._thread.start()

    def connect(self) -> None:
        """Start the background event loop and open + authenticate the socket."""
        with self._lock:
            if self._ws is not None:
                return
            self._ensure_loop()
            self._call_async(self._connect_and_auth())

    def close(self) -> None:
        with self._lock:
            if self._loop is None:
                return
            loop, self._loop = self._loop, None
            try:
                self._call_async(self._close_ws(), loop=loop)
            except Exception:
                pass
            loop.call_soon_threadsafe(loop.stop)
            if self._thread is not None:
                self._thread.join(timeout=5)
                self._thread = None
            loop.close()
            self._ws = None
            self._authed = False

    def _run_loop(self) -> None:
        assert self._loop is not None
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _call_async(self, coro: Any, loop: asyncio.AbstractEventLoop | None = None) -> Any:
        loop = loop or self._loop
        assert loop is not None
        future = asyncio.run_coroutine_threadsafe(coro, loop)
        return future.result(timeout=self.timeout + 10)

    async def _ssl_context(self) -> ssl.SSLContext | None:
        if not self.verify:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if self.ca_cert:
            ctx.load_verify_locations(self.ca_cert)
        else:
            ctx.load_default_certs()
        return ctx

    async def _connect_and_auth(self) -> None:
        ws = await websockets.connect(
            f"wss://{self.host}:{self.port}",
            ssl=await self._ssl_context(),
            open_timeout=self.timeout,
            # Match the daemon: the default 1 MiB cap rejects large screenshot
            # responses (base64 PNG) before they reach the caller.
            max_size=WS_MAX_MESSAGE_SIZE,
        )
        self._ws = ws
        await self._auth(ws)

    async def _close_ws(self) -> None:
        if self._ws is not None:
            await self._ws.close()
            self._ws = None
            self._authed = False

    async def _auth(self, ws: Any) -> None:
        resp = await self._roundtrip(ws, "auth", {"token": self.token})
        if "error" in resp:
            err = resp["error"]
            raise _error_for(int(err.get("code", AUTH_FAILED)), str(err.get("message", "auth failed")))
        self._authed = True

    # ------------------------------------------------------------------
    # JSON-RPC plumbing
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # JSON-RPC plumbing
    # ------------------------------------------------------------------

    #: Read-only methods: safe to resend if the connection drops mid-call,
    #: because repeating them cannot change the Mac's state. Every other
    #: method is state-mutating and must never be silently re-sent.
    _READ_ONLY_METHODS = frozenset(
        {"screenshot", "health", "list_processes", "read_file"}
    )

    def _read_timeout(self, method: str, params: dict[str, Any]) -> float:
        """Wall-clock budget for one request/response roundtrip.

        ``run_command`` carries its own timeout and the daemon will keep
        running the command for that long (clamped to MAX_COMMAND_TIMEOUT).
        A fixed read deadline shorter than that makes the client give up
        while the command is still executing — the agent sees a false
        failure for work that may succeed, and the daemon's late response
        lingers on the socket. Cover the command's full budget on top of
        the transport timeout so the response is always awaited.
        """
        try:
            extra = float(params.get("timeout") or 0.0)
        except (TypeError, ValueError):
            extra = 0.0
        extra = max(0.0, min(extra, MAX_COMMAND_TIMEOUT))
        return self.timeout + extra

    async def _roundtrip(
        self,
        ws: Any,
        method: str,
        params: dict[str, Any],
        read_timeout: float | None = None,
    ) -> dict[str, Any]:
        self._next_id += 1
        req_id = self._next_id
        req = {"id": req_id, "method": method, "params": params}
        await ws.send(json.dumps(req))
        self._request_sent = True
        # Match the response by JSON-RPC id. Without this, any response that
        # arrives after the client gave up on an earlier call (e.g. a long
        # run_command that outlived the read timeout) is silently returned as
        # the answer to the *next* request — every subsequent call in the
        # session reads the previous call's result. Discard stale responses
        # instead; the daemon pairs one response with one request, so the
        # matching response always follows the stragglers.
        loop = asyncio.get_running_loop()
        deadline = loop.time() + (
            self._read_timeout(method, params)
            if read_timeout is None
            else read_timeout
        )
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError
            raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
            resp = json.loads(raw)
            if resp.get("id") == req_id:
                return resp
            log.warning(
                "discarding stale response id=%r (expected %r) for %s",
                resp.get("id"),
                req_id,
                method,
            )

    async def _call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        for attempt in (1, 2):
            self._request_sent = False
            ws = self._ws
            if ws is None or self._authed is False:
                await self._connect_and_auth()
                ws = self._ws
            self._request_sent = False
            read_timeout = self._read_timeout(method, params)
            try:
                resp = await self._roundtrip(ws, method, params, read_timeout)
            except asyncio.TimeoutError as exc:
                # A slow/missing response must surface as a MacAgentError, not a
                # raw asyncio.TimeoutError, so callers catching the documented
                # exception type are not blindsided.
                raise MacAgentError(
                    INTERNAL_ERROR, f"request timed out after {read_timeout}s"
                ) from exc
            except (ConnectionClosed, OSError) as exc:
                if self._request_sent and method not in self._READ_ONLY_METHODS:
                    # The request reached the daemon but the connection died
                    # before its response: the action may already have been
                    # performed. Re-sending would duplicate a click/keypress/
                    # command, which is worse than an explicit error — the
                    # documented agent loop verifies effects via screenshot.
                    raise MacAgentError(
                        INTERNAL_ERROR,
                        f"connection lost after sending {method!r}; outcome "
                        "unknown — verify the Mac's state (screenshot/health) "
                        "before retrying",
                    ) from exc
                if attempt == 2:
                    raise
                self._authed = False
                self._ws = None
                continue
            if "error" in resp:
                err = resp["error"]
                code = int(err.get("code", INTERNAL_ERROR))
                if code in (AUTH_REQUIRED, AUTH_FAILED) and attempt == 1:
                    # session dropped server-side; reconnect and retry once
                    self._authed = False
                    self._ws = None
                    continue
                raise _error_for(code, str(err.get("message", "unknown error")))
            return resp.get("result", {})
        raise MacAgentError(INTERNAL_ERROR, "unreachable")

    def _invoke(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._ensure_loop()
            return self._call_async(self._call(method, params))

    # ------------------------------------------------------------------
    # Screen
    # ------------------------------------------------------------------

    def screenshot(self, monitor: int = 1) -> "Any":
        """Capture the screen and return a ``PIL.Image`` (RGB).

        ``monitor=1`` is the primary display, ``monitor=2/3/...`` the other
        displays, ``monitor=0`` captures all displays stitched into one image.
        """
        result = self._invoke("screenshot", {"monitor": monitor})
        from PIL import Image

        return Image.open(io.BytesIO(base64.b64decode(result["png_base64"])))

    def screenshot_bytes(self, monitor: int = 1) -> bytes:
        """Capture the screen and return raw PNG bytes."""
        result = self._invoke("screenshot", {"monitor": monitor})
        return base64.b64decode(result["png_base64"])

    # ------------------------------------------------------------------
    # Mouse
    # ------------------------------------------------------------------

    def mouse_move(self, x: int | float, y: int | float, duration: float = 0.0, monitor: int = 1) -> None:
        """Move the mouse to a screen position.

        Two coordinate modes:
        - **int** x/y: global pixel coordinates. The origin (0, 0) is the
          top-left of the PRIMARY display; monitors positioned to the left or
          above the primary use negative coordinates.
        - **float** x/y in [0, 1]: percentage of the *monitor*'s screenshot
          (``monitor=1`` is the primary display). The daemon converts to
          pixels, so this is resolution- and Retina-safe. Use this when the
          target was located in a screenshot.
        """
        self._invoke("mouse_move", {"x": x, "y": y, "duration": duration, "monitor": monitor})

    def mouse_click(self, x: int | float | None = None, y: int | float | None = None, button: str = "left", clicks: int = 1, monitor: int = 1) -> None:
        """Click the mouse, optionally at a screen position.

        See :meth:`mouse_move` for the two coordinate modes (global pixels vs.
        percentage of a monitor's screenshot). Omit x/y to click at the
        current cursor position.
        """
        params: dict[str, Any] = {"button": button, "clicks": clicks, "monitor": monitor}
        if x is not None:
            params["x"] = x
        if y is not None:
            params["y"] = y
        self._invoke("mouse_click", params)

    def mouse_drag(self, x1: int | float, y1: int | float, x2: int | float, y2: int | float, button: str = "left", duration: float = 0.5, monitor: int = 1) -> None:
        """Drag from (x1, y1) to (x2, y2).

        See :meth:`mouse_move` for the two coordinate modes. In percentage
        mode both endpoints are relative to the same *monitor*.
        """
        self._invoke("mouse_drag", {"x1": x1, "y1": y1, "x2": x2, "y2": y2, "button": button, "duration": duration, "monitor": monitor})

    def mouse_scroll(self, dx: int = 0, dy: int = 0) -> None:
        self._invoke("mouse_scroll", {"dx": dx, "dy": dy})

    # ------------------------------------------------------------------
    # Keyboard
    # ------------------------------------------------------------------

    def type_text(self, text: str, interval: float = 0.0) -> None:
        self._invoke("type_text", {"text": text, "interval": interval})

    def key_press(self, keys: list[str]) -> None:
        """Press a hotkey combination, e.g. ``["command", "t"]``."""
        self._invoke("key_press", {"keys": keys})

    # ------------------------------------------------------------------
    # Processes
    # ------------------------------------------------------------------

    def launch_app(self, app: str, url: str | None = None) -> int | None:
        """Launch a GUI app by name (``"Safari"``) or ``.app`` path. Returns its pid (best effort)."""
        params: dict[str, Any] = {"app": app}
        if url:
            params["url"] = url
        result = self._invoke("launch_app", params)
        return result.get("pid")

    def run_command(self, cmd: str, cwd: str | None = None, timeout: float = 60.0) -> dict[str, Any]:
        """Run a shell command. Returns ``{"exit_code", "stdout", "stderr"}``."""
        params: dict[str, Any] = {"cmd": cmd, "timeout": timeout}
        if cwd:
            params["cwd"] = cwd
        return self._invoke("run_command", params)

    def list_processes(self, filter: str | None = None) -> list[dict[str, Any]]:
        params = {"filter": filter} if filter else {}
        return self._invoke("list_processes", params)["processes"]

    def stop_process(self, pid: int, sig: str = "TERM") -> None:
        self._invoke("stop_process", {"pid": pid, "signal": sig})

    # ------------------------------------------------------------------
    # File transfer (chunked)
    # ------------------------------------------------------------------

    def read_file(self, path: str) -> bytes:
        """Read a file from the Mac (chunked). Returns the full contents."""
        chunks: list[bytes] = []
        offset = 0
        while True:
            result = self._invoke("read_file", {"path": path, "offset": offset})
            raw = base64.b64decode(result.get("data", ""))
            if raw:
                chunks.append(raw)
            if result.get("eof"):
                break
            offset += len(raw)
        return b"".join(chunks)

    def read_file_text(self, path: str, encoding: str = "utf-8") -> str:
        """Read a text file from the Mac and decode it."""
        return self.read_file(path).decode(encoding)

    def write_file(self, path: str, data: bytes) -> None:
        """Write bytes to a file on the Mac (chunked)."""
        offset = 0
        total = len(data)
        while offset < total:
            chunk = data[offset : offset + FILE_CHUNK_SIZE]
            self._invoke(
                "write_file",
                {
                    "path": path,
                    "data": base64.b64encode(chunk).decode("ascii"),
                    "offset": offset,
                },
            )
            offset += len(chunk)
        if total == 0:
            # Empty payload: still create/truncate the file.
            self._invoke("write_file", {"path": path, "data": "", "offset": 0})

    def write_file_text(self, path: str, text: str, encoding: str = "utf-8") -> None:
        """Write a string to a file on the Mac (chunked)."""
        self.write_file(path, text.encode(encoding))

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health(self) -> dict[str, Any]:
        return self._invoke("health", {})
