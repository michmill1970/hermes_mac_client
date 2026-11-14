"""TLS WebSocket daemon: token gate + JSON-RPC dispatch.

Run with ``hermes-mac-daemon`` (see pyproject entry point) or import
:func:`start_server` from tests.

Connection lifecycle:
  1. Client connects over TLS.
  2. Client's first frame MUST be ``auth`` with the shared token.
  3. Wrong/missing token → error response + connection closed.
  4. Any non-auth frame before a successful auth → ``AUTH_REQUIRED`` + close.
  5. Authenticated frames are dispatched to the tool registry with a
     per-request timeout.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import signal
import ssl
import threading
import time
from datetime import datetime, timezone
from typing import Any

import websockets
from websockets.asyncio.server import Server

from hermes_mac_agent.daemon.config import CONFIG_DIR, Config
from hermes_mac_agent.daemon.tools import PolicyBlockedError, ToolError, build_tools
from hermes_mac_agent.protocol import (
    AUTH_FAILED,
    AUTH_REQUIRED,
    BLOCKED_BY_POLICY,
    INTERNAL_ERROR,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    Method,
    ProtocolError,
    Request,
    Response,
    WS_MAX_MESSAGE_SIZE,
    make_error_response,
    make_result_response,
)

log = logging.getLogger("hermes_mac_agent.daemon")

# Per-request wall-clock cap. This MUST exceed tools.MAX_COMMAND_TIMEOUT
# (300s): run_command owns its own deadline and kills its process group when
# *it* expires. If this server-side cap fired first, asyncio.wait_for would
# cancel the to_thread future without stopping the worker thread, orphaning
# the subprocess and pinning the thread. Keeping this larger lets the handler
# always finish (and clean up its group) before the server gives up.
DEFAULT_REQUEST_TIMEOUT = 320.0


class Connection:
    """Per-connection state (auth flag)."""

    __slots__ = ("authenticated",)

    def __init__(self) -> None:
        self.authenticated = False


# Audit-log parameter redaction. An audit line must answer "who did what"
# without also becoming a copy of *what they sent*:
#   * write_file "data" — base64 chunks of up to 256 KiB (~341 KB of text per
#     log line) flooded audit.log and duplicated transferred file content.
#   * type_text  "text" — typed text routinely contains passwords and other
#     secrets; it has no business in an operator-readable log.
# Redacted fields keep a length + short sha256 so identical payloads can still
# be correlated across lines (e.g. the chunks of one streamed file).
_REDACTED_PARAMS: dict[str, tuple[str, ...]] = {
    "write_file": ("data",),
    "type_text": ("text",),
}

# Safety net for every other method/field: one audit line must stay bounded no
# matter what a client sends (a single frame can be 16 MiB). Over-long strings
# keep a short prefix — enough context to see what ran, not a copy of it.
_MAX_AUDIT_STR = 2000
_MAX_AUDIT_PREVIEW = 80


def _summarize(value: Any, preview: bool) -> dict[str, Any]:
    if not isinstance(value, str):
        return {"omitted": True}
    digest = hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()
    summary: dict[str, Any] = {"omitted": True, "length": len(value), "sha256_12": digest[:12]}
    if preview:
        summary["prefix"] = value[:_MAX_AUDIT_PREVIEW]
    return summary


def _redact_params(method: str, params: Any) -> Any:
    """Return *params* safe to write to the audit log (never raises)."""
    if not isinstance(params, dict):  # protocol guarantees dict; never trust it here
        return _summarize(params, preview=True)
    redact = _REDACTED_PARAMS.get(method, ())
    out: dict[str, Any] = {}
    for key, value in params.items():
        if key in redact:
            out[key] = _summarize(value, preview=False)
        elif isinstance(value, str) and len(value) > _MAX_AUDIT_STR:
            out[key] = _summarize(value, preview=True)
        else:
            out[key] = value
    return out


def _audit(event: str, remote: str, method: str, params: Any, outcome: str) -> None:
    """Append one line to the audit log (best-effort; never raises).

    Records every authenticated tool call and every auth attempt so an operator
    can see what a connected client actually did. Written to
    ``CONFIG_DIR/audit.log`` (mode 0600). Bulk/sensitive params (``write_file``
    data, ``type_text`` text) are replaced with length+sha256 summaries, and any
    other over-long string is truncated — see :func:`_redact_params`. Failures
    are swallowed — auditing must never take the daemon down.
    """
    try:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "remote": remote,
            "method": method,
            "params": _redact_params(method, params),
            "outcome": outcome,
        }
        path = CONFIG_DIR / "audit.log"
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        # Create with 0600 up front (subject to umask) instead of chmod'ing on
        # every write. O_APPEND keeps concurrent appends line-atomic.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")
    except Exception:  # noqa: BLE001 - auditing is best-effort
        log.debug("audit write failed", exc_info=True)


def build_ssl_context(config: Config) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=config.cert_file, keyfile=config.key_file)
    return ctx


async def _handle_auth(conn: Connection, req: Request, config: Config, ws: Any) -> Response:
    remote = getattr(ws, "remote_address", "?")
    if conn.authenticated:
        # Idempotent: re-authenticating an already-authenticated session is a no-op.
        return make_result_response(req.id, {"ok": True})
    token = req.params.get("token")
    if not isinstance(token, str) or not hmac.compare_digest(token, config.token):
        log.warning("auth failed from %s", remote)
        await asyncio.to_thread(_audit, "auth", remote, Method.AUTH.value, {}, "failed")
        return make_error_response(req.id, AUTH_FAILED, "invalid token")
    conn.authenticated = True
    log.info("client authenticated: %s", remote)
    await asyncio.to_thread(_audit, "auth", remote, Method.AUTH.value, {}, "ok")
    return make_result_response(req.id, {"ok": True})


async def _dispatch(conn: Connection, ws: Any, raw: str | bytes, config: Config, tools: dict) -> Response:
    try:
        req = Request.parse(raw)
    except ProtocolError as exc:
        return make_error_response(0, INVALID_REQUEST, str(exc))

    if req.method == Method.AUTH.value:
        return await _handle_auth(conn, req, config, ws)

    if not conn.authenticated:
        return make_error_response(req.id, AUTH_REQUIRED, "auth required: send the auth method first")

    handler = tools.get(req.method)
    if handler is None:
        return make_error_response(req.id, METHOD_NOT_FOUND, f"unknown method {req.method!r}")

    remote = getattr(ws, "remote_address", "?")
    tracker = _config_holder.tracker
    tracker.begin()
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(handler, req.params), timeout=DEFAULT_REQUEST_TIMEOUT
        )
        response = make_result_response(req.id, result)
    except ToolError as exc:
        response = make_error_response(req.id, exc.code, str(exc), exc.data)
    except PolicyBlockedError as exc:
        response = make_error_response(
            req.id,
            BLOCKED_BY_POLICY,
            str(exc),
            {"list": exc.list_name, "matched": exc.matched},
        )
    except asyncio.TimeoutError:
        response = make_error_response(req.id, INTERNAL_ERROR, f"request timed out after {DEFAULT_REQUEST_TIMEOUT}s")
    except Exception as exc:  # noqa: BLE001 - report, don't crash the connection
        log.exception("tool %s failed", req.method)
        response = make_error_response(req.id, INTERNAL_ERROR, f"internal error: {exc}")
    finally:
        tracker.end()

    outcome = "ok" if not response.is_error else str(response.error.code)
    await asyncio.to_thread(_audit, "call", remote, req.method, req.params, outcome)
    return response


async def _handler(websocket: Any) -> None:
    conn = Connection()
    remote = getattr(websocket, "remote_address", "?")
    log.info("connection from %s", remote)
    try:
        async for raw in websocket:
            response = await _dispatch(conn, websocket, raw, _config_holder.config, _config_holder.tools)
            await websocket.send(response.to_json())
            if response.is_error and response.error.code in (AUTH_FAILED, AUTH_REQUIRED):
                await websocket.close(code=4401, reason="auth failed")
                return
    except websockets.ConnectionClosed:
        pass
    finally:
        log.info("connection closed: %s", remote)


class ActivityTracker:
    """Thread-safe count of in-flight tool calls.

    The menubar host reads :attr:`active` to light up its icon while Hermes is
    driving the Mac. ``begin``/``end`` are called from the daemon's dispatch
    path (a worker thread); ``active`` is read from the UI thread, so all
    access is guarded by a lock.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active = 0
        self.last_activity = 0.0  # monotonic; 0.0 until the first call

    def begin(self) -> None:
        with self._lock:
            self._active += 1
            self.last_activity = time.monotonic()

    def end(self) -> None:
        with self._lock:
            self._active = max(0, self._active - 1)

    @property
    def active(self) -> bool:
        with self._lock:
            return self._active > 0

    @property
    def in_flight(self) -> int:
        with self._lock:
            return self._active


# Module-level holders so _handler/_dispatch share one config without
# threading it through websockets' handler signature.
class _ConfigHolder:
    def __init__(self) -> None:
        self.config: Config = Config()
        self.tools: dict = {}
        self.start_time: float = time.monotonic()
        self.tracker = ActivityTracker()


_config_holder = _ConfigHolder()


def is_active() -> bool:
    """Whether any authenticated tool call is currently in flight.

    Public accessor for the menubar host (in-process). Safe to call before the
    server has started (returns False).
    """
    return _config_holder.tracker.active


async def start_server(config: Config, host: str | None = None, port: int | None = None) -> Server:
    """Start the daemon. Returns the websockets server (use .sockets[0] for the bound port)."""
    if not config.token:
        raise RuntimeError("token is empty — run scripts/setup_mac.sh to generate credentials")
    for path in (config.cert_file, config.key_file):
        if not os.path.exists(path):
            raise RuntimeError(f"missing TLS material: {path} — run scripts/setup_mac.sh")

    _config_holder.config = config
    _config_holder.tracker = ActivityTracker()
    _config_holder.tools = build_tools(config, time.monotonic(), _config_holder.tracker)
    _config_holder.start_time = time.monotonic()

    ssl_ctx = build_ssl_context(config)
    host = host or config.host
    port = port if port is not None else config.port
    # Explicit max_size: the websockets default (1 MiB) is too small for
    # screenshot responses (large-display PNGs base64-encoded can exceed it).
    server = await websockets.serve(
        _handler, host, port, ssl=ssl_ctx, max_size=WS_MAX_MESSAGE_SIZE
    )
    log.info("hermes-mac-daemon listening on %s:%d (TLS)", host, port)
    return server


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    config = Config.load()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def _run() -> None:
        server = await start_server(config)
        stop = loop.create_future()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, stop.set_result, None)
            except NotImplementedError:  # pragma: no cover - non-UNIX
                pass
        await stop
        server.close()
        await server.wait_closed()

    try:
        loop.run_until_complete(_run())
    finally:
        loop.close()


if __name__ == "__main__":
    main()
