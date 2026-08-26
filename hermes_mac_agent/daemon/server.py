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
import hmac
import json
import logging
import os
import signal
import ssl
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


def _audit(event: str, remote: str, method: str, params: Any, outcome: str) -> None:
    """Append one line to the audit log (best-effort; never raises).

    Records every authenticated tool call and every auth attempt so an operator
    can see what a connected client actually did. Written to
    ``CONFIG_DIR/audit.log`` (mode 0600). Failures are swallowed — auditing
    must never take the daemon down.
    """
    try:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "remote": remote,
            "method": method,
            "params": params,
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


# Module-level holders so _handler/_dispatch share one config without
# threading it through websockets' handler signature.
class _ConfigHolder:
    def __init__(self) -> None:
        self.config: Config = Config()
        self.tools: dict = {}
        self.start_time: float = time.monotonic()


_config_holder = _ConfigHolder()


async def start_server(config: Config, host: str | None = None, port: int | None = None) -> Server:
    """Start the daemon. Returns the websockets server (use .sockets[0] for the bound port)."""
    if not config.token:
        raise RuntimeError("token is empty — run scripts/setup_mac.sh to generate credentials")
    for path in (config.cert_file, config.key_file):
        if not os.path.exists(path):
            raise RuntimeError(f"missing TLS material: {path} — run scripts/setup_mac.sh")

    _config_holder.config = config
    _config_holder.tools = build_tools(config, time.monotonic())
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
