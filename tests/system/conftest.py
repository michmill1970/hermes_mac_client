"""System tests: real daemon (TLS + token) in a background thread, real client.

The daemon runs in-process on an ephemeral port with a self-signed cert
generated in a temp dir. Policy lists are intentionally restrictive so the
allow/deny tests can exercise both paths against one daemon:

  allowlist: ls, echo *, sleep *, pgrep *, pwd, uname *
  denylist:  sudo, rm *

Tests that need macOS TCC permissions (screen recording / accessibility)
skip gracefully when the permissions are not granted.
"""

from __future__ import annotations

import asyncio
import secrets
import ssl
import subprocess
import sys
import threading
from pathlib import Path

import pytest
import websockets

from hermes_mac_agent.client import MacAgent
from hermes_mac_agent.daemon.config import Config
from hermes_mac_agent.daemon.server import start_server

IS_MAC = sys.platform == "darwin"

ALLOWLIST = ["ls", "echo *", "sleep *", "pgrep *", "pwd", "uname *"]
DENYLIST = ["sudo", "rm *"]


def _gen_cert(tmp_path: Path, name: str) -> tuple[str, str]:
    cert = tmp_path / f"{name}.crt"
    key = tmp_path / f"{name}.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-subj", "/CN=hermes-mac-agent-test",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )
    return str(cert), str(key)


def _client_ssl(ca_cert: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca_cert)
    ctx.check_hostname = False
    return ctx


@pytest.fixture(scope="session")
def daemon(tmp_path_factory):
    """Start the real daemon once for the whole system suite."""
    tmp = tmp_path_factory.mktemp("daemon")
    cert, key = _gen_cert(Path(tmp), "daemon")
    token = secrets.token_hex(32)
    config = Config(
        host="127.0.0.1",
        port=0,
        cert_file=cert,
        key_file=key,
        token=token,
        allowlist=list(ALLOWLIST),
        denylist=list(DENYLIST),
    )

    loop = asyncio.new_event_loop()
    ready = threading.Event()
    holder: dict = {}

    async def _run():
        server = await start_server(config, host="127.0.0.1", port=0)
        holder["server"] = server
        holder["port"] = server.sockets[0].getsockname()[1]
        ready.set()
        await server.wait_closed()

    def _thread():
        asyncio.set_event_loop(loop)
        loop.run_until_complete(_run())

    t = threading.Thread(target=_thread, daemon=True)
    t.start()
    assert ready.wait(15), "daemon did not start in time"

    yield {
        "host": "127.0.0.1",
        "port": holder["port"],
        "token": token,
        "ca_cert": cert,
        "config": config,
    }

    loop.call_soon_threadsafe(holder["server"].close)
    t.join(timeout=10)
    loop.close()


@pytest.fixture
def client(daemon):
    """A fresh authenticated MacAgent per test."""
    agent = MacAgent(
        host=daemon["host"],
        port=daemon["port"],
        token=daemon["token"],
        ca_cert=daemon["ca_cert"],
    )
    agent.connect()
    yield agent
    agent.close()


class RawWS:
    """Sync facade over an async websockets connection (works on v12–v14+)."""

    def __init__(self, loop: asyncio.AbstractEventLoop, ws) -> None:
        self._loop = loop
        self._ws = ws

    def send(self, data: str) -> None:
        self._loop.run_until_complete(self._ws.send(data))

    def recv(self) -> str:
        return self._loop.run_until_complete(self._ws.recv())

    def close(self) -> None:
        try:
            self._loop.run_until_complete(self._ws.close())
        except Exception:
            pass


def _open_raw_ws(daemon, authenticate: bool) -> RawWS:
    """Open a raw TLS WebSocket on a fresh loop, wrapped in a sync facade."""
    import json

    loop = asyncio.new_event_loop()

    async def _connect():
        from hermes_mac_agent.protocol import WS_MAX_MESSAGE_SIZE

        ws = await websockets.connect(
            f"wss://{daemon['host']}:{daemon['port']}",
            ssl=_client_ssl(daemon["ca_cert"]),
            open_timeout=10,
            max_size=WS_MAX_MESSAGE_SIZE,
        )
        if authenticate:
            await ws.send(json.dumps({"id": 1, "method": "auth", "params": {"token": daemon["token"]}}))
            reply = json.loads(await ws.recv())
            assert reply["result"] == {"ok": True}, reply
        return ws

    ws = loop.run_until_complete(_connect())
    return RawWS(loop, ws)


@pytest.fixture
def raw_ws(daemon):
    """A raw authenticated WebSocket (for protocol-level assertions)."""
    ws = _open_raw_ws(daemon, authenticate=True)
    yield ws
    ws.close()
    ws._loop.close()


@pytest.fixture
def unauth_ws(daemon):
    """A raw WebSocket that has NOT authenticated."""
    ws = _open_raw_ws(daemon, authenticate=False)
    yield ws
    ws.close()
    ws._loop.close()


def _tcc_ok(daemon) -> bool:
    """True if the test process has both TCC permissions (screen + accessibility)."""
    try:
        h = MacAgent(
            host=daemon["host"], port=daemon["port"],
            token=daemon["token"], ca_cert=daemon["ca_cert"],
        )
        h.connect()
        try:
            perms = h.health()["perms"]
            return perms["screen"] and perms["accessibility"]
        finally:
            h.close()
    except Exception:
        return False


@pytest.fixture
def gui_ok(daemon):
    """Skip the test unless we're on macOS with both TCC permissions granted."""
    if not IS_MAC:
        pytest.skip("GUI tests require macOS")
    if not _tcc_ok(daemon):
        pytest.skip("TCC permissions (Screen Recording + Accessibility) not granted to this Python")
