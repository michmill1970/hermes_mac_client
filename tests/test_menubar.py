"""Unit tests for the menubar host (ServerController).

The PyObjC UI (``main``) is not exercised here — it requires a real macOS GUI
session. ``ServerController`` is deliberately PyObjC-free, so we test it
directly against a real daemon (TLS + token, ephemeral port), the same way
``tests/system`` does.
"""

from __future__ import annotations

import secrets
import subprocess
from pathlib import Path

import pytest

from hermes_mac_agent.daemon.config import Config
from hermes_mac_agent.menubar.app import ServerController


def _gen_cert(tmp_path: Path, name: str) -> tuple[str, str]:
    cert = tmp_path / f"{name}.crt"
    key = tmp_path / f"{name}.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-subj", "/CN=hermes-mac-agent-menubar-test",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )
    return str(cert), str(key)


@pytest.fixture
def config(tmp_path) -> Config:
    cert, key = _gen_cert(Path(tmp_path), "menubar")
    return Config(
        host="127.0.0.1",
        port=0,
        cert_file=cert,
        key_file=key,
        token=secrets.token_hex(32),
    )


class TestServerController:
    def test_start_stop(self, config: Config) -> None:
        c = ServerController(config)
        assert not c.running
        c.start()
        try:
            assert c.running
            assert c.error is None
            st = c.status()
            assert st["running"] is True
            assert st["host"] == "127.0.0.1"
            assert isinstance(st["port"], int) and st["port"] > 0
        finally:
            c.stop()
        assert not c.running
        assert c.status()["running"] is False

    def test_start_is_idempotent(self, config: Config) -> None:
        c = ServerController(config)
        c.start()
        try:
            first_thread = c._thread
            c.start()  # no-op while running
            assert c._thread is first_thread
        finally:
            c.stop()

    def test_stop_without_start_is_safe(self, config: Config) -> None:
        c = ServerController(config)
        c.stop()  # must not raise
        assert not c.running

    def test_start_failure_sets_error(self, tmp_path) -> None:
        # Empty token → start_server raises → controller surfaces the error.
        c = ServerController(Config(token=""))
        c.start()
        assert not c.running
        assert c.error is not None
        assert "token" in c.error

    def test_start_failure_missing_cert(self, tmp_path) -> None:
        c = ServerController(
            Config(
                token="x" * 64,
                cert_file=str(tmp_path / "nope.crt"),
                key_file=str(tmp_path / "nope.key"),
            )
        )
        c.start()
        assert not c.running
        assert c.error is not None
        assert "TLS material" in c.error

    def test_perms_returns_bools(self, config: Config) -> None:
        c = ServerController(config)
        perms = c.perms()
        assert set(perms) == {"screen", "accessibility"}
        assert all(isinstance(v, bool) for v in perms.values())


class TestModuleImport:
    def test_imports_without_pyobjc(self) -> None:
        # The module must import cleanly even where pyobjc is absent — the
        # AppKit import happens only inside main().
        import hermes_mac_agent.menubar.app as app_mod  # noqa: F401

        assert callable(app_mod.main)
        assert hasattr(app_mod, "ServerController")
