"""Auth gate + TLS behavior over the wire."""

from __future__ import annotations

import json
import ssl

import pytest
import websockets
from websockets.exceptions import ConnectionClosed

from hermes_mac_agent.client import MacAgent
from hermes_mac_agent.protocol import AUTH_FAILED, AUTH_REQUIRED


class TestAuthGate:
    def test_non_auth_first_frame_rejected(self, unauth_ws):
        unauth_ws.send(json.dumps({"id": 2, "method": "health", "params": {}}))
        reply = json.loads(unauth_ws.recv())
        assert reply["error"]["code"] == AUTH_REQUIRED
        # Server closes the connection after an auth violation.
        with pytest.raises(ConnectionClosed):
            unauth_ws.recv()

    def test_wrong_token_rejected(self, unauth_ws):
        unauth_ws.send(json.dumps({"id": 1, "method": "auth", "params": {"token": "wrong-token"}}))
        reply = json.loads(unauth_ws.recv())
        assert reply["error"]["code"] == AUTH_FAILED
        with pytest.raises(ConnectionClosed):
            unauth_ws.recv()

    def test_missing_token_rejected(self, unauth_ws):
        unauth_ws.send(json.dumps({"id": 1, "method": "auth", "params": {}}))
        reply = json.loads(unauth_ws.recv())
        assert reply["error"]["code"] == AUTH_FAILED

    def test_auth_then_health(self, raw_ws):
        raw_ws.send(json.dumps({"id": 2, "method": "health", "params": {}}))
        reply = json.loads(raw_ws.recv())
        assert reply["result"]["ok"] is True

    def test_auth_twice_is_harmless(self, raw_ws):
        raw_ws.send(json.dumps({"id": 3, "method": "auth", "params": {"token": "ignored"}}))
        reply = json.loads(raw_ws.recv())
        # Already authenticated → second auth is a no-op success.
        assert reply["result"] == {"ok": True}


class TestClientAuth:
    def test_client_connects_and_health(self, client):
        h = client.health()
        assert h["ok"] is True
        assert "uptime" in h
        assert "perms" in h

    def test_client_wrong_token_fails(self, daemon):
        agent = MacAgent(
            host=daemon["host"],
            port=daemon["port"],
            token="definitely-wrong",
            ca_cert=daemon["ca_cert"],
        )
        with pytest.raises(Exception) as exc:
            agent.connect()
        agent.close()
        assert "auth" in str(exc.value).lower() or "token" in str(exc.value).lower()

    def test_client_reconnects_after_drop(self, client, daemon):
        # Force a fresh connection by closing the underlying one.
        client.close()
        result = client.run_command("echo back")
        assert result["stdout"].strip() == "back"


class TestTLS:
    def test_wrong_ca_fails_handshake(self, daemon):
        # A client that does not trust our self-signed cert must fail.
        agent = MacAgent(
            host=daemon["host"],
            port=daemon["port"],
            token=daemon["token"],
            verify=True,  # no ca_cert → system trust store → our cert is untrusted
        )
        with pytest.raises(Exception):
            agent.connect()
        agent.close()

    def test_plaintext_ws_fails(self, daemon):
        import asyncio

        async def _try():
            await websockets.connect(
                f"ws://{daemon['host']}:{daemon['port']}",
                open_timeout=5,
            )

        with pytest.raises(Exception):
            asyncio.run(_try())
