"""Client JSON-RPC roundtrip semantics (no network, no daemon).

These cover the response-correlation defects that desync an agent session:

* A late response from a call the client already gave up on must be
  DISCARDED, not handed to the next request (stale-response test).
* ``run_command`` must be awaited for its full (daemon-clamped) timeout,
  otherwise the client times out while the daemon is still working and
  manufactures the stale-response situation above.
* A connection lost AFTER a state-mutating request was sent must raise a
  loud "outcome unknown" error — never silently re-send the action.
* Read-only methods keep the transparent reconnect-and-retry behaviour.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from hermes_mac_agent.client.mac_agent import MacAgent, MacAgentError
from hermes_mac_agent.protocol import INTERNAL_ERROR, MAX_COMMAND_TIMEOUT


class FakeWS:
    """Stands in for a websockets connection.

    - ``auto_respond``: ``send()`` schedules a canned response for the
      request's id (after ``respond_delay`` seconds).
    - ``inbox``: responses the client will read, in order. Entries may be
      dicts (delivered immediately) or ``(delay, dict)`` tuples.
    - ``fail_recv`` / ``fail_send``: exception (or callable) raised by the
      first recv/send respectively.
    """

    def __init__(self, *, auto_respond=None, respond_delay: float = 0.0):
        self.sent: list[dict] = []
        self.inbox: list = []
        self.auto_respond = auto_respond
        self.respond_delay = respond_delay
        self.fail_recv: Exception | None = None
        self.fail_send: Exception | None = None
        self._tasks: list[asyncio.TimerHandle] = []
        self._loop = None

    async def send(self, raw: str) -> None:
        req = json.loads(raw)
        self.sent.append(req)
        if self.fail_send is not None:
            exc, self.fail_send = self.fail_send, None
            raise exc
        if self.auto_respond is not None:
            payload = dict(self.auto_respond(req))
            self._deliver(payload, self.respond_delay)

    async def recv(self) -> str:
        if self.fail_recv is not None:
            exc, self.fail_recv = self.fail_recv, None
            raise exc
        while not self.inbox:
            # Poll so responses scheduled by _deliver() wake us; the caller's
            # wait_for() timeout bounds how long this can spin.
            await asyncio.sleep(0.01)
        entry = self.inbox.pop(0)
        if isinstance(entry, tuple):
            delay, payload = entry
            await asyncio.sleep(delay)
        else:
            payload = entry
        return json.dumps(payload)

    def _deliver(self, payload: dict, delay: float) -> None:
        async def later() -> None:
            if delay:
                await asyncio.sleep(delay)
            self.inbox.append(payload)

        self._tasks.append(asyncio.ensure_future(later()))


def _agent(timeout: float = 5.0) -> MacAgent:
    agent = MacAgent(host="test", port=1, token="t", timeout=timeout)
    agent._authed = True  # skip the real handshake; tests own _ws
    return agent


async def _call(agent: MacAgent, method: str, params: dict):
    return await agent._call(method, params)


class TestResponseMatching:
    def test_stale_response_is_discarded(self, caplog):
        agent = _agent()
        ws = FakeWS(auto_respond=lambda req: {"id": req["id"], "result": {"ok": 1}})
        # A response that arrived after a previous call gave up sits in the
        # socket ahead of the real answer.
        ws.inbox.append({"id": 4242, "result": {"poison": True}})
        agent._ws = ws

        with caplog.at_level("WARNING", logger="hermes_mac_agent.client"):
            result = asyncio.run(_call(agent, "health", {}))

        assert result == {"ok": 1}  # NOT the poisoned stale response
        assert "stale" in caplog.text

    def test_desync_after_abandoned_call(self):
        """The classic desync: call 1 times out, its response lands late,
        call 2 must not receive call 1's answer."""
        agent = _agent(timeout=0.15)
        delivered = {"late": None}

        def auto(req):
            delivered["late"] = req["id"]
            return {"id": req["id"], "result": {"never": True}}

        ws = FakeWS(auto_respond=auto, respond_delay=10.0)  # never arrives
        agent._ws = ws
        with pytest.raises(MacAgentError):
            asyncio.run(_call(agent, "run_command", {"command": "sleep 100"}))

        # Daemon finally answers the abandoned request — before the next call.
        ws.inbox.clear()
        ws.auto_respond = lambda req: {"id": req["id"], "result": {"fresh": True}}
        ws.inbox.append({"id": 1, "result": {"late-answer": True}})
        ws.respond_delay = 0.0

        result = asyncio.run(_call(agent, "health", {}))
        assert result == {"fresh": True}  # not the late-answer

    def test_error_response_matched_by_id(self):
        agent = _agent()
        ws = FakeWS()
        ws.inbox.append({"id": 7, "error": {"code": INTERNAL_ERROR, "message": "old"}})
        agent._ws = ws

        def auto(req):
            return {
                "id": req["id"],
                "error": {"code": -32002, "message": "blocked now"},
            }

        ws.auto_respond = auto
        with pytest.raises(MacAgentError) as excinfo:
            asyncio.run(_call(agent, "run_command", {"command": "ls"}))
        assert "blocked now" in str(excinfo.value)  # current, not the stale error


class TestReadTimeout:
    def test_run_command_deadline_covers_command_timeout(self):
        agent = _agent(timeout=0.2)
        ws = FakeWS(
            auto_respond=lambda req: {"id": req["id"], "result": {"exit_code": 0}},
            respond_delay=0.4,
        )
        agent._ws = ws
        # Command budget 0.5s → deadline 0.2+0.5=0.7s > 0.4s delay → no timeout.
        result = asyncio.run(
            _call(agent, "run_command", {"command": "sleep 0.4", "timeout": 0.5})
        )
        assert result == {"exit_code": 0}

    def test_other_methods_do_not_get_the_extension(self):
        agent = _agent(timeout=0.15)
        ws = FakeWS(
            auto_respond=lambda req: {"id": req["id"], "result": {}},
            respond_delay=0.4,
        )
        agent._ws = ws
        with pytest.raises(MacAgentError, match="timed out"):
            asyncio.run(_call(agent, "screenshot", {}))

    def test_deadline_capped_at_max_command_timeout(self):
        agent = _agent(timeout=1.0)
        assert agent._read_timeout("run_command", {"timeout": 10_000}) == pytest.approx(
            1.0 + MAX_COMMAND_TIMEOUT
        )

    def test_bad_timeout_param_does_not_crash(self):
        agent = _agent(timeout=1.0)
        assert agent._read_timeout("run_command", {"timeout": "nonsense"}) == 1.0


class TestConnectionLossSemantics:
    def test_mutating_method_after_send_is_not_resent(self):
        agent = _agent()
        ws = FakeWS(auto_respond=lambda req: {"id": req["id"], "result": {}})
        ws.fail_recv = ConnectionResetError("boom")  # dies after send, pre-response
        agent._ws = ws
        with pytest.raises(MacAgentError, match="outcome unknown"):
            asyncio.run(_call(agent, "mouse_click", {"x": 1, "y": 2}))
        assert len(ws.sent) == 1  # never silently re-sent

    def test_read_only_method_retries_transparently(self):
        agent = _agent()
        ws1 = FakeWS()
        ws1.fail_recv = ConnectionResetError("boom")
        ws2 = FakeWS(auto_respond=lambda req: {"id": req["id"], "result": {"ok": True}})
        agent._ws = ws1

        async def reconnect():
            agent._ws = ws2
            agent._authed = True

        agent._connect_and_auth = reconnect
        result = asyncio.run(_call(agent, "screenshot", {}))
        assert result == {"ok": True}
        assert len(ws1.sent) == 1 and len(ws2.sent) == 1

    def test_send_failure_before_transit_retries(self):
        agent = _agent()
        ws1 = FakeWS()
        ws1.fail_send = ConnectionResetError("nope")
        ws2 = FakeWS(auto_respond=lambda req: {"id": req["id"], "result": {"ok": True}})
        agent._ws = ws1

        async def reconnect():
            agent._ws = ws2
            agent._authed = True

        agent._connect_and_auth = reconnect
        # Nothing reached the daemon, so retrying a click is safe.
        result = asyncio.run(_call(agent, "mouse_click", {"x": 1, "y": 2}))
        assert result == {"ok": True}
        # ws1 recorded the attempt, but the socket failed before transit,
        # so the retry on ws2 is not a duplicate execution.
        assert len(ws1.sent) == 1 and len(ws2.sent) == 1
