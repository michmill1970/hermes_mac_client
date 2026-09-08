"""Tests for daemon activity tracking.

Covers :class:`ActivityTracker` (the thread-safe in-flight counter) and that
:func:`_dispatch` brackets every tool call with ``begin``/``end`` so the
menubar's green dot reflects real activity.
"""

from __future__ import annotations

import asyncio
import time

from hermes_mac_agent.daemon import server
from hermes_mac_agent.daemon.config import Config
from hermes_mac_agent.daemon.server import ActivityTracker, Connection, _dispatch, is_active
from hermes_mac_agent.daemon.tools import build_tools, tool_health


class TestActivityTracker:
    def test_initially_idle(self) -> None:
        t = ActivityTracker()
        assert t.active is False
        assert t.in_flight == 0
        assert t.last_activity == 0.0

    def test_begin_end(self) -> None:
        t = ActivityTracker()
        t.begin()
        assert t.active is True
        assert t.in_flight == 1
        assert t.last_activity > 0.0
        t.end()
        assert t.active is False
        assert t.in_flight == 0

    def test_nested_begin(self) -> None:
        t = ActivityTracker()
        t.begin()
        t.begin()
        assert t.in_flight == 2
        t.end()
        assert t.in_flight == 1
        assert t.active is True
        t.end()
        assert t.in_flight == 0
        assert t.active is False

    def test_end_clamps_at_zero(self) -> None:
        t = ActivityTracker()
        t.end()  # no matching begin — must not go negative
        assert t.in_flight == 0
        assert t.active is False


class TestDispatchActivity:
    def test_dispatch_brackets_handler(self, monkeypatch) -> None:
        # _audit writes to the real CONFIG_DIR/audit.log — no-op it here.
        monkeypatch.setattr(server, "_audit", lambda *a, **k: None)

        # The handler runs via asyncio.to_thread, so it must be a sync fn.
        def slow(_params):
            time.sleep(0.3)
            return {"ok": True}

        tools = {"slow": slow}
        conn = Connection()
        conn.authenticated = True
        raw = '{"id":1,"method":"slow","params":{}}'

        async def scenario():
            task = asyncio.create_task(_dispatch(conn, None, raw, Config(), tools))
            await asyncio.sleep(0.1)  # handler (0.3s) is still in flight
            assert is_active() is True
            resp = await task
            assert is_active() is False
            return resp

        resp = asyncio.run(scenario())
        assert resp.is_error is False

    def test_dispatch_counts_error_path(self, monkeypatch) -> None:
        # A handler that raises must still release the tracker (finally path).
        monkeypatch.setattr(server, "_audit", lambda *a, **k: None)

        def boom(_params):
            time.sleep(0.3)
            raise RuntimeError("kaboom")

        tools = {"boom": boom}
        conn = Connection()
        conn.authenticated = True
        raw = '{"id":1,"method":"boom","params":{}}'

        async def scenario():
            task = asyncio.create_task(_dispatch(conn, None, raw, Config(), tools))
            await asyncio.sleep(0.05)
            assert is_active() is True
            resp = await task
            assert is_active() is False
            return resp

        resp = asyncio.run(scenario())
        assert resp.is_error is True


class TestHealthExposesActivity:
    def test_health_excludes_itself(self) -> None:
        # In production health() runs inside _dispatch's begin/end bracket, so
        # the tracker count includes the health call itself. tool_health
        # subtracts that one so the figures reflect the *other* calls.
        tracker = ActivityTracker()
        tracker.begin()  # the health call itself
        idle = tool_health({}, Config(), time.monotonic(), tracker)
        assert idle["active"] is False
        assert idle["in_flight"] == 0
        tracker.begin()  # one *other* call in flight alongside health
        busy = tool_health({}, Config(), time.monotonic(), tracker)
        assert busy["active"] is True
        assert busy["in_flight"] == 1
        tracker.end()
        tracker.end()

    def test_health_without_tracker_is_idle(self) -> None:
        # Backwards-compatible: no tracker → idle, no crash.
        result = tool_health({}, Config(), time.monotonic())
        assert result["active"] is False
        assert result["in_flight"] == 0

    def test_health_dispatch_excludes_itself(self, monkeypatch) -> None:
        # End-to-end: a health() call dispatched while another call is in
        # flight must report the *other* call, not itself.
        monkeypatch.setattr(server, "_audit", lambda *a, **k: None)

        tracker = ActivityTracker()
        monkeypatch.setattr(server._config_holder, "tracker", tracker)

        def slow(_params):
            time.sleep(0.4)
            return {"ok": True}

        tools = build_tools(Config(), time.monotonic(), tracker)
        tools["slow"] = slow

        conn = Connection()
        conn.authenticated = True

        async def scenario():
            slow_task = asyncio.create_task(
                _dispatch(conn, None, '{"id":1,"method":"slow","params":{}}', Config(), tools)
            )
            await asyncio.sleep(0.1)  # let the slow call get in flight
            health_resp = await _dispatch(
                conn, None, '{"id":2,"method":"health","params":{}}', Config(), tools
            )
            await slow_task
            return health_resp

        resp = asyncio.run(scenario())
        assert resp.is_error is False
        assert resp.result["in_flight"] == 1  # the slow call, not health itself
        assert resp.result["active"] is True
