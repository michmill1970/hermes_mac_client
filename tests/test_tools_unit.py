"""Unit tests for daemon tools: policy matching, arg validation, process tools.

GUI-dependent tools (screenshot, mouse, keyboard) are covered by the system
suite with the ``gui`` marker; here we test everything that runs headless.
"""

from __future__ import annotations

import base64
import os
import signal
import subprocess
import sys
import time

import psutil
import pytest

from hermes_mac_agent.daemon.config import Config, PolicyBlockedError
from hermes_mac_agent.daemon.tools import (
    ToolError,
    build_tools,
    tool_key_press,
    tool_list_processes,
    tool_mouse_click,
    tool_mouse_move,
    tool_read_file,
    tool_run_command,
    tool_stop_process,
    tool_type_text,
    tool_write_file,
)
from hermes_mac_agent.protocol import (
    BLOCKED_BY_POLICY,
    COMMAND_TIMEOUT,
    FILE_CHUNK_SIZE,
    INVALID_PARAMS,
    PROCESS_NOT_FOUND,
)

IS_MAC = sys.platform == "darwin"


def _quiet_sleeps(monkeypatch, record=None):
    """Skip real pacing sleeps during a test; optionally record durations.

    (Pacing code uses time.sleep; tests either wait for nothing or assert on
    the recorded duration sequence.)
    """
    from hermes_mac_agent.daemon import tools

    def _sleep(s):
        if record is not None:
            record.append(s)

    monkeypatch.setattr(tools.time, "sleep", _sleep)


def _no_quartz(monkeypatch):
    """Force _post_button's pyautogui fallback so NO real CGEvent is posted.

    On macOS ``import Quartz`` really succeeds, so an unstubbed _quartz in a
    click test would create AND POST real input events to the live HID tap
    (found running the suite on the test laptop). Tests that assert on
    pa.mouseDown/mouseUp must pin this path; the real poster is covered by
    TestEventPipelineHygiene with a fake Quartz.
    """
    from hermes_mac_agent.daemon import tools
    from hermes_mac_agent.protocol import INTERNAL_ERROR

    def _raise():
        raise tools.ToolError(INTERNAL_ERROR, "Quartz unavailable (test)")

    monkeypatch.setattr(tools, "_quartz", _raise)


def _position_from_moves(calls):
    """pyautogui.position() stub: the cursor 'is' where the last moveTo put it."""

    def _pos():
        for name, args, kwargs in reversed(calls):
            if name == "moveTo":
                return args
        return (0, 0)

    return _pos


@pytest.fixture
def config() -> Config:
    # allowlist=["*"] so command/app tests can run; the policy tests below
    # override the lists explicitly. (The real default is deny-all.)
    return Config(token="test-token", allowlist=["*"])


# ---------------------------------------------------------------------------
# Policy (allow/deny) matching
# ---------------------------------------------------------------------------


class TestPolicy:
    def test_default_deny_all(self):
        # Secure by default: a fresh Config permits nothing (empty allowlist).
        cfg = Config(token="t")
        with pytest.raises(PolicyBlockedError) as exc:
            cfg.check_command("ls")
        assert exc.value.list_name == "allowlist"
        with pytest.raises(PolicyBlockedError):
            cfg.check_app("Safari")

    def test_allow_all_opt_in(self):
        cfg = Config(token="t", allowlist=["*"])
        cfg.check_command("anything at all")
        cfg.check_app("Safari")

    def test_denylist_blocks(self, config):
        config.denylist = ["sudo"]
        with pytest.raises(PolicyBlockedError) as exc:
            config.check_command("sudo ls")
        assert exc.value.list_name == "denylist"
        assert exc.value.matched == "sudo"

    def test_denylist_case_insensitive(self, config):
        # macOS commands/paths are case-insensitive in practice, so a bare
        # "sudo" entry must block "SUDO ls" / "Sudo reboot" too (H3).
        config.denylist = ["sudo"]
        for cmd in ("SUDO ls", "Sudo reboot", "sUdO -i"):
            with pytest.raises(PolicyBlockedError) as exc:
                config.check_command(cmd)
            assert exc.value.list_name == "denylist"
            assert exc.value.matched == "sudo"

    def test_denylist_wins_over_allowlist(self, config):
        config.allowlist = ["*"]
        config.denylist = ["sudo"]
        with pytest.raises(PolicyBlockedError):
            config.check_command("sudo ls")

    def test_denylist_star_blocks_everything(self, config):
        config.denylist = ["*"]
        with pytest.raises(PolicyBlockedError):
            config.check_command("ls")

    def test_allowlist_restricts(self, config):
        config.allowlist = ["ls", "echo *"]
        config.check_command("ls -la")
        config.check_command("echo hello")
        with pytest.raises(PolicyBlockedError) as exc:
            config.check_command("rm x")
        assert exc.value.list_name == "allowlist"

    def test_glob_matching(self, config):
        config.denylist = ["dd if=*"]
        with pytest.raises(PolicyBlockedError):
            config.check_command("dd if=/dev/zero of=/tmp/x")
        config.check_command("dd status=progress")  # no 'if=' — allowed

    def test_app_check(self, config):
        config.allowlist = ["Safari", "Chrome"]
        config.check_app("Safari")
        with pytest.raises(PolicyBlockedError):
            config.check_app("Terminal")

    def test_default_denylist_safety_net(self):
        # Even with an open allowlist, the built-in denylist still blocks the
        # most destructive commands.
        cfg = Config(token="t", allowlist=["*"])
        for bad in ("sudo reboot", "rm -rf /", "dd if=/dev/zero of=/dev/sda", "mkfs.hfs /dev/disk0"):
            with pytest.raises(PolicyBlockedError):
                cfg.check_command(bad)
        cfg.check_command("ls -la /tmp")


# ---------------------------------------------------------------------------
# run_command
# ---------------------------------------------------------------------------


class TestRunCommand:
    def test_echo(self, config):
        result = tool_run_command({"cmd": "echo ok"}, config)
        assert result["exit_code"] == 0
        assert result["stdout"].strip() == "ok"

    def test_nonzero_exit(self, config):
        result = tool_run_command({"cmd": "exit 3"}, config)
        assert result["exit_code"] == 3

    def test_stderr(self, config):
        result = tool_run_command({"cmd": "echo boom >&2"}, config)
        assert "boom" in result["stderr"]

    def test_timeout(self, config):
        with pytest.raises(ToolError) as exc:
            tool_run_command({"cmd": "sleep 5", "timeout": 0.3}, config)
        assert exc.value.code == COMMAND_TIMEOUT

    def test_empty_cmd(self, config):
        with pytest.raises(ToolError) as exc:
            tool_run_command({"cmd": "   "}, config)
        assert exc.value.code == INVALID_PARAMS

    def test_blocked_by_denylist(self, config):
        config.denylist = ["sudo"]
        with pytest.raises(PolicyBlockedError):
            tool_run_command({"cmd": "sudo ls"}, config)

    def test_cwd(self, config, tmp_path):
        result = tool_run_command({"cmd": "pwd", "cwd": str(tmp_path)}, config)
        assert result["stdout"].strip() == str(tmp_path)

    def test_large_output_is_truncated(self, config):
        # ~2MB of output must be bounded to head+tail with a truncation marker.
        result = tool_run_command({"cmd": "yes A | head -c 2000000", "timeout": 30}, config)
        assert result["exit_code"] == 0
        out = result["stdout"]
        assert "bytes truncated" in out
        # Bounded well below the raw 2MB (head + tail + marker).
        assert len(out) < 600_000
        assert out.startswith("A")
        assert out.rstrip().endswith("A")

    def test_small_output_not_truncated(self, config):
        result = tool_run_command({"cmd": "echo hello"}, config)
        assert "truncated" not in result["stdout"]
        assert result["stdout"].strip() == "hello"


# ---------------------------------------------------------------------------
# list_processes / stop_process
# ---------------------------------------------------------------------------


class TestProcessControl:
    def test_list_processes(self):
        result = tool_list_processes({})
        pids = [p["pid"] for p in result["processes"]]
        assert 1 in pids  # launchd on macOS, init elsewhere

    def test_list_processes_filter(self):
        result = tool_list_processes({"filter": "nonexistent-process-xyz"})
        assert result["processes"] == []

    def test_stop_process_kills(self):
        proc = subprocess.Popen(["sleep", "30"])
        try:
            result = tool_stop_process({"pid": proc.pid})
            assert result["ok"] is True
            assert proc.wait(timeout=5) is not None
        finally:
            if proc.poll() is None:
                proc.kill()

    def test_stop_process_missing(self):
        with pytest.raises(ToolError) as exc:
            tool_stop_process({"pid": 2**22 - 1})
        assert exc.value.code == PROCESS_NOT_FOUND

    def test_stop_process_bad_signal(self):
        with pytest.raises(ToolError) as exc:
            tool_stop_process({"pid": 1, "signal": "BOGUS"})
        assert exc.value.code == INVALID_PARAMS

    def test_stop_process_bad_pid(self):
        with pytest.raises(ToolError) as exc:
            tool_stop_process({"pid": "123"})
        assert exc.value.code == INVALID_PARAMS


# ---------------------------------------------------------------------------
# Arg validation for GUI tools (no TCC needed to hit validation errors)
# ---------------------------------------------------------------------------


class TestGuiArgValidation:
    def test_mouse_move_requires_ints(self):
        with pytest.raises(ToolError) as exc:
            tool_mouse_move({"x": "10", "y": 5})
        assert exc.value.code == INVALID_PARAMS

    def test_mouse_move_bool_rejected(self):
        with pytest.raises(ToolError):
            tool_mouse_move({"x": True, "y": 5})

    def test_type_text_requires_string(self):
        with pytest.raises(ToolError) as exc:
            tool_type_text({"text": 42})
        assert exc.value.code == INVALID_PARAMS

    @pytest.mark.parametrize(
        "keys",
        [None, [], "command", ["command", 5]],
    )
    def test_key_press_requires_key_list(self, keys):
        with pytest.raises(ToolError) as exc:
            tool_key_press({"keys": keys})
        assert exc.value.code == INVALID_PARAMS

    def test_mouse_click_requires_coords_together(self):
        with pytest.raises(ToolError):
            tool_mouse_click({"x": 10})  # y missing


# ---------------------------------------------------------------------------
# GUI behavior (stubbed pyautogui)
# ---------------------------------------------------------------------------


class TestGuiBehavior:
    """Exercise the pyautogui call sites with a stub, headless.

    These guard against regressions in *how* the tools drive pyautogui (e.g.
    relative vs. absolute drag), which the ``gui``-marked system suite only
    covers on a real machine.
    """

    def _stub_pyautogui(self, monkeypatch):
        import types

        from hermes_mac_agent.daemon import tools

        calls = []
        stub = types.SimpleNamespace()

        def _record(name):
            def _fn(*args, **kwargs):
                calls.append((name, args, kwargs))
            return _fn

        for name in ("moveTo", "dragTo", "drag", "press", "hotkey", "mouseDown",
                     "mouseUp", "keyDown", "keyUp"):
            setattr(stub, name, _record(name))
        stub.position = _position_from_moves(calls)

        monkeypatch.setitem(sys.modules, "pyautogui", stub)
        monkeypatch.setattr(tools, "_require_accessibility", lambda: None)
        _quiet_sleeps(monkeypatch)
        _no_quartz(monkeypatch)
        return calls

    def test_mouse_drag_is_absolute(self, monkeypatch):
        # H1: drag must honor (x1, y1) as the origin. pyautogui.drag() is
        # relative, so the tool must moveTo the start then dragTo the end.
        calls = self._stub_pyautogui(monkeypatch)
        from hermes_mac_agent.daemon.tools import tool_mouse_drag

        result = tool_mouse_drag({"x1": 10, "y1": 10, "x2": 60, "y2": 60, "duration": 0.2})
        assert result == {"ok": True}

        names = [c[0] for c in calls]
        assert "moveTo" in names
        assert "dragTo" in names
        assert "drag" not in names  # relative drag must not be used

        move = next(c for c in calls if c[0] == "moveTo")
        assert move[1] == (10, 10)

        drag = next(c for c in calls if c[0] == "dragTo")
        assert drag[1] == (60, 60)
        assert drag[2].get("duration") == 0.2

    def test_key_press_single_key_is_paced_press(self, monkeypatch):
        # M4: a single key is a press, not a hotkey. Pacing fix: press =
        # paced keyDown/keyUp (pa.press posts them with zero gap, the
        # machine-speed burst that drops events under load).
        calls = self._stub_pyautogui(monkeypatch)
        from hermes_mac_agent.daemon.tools import tool_key_press

        tool_key_press({"keys": ["return"]})
        assert [c[0] for c in calls] == ["keyDown", "keyUp"]
        assert calls[0][1] == ("return",)
        assert "press" not in [c[0] for c in calls]
        assert "hotkey" not in [c[0] for c in calls]

    def test_key_press_combo_is_paced_chord(self, monkeypatch):
        calls = self._stub_pyautogui(monkeypatch)
        from hermes_mac_agent.daemon.tools import tool_key_press

        tool_key_press({"keys": ["command", "c"]})
        seq = [(c[0], c[1][0]) for c in calls]
        assert seq == [
            ("keyDown", "command"), ("keyDown", "c"),
            ("keyUp", "c"), ("keyUp", "command"),
        ]
        assert "hotkey" not in [c[0] for c in calls]


# ---------------------------------------------------------------------------
# Percentage (0..1) mouse coordinates → global pixel conversion
# ---------------------------------------------------------------------------


class TestPercentageCoordinates:
    """Verify the pct→pixel math headless by stubbing both ``mss`` (monitor
    geometry) and ``pyautogui`` (click space). Covers multi-monitor offsets
    and Retina scale != 1.
    """

    def _stub(self, monkeypatch, monitors, click_width, click_height):
        import types

        from hermes_mac_agent.daemon import tools

        class _MSS:
            def __init__(self):
                self.monitors = monitors

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        mss_stub = types.ModuleType("mss")
        mss_stub.MSS = _MSS
        monkeypatch.setitem(sys.modules, "mss", mss_stub)

        calls = []
        pa = types.SimpleNamespace()
        pa.size = lambda: types.SimpleNamespace(width=click_width, height=click_height)

        def _record(name):
            def _fn(*args, **kwargs):
                calls.append((name, args, kwargs))
            return _fn

        for name in ("moveTo", "dragTo", "click", "mouseDown", "mouseUp"):
            setattr(pa, name, _record(name))
        pa.position = _position_from_moves(calls)
        monkeypatch.setitem(sys.modules, "pyautogui", pa)
        monkeypatch.setattr(tools, "_require_accessibility", lambda: None)
        _quiet_sleeps(monkeypatch)
        return calls

    # Single 1000x800 primary; click space == screenshot space (scale 1.0).
    MONITORS_1 = [
        {"left": 0, "top": 0, "width": 1000, "height": 800},   # virtual
        {"left": 0, "top": 0, "width": 1000, "height": 800},   # monitor 1
    ]

    def test_percentage_primary(self, monkeypatch):
        calls = self._stub(monkeypatch, self.MONITORS_1, 1000, 800)
        from hermes_mac_agent.daemon.tools import tool_mouse_move

        tool_mouse_move({"x": 0.5, "y": 0.25})
        assert calls[0][0] == "moveTo"
        assert calls[0][1] == (500, 200)

    def test_percentage_boundaries(self, monkeypatch):
        calls = self._stub(monkeypatch, self.MONITORS_1, 1000, 800)
        from hermes_mac_agent.daemon.tools import tool_mouse_move

        tool_mouse_move({"x": 0.0, "y": 1.0})
        assert calls[0][1] == (0, 800)

    def test_percentage_secondary_monitor_offset(self, monkeypatch):
        # Monitor 2 sits to the LEFT of the primary (negative global coords).
        # pyautogui.size() reports the PRIMARY display (monitor 1, 1000 wide),
        # NOT the virtual screen (2200 wide) — so click_width is the primary's
        # width and the scale is 1000/1000 = 1.0.
        monitors = [
            {"left": -1200, "top": 0, "width": 2200, "height": 800},  # virtual
            {"left": 0, "top": 0, "width": 1000, "height": 800},      # monitor 1 (primary)
            {"left": -1200, "top": 0, "width": 1200, "height": 900},  # monitor 2
        ]
        calls = self._stub(monkeypatch, monitors, 1000, 800)  # primary click size
        from hermes_mac_agent.daemon.tools import tool_mouse_click

        tool_mouse_click({"x": 0.5, "y": 0.5, "monitor": 2})
        move = next(c for c in calls if c[0] == "moveTo")
        # scale = 1000/1000 = 1.0 ; -1200 + 0.5*1200 = -600 ; 0 + 0.5*900 = 450
        assert move[1] == (-600, 450)

    def test_multi_display_scale_uses_primary_not_virtual(self, monkeypatch):
        # Regression for the multi-display miss: with several displays the
        # virtual screen is far wider than the primary. pyautogui.size()
        # returns the PRIMARY size, so the scale must be
        # primary_click/primary_screenshot (1.0 here), not
        # primary_click/virtual_screenshot (0.25) — the latter squished clicks
        # on secondary displays toward the origin and made them miss.
        monitors = [
            {"left": -5120, "top": 0, "width": 6848, "height": 1440},  # virtual
            {"left": 0, "top": 0, "width": 1728, "height": 1117},      # monitor 1 (primary)
            {"left": -5120, "top": 0, "width": 2560, "height": 1440},  # monitor 2
        ]
        calls = self._stub(monkeypatch, monitors, 1728, 1117)  # primary click size
        from hermes_mac_agent.daemon.tools import tool_mouse_click

        # Center of monitor 2.
        tool_mouse_click({"x": 0.5, "y": 0.5, "monitor": 2})
        move = next(c for c in calls if c[0] == "moveTo")
        # scale = 1728/1728 = 1.0 ; -5120 + 0.5*2560 = -3840 ; 0 + 0.5*1440 = 720
        assert move[1] == (-3840, 720)

    def test_percentage_retina_scale(self, monkeypatch):
        # Unscaled Retina: mss reports 2x pixels, pyautogui clicks in points.
        monitors = [
            {"left": 0, "top": 0, "width": 3456, "height": 2232},  # virtual
            {"left": 0, "top": 0, "width": 3456, "height": 2232},  # monitor 1
        ]
        calls = self._stub(monkeypatch, monitors, 1728, 1116)  # scale = 0.5
        from hermes_mac_agent.daemon.tools import tool_mouse_move

        tool_mouse_move({"x": 0.5, "y": 0.5})
        assert calls[0][1] == (864, 558)

    def test_integer_valued_floats_are_pixels(self, monkeypatch):
        # MCP schema validation coerces JSON ints to float (500 -> 500.0);
        # whole-number floats must still mean global pixels, not percentages.
        calls = self._stub(monkeypatch, self.MONITORS_1, 1000, 800)
        from hermes_mac_agent.daemon.tools import tool_mouse_move

        tool_mouse_move({"x": 500.0, "y": 300.0})
        assert calls[0][1] == (500, 300)

    def test_int_pixels_still_work(self, monkeypatch):
        calls = self._stub(monkeypatch, self.MONITORS_1, 1000, 800)
        from hermes_mac_agent.daemon.tools import tool_mouse_move

        tool_mouse_move({"x": 500, "y": 300})
        assert calls[0][1] == (500, 300)

    def test_mixed_modes_rejected(self, monkeypatch):
        calls = self._stub(monkeypatch, self.MONITORS_1, 1000, 800)
        from hermes_mac_agent.daemon.tools import tool_mouse_move

        with pytest.raises(ToolError) as exc:
            tool_mouse_move({"x": 0.5, "y": 500})
        assert exc.value.code == INVALID_PARAMS

    def test_out_of_range_percentage_rejected(self, monkeypatch):
        calls = self._stub(monkeypatch, self.MONITORS_1, 1000, 800)
        from hermes_mac_agent.daemon.tools import tool_mouse_move

        with pytest.raises(ToolError) as exc:
            tool_mouse_move({"x": 1.5, "y": 0.5})
        assert exc.value.code == INVALID_PARAMS

    def test_bad_monitor_rejected(self, monkeypatch):
        calls = self._stub(monkeypatch, self.MONITORS_1, 1000, 800)
        from hermes_mac_agent.daemon.tools import tool_mouse_move

        with pytest.raises(ToolError) as exc:
            tool_mouse_move({"x": 0.5, "y": 0.5, "monitor": 5})
        assert exc.value.code == INVALID_PARAMS

    def test_drag_percentages_both_endpoints(self, monkeypatch):
        calls = self._stub(monkeypatch, self.MONITORS_1, 1000, 800)
        from hermes_mac_agent.daemon.tools import tool_mouse_drag

        tool_mouse_drag({"x1": 0.1, "y1": 0.1, "x2": 0.9, "y2": 0.9})
        move = next(c for c in calls if c[0] == "moveTo")
        drag = next(c for c in calls if c[0] == "dragTo")
        assert move[1] == (100, 80)
        assert drag[1] == (900, 720)


# ---------------------------------------------------------------------------
# File transfer (read_file / write_file)
# ---------------------------------------------------------------------------


class TestFileTransfer:
    def _allow_files(self, config: Config) -> Config:
        config.file_allowlist = ["*"]
        return config

    def test_read_file_single_chunk(self, config, tmp_path):
        self._allow_files(config)
        target = tmp_path / "hello.txt"
        payload = b"hello world\n" * 100
        target.write_bytes(payload)
        result = tool_read_file({"path": str(target), "offset": 0}, config)
        assert result["eof"] is True
        assert result["size"] == len(payload)
        assert base64.b64decode(result["data"]) == payload

    def test_read_file_chunked(self, config, tmp_path):
        self._allow_files(config)
        target = tmp_path / "big.bin"
        payload = os.urandom(FILE_CHUNK_SIZE + 10)  # forces >= 2 chunks
        target.write_bytes(payload)
        got = b""
        offset = 0
        while True:
            r = tool_read_file({"path": str(target), "offset": offset}, config)
            raw = base64.b64decode(r["data"])
            got += raw
            if r["eof"]:
                break
            offset += len(raw)
        assert got == payload

    def test_write_file_chunked(self, config, tmp_path):
        self._allow_files(config)
        target = tmp_path / "out.bin"
        payload = os.urandom(FILE_CHUNK_SIZE + 5)  # forces >= 2 chunks
        offset = 0
        while offset < len(payload):
            chunk = payload[offset : offset + FILE_CHUNK_SIZE]
            tool_write_file(
                {
                    "path": str(target),
                    "data": base64.b64encode(chunk).decode("ascii"),
                    "offset": offset,
                },
                config,
            )
            offset += len(chunk)
        assert target.read_bytes() == payload

    def test_read_file_policy_deny_all(self, config, tmp_path):
        # Default file policy is deny-all (empty file_allowlist).
        target = tmp_path / "x.txt"
        target.write_bytes(b"data")
        with pytest.raises(PolicyBlockedError) as exc:
            tool_read_file({"path": str(target)}, config)
        assert exc.value.list_name == "allowlist"

    def test_read_file_not_a_file(self, config, tmp_path):
        self._allow_files(config)
        with pytest.raises(ToolError) as exc:
            tool_read_file({"path": str(tmp_path)}, config)  # a directory
        assert exc.value.code == INVALID_PARAMS

    def test_write_file_bad_base64(self, config, tmp_path):
        self._allow_files(config)
        with pytest.raises(ToolError) as exc:
            tool_write_file({"path": str(tmp_path / "y"), "data": "!!!not-base64!!!"}, config)
        assert exc.value.code == INVALID_PARAMS

    def test_write_file_chunk_too_large(self, config, tmp_path):
        self._allow_files(config)
        big = base64.b64encode(b"x" * (FILE_CHUNK_SIZE + 1)).decode("ascii")
        with pytest.raises(ToolError) as exc:
            tool_write_file({"path": str(tmp_path / "z"), "data": big, "offset": 0}, config)
        assert exc.value.code == INVALID_PARAMS


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_all_methods_registered(self, config):
        tools = build_tools(config, time.monotonic())
        from hermes_mac_agent.protocol import Method

        expected = {m.value for m in Method if m is not Method.AUTH}
        assert set(tools) == expected


# ---------------------------------------------------------------------------
# Audit log (F7)
# ---------------------------------------------------------------------------


class TestAuditLog:
    def test_audit_writes_jsonl(self, tmp_path, monkeypatch):
        import hermes_mac_agent.daemon.server as server

        monkeypatch.setattr("hermes_mac_agent.daemon.server.CONFIG_DIR", tmp_path)
        server._audit("call", "127.0.0.1:54321", "run_command", {"cmd": "ls"}, "ok")
        server._audit("auth", "127.0.0.1:54322", "auth", {}, "failed")

        log_file = tmp_path / "audit.log"
        assert log_file.exists()
        lines = log_file.read_text().strip().splitlines()
        assert len(lines) == 2

        import json

        first = json.loads(lines[0])
        assert first["event"] == "call"
        assert first["method"] == "run_command"
        assert first["params"] == {"cmd": "ls"}
        assert first["outcome"] == "ok"
        assert first["remote"] == "127.0.0.1:54321"
        assert "ts" in first

        second = json.loads(lines[1])
        assert second["event"] == "auth"
        assert second["outcome"] == "failed"

    def test_audit_redacts_bulk_and_sensitive_params(self, tmp_path, monkeypatch):
        import hermes_mac_agent.daemon.server as server
        import json

        monkeypatch.setattr("hermes_mac_agent.daemon.server.CONFIG_DIR", tmp_path)
        payload = "A" * 300_000  # a full 256 KiB chunk encoded as base64
        server._audit("call", "r", "write_file",
                      {"path": "/tmp/x.bin", "offset": 0, "data": payload}, "ok")
        server._audit("call", "r", "write_file",
                      {"path": "/tmp/x.bin", "offset": 262144, "data": payload}, "ok")
        # sensitive regardless of length: passwords are short
        server._audit("call", "r", "type_text", {"text": "hunter2"}, "ok")

        lines = (tmp_path / "audit.log").read_text().strip().splitlines()
        wf1, wf2, tt = (json.loads(line) for line in lines)

        # non-payload params survive untouched — the audit trail stays useful
        assert wf1["params"]["path"] == "/tmp/x.bin"
        assert wf1["params"]["offset"] == 0
        # the payload itself is gone, replaced by a correlation summary
        redacted = wf1["params"]["data"]
        assert redacted["omitted"] is True
        assert redacted["length"] == 300_000
        assert "prefix" not in redacted  # bulk/sensitive fields are never previewed
        assert payload[:100] not in lines[0]
        # identical chunks hash identically, so writes of one file stay correlatable
        assert redacted["sha256_12"] == wf2["params"]["data"]["sha256_12"]
        # short-but-sensitive text is redacted too
        assert tt["params"]["text"]["omitted"] is True
        assert tt["params"]["text"]["length"] == 7
        assert "hunter2" not in lines[2]

    def test_audit_long_param_safety_net(self, tmp_path, monkeypatch):
        import hermes_mac_agent.daemon.server as server
        import json

        monkeypatch.setattr("hermes_mac_agent.daemon.server.CONFIG_DIR", tmp_path)
        # a legitimately long command still yields a bounded line, but keeps
        # enough prefix to see what ran
        long_cmd = "echo " + "x" * 5000 + " && true"
        server._audit("call", "r", "run_command", {"cmd": long_cmd}, "ok")

        entry = json.loads((tmp_path / "audit.log").read_text().strip())
        cmd = entry["params"]["cmd"]
        assert cmd["omitted"] is True
        assert cmd["length"] == len(long_cmd)
        assert cmd["prefix"] == long_cmd[:80]
        assert long_cmd not in json.dumps(entry)
        # short commands are logged verbatim (covered by test_audit_writes_jsonl)

    def test_audit_never_raises(self, tmp_path, monkeypatch):
        import hermes_mac_agent.daemon.server as server

        # Point at a path that can't be created (a file, not a dir); _audit must
        # swallow the resulting error rather than raise.
        blocker = tmp_path / "blocker"
        blocker.write_text("x")
        monkeypatch.setattr("hermes_mac_agent.daemon.server.CONFIG_DIR", blocker / "subdir")
        server._audit("call", "x", "y", {}, "ok")  # must not raise


# ---------------------------------------------------------------------------
# MCP run_command gate (F8)
# ---------------------------------------------------------------------------


class TestMcpRunCommandGate:
    """The MCP adapter must not expose run_command unless explicitly opted in."""

    def _build_tools(self, monkeypatch):
        """Build the MCP server with a stub server class and return {name: fn}.

        Stubs ``mcp.server.MCPServer`` (the mcp 2.x primary path). The adapter
        falls back to ``mcp.server.fastmcp.FastMCP`` for mcp 1.x, but the real
        environment is 2.x, so we exercise the primary import.
        """
        import sys
        import types

        import hermes_mac_agent.mcp_adapter as adapter

        registered: dict[str, object] = {}

        class _StubServer:
            def __init__(self, name):
                pass

            def tool(self, *a, **k):
                def deco(fn):
                    registered[fn.__name__] = fn
                    return fn

                return deco

        # Inject a fake mcp.server module exposing MCPServer (mcp 2.x).
        server_mod = types.ModuleType("mcp.server")
        server_mod.MCPServer = _StubServer
        mcp_mod = types.ModuleType("mcp")
        mcp_mod.server = server_mod
        monkeypatch.setitem(sys.modules, "mcp", mcp_mod)
        monkeypatch.setitem(sys.modules, "mcp.server", server_mod)
        monkeypatch.setenv("HERMES_MAC_HOST", "127.0.0.1")
        monkeypatch.setenv("HERMES_MAC_TOKEN", "x")

        adapter.build_mcp_server()
        return registered

    def test_run_command_gated_off(self, monkeypatch):
        monkeypatch.delenv("HERMES_MAC_ALLOW_RUN_COMMAND", raising=False)
        tools = self._build_tools(monkeypatch)
        assert "run_command" in tools  # registered, but...
        with pytest.raises(RuntimeError, match="HERMES_MAC_ALLOW_RUN_COMMAND"):
            tools["run_command"]("echo hi")

    def test_run_command_enabled(self, monkeypatch):
        monkeypatch.setenv("HERMES_MAC_ALLOW_RUN_COMMAND", "1")
        tools = self._build_tools(monkeypatch)
        # With the gate open it should attempt the (unreachable) agent call, not
        # raise the gate error.
        try:
            tools["run_command"]("echo hi")
        except RuntimeError as exc:
            assert "HERMES_MAC_ALLOW_RUN_COMMAND" not in str(exc)
        except Exception:
            pass  # connection error is fine — the gate was passed


class TestMcpFileTransferGate:
    """The MCP adapter must not expose read_file/write_file unless opted in."""

    def _build_tools(self, monkeypatch):
        import sys
        import types

        import hermes_mac_agent.mcp_adapter as adapter

        registered: dict[str, object] = {}

        class _StubServer:
            def __init__(self, name):
                pass

            def tool(self, *a, **k):
                def deco(fn):
                    registered[fn.__name__] = fn
                    return fn

                return deco

        server_mod = types.ModuleType("mcp.server")
        server_mod.MCPServer = _StubServer
        mcp_mod = types.ModuleType("mcp")
        mcp_mod.server = server_mod
        monkeypatch.setitem(sys.modules, "mcp", mcp_mod)
        monkeypatch.setitem(sys.modules, "mcp.server", server_mod)
        monkeypatch.setenv("HERMES_MAC_HOST", "127.0.0.1")
        monkeypatch.setenv("HERMES_MAC_TOKEN", "x")

        adapter.build_mcp_server()
        return registered

    def test_file_transfer_gated_off(self, monkeypatch):
        monkeypatch.delenv("HERMES_MAC_ALLOW_FILE_TRANSFER", raising=False)
        tools = self._build_tools(monkeypatch)
        assert "read_file" in tools
        assert "write_file" in tools
        with pytest.raises(RuntimeError, match="HERMES_MAC_ALLOW_FILE_TRANSFER"):
            tools["read_file"]("/etc/hosts")
        with pytest.raises(RuntimeError, match="HERMES_MAC_ALLOW_FILE_TRANSFER"):
            tools["write_file"]("/tmp/x", "aGk=")

    def test_file_transfer_enabled(self, monkeypatch):
        monkeypatch.setenv("HERMES_MAC_ALLOW_FILE_TRANSFER", "1")
        tools = self._build_tools(monkeypatch)
        # With the gate open it should attempt the (unreachable) agent call, not
        # raise the gate error.
        for name, args in (("read_file", ("/etc/hosts",)), ("write_file", ("/tmp/x", "aGk="))):
            try:
                tools[name](*args)
            except RuntimeError as exc:
                assert "HERMES_MAC_ALLOW_FILE_TRANSFER" not in str(exc)
            except Exception:
                pass  # connection error is fine — the gate was passed


# ---------------------------------------------------------------------------
# key_press validation & parameter coercion
# ---------------------------------------------------------------------------


class TestKeyPressValidation:
    """key_press must answer INVALID_PARAMS (with hints) for bad key input.

    The failed-agent pattern: a misspelled key like 'cmd+c' or 'retunr'
    reaches pyautogui, dies as FindKeyError → INTERNAL_ERROR, and agents
    (correctly) treat INTERNAL_ERROR as a daemon fault and retry forever.
    """

    def _stub(self, monkeypatch, *, key_names=None, press_raises=None):
        import types

        from hermes_mac_agent.daemon import tools

        calls = []

        def _record(name):
            def _fn(*args, **kwargs):
                calls.append((name, args, kwargs))
            return _fn

        stub = types.SimpleNamespace()
        for name in ("keyDown", "keyUp"):
            setattr(stub, name, _record(name))
        if key_names is not None:
            stub.KEY_NAMES = set(key_names)
        if press_raises is not None:
            def _boom(*a, **k):
                raise press_raises
            stub.keyDown = _boom
        stub.FindKeyError = getattr(press_raises, "__class__", Exception) \
            if press_raises is not None else Exception

        monkeypatch.setitem(sys.modules, "pyautogui", stub)
        monkeypatch.setattr(tools, "_require_accessibility", lambda: None)
        _quiet_sleeps(monkeypatch)
        return calls

    def test_alias_cmd_becomes_command(self, monkeypatch):
        calls = self._stub(monkeypatch)
        from hermes_mac_agent.daemon.tools import tool_key_press

        tool_key_press({"keys": ["cmd", "c"]})
        seq = [(name, args[0]) for name, args, _ in calls]
        assert seq == [
            ("keyDown", "command"), ("keyDown", "c"),
            ("keyUp", "c"), ("keyUp", "command"),
        ]

    def test_alias_control_becomes_ctrl_case_insensitive(self, monkeypatch):
        calls = self._stub(monkeypatch)
        from hermes_mac_agent.daemon.tools import tool_key_press

        tool_key_press({"keys": ["Control"]})
        assert calls[0][0] == "keyDown"
        assert calls[0][1] == ("ctrl",)

    def test_combo_in_one_string_rejected(self, monkeypatch):
        from hermes_mac_agent.daemon.tools import ToolError, tool_key_press

        self._stub(monkeypatch)
        with pytest.raises(ToolError) as exc:
            tool_key_press({"keys": ["cmd+c"]})
        assert exc.value.code == INVALID_PARAMS
        assert "combo" in str(exc.value)

    def test_unknown_key_rejected_with_suggestion(self, monkeypatch):
        from hermes_mac_agent.daemon.tools import ToolError, tool_key_press

        self._stub(monkeypatch, key_names=["return", "command", "escape"])
        with pytest.raises(ToolError) as exc:
            tool_key_press({"keys": ["retunr"]})
        assert exc.value.code == INVALID_PARAMS
        assert "retunr" in str(exc.value)
        assert "return" in str(exc.value)  # suggestion

    def test_known_key_passes_when_table_present(self, monkeypatch):
        calls = self._stub(monkeypatch, key_names=["return", "command"])
        from hermes_mac_agent.daemon.tools import tool_key_press

        tool_key_press({"keys": ["return"]})
        assert calls[0][1] == ("return",)

    def test_findkey_error_mapped_to_invalid_params(self, monkeypatch):
        from hermes_mac_agent.daemon import tools
        from hermes_mac_agent.daemon.tools import ToolError

        class FindKeyError(Exception):
            pass

        calls = self._stub(
            monkeypatch, press_raises=FindKeyError("retunr")
        )
        with pytest.raises(ToolError) as exc:
            tools.tool_key_press({"keys": ["retunr"]})  # no KEY_NAMES table
        assert exc.value.code == INVALID_PARAMS
        assert calls == []


class TestParamCoercion:
    """Numeric params accept JSON numbers/numeric strings; garbage → INVALID_PARAMS."""

    def _pa(self, monkeypatch):
        import types

        from hermes_mac_agent.daemon import tools

        calls = []

        def _record(name):
            def _fn(*args, **kwargs):
                calls.append((name, args, kwargs))
            return _fn

        stub = types.SimpleNamespace()
        for name in ("scroll", "hscroll", "click", "write", "moveTo",
                     "mouseDown", "mouseUp"):
            setattr(stub, name, _record(name))
        stub.position = _position_from_moves(calls)
        monkeypatch.setitem(sys.modules, "pyautogui", stub)
        monkeypatch.setattr(tools, "_require_accessibility", lambda: None)
        _quiet_sleeps(monkeypatch)
        _no_quartz(monkeypatch)
        return calls

    def test_scroll_numeric_string_accepted(self, monkeypatch):
        calls = self._pa(monkeypatch)
        from hermes_mac_agent.daemon.tools import tool_mouse_scroll

        tool_mouse_scroll({"dy": "5"})
        assert ("scroll", (5,), {}) in calls

    def test_scroll_garbage_is_invalid_params(self, monkeypatch):
        self._pa(monkeypatch)
        from hermes_mac_agent.daemon.tools import ToolError, tool_mouse_scroll

        with pytest.raises(ToolError) as exc:
            tool_mouse_scroll({"dy": "lots"})
        assert exc.value.code == INVALID_PARAMS

    def test_clicks_numeric_string_reaches_pyautogui(self, monkeypatch):
        calls = self._pa(monkeypatch)
        from hermes_mac_agent.daemon.tools import tool_mouse_click

        tool_mouse_click({"clicks": "2"})
        downs = [c for c in calls if c[0] == "mouseDown"]
        ups = [c for c in calls if c[0] == "mouseUp"]
        assert len(downs) == 2 and len(ups) == 2
        assert downs[0][2] == ups[0][2] == {"button": "left"}

    def test_clicks_garbage_is_invalid_params(self, monkeypatch):
        self._pa(monkeypatch)
        from hermes_mac_agent.daemon.tools import ToolError, tool_mouse_click

        with pytest.raises(ToolError) as exc:
            tool_mouse_click({"clicks": "two"})
        assert exc.value.code == INVALID_PARAMS

    def test_drag_duration_garbage_is_invalid_params(self, monkeypatch):
        self._pa(monkeypatch)
        from hermes_mac_agent.daemon.tools import ToolError, tool_mouse_drag

        with pytest.raises(ToolError) as exc:
            tool_mouse_drag({"x1": 1, "y1": 1, "x2": 2, "y2": 2, "duration": "slow"})
        assert exc.value.code == INVALID_PARAMS

    def test_bool_is_not_a_number(self, monkeypatch):
        self._pa(monkeypatch)
        from hermes_mac_agent.daemon.tools import ToolError, tool_mouse_click

        with pytest.raises(ToolError) as exc:
            tool_mouse_click({"clicks": True})
        assert exc.value.code == INVALID_PARAMS

    def test_pyautogui_failsafe_disabled_by_daemon(self, monkeypatch):
        import types

        from hermes_mac_agent.daemon import tools

        stub = types.SimpleNamespace(FAILSAFE=True, PAUSE=0.1)
        monkeypatch.setitem(sys.modules, "pyautogui", stub)
        tools._pyautogui()
        assert stub.FAILSAFE is False
        assert stub.PAUSE == 0


class TestInputPacing:
    """Human-scale event pacing (the machine-speed-defect fix).

    Bursts of machine-speed CGEvents get partially dropped on a loaded
    macOS: partial key-up loss sticks modifiers (later keys become system
    hotkeys) and button events overtake cursor warps (clicks land at the
    OLD cursor position). The tools must therefore verify cursor arrival
    before pressing, hold buttons, floor type intervals, and release every
    modifier they pressed — all asserted here deterministically.
    """

    def _stub(self, monkeypatch, *, position=None, raises_on=None):
        import types

        from hermes_mac_agent.daemon import tools

        calls, sleeps = [], []

        def _record(name):
            def _fn(*args, **kwargs):
                if raises_on and (name, args[0] if args else None) == raises_on:
                    raise RuntimeError(f"boom on {name} {args}")
                calls.append((name, args, kwargs))
            return _fn

        stub = types.SimpleNamespace()
        for name in ("moveTo", "dragTo", "mouseDown", "mouseUp", "keyDown", "keyUp",
                     "write", "scroll", "hscroll", "press", "hotkey"):
            setattr(stub, name, _record(name))
        stub.position = position or (lambda: (0, 0))

        monkeypatch.setitem(sys.modules, "pyautogui", stub)
        monkeypatch.setattr(tools, "_require_accessibility", lambda: None)
        monkeypatch.setattr(tools.time, "sleep", sleeps.append)
        _no_quartz(monkeypatch)
        return calls, sleeps

    # --- click -------------------------------------------------------------

    def test_click_warp_verified_before_button(self, monkeypatch):
        calls, sleeps = self._stub(monkeypatch, position=lambda: (983, 396))
        from hermes_mac_agent.daemon import tools

        result = tools.tool_mouse_click({"x": 983, "y": 396})
        names = [c[0] for c in calls]
        assert names == ["moveTo", "mouseDown", "mouseUp"]
        # settle BEFORE the press, hold while down, tail after release
        assert sleeps == [tools.CLICK_SETTLE, tools.CLICK_PRESS, tools.ACTION_TAIL]
        assert result == {"ok": True, "cursor": [983, 396]}

    def test_click_refuses_to_press_when_cursor_stuck(self, monkeypatch):
        calls, _ = self._stub(monkeypatch, position=lambda: (10, 10))
        from hermes_mac_agent.daemon import tools
        from hermes_mac_agent.protocol import INTERNAL_ERROR

        monkeypatch.setattr(tools, "CLICK_VERIFY_TIMEOUT", 0.05)
        monkeypatch.setattr(tools, "CLICK_VERIFY_POLL", 0.01)
        with pytest.raises(tools.ToolError) as exc:
            tools.tool_mouse_click({"x": 500, "y": 500})
        assert exc.value.code == INTERNAL_ERROR
        assert "cursor did not reach" in str(exc.value)
        # THE point of the check: no button events at the wrong position.
        assert [c[0] for c in calls] == ["moveTo"]

    def test_multiclick_has_gapped_presses(self, monkeypatch):
        calls, sleeps = self._stub(monkeypatch, position=lambda: (5, 5))
        from hermes_mac_agent.daemon import tools

        tools.tool_mouse_click({"x": 5, "y": 5, "clicks": 2})
        names = [c[0] for c in calls]
        assert names == ["moveTo", "mouseDown", "mouseUp", "mouseDown", "mouseUp"]
        # settle, press, gap, press, tail — gap keeps the double-click inside
        # the OS double-click window without tripping click-debounce.
        assert sleeps == [
            tools.CLICK_SETTLE, tools.CLICK_PRESS, tools.CLICK_MULTI_GAP,
            tools.CLICK_PRESS, tools.ACTION_TAIL,
        ]

    def test_drag_verifies_start_warp_before_grab(self, monkeypatch):
        calls, sleeps = self._stub(monkeypatch, position=lambda: (10, 10))
        from hermes_mac_agent.daemon import tools

        tools.tool_mouse_drag({"x1": 10, "y1": 10, "x2": 90, "y2": 90})
        names = [c[0] for c in calls]
        assert names == ["moveTo", "dragTo"]
        assert sleeps[0] == tools.CLICK_SETTLE  # verified before dragTo's mouseDown

    # --- typing ------------------------------------------------------------

    def test_type_interval_floored(self, monkeypatch):
        calls, _ = self._stub(monkeypatch)
        from hermes_mac_agent.daemon import tools

        tools.tool_type_text({"text": "hi", "interval": 0})
        write = next(c for c in calls if c[0] == "write")
        assert write[2]["interval"] == tools.TYPE_INTERVAL_FLOOR

    def test_type_interval_above_floor_passes_through(self, monkeypatch):
        calls, _ = self._stub(monkeypatch)
        from hermes_mac_agent.daemon import tools

        tools.tool_type_text({"text": "hi", "interval": 0.5})
        write = next(c for c in calls if c[0] == "write")
        assert write[2]["interval"] == 0.5

    # --- keyboard ----------------------------------------------------------

    def test_single_key_paced_press(self, monkeypatch):
        calls, sleeps = self._stub(monkeypatch)
        from hermes_mac_agent.daemon import tools

        tools.tool_key_press({"keys": ["a"]})
        assert [c[0] for c in calls] == ["keyDown", "keyUp"]
        assert sleeps == [tools.KEY_SETTLE, tools.ACTION_TAIL]

    def test_chord_releases_in_reverse_order(self, monkeypatch):
        calls, _ = self._stub(monkeypatch)
        from hermes_mac_agent.daemon import tools

        tools.tool_key_press({"keys": ["command", "shift", "3"]})
        seq = [(n, a[0]) for n, a, _ in calls]
        assert seq == [
            ("keyDown", "command"), ("keyDown", "shift"),
            ("keyDown", "3"), ("keyUp", "3"),
            ("keyUp", "shift"), ("keyUp", "command"),
        ]

    def test_chord_releases_modifiers_even_if_key_fails(self, monkeypatch):
        # A leaked modifier key-up poisons every later keystroke (stuck-mod
        # system hotkeys), so releases run in finally, not on the happy path.
        calls, _ = self._stub(monkeypatch, raises_on=("keyDown", "v"))
        from hermes_mac_agent.daemon.tools import tool_key_press

        with pytest.raises(RuntimeError):
            tool_key_press({"keys": ["command", "v"]})
        seq = [(n, a[0]) for n, a, _ in calls]
        assert ("keyUp", "command") in seq  # command released despite failure

    # --- percentage precision (user-mandated ≥5 decimals) -------------------

    def test_five_decimal_percentage_round_trips_to_exact_pixel(self, monkeypatch):
        # The documented agent pattern: measure (983,396) in a 1792x1120
        # screenshot, send round(px/w, 5); the daemon must integer-round
        # back to the exact pixel (0.00001 * 1792px = 0.02px error budget).
        calls = TestPercentageCoordinates()._stub(
            monkeypatch,
            [{"left": 0, "top": 0, "width": 1792, "height": 1120},
             {"left": 0, "top": 0, "width": 1792, "height": 1120}],
            1792, 1120,
        )
        from hermes_mac_agent.daemon.tools import tool_mouse_click

        tool_mouse_click({"x": round(983 / 1792, 5), "y": round(396 / 1120, 5)})
        move = next(c for c in calls if c[0] == "moveTo")
        assert move[1] == (983, 396)


class TestEventPipelineHygiene:
    """Clean keyboard event source (fn-latch) + real double-clicks (click state).

    Both defects measured on macbookpro-i9 (2026-11-14):
    - NULL-source chords (what pyautogui posts) re-assert the fn bit at the
      HID source: 40/40 chords latched fn, 0/40 from an explicit
      CGEventSource (and the source events were fully functional — keystrokes
      and selections confirmed via page beacons).
    - pyautogui's mouseDown/mouseUp never sets kCGMouseEventClickState:
      123 measured click pairs produced zero dblclick events (e.detail always
      1), so clicks=2 was never a double-click in any app.
    """

    def _fake_quartz(self, monkeypatch):
        import types

        from hermes_mac_agent.daemon import tools

        created, posts = [], []

        def _create_mouse(source, kind, pt, btn):
            evt = ["mouse", kind, pt, btn, source]
            created.append(evt)
            return evt

        def _create_kbd(source, key, down):
            evt = ["kbd", key, down, source]
            created.append(evt)
            return evt

        qz = types.SimpleNamespace(
            CGEventCreateMouseEvent=_create_mouse,
            CGEventCreateKeyboardEvent=_create_kbd,
            CGEventSourceCreate=lambda state: created.append(
                ["source", state]) or "SRC",
            CGEventSetIntegerValueField=lambda evt, field, val: created.append(
                ["field", evt, field, val]),
            CGEventPost=lambda tap, evt: posts.append((tap, evt)),
            kCGEventSourceStateCombinedSessionState=1,
            kCGMouseEventClickState=99,
            kCGHIDEventTap=0,
            kCGEventLeftMouseDown=1, kCGEventLeftMouseUp=2,
            kCGMouseButtonLeft=0,
            kCGEventRightMouseDown=3, kCGEventRightMouseUp=4,
            kCGMouseButtonRight=1,
            kCGEventOtherMouseDown=5, kCGEventOtherMouseUp=6,
            kCGMouseButtonMiddle=2,
        )
        monkeypatch.setattr(tools, "_quartz", lambda: qz)
        monkeypatch.setattr(tools, "_EVENT_SRC", None)
        return qz, created, posts

    def _fake_pa(self, monkeypatch):
        import types

        calls = []

        def _rec(name):
            def _fn(*a, **k):
                calls.append((name, a, k))
            return _fn

        pa = types.SimpleNamespace(
            moveTo=_rec("moveTo"), position=lambda: (5, 5),
            mouseDown=_rec("mouseDown"), mouseUp=_rec("mouseUp"),
        )
        for n in ("keyDown", "keyUp"):
            setattr(pa, n, _rec(n))
        pa.FAILSAFE = pa.PAUSE = None
        return pa, calls

    # --- keyboard source hook (fn-latch fix) --------------------------------

    def test_pyautogui_import_installs_the_hook(self, monkeypatch):
        from hermes_mac_agent.daemon import tools

        qz, created, _ = self._fake_quartz(monkeypatch)
        pa, _ = self._fake_pa(monkeypatch)
        monkeypatch.setitem(sys.modules, "pyautogui", pa)
        monkeypatch.setitem(sys.modules, "Quartz", qz)

        assert tools._pyautogui() is pa
        assert qz._hermes_kbd_hook is True

    def test_hook_routes_null_source_to_clean_source(self, monkeypatch):
        from hermes_mac_agent.daemon import tools

        qz, created, _ = self._fake_quartz(monkeypatch)
        assert tools.install_keyboard_source_hook(qz) is True
        assert tools.install_keyboard_source_hook(qz) is False  # idempotent

        qz.CGEventCreateKeyboardEvent(None, 56, True)   # pa's NULL-source call
        qz.CGEventCreateKeyboardEvent("explicit", 56, False)

        assert created[0] == ["source", qz.kCGEventSourceStateCombinedSessionState]
        assert created[1][3] == "SRC"          # NULL replaced by our source
        assert created[2][3] == "explicit"     # explicit source passes through

    def test_hook_survives_pa_keydown_call_shape(self, monkeypatch):
        # The wrapper must keep pa's exact 3-positional-arg call signature.
        from hermes_mac_agent.daemon import tools

        qz, created, _ = self._fake_quartz(monkeypatch)
        tools.install_keyboard_source_hook(qz)
        qz.CGEventCreateKeyboardEvent(None, 0, True)   # keyDown('a') shape
        assert created[1][:3] == ["kbd", 0, True]

    # --- button click state (double-click fix) -------------------------------

    def test_double_click_tags_both_halves_with_click_state(self, monkeypatch):
        from hermes_mac_agent.daemon import tools

        _, created, posts = self._fake_quartz(monkeypatch)
        pa, _ = self._fake_pa(monkeypatch)
        monkeypatch.setattr(tools, "_pyautogui", lambda: pa)
        monkeypatch.setattr(tools, "_require_accessibility", lambda: None)

        tools.tool_mouse_click({"x": 5, "y": 5, "clicks": 2})

        kinds = [c[1] for c in created if c[0] == "mouse"]
        assert kinds == [
            1, 2, 1, 2,  # LeftDown, LeftUp, LeftDown, LeftUp
        ]
        states = [c[3] for c in created if c[0] == "field"]
        assert states == [1, 1, 2, 2]  # down+up of click 1, then of click 2
        assert all(c[4] == "SRC" for c in created if c[0] == "mouse")
        assert [posts[i][1][0] for i in range(4)] == ["mouse"] * 4
        assert [posts[i][0] for i in range(4)] == [0] * 4  # posted to HID tap

    def test_third_click_state_increments(self, monkeypatch):
        from hermes_mac_agent.daemon import tools

        _, created, _ = self._fake_quartz(monkeypatch)
        pa, _ = self._fake_pa(monkeypatch)
        monkeypatch.setattr(tools, "_pyautogui", lambda: pa)
        monkeypatch.setattr(tools, "_require_accessibility", lambda: None)

        tools.tool_mouse_click({"x": 5, "y": 5, "clicks": 3})
        assert [c[3] for c in created if c[0] == "field"] == [1, 1, 2, 2, 3, 3]

    def test_right_button_uses_right_event_kinds(self, monkeypatch):
        from hermes_mac_agent.daemon import tools

        _, created, _ = self._fake_quartz(monkeypatch)
        pa, _ = self._fake_pa(monkeypatch)
        monkeypatch.setattr(tools, "_pyautogui", lambda: pa)
        monkeypatch.setattr(tools, "_require_accessibility", lambda: None)

        tools.tool_mouse_click({"x": 5, "y": 5, "button": "right"})
        kinds = [c[1] for c in created if c[0] == "mouse"]
        assert kinds == [3, 4]  # RightDown, RightUp

    def test_no_quartz_falls_back_to_pyautogui_button(self, monkeypatch):
        # Non-macOS dev/test only (pyautogui hard-requires Quartz on macOS):
        # clicks must still work, just without CG-level click state.
        from hermes_mac_agent.daemon import tools
        from hermes_mac_agent.protocol import INTERNAL_ERROR

        def _raise():
            raise tools.ToolError(INTERNAL_ERROR, "Quartz unavailable")

        monkeypatch.setattr(tools, "_quartz", _raise)
        pa, calls = self._fake_pa(monkeypatch)
        monkeypatch.setattr(tools, "_pyautogui", lambda: pa)
        monkeypatch.setattr(tools, "_require_accessibility", lambda: None)

        tools.tool_mouse_click({"x": 5, "y": 5, "clicks": 2})
        assert [c[0] for c in calls if c[0].startswith("mouse")] == [
            "mouseDown", "mouseUp", "mouseDown", "mouseUp",
        ]
