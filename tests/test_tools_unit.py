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

        for name in ("moveTo", "dragTo", "drag", "press", "hotkey"):
            setattr(stub, name, _record(name))

        monkeypatch.setitem(sys.modules, "pyautogui", stub)
        monkeypatch.setattr(tools, "_require_accessibility", lambda: None)
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

    def test_key_press_single_key_uses_press(self, monkeypatch):
        # M4: a single key is a press, not a hotkey.
        calls = self._stub_pyautogui(monkeypatch)
        from hermes_mac_agent.daemon.tools import tool_key_press

        tool_key_press({"keys": ["return"]})
        assert [c[0] for c in calls] == ["press"]
        assert calls[0][1] == ("return",)

    def test_key_press_combo_uses_hotkey(self, monkeypatch):
        calls = self._stub_pyautogui(monkeypatch)
        from hermes_mac_agent.daemon.tools import tool_key_press

        tool_key_press({"keys": ["command", "c"]})
        assert [c[0] for c in calls] == ["hotkey"]
        assert calls[0][1] == ("command", "c")


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
