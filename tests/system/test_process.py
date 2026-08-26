"""Process lifecycle over the wire: run_command, list_processes, stop_process."""

from __future__ import annotations

import subprocess
import time

import pytest

from hermes_mac_agent.client import MacAgentError
from hermes_mac_agent.protocol import COMMAND_TIMEOUT, PROCESS_NOT_FOUND


class TestRunCommand:
    def test_echo(self, client):
        result = client.run_command("echo system-ok")
        assert result["exit_code"] == 0
        assert result["stdout"].strip() == "system-ok"

    def test_exit_code_propagates(self, client):
        result = client.run_command("pwd")
        assert result["exit_code"] == 0
        assert result["stdout"].strip()

    def test_timeout_kills_process(self, client):
        start = time.monotonic()
        with pytest.raises(MacAgentError) as exc:
            client.run_command("sleep 30", timeout=1.0)
        elapsed = time.monotonic() - start
        assert exc.value.code == COMMAND_TIMEOUT
        assert elapsed < 10, "timeout did not fire promptly"

    def test_cwd(self, client, tmp_path):
        result = client.run_command("pwd", cwd=str(tmp_path))
        assert result["stdout"].strip() == str(tmp_path)


class TestListProcesses:
    def test_lists_current_process(self, client):
        procs = client.list_processes()
        pids = [p["pid"] for p in procs]
        assert len(pids) > 0
        assert 1 in pids  # launchd / init

    def test_filter(self, client):
        procs = client.list_processes(filter="python")
        assert all("python" in p["name"].lower() for p in procs)


class TestStopProcess:
    def test_kill_spawned_process(self, client):
        # Spawn a real long-running process directly, then kill it via the daemon.
        proc = subprocess.Popen(["sleep", "60"])
        try:
            client.stop_process(proc.pid)
            assert proc.wait(timeout=5) is not None  # returns once it exits
            remaining = client.list_processes(filter="sleep")
            assert all(p["pid"] != proc.pid for p in remaining)
        finally:
            if proc.poll() is None:
                proc.kill()

    def test_stop_missing_process(self, client):
        with pytest.raises(MacAgentError) as exc:
            client.stop_process(2**22 - 1)
        assert exc.value.code == PROCESS_NOT_FOUND
