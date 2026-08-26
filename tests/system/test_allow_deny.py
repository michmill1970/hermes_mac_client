"""Allow/deny policy enforcement over the wire.

The session daemon runs with:
  allowlist: ls, echo *, sleep *, pgrep *, pwd, uname *
  denylist:  sudo, rm *
"""

from __future__ import annotations

import pytest

from hermes_mac_agent.client import BlockedByPolicyError
from hermes_mac_agent.protocol import BLOCKED_BY_POLICY


class TestDenylist:
    def test_sudo_blocked(self, client):
        with pytest.raises(BlockedByPolicyError) as exc:
            client.run_command("sudo ls")
        assert exc.value.code == BLOCKED_BY_POLICY
        assert "denylist" in str(exc.value)

    def test_rm_blocked(self, client):
        with pytest.raises(BlockedByPolicyError):
            client.run_command("rm -rf /tmp/whatever")

    def test_denylist_wins_over_allowlist(self, client):
        # "echo *" is allowed, but "sudo echo hi" must still be denied.
        with pytest.raises(BlockedByPolicyError):
            client.run_command("sudo echo hi")


class TestAllowlist:
    def test_allowed_command_runs(self, client):
        result = client.run_command("echo hello-policy")
        assert result["exit_code"] == 0
        assert result["stdout"].strip() == "hello-policy"

    def test_unlisted_command_blocked(self, client):
        # "date" is in neither list → allowlist (no "*") blocks it.
        with pytest.raises(BlockedByPolicyError) as exc:
            client.run_command("date")
        assert "allowlist" in str(exc.value)

    def test_glob_pattern_matches(self, client):
        result = client.run_command("echo a b c")
        assert result["stdout"].strip() == "a b c"

    def test_launch_app_policy(self, client):
        # App names are checked against the same lists; "Safari" is unlisted.
        with pytest.raises(BlockedByPolicyError):
            client.launch_app("Safari")


class TestErrorShape:
    def test_blocked_error_carries_data(self, raw_ws):
        import json

        raw_ws.send(json.dumps({"id": 5, "method": "run_command", "params": {"cmd": "sudo ls"}}))
        reply = json.loads(raw_ws.recv())
        err = reply["error"]
        assert err["code"] == BLOCKED_BY_POLICY
        assert err["data"]["list"] == "denylist"
        assert err["data"]["matched"] == "sudo"
