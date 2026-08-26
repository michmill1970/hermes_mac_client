"""GUI input (mouse + keyboard) over the wire.

These tests ACTUALLY move the mouse and type on the Mac. They are marked
``gui`` and only run when:
  - on macOS, and
  - both TCC permissions (Screen Recording + Accessibility) are granted.

Run them explicitly with:  pytest -m gui
They are excluded from the default run (see pyproject addopts).
"""

from __future__ import annotations

import pytest

from hermes_mac_agent.client import MacAgentError

pytestmark = pytest.mark.gui


class TestMouse:
    def test_move_and_click(self, client, gui_ok):
        # Move to a harmless spot (top-left corner) and click there.
        client.mouse_move(5, 5)
        client.mouse_click(5, 5)

    def test_scroll(self, client, gui_ok):
        client.mouse_scroll(dx=0, dy=-3)

    def test_drag(self, client, gui_ok):
        client.mouse_drag(10, 10, 60, 60)

    def test_secondary_monitor_coordinates(self, client, gui_ok):
        # Global coordinates: origin is the primary display's top-left, so
        # monitors to the left/above it use negative coordinates. Moving the
        # cursor into such a monitor must succeed (no clamping, no error).
        from mss import MSS

        with MSS() as sct:
            monitors = [dict(m) for m in sct.monitors[1:]]  # skip virtual screen
        secondary = [m for m in monitors if m["left"] < 0 or m["top"] < 0]
        if not secondary:
            pytest.skip("no secondary monitor positioned left/above the primary")
        m = secondary[0]
        client.mouse_move(m["left"] + 10, m["top"] + 10)

    def test_bad_button_rejected(self, client, gui_ok):
        with pytest.raises(MacAgentError) as exc:
            client.mouse_click(5, 5, button="sideways")
        assert exc.value.code == -32602  # INVALID_PARAMS


class TestKeyboard:
    def test_type_text(self, client, gui_ok):
        # Types into whatever has focus — run only when you're watching.
        client.type_text("hermes-mac-agent-test")

    def test_key_press(self, client, gui_ok):
        # Cmd+Shift+3 is the macOS "screenshot to file" shortcut — harmless.
        client.key_press(["command", "shift", "3"])

    def test_bad_keys_rejected(self, client, gui_ok):
        with pytest.raises(MacAgentError) as exc:
            client.key_press([])
        assert exc.value.code == -32602
