"""Screen capture over the wire.

Requires macOS + Screen Recording TCC permission for the Python running the
daemon (here: the pytest process). Skips gracefully otherwise.
"""

from __future__ import annotations

import io

import pytest

from hermes_mac_agent.client import MacAgentError, TccPermissionError


@pytest.mark.gui
class TestScreenshot:
    def test_returns_decodable_png(self, client, gui_ok):
        data = client.screenshot_bytes()
        assert data[:8] == b"\x89PNG\r\n\x1a\n"
        img = client.screenshot()
        assert img.size[0] > 0 and img.size[1] > 0
        assert img.mode == "RGB"

    def test_dimensions_match_monitor(self, client, gui_ok):
        result = client.screenshot_bytes()
        from PIL import Image

        img = Image.open(io.BytesIO(result))
        # A real Mac display is at least 720p-ish in at least one dimension.
        assert max(img.size) >= 720

    def test_bad_monitor_param(self, client, gui_ok):
        with pytest.raises(MacAgentError) as exc:
            client.screenshot(monitor=-1)
        assert exc.value.code == -32602  # INVALID_PARAMS


class TestScreenshotWithoutTcc:
    """When Screen Recording is not granted, the daemon must return a clean
    TCC error (not crash, not hang)."""

    def test_tcc_error_code(self, client):
        try:
            screen_granted = client.health()["perms"]["screen"]
        except Exception:
            screen_granted = False
        if screen_granted:
            pytest.skip("Screen Recording granted — covered by TestScreenshot")
        with pytest.raises(TccPermissionError) as exc:
            client.screenshot()
        assert exc.value.code == -32003  # TCC_PERMISSION_DENIED
