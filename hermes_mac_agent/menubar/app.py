"""macOS menubar host for the hermes-mac daemon.

Why a menubar app?
  macOS TCC (Screen Recording / Accessibility) attributes permissions to the
  *responsible process* — the app that owns the process tree. Running the
  daemon from a terminal binds the grants to your terminal (or the raw Python
  binary), which is fragile: a new venv or interpreter upgrade resets them.
  Running the daemon inside ``HermesMacAgent.app`` scopes the grants to the
  app's code-signing identity, which is stable across daemon restarts and
  config changes, and revoking the app's permission is a clean kill switch.

The Hermes side is unchanged: it still dials ``wss://mac:8765`` with the token.

Layout:
  * :class:`ServerController` — plain-Python owner of the daemon (background
    asyncio thread). No PyObjC dependency, fully unit-testable.
  * :func:`main` — the PyObjC menubar UI (NSStatusItem + menu). PyObjC is
    imported lazily here so the module imports cleanly on non-macOS hosts and
    in test environments without pyobjc installed.

Build a real .app with ``scripts/build_app.sh`` (PyInstaller + ad-hoc sign).
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
import sys
import threading
from typing import Any

from hermes_mac_agent.daemon.config import CONFIG_DIR, Config
from hermes_mac_agent.daemon.server import start_server
from hermes_mac_agent.daemon.tools import (
    _accessibility_granted,
    _prompt_accessibility,
    _prompt_screen_recording,
    _screen_recording_granted,
)

log = logging.getLogger("hermes_mac_agent.menubar")

# System Settings deep links (open the exact TCC pane).
SCREEN_SETTINGS_URL = (
    "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture"
)
ACCESSIBILITY_SETTINGS_URL = (
    "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility"
)


class ServerController:
    """Runs the daemon on a background asyncio thread.

    Deliberately free of any AppKit/PyObjC dependency so it can be unit-tested
    (and reused by a future non-GUI host). Thread-safety: ``start``/``stop``
    are expected to be called from the main (UI) thread only.
    """

    def __init__(self, config: Config | None = None) -> None:
        self.config = config
        self.error: str | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server: Any = None
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    @property
    def running(self) -> bool:
        return (
            self._server is not None
            and self._thread is not None
            and self._thread.is_alive()
        )

    def status(self) -> dict[str, Any]:
        """Snapshot for the menu: running flag, bind address, last error."""
        port: int | None = None
        if self._server is not None:
            try:
                port = next(iter(self._server.sockets)).getsockname()[1]
            except (StopIteration, OSError):
                port = None
        config = self.config
        return {
            "running": self.running,
            "host": config.host if config else None,
            "port": port,
            "error": self.error,
        }

    def perms(self) -> dict[str, bool]:
        """Current TCC permission state (best-effort; False off macOS)."""
        return {
            "screen": _screen_recording_granted(),
            "accessibility": _accessibility_granted(),
        }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the daemon in a background thread. Sets ``self.error`` on failure."""
        if self.running:
            return
        self.config = self.config or Config.load()
        self.error = None

        ready = threading.Event()
        holder: dict[str, Any] = {}

        def _run() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                server = loop.run_until_complete(start_server(self.config))
                holder["server"] = server
                holder["loop"] = loop
                ready.set()
                loop.run_forever()
            except Exception as exc:  # noqa: BLE001 - surfaced via self.error
                holder["error"] = exc
                ready.set()
            finally:
                try:
                    loop.run_until_complete(loop.shutdown_asyncgens())
                except Exception:  # pragma: no cover - best effort
                    pass
                loop.close()

        self._thread = threading.Thread(target=_run, name="hermes-mac-daemon", daemon=True)
        self._thread.start()
        ready.wait(timeout=15)

        if "error" in holder:
            self.error = str(holder["error"])
            self._thread = None
            log.error("daemon failed to start: %s", self.error)
            return
        self._loop = holder["loop"]
        self._server = holder["server"]
        log.info("daemon started (host=%s port=%s)", self.config.host, self.config.port)

    def stop(self) -> None:
        """Stop the daemon and join the worker thread."""
        loop, server = self._loop, self._server
        self._loop = None
        self._server = None
        if loop is not None and server is not None:
            try:
                asyncio.run_coroutine_threadsafe(server.close(), loop).result(timeout=5)
            except Exception:  # noqa: BLE001 - shutdown is best-effort
                pass
            loop.call_soon_threadsafe(loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        log.info("daemon stopped")


# ----------------------------------------------------------------------
# Menubar UI (PyObjC — imported lazily so the module is importable anywhere)
# ----------------------------------------------------------------------


def _open_url(url: str) -> None:
    subprocess.run(["open", url], check=False)


def _open_path(path: str, reveal: bool = False) -> None:
    cmd = ["open", "-R", path] if reveal else ["open", path]
    subprocess.run(cmd, check=False)


def main() -> None:
    """Launch the menubar app. macOS + pyobjc-framework-Cocoa required."""
    if sys.platform != "darwin":
        raise SystemExit("the menubar app only runs on macOS")
    try:
        from AppKit import (
            NSApplication,
            NSApplicationActivationPolicyAccessory,
            NSMenu,
            NSMenuItem,
            NSRunLoopCommonModes,
            NSStatusBar,
            NSVariableStatusItemLength,
        )
        from Foundation import NSRunLoop, NSObject, NSTimer
    except ImportError as exc:
        raise SystemExit(
            f"pyobjc-framework-Cocoa is required for the menubar app: {exc}\n"
            'Install it with:  pip install -e ".[menubar]"'
        ) from exc

    controller = ServerController()

    def _add_item(menu, target, title, action=None, enabled=True):
        item = menu.addItemWithTitle_action_keyEquivalent_(title, action, "")
        item.setEnabled_(enabled)
        if action is not None:
            item.setTarget_(target)

    def _rebuild_menu(status_item, menu, target) -> None:
        menu.removeAllItems()
        st = controller.status()
        perms = controller.perms()

        if st["running"]:
            status_item.button().setTitle_("●")
            _add_item(menu, target, f"Running on {st['host']}:{st['port']}", enabled=False)
        else:
            status_item.button().setTitle_("○")
            detail = f"Stopped — {st['error']}" if st["error"] else "Stopped"
            _add_item(menu, target, detail, enabled=False)

        _add_item(
            menu, target,
            f"Screen Recording: {'granted' if perms['screen'] else 'MISSING'}",
            enabled=False,
        )
        _add_item(
            menu, target,
            f"Accessibility: {'granted' if perms['accessibility'] else 'MISSING'}",
            enabled=False,
        )

        menu.addItem_(NSMenuItem.separatorItem())
        _add_item(menu, target, "Stop server" if st["running"] else "Start server", "toggleServer:")
        if not (perms["screen"] and perms["accessibility"]):
            # Triggers the system TCC dialogs (they only appear when the app
            # actually *requests* the permission, never on preflight checks).
            _add_item(menu, target, "Grant permissions…", "grantPermissions:")
        _add_item(menu, target, "Open Screen Recording settings", "openScreenSettings:")
        _add_item(menu, target, "Open Accessibility settings", "openAccessibilitySettings:")

        menu.addItem_(NSMenuItem.separatorItem())
        _add_item(menu, target, "Open config.json", "openConfig:")
        _add_item(menu, target, "Open audit log", "openAuditLog:")
        _add_item(menu, target, "Reveal config folder", "revealConfigDir:")

        menu.addItem_(NSMenuItem.separatorItem())
        _add_item(menu, target, "Quit Hermes Mac Agent", "quit:")

    class MenuDelegate(NSObject):
        def applicationDidFinishLaunching_(self, _notification) -> None:
            status_item = (
                NSStatusBar.systemStatusBar()
                .statusItemWithLength_(NSVariableStatusItemLength)
            )
            self.status_item = status_item
            self.menu = NSMenu.alloc().init()
            self.menu.setDelegate_(self)
            status_item.setMenu_(self.menu)
            self._menu_open = False

            # Refresh status/permission lines every 2s. The timer runs in
            # NSRunLoopCommonModes so it also fires during menu tracking, but
            # tick_ skips the rebuild while the menu is open — rebuilding
            # under the user's cursor would flicker/close the menu before
            # they can click an item (e.g. Quit).
            timer = NSTimer.scheduledTimerWithTimeInterval_target_selector_userInfo_repeats_(
                2.0, self, "tick:", None, True
            )
            NSRunLoop.currentRunLoop().addTimer_forMode_(timer, NSRunLoopCommonModes)

            # Auto-start the daemon; failures surface in the menu.
            controller.start()
            _rebuild_menu(self.status_item, self.menu, self)

            # TCC only shows its dialogs when the app *requests* a
            # permission (preflight checks never prompt). Ask for any
            # missing grants right after launch so the user sees the
            # system dialogs immediately.
            self._prompt_missing_permissions()

        def _prompt_missing_permissions(self) -> None:
            if not _screen_recording_granted():
                _prompt_screen_recording()
            if not _accessibility_granted():
                _prompt_accessibility()

        # -- NSMenuDelegate: track open state so tick_ doesn't rebuild
        #    the menu out from under the user's cursor -------------------

        def menuWillOpen_(self, _notification) -> None:
            self._menu_open = True
            _rebuild_menu(self.status_item, self.menu, self)

        def menuDidClose_(self, _notification) -> None:
            self._menu_open = False

        def tick_(self, _timer) -> None:
            if self._menu_open:
                return
            _rebuild_menu(self.status_item, self.menu, self)

        # -- actions ------------------------------------------------------

        def toggleServer_(self, _sender) -> None:
            if controller.running:
                controller.stop()
            else:
                controller.start()
            _rebuild_menu(self.status_item, self.menu, self)

        def grantPermissions_(self, _sender) -> None:
            self._prompt_missing_permissions()

        def openScreenSettings_(self, _sender) -> None:
            _open_url(SCREEN_SETTINGS_URL)

        def openAccessibilitySettings_(self, _sender) -> None:
            _open_url(ACCESSIBILITY_SETTINGS_URL)

        def openConfig_(self, _sender) -> None:
            _open_path(str(CONFIG_DIR / "config.json"))

        def openAuditLog_(self, _sender) -> None:
            _open_path(str(CONFIG_DIR / "audit.log"))

        def revealConfigDir_(self, _sender) -> None:
            _open_path(str(CONFIG_DIR), reveal=True)

        def quit_(self, _sender) -> None:
            controller.stop()
            NSApplication.sharedApplication().terminate_(None)

    app = NSApplication.sharedApplication()
    app.setActivationPolicy_(NSApplicationActivationPolicyAccessory)  # no Dock icon
    app.setDelegate_(MenuDelegate.alloc().init())
    app.run()


if __name__ == "__main__":
    main()
