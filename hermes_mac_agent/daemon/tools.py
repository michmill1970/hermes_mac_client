"""Tool implementations for the daemon.

Each handler has the signature ``handler(params: dict) -> dict`` and raises
:class:`ToolError` (mapped to a JSON-RPC error code) on failure.

GUI libraries (``mss``, ``pyautogui``) are imported lazily inside handlers so
that the daemon — and the unit tests — can be imported on machines without a
GUI session.
"""

from __future__ import annotations

import base64
import binascii
import io
import os
import selectors
import shlex
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

import psutil

from hermes_mac_agent.daemon.config import Config, PolicyBlockedError
from hermes_mac_agent.protocol import (
    COMMAND_TIMEOUT,
    FILE_CHUNK_SIZE,
    INTERNAL_ERROR,
    INVALID_PARAMS,
    MAX_COMMAND_TIMEOUT,
    MAX_FILE_SIZE,
    PROCESS_NOT_FOUND,
    TCC_PERMISSION_DENIED,
)

Handler = Callable[[dict[str, Any]], dict[str, Any]]


class ToolError(Exception):
    """Tool-level failure carrying a JSON-RPC error code."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        self.code = code
        self.data = data
        super().__init__(message)


# ---------------------------------------------------------------------------
# macOS TCC preflight (ctypes, no extra deps)
# ---------------------------------------------------------------------------

def _screen_recording_granted() -> bool:
    """CGPreflightScreenCaptureAccess — True if Screen Recording is granted."""
    if sys.platform != "darwin":
        return True
    try:
        from ctypes import CDLL, c_bool

        cg = CDLL("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics")
        cg.CGPreflightScreenCaptureAccess.restype = c_bool
        return bool(cg.CGPreflightScreenCaptureAccess())
    except (OSError, AttributeError):
        return True  # cannot determine; let the capture attempt decide


def _accessibility_granted() -> bool:
    """AXIsProcessTrusted — True if Accessibility is granted."""
    if sys.platform != "darwin":
        return True
    try:
        from ctypes import CDLL, c_bool

        app_services = CDLL(
            "/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices"
        )
        app_services.AXIsProcessTrusted.restype = c_bool
        return bool(app_services.AXIsProcessTrusted())
    except (OSError, AttributeError):
        return True


def _prompt_screen_recording() -> bool:
    """Trigger the system Screen Recording prompt if not yet granted.

    Uses ``CGRequestScreenCaptureAccess`` (macOS 10.15+), which shows the
    TCC dialog and returns the current grant state. Returns True if
    permission is (now) granted.
    """
    if sys.platform != "darwin":
        return True
    if _screen_recording_granted():
        return True
    try:
        from ctypes import CDLL, c_bool

        cg = CDLL("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics")
        cg.CGRequestScreenCaptureAccess.restype = c_bool
        return bool(cg.CGRequestScreenCaptureAccess())
    except (OSError, AttributeError):
        return _screen_recording_granted()


def _prompt_accessibility() -> bool:
    """Trigger the system Accessibility prompt if not yet granted.

    Uses ``AXIsProcessTrustedWithOptions`` with ``kAXTrustedCheckOptionPrompt``
    (the non-preflight variant of :func:`_accessibility_granted`, which never
    prompts). Returns True if permission is (now) granted.
    """
    if sys.platform != "darwin":
        return True
    if _accessibility_granted():
        return True
    # Preferred path: PyObjC. It bridges the CFDictionary through the same
    # CoreFoundation runtime the process is already using, so it works both in
    # the venv and inside the PyInstaller bundle (which ships its own
    # CoreFoundation — raw ctypes CDLL to the *system* framework hits a CF
    # instance mismatch and segfaults in CFGetTypeID).
    #
    # HIServices is the C extension that is reliably bundled by PyInstaller;
    # ApplicationServices is a thin pure-Python re-export of it. Try both.
    for _mod in ("HIServices", "ApplicationServices"):
        try:
            mod = __import__(_mod)
            return bool(
                mod.AXIsProcessTrustedWithOptions(
                    {mod.kAXTrustedCheckOptionPrompt: True}
                )
            )
        except Exception:
            continue
    return _accessibility_granted()


def _require_screen() -> None:
    if not _screen_recording_granted():
        raise ToolError(
            TCC_PERMISSION_DENIED,
            "Screen Recording permission not granted. Grant it in "
            "System Settings → Privacy & Security → Screen Recording for the "
            "Python interpreter running this daemon, then restart the daemon.",
        )


def _require_accessibility() -> None:
    if not _accessibility_granted():
        raise ToolError(
            TCC_PERMISSION_DENIED,
            "Accessibility permission not granted. Grant it in "
            "System Settings → Privacy & Security → Accessibility for the "
            "Python interpreter running this daemon, then restart the daemon.",
        )


def _pyautogui():
    try:
        import pyautogui
    except Exception as exc:  # pragma: no cover - import failure
        raise ToolError(INTERNAL_ERROR, f"pyautogui unavailable: {exc}") from exc
    # pyautogui's failsafe raises FailSafeException when an action targets
    # (0,0)..(FAILSAFEPOINT,FAILSAFEPOINT). For an interactive desktop script
    # it's an escape hatch; for a *headless remote daemon* it is a pure defect:
    # the Apple menu and hot-corner controls live at x=0, so legitimate clicks
    # there (a) die with an opaque INTERNAL_ERROR after earlier events of the
    # same call already executed (e.g. mouse_drag moveTo's to (0,0), *raises
    # mid-drag* and leaves pyautogui holding the mouse button), and (b) there
    # is no operator with Ctrl+C on that machine to abort anything anyway.
    # PAUSE is likewise dead weight: the daemon is strictly sequential.
    pyautogui.FAILSAFE = False
    pyautogui.PAUSE = 0
    # fn-latch fix (see the event-pipeline hygiene note): pyautogui's
    # NULL-source keyboard events inherit the session's modifier flags;
    # install once, keep going on platforms without Quartz.
    try:
        import Quartz

        install_keyboard_source_hook(Quartz)
    except ImportError:  # pragma: no cover - only on non-macOS
        pass
    return pyautogui


# ---------------------------------------------------------------------------
# Param coercion
# ---------------------------------------------------------------------------


def _num_int(params: dict[str, Any], name: str, default: int) -> int:
    """int param tolerating numeric JSON (2.0) and numeric strings.

    A raw int()/float() TypeError/ValueError escaping a handler surfaces as
    INTERNAL_ERROR, which agents (correctly) treat as a daemon fault and
    retry forever. Bad parameter values must answer INVALID_PARAMS.
    """
    val = params.get(name, default)
    if isinstance(val, bool):
        raise ToolError(INVALID_PARAMS, f"'{name}' must be a number, got {val!r}")
    try:
        return int(val)
    except (TypeError, ValueError):
        raise ToolError(INVALID_PARAMS, f"'{name}' must be a number, got {val!r}") from None


def _num_float(params: dict[str, Any], name: str, default: float) -> float:
    val = params.get(name, default)
    if isinstance(val, bool):
        raise ToolError(INVALID_PARAMS, f"'{name}' must be a number, got {val!r}")
    try:
        return float(val)
    except (TypeError, ValueError):
        raise ToolError(INVALID_PARAMS, f"'{name}' must be a number, got {val!r}") from None


# ---------------------------------------------------------------------------
# Screen
# ---------------------------------------------------------------------------

def tool_screenshot(params: dict[str, Any]) -> dict[str, Any]:
    monitor = params.get("monitor", 1)
    if not isinstance(monitor, int) or isinstance(monitor, bool) or monitor < 0:
        raise ToolError(INVALID_PARAMS, "'monitor' must be a non-negative integer (0 = all monitors)")
    _require_screen()
    try:
        from mss import MSS
        from PIL import Image
    except Exception as exc:  # pragma: no cover - import failure
        raise ToolError(INTERNAL_ERROR, f"mss/Pillow unavailable: {exc}") from exc

    with MSS() as sct:
        if monitor == 0:
            raw = sct.grab(sct.monitors[0])  # all monitors
        else:
            if monitor >= len(sct.monitors):
                raise ToolError(
                    INVALID_PARAMS, f"monitor {monitor} does not exist (1..{len(sct.monitors) - 1})"
                )
            raw = sct.grab(sct.monitors[monitor])
        img = Image.frombytes("RGB", raw.size, raw.bgra, "raw", "BGRX")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return {
        "png_base64": base64.b64encode(buf.getvalue()).decode("ascii"),
        "width": img.width,
        "height": img.height,
    }


# ---------------------------------------------------------------------------
# Input pacing (human-scale event timing)
# ---------------------------------------------------------------------------
#
# macOS queues synthetic input exactly like real HID input. Events posted in a
# machine-speed burst — a cursor warp and the button event in the same
# microsecond, or 44 keystrokes at 20 ms apart on a busy machine — outrun the
# WindowServer session queue and the target app's run loop, and parts of the
# stream get dropped. The failures are stateful and ugly: a dropped key-UP
# leaves the modifier stuck (the next ordinary keystrokes become system
# hotkeys — double Control opens the Dictation dialog, Ctrl+Cmd+Space the
# Character Viewer), and a button event processed before the warp lands
# clicks wherever the cursor *was*. Measured on a loaded test laptop: 2 of 22
# keystrokes delivered at interval=0, and clicks landing ~100 px off.
#
# These floors put a human scale on the event pipeline. They are minimums
# (smaller explicit values are raised to them), not padding: each sleep is
# the smallest gap that measured clean delivery across the click/scroll/type
# batteries, and callers still verify every action's effect with a screenshot.
CLICK_SETTLE = 0.05     # cursor arrival verified -> mouseDown
CLICK_PRESS = 0.04      # mouseDown -> mouseUp (button hold)
CLICK_MULTI_GAP = 0.12  # mouseUp -> next mouseDown (above click-debounce,
                        # well inside the double-click window)
CLICK_VERIFY_TIMEOUT = 1.0   # bound for cursor-arrival verification
CLICK_VERIFY_POLL = 0.01
KEY_SETTLE = 0.02       # keyDown -> keyUp (and chord key gaps)
TYPE_INTERVAL_FLOOR = 0.02   # minimum per-character interval for type_text
ACTION_TAIL = 0.03      # after the last event of a call, so the next call's
                        # events start on a quiet pipeline


# ---------------------------------------------------------------------------
# Event-pipeline hygiene: clean keyboard event source + real double-clicks
# ---------------------------------------------------------------------------
#
# Two defects measured on the test laptop (2026-11-14), both invisible in the
# RPC reply but fatal to reliability:
#
# 1. fn/Globe latch. pyautogui creates keyboard events with
#    CGEventCreateKeyboardEvent(NULL, ...); a NULL-source event takes its
#    modifier flags from the live HID session state. Measured: on a session
#    whose flags carry the fn bit, every modifier chord posted that way
#    re-asserted fn at the HID source (40/40 chords latched; watcher caught
#    'Cmd up' and 'fn down' in the same millisecond). A latched fn hijacks
#    later typing through the system input method (Globe action) and turns
#    the wheel horizontal. The same chords created from an explicit
#    CGEventSource latched 0/40 AND were fully functional (uppercase
#    keystrokes and Cmd+A selections confirmed via page beacons), so the
#    daemon routes every NULL-source keyboard event through one dedicated
#    combined-session source. pyautogui's key mapping/vocabulary is untouched
#    — only the event source changes.
#
# 2. double-click never pairs. pyautogui's mouseDown/mouseUp never sets
#    kCGMouseEventClickState, so clicks=2 is two independent single clicks
#    that macOS never pairs: 123 measured click pairs produced ZERO dblclick
#    events (e.detail always 1) — word-select, open-by-double-click, and
#    detail>=2 handling were all silently dead in every app. The daemon posts
#    button events itself, tagging both halves of click #N with state N.

#: Dedicated CGEventSource for all synthesized input (lazy, see _event_source).
_EVENT_SRC: Any = None

#: button -> (down-kind attr, up-kind attr, cg-button attr) on the Quartz module
_BUTTON_EVENTS = {
    "left": ("kCGEventLeftMouseDown", "kCGEventLeftMouseUp", "kCGMouseButtonLeft"),
    "right": ("kCGEventRightMouseDown", "kCGEventRightMouseUp", "kCGMouseButtonRight"),
    "middle": ("kCGEventOtherMouseDown", "kCGEventOtherMouseUp", "kCGMouseButtonMiddle"),
}


def _quartz():
    try:
        import Quartz
    except ImportError as exc:  # pragma: no cover - only on non-macOS
        raise ToolError(INTERNAL_ERROR, f"Quartz unavailable: {exc}") from exc
    return Quartz


def _event_source(quartz):
    global _EVENT_SRC
    if _EVENT_SRC is None:
        _EVENT_SRC = quartz.CGEventSourceCreate(
            quartz.kCGEventSourceStateCombinedSessionState
        )
    return _EVENT_SRC


def install_keyboard_source_hook(quartz) -> bool:
    """Route NULL-source keyboard CGEvents through a clean event source.

    pyautogui resolves ``Quartz.CGEventCreateKeyboardEvent`` via the Quartz
    module at call time, so replacing that attribute covers every keyboard
    path pyautogui has (keyDown/keyUp/press/typewrite/write) without
    reimplementing its key mapping. Idempotent across daemon restarts and
    module reloads within one process; explicit sources pass through.
    Returns True if THIS call installed the hook.
    """
    if getattr(quartz, "_hermes_kbd_hook", False):
        return False
    original = quartz.CGEventCreateKeyboardEvent

    def _create(source, virtual_key, is_down):
        if source is None:
            source = _event_source(quartz)
        return original(source, virtual_key, is_down)

    quartz.CGEventCreateKeyboardEvent = _create
    quartz._hermes_kbd_hook = True
    return True


# ---------------------------------------------------------------------------
# Input ledger — self-bookkeeping of events the daemon posts
# ---------------------------------------------------------------------------
# This class reads NOTHING: no app state, no system state, no API beyond
# counting the daemon's own actions, so it adds zero permission surface.
# Rationale: a key-up lost mid-posting (OS queue under load, or a write()
# aborted mid-string that was holding an implicit shift) leaves a REAL
# modifier pressed at the HID layer, and the next ordinary keystroke then
# fires a system hotkey (Dictation, Character Viewer) with focus-stealing
# consequences — invisible to whoever posted it unless the daemon keeps
# its own down/up balance. ``input_state()`` exposes that balance.

#: cap on the anomaly log returned by input_state() (most recent kept).
LEDGER_LOG_LIMIT = 20


class _InputLedger:
    def __init__(self) -> None:
        # Handlers run via asyncio.to_thread and several clients may post
        # input concurrently, so every mutation is lock-guarded.
        self._lock = threading.Lock()
        self._down: dict[str, int] = {}
        self._suspect: dict[str, str] = {}
        self._log: list[dict[str, Any]] = []
        self.typed_chars = 0
        self.last_chord: list[str] | None = None

    def reset(self) -> None:
        """Clear all state (test support)."""
        with self._lock:
            self._down.clear()
            self._suspect.clear()
            self._log.clear()
            self.typed_chars = 0
            self.last_chord = None

    def _note_locked(self, event: str, **fields: Any) -> None:
        self._log.append({"event": event, "t": round(time.monotonic(), 3), **fields})
        del self._log[:-LEDGER_LOG_LIMIT]

    def note(self, event: str, **fields: Any) -> None:
        with self._lock:
            self._note_locked(event, **fields)

    def down(self, key: str) -> None:
        with self._lock:
            self._down[key] = self._down.get(key, 0) + 1

    def up(self, key: str) -> None:
        with self._lock:
            was_suspect = self._suspect.pop(key, None) is not None
            if was_suspect:
                # This keyUp posted successfully for a key whose release had
                # previously failed or was unknown: direct evidence the OS key
                # is no longer held. Zero any stale ledger debt on it — an
                # alarm the agent cannot clear becomes noise the agent
                # ignores.
                self._down.pop(key, None)
                self._note_locked("resettled", key=key)
                return
            n = self._down.get(key, 0)
            if n <= 0:
                # keyUp recorded with no matching keyDown: a bookkeeping
                # break, never a negative count (which would mask the next
                # genuine leak).
                self._note_locked("unbalanced_key_up", key=key)
                return
            if n == 1:
                del self._down[key]
            else:
                self._down[key] = n - 1

    def suspect(self, key: str, why: str) -> None:
        with self._lock:
            self._suspect[key] = why
            self._note_locked("suspect", key=key, why=why)

    def typed(self, n: int) -> None:
        with self._lock:
            self.typed_chars += n

    def chord(self, keys: list[str]) -> None:
        with self._lock:
            self.last_chord = list(keys)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                # Keys the daemon pressed down and has NOT seen released.
                # Non-empty here == stuck-modifier hazard from daemon
                # events; 'suspect' lists keys whose release failed or
                # whose state is unknown (aborted mid-string typing).
                "held": dict(self._down),
                "suspect": dict(self._suspect),
                "typed_chars": self.typed_chars,
                "last_chord": self.last_chord,
                "log": list(self._log),
            }


_LEDGER = _InputLedger()


def _post_button(pa, button: str, down: bool, click_state: int) -> None:
    """Post one mouse-button half-event tagged with its click sequence number.

    The click state (kCGMouseEventClickState) is what lets macOS pair two
    rapid clicks into a real double-click — see the note above. Events carry
    the current cursor position, like pyautogui's own button posts.
    """
    key = f"button:{button}"
    if down:
        _LEDGER.down(key)
    posted = False
    try:
        try:
            quartz = _quartz()
        except ToolError:
            # Only reachable where Quartz is absent: pyautogui itself
            # hard-requires Quartz on macOS, so any Mac that reaches here has
            # it. Non-macOS dev/test falls back to pyautogui's plain button.
            (pa.mouseDown if down else pa.mouseUp)(button=button)
            posted = True
        else:
            down_kind, up_kind, cg_button = _BUTTON_EVENTS[button]
            x, y = pa.position()
            event = quartz.CGEventCreateMouseEvent(
                _event_source(quartz),
                getattr(quartz, down_kind if down else up_kind),
                (x, y),
                getattr(quartz, cg_button),
            )
            quartz.CGEventSetIntegerValueField(
                event, quartz.kCGMouseEventClickState, click_state
            )
            quartz.CGEventPost(quartz.kCGHIDEventTap, event)
            posted = True
    except Exception:
        if down and not posted:
            _LEDGER.up(key)  # nothing reached the OS; balance the book
        elif not down:
            # A half-posted release is a stuck-button hazard, not a clean
            # release: leave the ledger down and flag it.
            _LEDGER.suspect(key, "button_up_failed")
        raise
    if not down:
        _LEDGER.up(key)


def _verify_cursor(pa, px: int, py: int) -> None:
    """Verify the warp actually landed before pressing a button.

    Polls pyautogui's own cursor read (not a blind sleep): under load the
    warp can still be in flight when the click is posted, and a button event
    lands at the cursor's *previous* position. Raises INTERNAL_ERROR after
    the timeout — a degraded pipeline is a retryable condition, not a lie of
    "ok" for a click that did not go where asked.
    """
    deadline = time.monotonic() + CLICK_VERIFY_TIMEOUT
    while True:
        pos = pa.position()
        if abs(int(pos[0]) - px) <= 1 and abs(int(pos[1]) - py) <= 1:
            time.sleep(CLICK_SETTLE)
            return
        if time.monotonic() >= deadline:
            raise ToolError(
                INTERNAL_ERROR,
                f"cursor did not reach ({px},{py}) within "
                f"{CLICK_VERIFY_TIMEOUT:.1f}s (stuck at "
                f"{(int(pos[0]), int(pos[1]))}); input pipeline degraded — "
                "retry the click",
            )
        time.sleep(CLICK_VERIFY_POLL)


def _press_paced(pa, key: str) -> None:
    """One key down/up with the settle gap; keyUp is finally-safe.

    Ledgered: a keyDown whose keyUp failed (or never ran) is exactly the
    stuck-modifier hazard class, so the ledger records it as SUSPECT /
    still-held instead of assuming balance.
    """
    _LEDGER.down(key)
    try:
        pa.keyDown(key)
    except Exception:
        _LEDGER.up(key)  # nothing reached the OS; balance the book
        raise
    try:
        time.sleep(KEY_SETTLE)
    finally:
        try:
            pa.keyUp(key)
        except Exception:
            _LEDGER.suspect(key, "key_up_failed")
            raise
        _LEDGER.up(key)


def _hotkey_paced(pa, keys: list[str]) -> None:
    """Chord: modifiers down (in order), key, up in reverse.

    Every pressed modifier is released even if the final key's events raise —
    a leaked modifier keyUp poisons ALL later input (stuck-modifier
    hotkeys), so release runs in finally, never on the happy path only.
    One modifier's failed release must not strand the REST of the releases
    (the original code's first failure in the finally loop did), so failures
    are collected: every modifier still gets its keyUp posted, every failure
    is ledgered, and the first error is re-raised after the loop.
    """
    _LEDGER.chord(keys)
    held: list[str] = []
    try:
        for mod in keys[:-1]:
            _LEDGER.down(mod)
            try:
                pa.keyDown(mod)
            except Exception:
                _LEDGER.up(mod)  # nothing reached the OS; balance the book
                raise
            held.append(mod)
            time.sleep(KEY_SETTLE)
        _press_paced(pa, keys[-1])
    finally:
        first_err: Exception | None = None
        for mod in reversed(held):
            try:
                pa.keyUp(mod)
            except Exception as exc:
                _LEDGER.suspect(mod, "key_up_failed")
                first_err = first_err or exc
                continue
            _LEDGER.up(mod)
        if first_err is not None:
            raise first_err


# ---------------------------------------------------------------------------
# Mouse
# ---------------------------------------------------------------------------

def _validate_button(button: Any) -> str:
    button = str(button)
    if button not in ("left", "right", "middle"):
        raise ToolError(INVALID_PARAMS, f"'button' must be one of left/right/middle, got {button!r}")
    return button


def _resolve_point(params: dict[str, Any], x_name: str = "x", y_name: str = "y") -> tuple[int, int]:
    """Resolve a coordinate pair to global pixel coordinates for pyautogui.

    Two modes:
    - **int** values: global pixel coordinates (origin = top-left of primary
      display; monitors left/above the primary use negative coordinates).
    - **float** values in [0, 1]: percentage of the named monitor's screenshot.
      The ``monitor`` param (default 1) selects which display the percentage
      is relative to. The server converts to global pixels using the monitor's
      geometry and the screenshot→click scale factor (handles Retina).
    """
    x = params.get(x_name)
    y = params.get(y_name)

    if (x is None) != (y is None):
        raise ToolError(INVALID_PARAMS, f"'{x_name}' and '{y_name}' must be provided together")
    if x is None:
        raise ToolError(INVALID_PARAMS, f"'{x_name}' and '{y_name}' are required")

    for name, val in ((x_name, x), (y_name, y)):
        if not isinstance(val, (int, float)) or isinstance(val, bool):
            raise ToolError(
                INVALID_PARAMS,
                f"'{name}' must be a number (int = global pixels, float 0..1 = percentage of monitor)",
            )

    # Mode resolution (order matters):
    # 1. Both ints → global pixels (original behavior).
    if isinstance(x, int) and isinstance(y, int):
        return (x, y)
    # 2. Both in [0, 1] → percentage of the named monitor's screenshot.
    if 0.0 <= x <= 1.0 and 0.0 <= y <= 1.0:
        pass  # percentage mode
    # 3. Both integer-valued floats (e.g. 500.0 — JSON ints coerced to float
    #    by MCP schema validation) → global pixels.
    elif x == int(x) and y == int(y):
        return (int(x), int(y))
    # 4. Anything else mixes the two modes → reject.
    else:
        raise ToolError(
            INVALID_PARAMS,
            f"mixed coordinate modes: both '{x_name}' and '{y_name}' must be "
            "percentages in [0, 1] or both (whole) pixel values",
        )

    monitor = params.get("monitor", 1)
    if not isinstance(monitor, int) or isinstance(monitor, bool) or monitor < 1:
        raise ToolError(INVALID_PARAMS, "'monitor' must be a positive integer (1 = primary)")

    try:
        from mss import MSS
    except Exception as exc:
        raise ToolError(INTERNAL_ERROR, f"mss unavailable: {exc}") from exc

    with MSS() as sct:
        if monitor >= len(sct.monitors):
            raise ToolError(
                INVALID_PARAMS,
                f"monitor {monitor} does not exist (1..{len(sct.monitors) - 1})",
            )
        mon = sct.monitors[monitor]
        # monitors[0] is the *virtual* (all-displays) screen; monitors[1] is
        # the primary display. pyautogui.size() reports the PRIMARY display's
        # size, so the screenshot→click scale must be derived from the
        # primary, not the virtual screen. Using the virtual width (the old
        # code) made the scale < 1 on multi-display setups and squished every
        # percentage click toward the origin, so clicks on secondary displays
        # missed their target.
        primary_w = sct.monitors[1]["width"]

    # Scale: pyautogui click-space / mss screenshot-space, derived from the
    # primary display (1.0 on scaled displays, 0.5 on unscaled Retina).
    pa_size = _pyautogui().size()
    scale = pa_size.width / primary_w

    px = int(round((mon["left"] + x * mon["width"]) * scale))
    py = int(round((mon["top"] + y * mon["height"]) * scale))
    return (px, py)


def tool_mouse_move(params: dict[str, Any]) -> dict[str, Any]:
    duration = _num_float(params, "duration", 0.0)
    px, py = _resolve_point(params, "x", "y")  # validates + converts before TCC
    _require_accessibility()
    pa = _pyautogui()
    pa.moveTo(px, py, duration=duration)
    _verify_cursor(pa, px, py)
    time.sleep(ACTION_TAIL)
    pos = pa.position()
    return {"ok": True, "cursor": [int(pos[0]), int(pos[1])]}


def tool_mouse_click(params: dict[str, Any]) -> dict[str, Any]:
    x = params.get("x")
    y = params.get("y")
    if (x is None) != (y is None):
        raise ToolError(INVALID_PARAMS, "'x' and 'y' must be provided together")
    button = _validate_button(params.get("button", "left"))
    clicks = _num_int(params, "clicks", 1)
    if clicks < 1:
        raise ToolError(INVALID_PARAMS, "'clicks' must be >= 1")
    if x is not None:
        px, py = _resolve_point(params, "x", "y")  # validates + converts before TCC
    _require_accessibility()
    pa = _pyautogui()
    if x is not None:
        # Warp first, verify the cursor is actually there, only then press.
        # (pa.click warps and presses back-to-back with zero gap — under
        # load the press overtakes the warp and lands at the old position.)
        pa.moveTo(px, py)
        _verify_cursor(pa, px, py)
    # Manual down/up so the button has a real hold time (pa.click posts
    # down+up back-to-back; some apps' hit-testing drops zero-width presses)
    # AND carries an explicit click state — pyautogui's own mouseDown/mouseUp
    # never sets it, so clicks=2 through pa would never pair as a
    # double-click (see the event-pipeline hygiene note).
    for i in range(clicks):
        _post_button(pa, button, True, i + 1)
        time.sleep(CLICK_PRESS)
        _post_button(pa, button, False, i + 1)
        if i + 1 < clicks:
            time.sleep(CLICK_MULTI_GAP)
    time.sleep(ACTION_TAIL)
    pos = pa.position()
    return {"ok": True, "cursor": [int(pos[0]), int(pos[1])]}


def tool_mouse_drag(params: dict[str, Any]) -> dict[str, Any]:
    button = _validate_button(params.get("button", "left"))
    duration = _num_float(params, "duration", 0.5)
    x1, y1 = _resolve_point(params, "x1", "y1")  # validates + converts before TCC
    x2, y2 = _resolve_point(params, "x2", "y2")
    _require_accessibility()
    # Absolute drag: move to the start point, then drag to the end point.
    # pyautogui.drag() is *relative* to the current cursor position, so it
    # would not honor (x1, y1) as the origin.
    pa = _pyautogui()
    pa.moveTo(x1, y1, duration=0.0)
    _verify_cursor(pa, x1, y1)  # the drag's mouseDown must not outrun the warp
    pa.dragTo(x2, y2, button=button, duration=duration)
    time.sleep(ACTION_TAIL)
    return {"ok": True}


def tool_mouse_scroll(params: dict[str, Any]) -> dict[str, Any]:
    dx = _num_int(params, "dx", 0)
    dy = _num_int(params, "dy", 0)
    _require_accessibility()
    pa = _pyautogui()
    if dy:
        pa.scroll(dy)
    if dx:
        pa.hscroll(dx)
    # Tail gap keeps rapid scroll calls (and a move->scroll pair targeting a
    # pane) from coalescing or landing before the prior move is settled.
    time.sleep(ACTION_TAIL)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Keyboard
# ---------------------------------------------------------------------------

def tool_type_text(params: dict[str, Any]) -> dict[str, Any]:
    text = params.get("text")
    if not isinstance(text, str):
        raise ToolError(INVALID_PARAMS, "'text' must be a string")
    interval = _num_float(params, "interval", 0.0)
    # Floor the interval: interval=0 posts one event per microsecond and the
    # pipeline drops part of the stream on a loaded machine (measured: 2 of
    # 22 keystrokes delivered). Callers may ask for MORE spacing, never less.
    if interval < TYPE_INTERVAL_FLOOR:
        interval = TYPE_INTERVAL_FLOOR
    _require_accessibility()
    try:
        _pyautogui().write(text, interval=interval)
    except Exception as exc:
        # write() aborts mid-string: the interrupted character's key-up —
        # or the implicit SHIFT it was holding for a capital/unicode char —
        # may never have posted. The abort point is unknowable from here,
        # and a stuck shift is a system-hotkey hazard, so flag shift
        # conservatively (a later real release clears the suspicion).
        _LEDGER.suspect("shift", "type_text_aborted_mid_string")
        _LEDGER.note("type_text_aborted", length=len(text))
        raise ToolError(INTERNAL_ERROR, f"type_text interrupted: {exc}") from exc
    _LEDGER.typed(len(text))
    time.sleep(ACTION_TAIL)
    return {"ok": True}


#: Spellings agents habitually use that pyautogui rejects, mapped to the
#: name it accepts (applied case-insensitively BEFORE validation). The
#: authoritative vocabulary is pyautogui's own KEY_NAMES (~194 entries on
#: macOS, incl. 'esc', 'del', 'pgup', single punctuation chars) — validated
#: against the live table in _validate_key, never a static copy that can
#: drift out of sync.
_KEY_ALIASES = {
    "cmd": "command",
    "cmdkey": "command",
    "meta": "command",
    "super": "command",
    "windows": "command",
    "control": "ctrl",
    "opt": "option",
    "volume_mute": "volumemute",
    "mute": "volumemute",
}


def _validate_key(name: Any, valid_names: frozenset[str] | None) -> str:
    if not isinstance(name, str) or not name:
        raise ToolError(INVALID_PARAMS, "every key name must be a non-empty string")
    key = name.strip().lower()
    if "+" in key:
        raise ToolError(
            INVALID_PARAMS,
            f"key {name!r} looks like a combo; pass each key as its own "
            "element, e.g. keys=[\"command\", \"c\"]",
        )
    key = _KEY_ALIASES.get(key, key)
    if valid_names is not None and key not in valid_names:
        import difflib

        close = difflib.get_close_matches(key, sorted(valid_names), n=3)
        hint = f" — did you mean {', '.join(repr(c) for c in close)}?" if close else ""
        raise ToolError(
            INVALID_PARAMS,
            f"unknown key name {name!r}{hint}; see SKILL.md for key names",
        )
    return key


def _key_valid_names(pa) -> frozenset[str] | None:
    """Live pyautogui key vocabulary + aliases; None if not introspectable."""
    names = getattr(pa, "KEY_NAMES", None)
    if not names:
        return None
    return frozenset(names) | frozenset(_KEY_ALIASES.values())


def tool_key_press(params: dict[str, Any]) -> dict[str, Any]:
    keys = params.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ToolError(INVALID_PARAMS, "'keys' must be a non-empty list of key names")
    # Structural validation (types, combos, aliases) runs first — it needs no
    # pyautogui, so malformed parameters never reach the GUI layer at all.
    keys = [_validate_key(k, None) for k in keys]
    _require_accessibility()
    pa = _pyautogui()
    # Membership validation against pyautogui's live vocabulary (when
    # introspectable) turns unknown spellings into INVALID_PARAMS + hint
    # instead of an obscure FindKeyError.
    valid = _key_valid_names(pa)
    if valid is not None:
        keys = [_validate_key(k, valid) for k in keys]
    # A single key is a paced press; a combination is a chord whose releases
    # are finally-safe (see _hotkey_paced). FindKeyError (key accepted by us
    # but unknown to pyautogui — only reachable when KEY_NAMES introspection
    # fails) is a parameter fault, not a daemon fault: report INVALID_PARAMS
    # with a clear message.
    find_key_error = getattr(pa, "FindKeyError", ())
    try:
        if len(keys) == 1:
            _press_paced(pa, keys[0])
        else:
            _hotkey_paced(pa, keys)
    except find_key_error as exc:
        raise ToolError(INVALID_PARAMS, f"key not supported: {exc}") from exc
    time.sleep(ACTION_TAIL)
    return {"ok": True}


def tool_input_state(params: dict[str, Any]) -> dict[str, Any]:
    """The daemon's self-assessment of input IT posted — no system reads.

    ``held`` lists keys/buttons pressed down and never seen released and
    ``suspect`` keys whose release failed or is unknown (aborted typing).
    Either non-empty means later keystrokes may fire unintended system
    hotkeys: release the listed keys with key_press (or restart the
    daemon) before trusting input. Agents should check this after a
    chord/typing error and before sensitive sequences.
    """
    return {"ok": True, **_LEDGER.snapshot()}


# ---------------------------------------------------------------------------
# Processes
# ---------------------------------------------------------------------------

def tool_launch_app(params: dict[str, Any], config: Config) -> dict[str, Any]:
    app = params.get("app")
    if not isinstance(app, str) or not app:
        raise ToolError(INVALID_PARAMS, "'app' must be a non-empty string (app name or .app path)")
    config.check_app(app)

    url = params.get("url")
    if app.endswith(".app") or os.path.sep in app:
        cmd = ["open", app] + ([url] if url else [])
    else:
        cmd = ["open", "-a", app] + ([url] if url else [])

    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=15)
    except subprocess.CalledProcessError as exc:
        raise ToolError(INTERNAL_ERROR, f"failed to launch {app!r}: {exc.stderr.strip()}")
    except subprocess.TimeoutExpired as exc:
        raise ToolError(COMMAND_TIMEOUT, f"timed out launching {app!r}") from exc

    pid = _find_app_pid(app)
    return {"pid": pid, "app": app}


def _find_app_pid(app: str) -> int | None:
    """Best-effort: find the pid of the app we just launched."""
    name = os.path.basename(app)
    if name.endswith(".app"):
        name = name[: -len(".app")]
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        for proc in psutil.process_iter(["name"]):
            try:
                if proc.info["name"] and proc.info["name"].lower() == name.lower():
                    return proc.pid
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        time.sleep(0.2)
    return None


# MAX_COMMAND_TIMEOUT (protocol.py) is the hard cap on the client-supplied
# command timeout. The server's per-request cap (DEFAULT_REQUEST_TIMEOUT) must
# exceed it; a child must never outlive the daemon's ability to reap it, so we
# clamp the client value into a sane range.

# Bound on how much of a command's output we retain. A remote command can emit
# arbitrarily large output (``yes``, ``cat /dev/zero``, a huge log dump);
# retaining it all would let a single call exhaust daemon memory. We keep the
# first and last ``MAX_OUTPUT_KEEP`` bytes of each stream and drop the middle,
# while still *draining* the pipes so the child never blocks on a full pipe.
MAX_OUTPUT_KEEP = 256 * 1024  # bytes retained per stream (head + tail)


def _kill_process_group(proc: subprocess.Popen) -> None:
    """Best-effort kill of the whole process group that *proc* leads.

    ``tool_run_command`` starts each command in its own session
    (``start_new_session=True``), so killing the group terminates the shell
    *and* everything it spawned — not just the direct child.
    """
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass


class _BoundedBuffer:
    """Accumulates a stream, retaining only the first and last *keep* bytes.

    The full stream is drained (so the child never blocks on a full pipe) but
    only a bounded amount is kept in memory.
    """

    __slots__ = ("head", "tail", "dropped", "keep")

    def __init__(self, keep: int) -> None:
        self.keep = keep
        self.head = bytearray()
        self.tail = bytearray()
        self.dropped = 0

    def add(self, chunk: bytes) -> None:
        if len(self.head) < self.keep:
            room = self.keep - len(self.head)
            self.head.extend(chunk[:room])
            chunk = chunk[room:]
        if not chunk:
            return
        if len(self.tail) + len(chunk) <= self.keep:
            self.tail.extend(chunk)
        else:
            self.dropped += len(chunk) - (self.keep - len(self.tail))
            self.tail.extend(chunk[-(self.keep - len(self.tail)) :])
            if len(self.tail) > self.keep:
                del self.tail[: len(self.tail) - self.keep]

    def text(self) -> str:
        if self.dropped <= 0:
            return self.head.decode("utf-8", "replace")
        return (
            self.head.decode("utf-8", "replace")
            + f"\n... [{self.dropped} bytes truncated] ...\n"
            + self.tail.decode("utf-8", "replace")
        )


def _drain_pipes(
    proc: subprocess.Popen, keep: int, deadline: float
) -> tuple[str, str] | None:
    """Concurrently drain *proc*'s stdout/stderr to EOF, bounded to *keep* bytes.

    Both pipes are read in a single ``select`` loop so a child that writes a lot
    to one stream can't block on the other (the classic ``communicate``-style
    deadlock). Returns ``(stdout, stderr)`` on normal completion, or ``None`` if
    the wall-clock *deadline* is reached first (caller is responsible for
    killing the process group).
    """
    out = _BoundedBuffer(keep)
    err = _BoundedBuffer(keep)
    sel = selectors.DefaultSelector()
    sel.register(proc.stdout, selectors.EVENT_READ, data=out)
    sel.register(proc.stderr, selectors.EVENT_READ, data=err)
    open_count = 2
    try:
        while open_count:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            events = sel.select(timeout=remaining)
            for key, _ in events:
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:  # EOF on this stream
                    sel.unregister(key.fileobj)
                    open_count -= 1
                else:
                    key.data.add(chunk)
    finally:
        sel.close()
    return out.text(), err.text()


def tool_run_command(params: dict[str, Any], config: Config) -> dict[str, Any]:
    cmd = params.get("cmd")
    if not isinstance(cmd, str) or not cmd.strip():
        raise ToolError(INVALID_PARAMS, "'cmd' must be a non-empty string")
    config.check_command(cmd)

    cwd = params.get("cwd")
    try:
        timeout = float(params.get("timeout", 60.0))
    except (TypeError, ValueError):
        raise ToolError(INVALID_PARAMS, "'timeout' must be a number")
    timeout = max(0.1, min(timeout, MAX_COMMAND_TIMEOUT))

    # Run in its own process group so a timeout (or a misbehaving shell) can be
    # cleaned up by killing the whole group, preventing orphaned grandchildren.
    proc = subprocess.Popen(
        cmd,
        shell=True,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )

    deadline = time.monotonic() + timeout
    try:
        drained = _drain_pipes(proc, MAX_OUTPUT_KEEP, deadline)
    except OSError as exc:
        _kill_process_group(proc)
        proc.wait()
        raise ToolError(INTERNAL_ERROR, f"failed to run command: {exc}") from exc

    if drained is None:
        # Deadline hit before the child closed its pipes: kill the whole group
        # and reap it.
        _kill_process_group(proc)
        proc.wait()
        raise ToolError(COMMAND_TIMEOUT, f"command timed out after {timeout}s: {cmd!r}")

    stdout, stderr = drained
    proc.wait()
    return {
        "exit_code": proc.returncode,
        "stdout": stdout,
        "stderr": stderr,
    }


def tool_list_processes(params: dict[str, Any]) -> dict[str, Any]:
    flt = (params.get("filter") or "").lower()
    procs: list[dict[str, Any]] = []
    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
        try:
            name = proc.info["name"] or ""
            if flt and flt not in name.lower():
                continue
            procs.append(
                {
                    "pid": proc.info["pid"],
                    "name": name,
                    "cpu": proc.info["cpu_percent"] or 0.0,
                    "mem": proc.info["memory_percent"] or 0.0,
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return {"processes": procs}


def tool_stop_process(params: dict[str, Any]) -> dict[str, Any]:
    pid = params.get("pid")
    if not isinstance(pid, int):
        raise ToolError(INVALID_PARAMS, "'pid' must be an integer")
    sig_name = str(params.get("signal", "TERM")).upper()
    if not sig_name.startswith("SIG"):
        sig_name = "SIG" + sig_name  # TERM → SIGTERM, KILL → SIGKILL
    sig = getattr(signal, sig_name, None)
    if sig is None:
        raise ToolError(INVALID_PARAMS, f"unknown signal {sig_name!r}")
    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        raise ToolError(PROCESS_NOT_FOUND, f"no process with pid {pid}")
    try:
        if sig == signal.SIGKILL:
            proc.kill()
        else:
            proc.terminate() if sig == signal.SIGTERM else proc.send_signal(sig)
        proc.wait(timeout=5)
    except psutil.NoSuchProcess:
        pass
    except psutil.TimeoutExpired:
        proc.kill()
    return {"ok": True, "pid": pid}


# ---------------------------------------------------------------------------
# File transfer (chunked)
# ---------------------------------------------------------------------------

def _path_param(params: dict[str, Any], name: str) -> str:
    value = params.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ToolError(INVALID_PARAMS, f"'{name}' must be a non-empty string")
    return value


def _offset_param(params: dict[str, Any]) -> int:
    offset = params.get("offset", 0)
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise ToolError(INVALID_PARAMS, "'offset' must be a non-negative integer")
    return offset


def tool_read_file(params: dict[str, Any], config: Config) -> dict[str, Any]:
    """Read up to FILE_CHUNK_SIZE bytes of *path* starting at *offset*.

    Returns base64 of the chunk plus the total file size and an ``eof`` flag so
    the client can loop until the whole file is retrieved.
    """
    path = _path_param(params, "path")
    offset = _offset_param(params)
    length = int(params.get("length", FILE_CHUNK_SIZE))
    length = max(1, min(length, FILE_CHUNK_SIZE))
    config.check_path(path)

    p = Path(path).expanduser()
    if not p.is_file():
        raise ToolError(INVALID_PARAMS, f"not a regular file: {path!r}")
    size = p.stat().st_size
    if size > MAX_FILE_SIZE:
        raise ToolError(INVALID_PARAMS, f"file too large ({size} bytes > {MAX_FILE_SIZE})")
    if offset >= size:
        return {"data": "", "size": size, "offset": offset, "eof": True}
    with open(p, "rb") as fh:
        fh.seek(offset)
        chunk = fh.read(length)
    eof = offset + len(chunk) >= size
    return {
        "data": base64.b64encode(chunk).decode("ascii"),
        "size": size,
        "offset": offset,
        "eof": eof,
    }


def tool_write_file(params: dict[str, Any], config: Config) -> dict[str, Any]:
    """Write a base64 *data* chunk to *path* at *offset*.

    ``offset == 0`` creates/truncates the file; later offsets seek and write,
    so the client can stream a file in FILE_CHUNK_SIZE pieces.
    """
    path = _path_param(params, "path")
    data_b64 = params.get("data")
    if not isinstance(data_b64, str):
        raise ToolError(INVALID_PARAMS, "'data' must be a base64 string")
    offset = _offset_param(params)
    config.check_path(path)

    try:
        chunk = base64.b64decode(data_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ToolError(INVALID_PARAMS, f"'data' is not valid base64: {exc}") from exc
    if len(chunk) > FILE_CHUNK_SIZE:
        raise ToolError(INVALID_PARAMS, f"chunk too large ({len(chunk)} > {FILE_CHUNK_SIZE})")
    if offset + len(chunk) > MAX_FILE_SIZE:
        raise ToolError(INVALID_PARAMS, f"file would exceed {MAX_FILE_SIZE} bytes")

    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    if offset == 0:
        with open(p, "wb") as fh:
            fh.write(chunk)
    else:
        with open(p, "r+b") as fh:
            fh.seek(offset)
            fh.write(chunk)
    return {"ok": True, "written": offset + len(chunk)}


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

def _tcc_hint(missing: list[str]) -> str:
    """Actionable guidance for the TCC permissions that are not yet granted."""
    panes = []
    if "screen" in missing:
        panes.append("Screen Recording")
    if "accessibility" in missing:
        panes.append("Accessibility")
    pane_text = " and ".join(panes)
    return (
        f"{pane_text} not granted to the process running this daemon. "
        "TCC keys permission to the executable's code-signing identity (a venv "
        "resolves to its parent interpreter), not to the venv itself. Easiest fix: "
        f"grant {pane_text} to the terminal you launch the daemon from "
        "(System Settings → Privacy & Security), fully quit and relaunch that "
        "terminal, then restart the daemon. For a launchd daemon, grant the exact "
        "Python binary the plist runs instead."
    )


def tool_health(
    params: dict[str, Any],
    config: Config,
    start_time: float,
    tracker: Any = None,
) -> dict[str, Any]:
    screen = _screen_recording_granted()
    accessibility = _accessibility_granted()
    missing = [name for name, ok in (("screen", screen), ("accessibility", accessibility)) if not ok]
    # This health() call is itself dispatched through _dispatch, so the tracker
    # count includes it. Subtract 1 (clamped at 0) so the reported figures
    # reflect the *other* in-flight calls, not this one.
    in_flight = max(0, tracker.in_flight - 1) if tracker is not None else 0
    result: dict[str, Any] = {
        "ok": True,
        "uptime": round(time.monotonic() - start_time, 1),
        "perms": {
            "screen": screen,
            "accessibility": accessibility,
        },
        "active": in_flight > 0,
        "in_flight": in_flight,
    }
    if missing:
        result["tcc"] = {"missing": missing, "hint": _tcc_hint(missing)}
    return result


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def build_tools(config: Config, start_time: float, tracker: Any = None) -> dict[str, Handler]:
    """Map method name → handler, bound to *config*, daemon start time, and the
    activity tracker (so ``health`` can report in-flight calls)."""
    return {
        "screenshot": tool_screenshot,
        "mouse_move": tool_mouse_move,
        "mouse_click": tool_mouse_click,
        "mouse_drag": tool_mouse_drag,
        "mouse_scroll": tool_mouse_scroll,
        "type_text": tool_type_text,
        "key_press": tool_key_press,
        "input_state": tool_input_state,
        "launch_app": lambda p: tool_launch_app(p, config),
        "run_command": lambda p: tool_run_command(p, config),
        "list_processes": tool_list_processes,
        "stop_process": tool_stop_process,
        "read_file": lambda p: tool_read_file(p, config),
        "write_file": lambda p: tool_write_file(p, config),
        "health": lambda p: tool_health(p, config, start_time, tracker),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _int_param(params: dict[str, Any], name: str) -> int:
    value = params.get(name)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ToolError(INVALID_PARAMS, f"'{name}' must be an integer")
    return value
