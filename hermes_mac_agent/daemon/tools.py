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
    return pyautogui


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
# Mouse
# ---------------------------------------------------------------------------

def _validate_button(button: Any) -> str:
    button = str(button)
    if button not in ("left", "right", "middle"):
        raise ToolError(INVALID_PARAMS, f"'button' must be one of left/right/middle, got {button!r}")
    return button


def tool_mouse_move(params: dict[str, Any]) -> dict[str, Any]:
    x = _int_param(params, "x")
    y = _int_param(params, "y")
    duration = float(params.get("duration", 0.0))
    _require_accessibility()
    _pyautogui().moveTo(x, y, duration=duration)
    return {"ok": True}


def tool_mouse_click(params: dict[str, Any]) -> dict[str, Any]:
    x = params.get("x")
    y = params.get("y")
    if (x is None) != (y is None):
        raise ToolError(INVALID_PARAMS, "'x' and 'y' must be provided together")
    if x is not None:
        x = _int_param(params, "x")
        y = _int_param(params, "y")
    button = _validate_button(params.get("button", "left"))
    clicks = int(params.get("clicks", 1))
    if clicks < 1:
        raise ToolError(INVALID_PARAMS, "'clicks' must be >= 1")
    _require_accessibility()
    pa = _pyautogui()
    if x is not None:
        pa.click(x, y, button=button, clicks=clicks)
    else:
        pa.click(button=button, clicks=clicks)
    return {"ok": True}


def tool_mouse_drag(params: dict[str, Any]) -> dict[str, Any]:
    x1 = _int_param(params, "x1")
    y1 = _int_param(params, "y1")
    x2 = _int_param(params, "x2")
    y2 = _int_param(params, "y2")
    button = _validate_button(params.get("button", "left"))
    duration = float(params.get("duration", 0.5))
    _require_accessibility()
    # Absolute drag: move to the start point, then drag to the end point.
    # pyautogui.drag() is *relative* to the current cursor position, so it
    # would not honor (x1, y1) as the origin.
    pa = _pyautogui()
    pa.moveTo(x1, y1, duration=0.0)
    pa.dragTo(x2, y2, button=button, duration=duration)
    return {"ok": True}


def tool_mouse_scroll(params: dict[str, Any]) -> dict[str, Any]:
    dx = int(params.get("dx", 0))
    dy = int(params.get("dy", 0))
    _require_accessibility()
    pa = _pyautogui()
    if dy:
        pa.scroll(dy)
    if dx:
        pa.hscroll(dx)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Keyboard
# ---------------------------------------------------------------------------

def tool_type_text(params: dict[str, Any]) -> dict[str, Any]:
    text = params.get("text")
    if not isinstance(text, str):
        raise ToolError(INVALID_PARAMS, "'text' must be a string")
    interval = float(params.get("interval", 0.0))
    _require_accessibility()
    _pyautogui().write(text, interval=interval)
    return {"ok": True}


def tool_key_press(params: dict[str, Any]) -> dict[str, Any]:
    keys = params.get("keys")
    if not isinstance(keys, list) or not keys or not all(isinstance(k, str) and k for k in keys):
        raise ToolError(INVALID_PARAMS, "'keys' must be a non-empty list of key names")
    _require_accessibility()
    pa = _pyautogui()
    # A single key is a press; a combination is a simultaneous hotkey.
    if len(keys) == 1:
        pa.press(keys[0])
    else:
        pa.hotkey(*keys)
    return {"ok": True}


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


# Hard cap on the client-supplied command timeout. The server's per-request
# timeout is 120s; a child must never be allowed to outlive the daemon's ability
# to reap it, so we clamp the client value into a sane range.
MAX_COMMAND_TIMEOUT = 300.0

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


def tool_health(params: dict[str, Any], config: Config, start_time: float) -> dict[str, Any]:
    screen = _screen_recording_granted()
    accessibility = _accessibility_granted()
    missing = [name for name, ok in (("screen", screen), ("accessibility", accessibility)) if not ok]
    result: dict[str, Any] = {
        "ok": True,
        "uptime": round(time.monotonic() - start_time, 1),
        "perms": {
            "screen": screen,
            "accessibility": accessibility,
        },
    }
    if missing:
        result["tcc"] = {"missing": missing, "hint": _tcc_hint(missing)}
    return result


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def build_tools(config: Config, start_time: float) -> dict[str, Handler]:
    """Map method name → handler, bound to *config* and daemon start time."""
    return {
        "screenshot": tool_screenshot,
        "mouse_move": tool_mouse_move,
        "mouse_click": tool_mouse_click,
        "mouse_drag": tool_mouse_drag,
        "mouse_scroll": tool_mouse_scroll,
        "type_text": tool_type_text,
        "key_press": tool_key_press,
        "launch_app": lambda p: tool_launch_app(p, config),
        "run_command": lambda p: tool_run_command(p, config),
        "list_processes": tool_list_processes,
        "stop_process": tool_stop_process,
        "read_file": lambda p: tool_read_file(p, config),
        "write_file": lambda p: tool_write_file(p, config),
        "health": lambda p: tool_health(p, config, start_time),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _int_param(params: dict[str, Any], name: str) -> int:
    value = params.get(name)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ToolError(INVALID_PARAMS, f"'{name}' must be an integer")
    return value
