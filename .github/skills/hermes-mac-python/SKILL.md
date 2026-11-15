---
name: hermes-mac-python
description: "Use when the user wants to control their MacBook from Hermes or any Python code: take a screenshot / read the screen, move or click the mouse, type text or press hotkeys, launch a GUI app (e.g. 'open LinkedIn in Safari'), run a shell command, list or kill a process, or check daemon health. Covers the MacAgent Python client, the allow/deny policy, and macOS TCC permission troubleshooting."
---

# Controlling the Mac with the `MacAgent` Python client

This is the **default** integration. The Mac runs the `hermes-mac-daemon` (a TLS
WebSocket server); you run the `MacAgent` client and dial in over the LAN.

## When to use

- "Take a screenshot of my Mac" / "what's on my screen?"
- "Click / type / scroll on my Mac"
- "Open <app> (with a URL) on my Mac" — e.g. LinkedIn in Safari
- "Run <command> on my Mac"
- "List processes on my Mac" / "kill <pid> on my Mac"
- "Is the Mac agent running / do I have permissions?"

## Prerequisites (one-time, on the Mac)

1. `./scripts/setup_mac.sh` — generates the TLS cert, token, and `config.json`, and
   prints the token + TCC steps.
2. Grant **Screen Recording** and **Accessibility** to the Python interpreter binary
   that runs the daemon (System Settings → Privacy & Security).
3. Verify with `agent.health()` → `perms.screen` and `perms.accessibility` both `True`.

## Basic usage

```python
from hermes_mac_agent import MacAgent

agent = MacAgent(
    host="192.168.1.50",          # the Mac's LAN IP
    port=8765,
    token="<token from setup>",
    ca_cert="~/.hermes_mac_agent/ca.pem",  # the Mac's local CA (signed the leaf cert)
)

with agent:
    img = agent.screenshot()              # PIL.Image (RGB)
    agent.mouse_click(500, 300)           # global pixels; button="left"|"right"|"middle"
    agent.mouse_click(0.5, 0.5)           # OR percentage of monitor 1's screenshot
    agent.type_text("hello")
    agent.key_press(["command", "t"])     # hotkey combo
    agent.launch_app("Safari", url="https://www.linkedin.com")
    result = agent.run_command("echo ok") # {'exit_code':0,'stdout':'ok\n','stderr':''}
    procs  = agent.list_processes(filter="python")
    agent.stop_process(pid)               # SIGTERM, then SIGKILL if needed

    # Files (chunked, gated by the daemon's file_allowlist/file_denylist)
    data = agent.read_file("/path/on/mac")        # bytes
    text = agent.read_file_text("/path/on/mac")   # str (utf-8)
    agent.write_file("/path/on/mac", data)        # bytes
    agent.write_file_text("/path/on/mac", text)   # str (utf-8)

    print(agent.health())
```

The client authenticates lazily on first use and transparently re-authenticates if
the connection drops.

## Method reference

| Method | Returns | Notes |
|---|---|---|
| `screenshot(monitor=1)` | `PIL.Image` | `monitor=0` = all monitors |
| `screenshot_bytes(monitor=1)` | `bytes` | raw PNG |
| `mouse_move(x, y, duration=0.0, monitor=1)` | `None` | int = global pixels; float [0,1] = % of `monitor`'s screenshot |
| `mouse_click(x, y, button="left", clicks=1, monitor=1)` | `None` | `x` and `y` must be given together; same two modes |
| `mouse_drag(x1, y1, x2, y2, ..., monitor=1)` | `None` | both endpoints in the same mode |
| `mouse_scroll(dx=0, dy=0)` | `None` | negative `dy` scrolls down; **targets the pane under the cursor** — move first |
| `type_text(text, interval=0.0)` | `None` | `interval` per char in s; daemon floors it at ~0.02s (see Pacing) |
| `key_press(keys)` | `None` | list of key names, e.g. `["command","shift","3"]` |
| `input_state()` | `dict` | daemon's ledger of input **it** posted: `held`/`suspect` keys, `typed_chars`, `last_chord`, `log` — see Input self-diagnostics |
| `launch_app(app, url=None)` | `int \| None` | pid if it could be found, else `None`. **Returns before the window exists** — see Pacing |
| `run_command(cmd, cwd=None, timeout=60.0)` | `dict` | `{'exit_code','stdout','stderr'}` |
| `list_processes(filter=None)` | `list[dict]` | **returns the list directly** |
| `stop_process(pid, sig="TERM")` | `None` | |
| `read_file(path)` | `bytes` | chunked; needs `file_allowlist` match |
| `read_file_text(path, encoding="utf-8")` | `str` | |
| `write_file(path, data)` | `None` | offset 0 = create/truncate; ≤10 MB |
| `write_file_text(path, text, encoding="utf-8")` | `None` | |
| `health()` | `dict` | `{'ok','uptime','perms':{...},'active','in_flight'}` (+`tcc` if a perm is missing) |

**Mouse coordinates — two modes.** `int` x/y are global pixels: origin (0,0) is
the top-left of the PRIMARY display, monitors left/above it use negative
coordinates. `float` x/y in [0,1] are percentages of the `monitor`'s screenshot
(0.0 = left/top edge, 1.0 = right/bottom edge); the daemon converts them to
integer pixel coordinates, so this is resolution- and Retina-safe. **Prefer
percentages when the target was located in a screenshot.** Don't mix int and
float in one call.

## Targeting precision & pacing

Two defect classes cause most automation failures, and both come from treating
the GUI like an API: imprecise targeting, and machine-speed input.

### Measure coordinates from the saved screenshot, at full precision

- Read target coordinates from the **saved full-resolution PNG** (`img.getpixel`,
  color/edge measurement, or an overlaid coordinate grid) — **never by
  eyeballing a resized display copy** of the screenshot; a preview scaled to
  ~80% width biases every coordinate by ~20%, and clicks land a hundred-plus
  pixels off.
- Convert to percentages with **at least 5 decimal places** (full float
  precision is preferred):
  ```python
  x_px, y_px = 983, 396                      # measured in the saved PNG
  agent.mouse_click(x_px / img.width, y_px / img.height)   # ~0.5485491, 0.3535714
  ```
  `round(..., 2)` or `(..., 3)` moves the click up to ~2–20 px (0.001 of a
  1792-px-wide screen ≈ 1.8 px) — enough to miss checkboxes, radio buttons,
  and menu items. The daemon rounds the percentage to the exact integer pixel.
- Verify the geometry math with the screenshot's own `img.size`
  (1792×1120-style point space = the click space); never assume a display
  resolution.

### Act → verify → act (never blind chains)

macOS finishes things asynchronously; a client-side action returning `ok`
means *events were delivered*, not that the UI reacted yet.

- **After every action, take a screenshot and confirm the effect** before
  issuing the next dependent action: window raised (title bar active, window
  count changed), field focused (caret / focus ring), text landed, checkbox
  toggled. This polling loop **is** the wait mechanism — budget a few seconds
  of screenshot rounds rather than inserting fixed sleeps.
- **After `launch_app`**, the pid returns before the window appears. Poll
  screenshots (0.5–1 s apart, up to ~10 s for cold launches; browsers can
  take longer) until the window is visible before clicking or typing.
- **After clicking into a new app/window, confirm focus** with a screenshot
  before `type_text` — keystrokes follow keyboard focus, which you do not
  control directly.
- **Type in probe-then-commit order.** `type_text` returning `ok` only means
  events were posted, not that they landed in the field you meant. Send the
  first ~3 characters, take a screenshot to confirm *those* landed in the
  target, then send the rest. A blind 26-character string that starts on the
  wrong focus dumps 26 characters into whatever app actually had it; a 3-char
  probe bounds the blast radius and tells you to stop before committing the
  rest.

### Input self-diagnostics (`input_state`)

The usual cause of a sudden focus shift or "why did typing go haywire" is a
**stuck modifier from a previous action** — a dropped key-up leaves Ctrl/Fn/Cmd
physically held, and the next ordinary keystrokes then fire system hotkeys
(Dictation, Character Viewer, Launchpad). The daemon keeps a ledger of the
input **it** posted (no reads of app or system state) and exposes it via
`input_state()`:

- `held` — keys pressed down that were never seen released.
- `suspect` — keys whose release failed or is unknown (e.g. typing aborted
  mid-string may have leaked the implicit Shift for capitals).

If either is non-empty, **do not continue typing**: release each listed key
with a single `key_press([key])` (a clean release clears the flag), or restart
the daemon. Check it after any chord/typing error, and before a sensitive
sequence (passwords, sends, submits).

### Pacing (the daemon enforces floors; don't fight them)

Machine-speed input — zero-gap warps+clicks, `interval=0` typing bursts —
outruns macOS event delivery under CPU load: parts of the event stream are
dropped, a lost key-up sticks a modifier (the next ordinary keystrokes then
fire **system hotkeys** — Dictation, Character Viewer, Launchpad — which
steal focus and cascade), and clicks fire before the cursor warp lands. The
daemon therefore settles cursor warps before every press (with position
verification), holds buttons, spaces key chords, and floors `type_text`
`interval` at ~0.02 s. Larger `interval` values are honored; if keystrokes
still look garbled on a heavily loaded machine, **increase** it (0.05–0.1).

- **Never send bare `["ctrl"]`, `["fn"]`/globe presses, or stray F-keys** as
  "safe" no-op keys: a double-Control tap opens Dictation and the Globe key
  opens the Character Viewer on the user's actual screen.
- `mouse_scroll` follows the cursor: `mouse_move` to the target pane, take a
  confirming screenshot, then scroll.

### Native popups (select menus, color pickers, context menus)

`<select>`-style popups are rendered by macOS, not the page: their geometry
depends on the current value (the highlighted row sits under the control),
so coordinates from the *closed* control are wrong once open. Either take a
fresh screenshot **after** opening and click the measured row, or skip the
pointer: open the control, type the option's first letter, press `return`.

## Error handling

Catch the specific exceptions (all subclass `MacAgentError`, which has `.code`):

```python
from hermes_mac_agent import MacAgent, BlockedByPolicyError, TccPermissionError

try:
    agent.run_command("sudo reboot")
except BlockedByPolicyError as e:
    ...  # blocked by the daemon's allow/deny policy (code -32002)
except TccPermissionError as e:
    ...  # macOS permission missing (code -32003) — tell the user to grant it
```

## Allow / deny policy (why a command might be blocked)

The daemon enforces an allowlist + denylist on `run_command` (full command string)
and `launch_app` (app name/path). **Denylist wins.** The allowlist is **deny-all by
default** (empty = nothing allowed); `*` in the allowlist = allow all (not
recommended); `*` in the denylist = block all. A pattern with no glob chars also
matches as a whole-word prefix, so `"sudo"` blocks `"sudo ls"` but not `"sudoedit"`.

`read_file` / `write_file` use a **separate** namespace (`file_allowlist` /
`file_denylist`), also deny-all by default.

If a command is blocked, check `~/.hermes_mac_agent/config.json` on the Mac and add
the command (or a glob) to the allowlist, then restart the daemon.

## Troubleshooting

- **`TccPermissionError` on screenshot / mouse / keyboard** → grant Screen Recording
  and/or Accessibility to the daemon's Python binary, then restart the daemon.
- **TLS handshake fails** → pass the Mac's `ca.pem` (the local CA that signed the
  leaf cert) as `ca_cert=` (or set `verify=False` for debugging only).
- **`AUTH_FAILED`** → the token doesn't match `config.json` on the Mac.
- **Connection refused** → daemon not running, or wrong host/port. Check
  `~/.hermes_mac_agent/daemon.log`.
