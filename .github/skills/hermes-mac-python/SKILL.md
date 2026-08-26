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
    agent.mouse_click(500, 300)           # button="left"|"right"|"middle"
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
| `mouse_move(x, y, duration=0.0)` | `None` | |
| `mouse_click(x, y, button="left", clicks=1)` | `None` | `x` and `y` must be given together |
| `mouse_drag(x1, y1, x2, y2, ...)` | `None` | |
| `mouse_scroll(dx=0, dy=0)` | `None` | negative `dy` scrolls down |
| `type_text(text, interval=0.0)` | `None` | |
| `key_press(keys)` | `None` | list of key names, e.g. `["command","shift","3"]` |
| `launch_app(app, url=None)` | `int \| None` | pid if it could be found, else `None` |
| `run_command(cmd, cwd=None, timeout=60.0)` | `dict` | `{'exit_code','stdout','stderr'}` |
| `list_processes(filter=None)` | `list[dict]` | **returns the list directly** |
| `stop_process(pid, sig="TERM")` | `None` | |
| `read_file(path)` | `bytes` | chunked; needs `file_allowlist` match |
| `read_file_text(path, encoding="utf-8")` | `str` | |
| `write_file(path, data)` | `None` | offset 0 = create/truncate; ≤10 MB |
| `write_file_text(path, text, encoding="utf-8")` | `None` | |
| `health()` | `dict` | `{'ok','uptime','perms':{...}}` |

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
