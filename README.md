# hermes-mac-agent

Remote-control agent for a computer running **MacOS**, driven by the **Hermes** agent over a
TLS-secured WebSocket. Hermes (running anywhere on your LAN) can:

- **Read the screen** — capture any monitor as a PNG.
- **Drive the desktop** — move/click/drag/scroll the mouse, type text, press hotkeys.
- **Control processes** — launch GUI apps, run shell commands, list and kill processes.

Example: *"Hermes, open LinkedIn in my default browser on my Mac"* → Hermes calls
`launch_app("Safari", url="https://www.linkedin.com")` on the Mac.

```
┌─────────────────────────────┐        TLS WebSocket (JSON-RPC 2.0)        ┌──────────────────────────────┐
│  Hermes agent (Python)      │  ───────────────────────────────────────▶  │  MacBook Pro                │
│  MacAgent client            │   wss://mac:8765  ·  shared token auth     │  hermes-mac-daemon          │
│  (dials the Mac)            │  ◀───────────────────────────────────────  │  · mss (screen)             │
└─────────────────────────────┘                                            │  · pyautogui (mouse/keys)   │
                                                                            │  · subprocess/psutil (procs)│
                                                                            └──────────────────────────────┘
```

The Mac runs a **daemon** (the server). Hermes runs the **client** and dials in over
the LAN. Every connection must present the shared token as its first frame, and all
traffic is TLS-encrypted.

---

## Architecture

| Piece | File | Role |
|---|---|---|
| Protocol | `hermes_mac_agent/protocol.py` | JSON-RPC 2.0 types + error codes (single source of truth) |
| Daemon config | `hermes_mac_agent/daemon/config.py` | Config loading + allow/deny policy |
| Tools | `hermes_mac_agent/daemon/tools.py` | Screen / mouse / keyboard / process handlers |
| Daemon server | `hermes_mac_agent/daemon/server.py` | TLS WebSocket server + auth gate + dispatch |
| Client | `hermes_mac_agent/client/mac_agent.py` | `MacAgent` — the Hermes-facing API |
| MCP adapter | `hermes_mac_agent/mcp_adapter.py` | Optional MCP server wrapping the same tools |
| Menubar app | `hermes_mac_agent/menubar/app.py` | Optional macOS menubar host (scopes TCC to the app) |
| Setup | `scripts/setup_mac.sh` | One-time Mac setup (cert, token, config, TCC steps) |
| App build | `scripts/build_app.sh` | Build `HermesMacAgent.app` (PyInstaller + ad-hoc sign) |
| Launchd | `launchd/com.hermes.mac-agent.plist` | Run the daemon as a macOS LaunchAgent |

**Transport:** `websockets` (asyncio) + a self-signed TLS cert + a shared token.
The client's first frame **must** be `auth`; the server rejects everything else until
the token verifies (constant-time compare via `hmac.compare_digest`).

**Screen capture:** `mss` (lazy import) → BGRA→RGB via Pillow → PNG.
**Mouse/keyboard:** `pyautogui` (lazy import).
**Processes:** `subprocess` (`open -a <app>` for GUI apps, `shell=True` for commands) + `psutil`.

---

## Install

### On the MacBook (the daemon)

```bash
cd hermes_mac_agent
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# One-time setup: generates TLS cert + token + config, prints TCC steps
./scripts/setup_mac.sh
```

The setup script:
1. Creates `~/.hermes_mac_agent/` (mode 700).
2. Generates a self-signed TLS cert + key (10 years).
3. Generates a random 256-bit token.
4. Writes `config.json` (mode 600) with default allow/deny lists.
5. Prints the **token** and the exact macOS permission steps.

To run it as a background service that survives reboots:

```bash
./scripts/setup_mac.sh --install-launchd
```

### Alternative: run the daemon in a menubar app (recommended)

macOS TCC binds Screen Recording / Accessibility to the **responsible process** —
the app that owns the process tree. Running the daemon from a terminal binds the
grants to your terminal (or the raw Python binary), which is fragile: a new venv
or interpreter upgrade resets them. A menubar app scopes the grants to the app's
code-signing identity instead — stable across daemon restarts and config changes,
and revoking the app's permission is a clean kill switch.

```bash
./scripts/build_app.sh            # builds dist/HermesMacAgent.app (PyInstaller + ad-hoc sign)
./scripts/build_app.sh --install  # also copies it to /Applications
open dist/HermesMacAgent.app
```

The app shows a menu bar icon (● = running, ○ = stopped) with live status,
permission state, Start/Stop, deep links into the right System Settings panes,
and shortcuts to `config.json` / `audit.log`. It reads the **same**
`~/.hermes_mac_agent/config.json` as the terminal daemon — run
`./scripts/setup_mac.sh` first. The Hermes side is unchanged.

> ⚠️ **Ad-hoc signing caveat:** TCC identity is derived from the code signature.
> Every rebuild changes the ad-hoc signature, so macOS drops the permission
> grants — re-grant them after each rebuild. For a stable identity, sign with a
> Developer ID certificate (see the note in `scripts/build_app.sh`).

### Grant macOS permissions (TCC)

macOS binds these permissions to the **responsible process** that runs the
daemon: the menubar app (if you built it), or the Python interpreter binary
(terminal daemon). If you change interpreters (e.g. a new venv), re-grant them.

1. **Screen Recording** — System Settings → Privacy & Security → Screen Recording →
   enable for `HermesMacAgent` (or your `python3` / the venv's `bin/python`).
2. **Accessibility** — System Settings → Privacy & Security → Accessibility →
   enable for the same app/binary.
3. Restart the daemon (or the app).

Verify:

```python
from hermes_mac_agent import MacAgent
a = MacAgent("127.0.0.1", 8765, "<token>", ca_cert="~/.hermes_mac_agent/ca.pem")
print(a.health())
# {'ok': True, 'uptime': ..., 'perms': {'screen': True, 'accessibility': True}}
```

### On the Hermes host (the client)

```bash
pip install hermes-mac-agent   # or: pip install -e /path/to/hermes_mac_agent
```

---

## Using the Python client (default integration)

```python
from hermes_mac_agent import MacAgent

agent = MacAgent(
    host="192.168.1.50",          # the Mac's LAN IP
    port=8765,
    token="<token from setup>",
    ca_cert="/path/to/ca.pem",  # the Mac's local CA (signed the daemon's leaf cert)
)

with agent:
    # Screen
    img = agent.screenshot()              # PIL.Image (RGB)
    png = agent.screenshot_bytes()        # raw PNG bytes

    # Mouse — coordinates are global: origin (0,0) is the top-left of the
    # PRIMARY display; monitors to the left/above it use negative coordinates.
    agent.mouse_move(500, 300)
    agent.mouse_click(500, 300)           # or mouse_click(button="right")
    agent.mouse_drag(500, 300, 700, 400)
    agent.mouse_scroll(dy=-3)

    # Keyboard
    agent.type_text("hello from hermes")
    agent.key_press(["command", "t"])     # hotkey combo

    # Processes
    agent.launch_app("Safari", url="https://www.linkedin.com")
    result = agent.run_command("echo ok") # {'exit_code':0,'stdout':'ok\n','stderr':''}
    procs  = agent.list_processes(filter="python")
    agent.stop_process(pid)               # SIGTERM, then SIGKILL if needed

    # Files (chunked transfer, gated by file_allowlist/file_denylist)
    data = agent.read_file("/path/on/mac")        # bytes
    text = agent.read_file_text("/path/on/mac")   # str (utf-8)
    agent.write_file("/path/on/mac", data)        # bytes
    agent.write_file_text("/path/on/mac", text)   # str (utf-8)

    # Health
    print(agent.health())
```

The client authenticates lazily on first use and transparently re-authenticates if
the connection drops.

### Exceptions

| Exception | Meaning |
|---|---|
| `MacAgentError` | Base error; `.code` is the JSON-RPC error code |
| `BlockedByPolicyError` | The daemon's allow/deny policy blocked the request |
| `TccPermissionError` | A macOS TCC permission is missing |

---

## Allow / deny policy

The daemon enforces an **allowlist + denylist** on `run_command` (full command
string), `launch_app` (app name / path), and `read_file` / `write_file` (file
path). The file tools use a **separate** policy namespace (`file_allowlist` /
`file_denylist`) so you can allow file transfer without loosening command or app
policy. Semantics:

- **Denylist wins.** A match blocks the request even if the allowlist also matches.
- Otherwise the request must match an allowlist entry.
- **Secure by default: the allowlist is empty, so nothing is allowed** until you
  add entries. Set `"allowlist": ["*"]` to allow everything (not recommended).
- `*` in the **denylist** = block everything.
- Matching is a **glob** (`fnmatch`) on the full string. A pattern with no glob
  characters also matches as a **whole-word prefix**, so `"sudo"` blocks
  `"sudo ls"` and `"sudo reboot"` but not `"sudoedit"`.

The default safety-net denylist blocks `sudo`, `rm -rf /`, `dd if=*`, `mkfs*`, and
`diskutil eraseDisk*`.

> ⚠️ **The policy is a safety net, not a sandbox.** It is a blocklist in front of
> `shell=True` and can be bypassed by an authenticated caller (e.g. `rm -rf /*`,
> `doas`, `curl … | sh`). The real security boundary is the **token + TLS**. See
> [Security notes](#security-notes).

Edit the lists in `~/.hermes_mac_agent/config.json`, then restart the daemon:

```json
{
  "allowlist": ["ls", "echo *", "open -a Safari*"],
  "denylist":  ["sudo", "rm -rf /", "dd if=*"],
  "file_allowlist": ["/Users/me/shared/*"],
  "file_denylist":  ["/Users/me/.ssh/*"]
}
```

File transfer is **off by default** (empty `file_allowlist`), and each transfer is
capped at **10 MB** total, moved in **256 KB** chunks.

---

## Agent skills

Two [agent skills](.github/skills/) teach an AI agent how to drive the Mac:

- `.github/skills/hermes-mac-python/SKILL.md` — the default `MacAgent` Python client.
- `.github/skills/hermes-mac-mcp/SKILL.md` — the MCP server integration.

## MCP adapter (optional)

If you'd rather consume the Mac through **Model Context Protocol**, run the adapter
as a stdio MCP server. It wraps the same tools via `MacAgent`.

```bash
pip install -e ".[mcp]"
hermes-mac-mcp
```

Configure it in your MCP client (e.g. `mcp.json`):

```json
{
  "mcpServers": {
    "hermes-mac": {
      "command": "hermes-mac-mcp",
      "env": {
        "HERMES_MAC_HOST": "192.168.1.50",
        "HERMES_MAC_TOKEN": "<token>",
        "HERMES_MAC_CA_CERT": "/path/to/ca.pem"
      }
    }
  }
}
```

Env vars: `HERMES_MAC_HOST` (required), `HERMES_MAC_PORT` (default 8765),
`HERMES_MAC_TOKEN` (required), `HERMES_MAC_CA_CERT` (the local CA, `ca.pem`),
`HERMES_MAC_NO_VERIFY=1` (skip TLS verification — not recommended),
`HERMES_MAC_ALLOW_RUN_COMMAND=1` to expose the `run_command` tool, and
`HERMES_MAC_ALLOW_FILE_TRANSFER=1` to expose the `read_file` / `write_file` tools.

> **`run_command` is off by default in the MCP adapter.** An LLM-facing tool that
> can run arbitrary shell commands is a prompt-injection → RCE path, so it is
> only registered as callable when `HERMES_MAC_ALLOW_RUN_COMMAND=1` is set. The
> other tools (screenshot, mouse, keyboard, launch_app, processes) are unaffected.

> **`read_file` / `write_file` are off by default in the MCP adapter.** An
> LLM-facing file read/write is a data-exfiltration and arbitrary-write path, so
> they are only callable when `HERMES_MAC_ALLOW_FILE_TRANSFER=1` is set (and the
> daemon's `file_allowlist` still applies).

---

## Error codes

| Code | Name | Meaning |
|---|---|---|
| -32700 | PARSE_ERROR | Malformed JSON frame |
| -32600 | INVALID_REQUEST | Not a valid JSON-RPC request |
| -32601 | METHOD_NOT_FOUND | Unknown method |
| -32602 | INVALID_PARAMS | Bad/missing parameters |
| -32603 | INTERNAL_ERROR | Unexpected daemon error |
| -32000 | AUTH_REQUIRED | Non-auth frame before a successful auth |
| -32001 | AUTH_FAILED | Wrong/missing token |
| -32002 | BLOCKED_BY_POLICY | Blocked by allow/deny list |
| -32003 | TCC_PERMISSION_DENIED | macOS permission missing |
| -32004 | COMMAND_TIMEOUT | Command/app launch timed out |
| -32005 | PROCESS_NOT_FOUND | No such pid |

---

## Tests

```bash
source .venv/bin/activate
pytest                 # unit + system (GUI-input tests excluded by default)
pytest -m gui          # also run the mouse/keyboard tests (moves your real cursor!)
```

- **Unit tests** (`tests/test_protocol.py`, `tests/test_tools_unit.py`,
  `tests/test_menubar.py`) — protocol parsing, policy matching, arg validation,
  process tools, and the menubar `ServerController` (real daemon, no GUI needed).
- **System tests** (`tests/system/`) — spin up a **real daemon** in a background
  thread (self-signed cert, random token, ephemeral port) and drive it with a real
  `MacAgent` over TLS: auth gate, TLS handshake, allow/deny over the wire, process
  lifecycle, and screen capture.
- **GUI tests** (`@pytest.mark.gui`) — actually move the mouse and type. They skip
  automatically unless you're on macOS with both TCC permissions granted.

---

## Security notes

The daemon grants **full control of the Mac** (screen, keyboard, arbitrary shell
commands, process kill). Treat it accordingly.

- **Binds to loopback by default** (`127.0.0.1`). To let Hermes reach it over the
  LAN, set `"host": "0.0.0.0"` (or a specific IP) in `config.json` — or pass
  `--host` to `setup_mac.sh`. Only do this on a trusted network.
- **Command policy is deny-all by default** (empty allowlist). Add the commands/apps
  you need, or set `"allowlist": ["*"]` to allow everything (not recommended).
- **TLS is on and verified by default.** `setup_mac.sh` generates a **local CA**
  (`ca.pem`) and a **leaf cert** (`cert.pem`) it signs. The daemon serves the leaf;
  the client verifies it against the CA (pass `ca_cert=.../ca.pem`). This is real
  certificate verification — no `verify=False` needed. Setting `verify=False` (or
  `HERMES_MAC_NO_VERIFY=1`) **disables verification and logs a loud warning** — an
  on-path attacker can then MITM the connection and steal the token. Use it only for
  debugging on a trusted network.
- **The token is the only credential** (256-bit). Keep `config.json` at mode 600 and
  the token secret. There is no per-client scoping or rotation yet.
- **Commands run in their own process group** and are killed (whole group) on
  timeout, so a hung command can't orphan grandchildren. The client-supplied timeout
  is clamped to 300s.
- **Command output is bounded.** `run_command` retains only the first and last 256 KB
  of each stream (with a `... [N bytes truncated] ...` marker) while still draining
  the pipes, so a chatty command can't exhaust daemon memory.
- **File transfer is deny-all by default and size-capped.** `read_file` /
  `write_file` require a `file_allowlist` match (empty by default) and are limited
  to 10 MB per file, moved in 256 KB chunks. `write_file` can create parent
  directories, so scope `file_allowlist` to the directories you actually want
  reachable.
- **Every call is audit-logged.** Each authenticated tool call and every auth attempt
  (success or failure) is appended to `~/.hermes_mac_agent/audit.log` (mode 600) with
  a UTC timestamp, source address, method, params, and outcome.
- **The MCP `run_command` tool is opt-in.** It is disabled unless
  `HERMES_MAC_ALLOW_RUN_COMMAND=1` is set, because an LLM-facing shell tool is a
  prompt-injection → RCE path.
- **The allow/deny policy is a safety net, not a sandbox** — it is a blocklist in
  front of `shell=True` and can be bypassed by an authenticated caller. The real
  boundary is the token + TLS. For a hardened deployment, run the daemon as a
  dedicated low-privilege user and/or inside a sandbox.
- **Prefer the menubar app for TCC scoping.** Running the daemon inside
  `HermesMacAgent.app` binds Screen Recording / Accessibility to the app's
  code-signing identity instead of your terminal or a raw Python binary — the
  grants survive daemon restarts and config changes, and revoking the app's
  permission is a clean kill switch. (Ad-hoc-signed builds: re-grant after each
  rebuild; see the build script.)
