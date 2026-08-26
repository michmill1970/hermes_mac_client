---
name: hermes-mac-mcp
description: "Use when the user wants to control their MacBook through Model Context Protocol (MCP) instead of the Python client: configure the hermes-mac MCP server in an MCP client (mcp.json), set HERMES_MAC_* environment variables, or use the exposed MCP tools (screenshot, mouse_click, type_text, key_press, launch_app, run_command, list_processes, stop_process, health). Prefer the hermes-mac-python skill when writing Python code directly."
---

# Controlling the Mac via the MCP adapter

This is the **alternative** integration. Instead of importing `MacAgent` in Python,
you run `hermes-mac-mcp` as a **stdio MCP server** and let an MCP client (Hermes,
Claude, VS Code, etc.) call the Mac-control tools. It wraps the same daemon over the
same TLS WebSocket.

Use the `hermes-mac-python` skill instead when you're writing Python code directly.

## When to use

- "Set up the Mac as an MCP server"
- "Add the Mac tools to my MCP client / mcp.json"
- "How do I configure the hermes-mac MCP server?"
- Using the Mac-control MCP tools from an MCP-capable agent.

## Install

```bash
pip install -e ".[mcp]"     # adds the 'mcp' package + the hermes-mac-mcp entry point
```

The server runs over **stdio** — the MCP client launches it as a subprocess.

## Configure the MCP client

Example `mcp.json`:

```json
{
  "mcpServers": {
    "hermes-mac": {
      "command": "hermes-mac-mcp",
      "env": {
        "HERMES_MAC_HOST": "192.168.1.50",
        "HERMES_MAC_TOKEN": "<token from setup>",
        "HERMES_MAC_CA_CERT": "~/.hermes_mac_agent/ca.pem"
      }
    }
  }
}
```

### Environment variables

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `HERMES_MAC_HOST` | yes | — | The Mac's LAN IP |
| `HERMES_MAC_PORT` | no | `8765` | Daemon port |
| `HERMES_MAC_TOKEN` | yes | — | Shared auth token (from `setup_mac.sh`) |
| `HERMES_MAC_CA_CERT` | no | — | Path to the Mac's local CA cert (`ca.pem`) that signed the leaf cert |
| `HERMES_MAC_NO_VERIFY` | no | — | Set to `"1"` to skip TLS verification (debugging only) |
| `HERMES_MAC_ALLOW_RUN_COMMAND` | no | — | Set to `"1"` to enable the `run_command` tool (off by default) |
| `HERMES_MAC_ALLOW_FILE_TRANSFER` | no | — | Set to `"1"` to enable `read_file` / `write_file` (off by default) |

## Exposed MCP tools

All tools return **strings** (MCP-friendly). `screenshot` returns base64-encoded PNG.

| Tool | Args | Returns |
|---|---|---|
| `screenshot` | `monitor=1` (`0`=all) | base64 PNG |
| `mouse_move` | `x, y, duration=0.0` | `"ok"` |
| `mouse_click` | `x, y, button="left", clicks=1` | `"ok"` |
| `mouse_drag` | `x1, y1, x2, y2, button="left"` | `"ok"` |
| `mouse_scroll` | `dx=0, dy=0` | `"ok"` |
| `type_text` | `text, interval=0.0` | `"ok"` |
| `key_press` | `keys` (list, e.g. `["command","t"]`) | `"ok"` |
| `launch_app` | `app, url=None` | `"launched <app> (pid=<pid>)"` |
| `run_command` | `cmd, cwd=None, timeout=60.0` | `exit_code=...\nstdout:...\nstderr:...` |
| `list_processes` | `filter=None` | one line per process: `pid\tname\tcpu=..%\tmem=..%` |
| `stop_process` | `pid, sig="TERM"` | `"stopped <pid>"` |
| `read_file` | `path` | base64 of the file bytes (gated, see below) |
| `write_file` | `path, data_base64` | `"ok"` (gated, see below) |
| `health` | — | `str(agent.health())` |

> **`read_file` / `write_file` are off by default.** They only work when
> `HERMES_MAC_ALLOW_FILE_TRANSFER=1` is set in the MCP env **and** the daemon's
> `file_allowlist` permits the path. An LLM-facing file read/write is an
> exfiltration / arbitrary-write path, so it is disabled unless explicitly enabled.

## Prerequisites & troubleshooting

Same as the Python client — the daemon must be running on the Mac with TCC
permissions granted:

- Run `./scripts/setup_mac.sh` on the Mac (cert + token + config).
- Grant **Screen Recording** and **Accessibility** to the daemon's Python binary.
- **`AUTH_FAILED`** → `HERMES_MAC_TOKEN` doesn't match the Mac's `config.json`.
- **TLS handshake fails** → set `HERMES_MAC_CA_CERT` to the Mac's `ca.pem`
  (the local CA that signed the leaf cert; or `HERMES_MAC_NO_VERIFY=1` for
  debugging only).
- **`HERMES_MAC_HOST is not set`** → the env var is missing from the MCP config.
- **Command blocked** → the daemon's allow/deny policy rejected it; edit
  `~/.hermes_mac_agent/config.json` on the Mac and restart the daemon.
