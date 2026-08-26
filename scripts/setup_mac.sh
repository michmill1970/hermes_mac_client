#!/usr/bin/env bash
#
# setup_mac.sh — one-time setup for the Hermes Mac agent daemon on the MacBook.
#
#   1. Creates ~/.hermes_mac_agent/ with a local CA + a leaf TLS cert it signs
#   2. Generates a random shared token
#   3. Writes config.json (with default allow/deny lists)
#   4. Prints the exact macOS TCC permission steps
#   5. Optionally installs the launchd agent (pass --install-launchd)
#
# Usage:
#   ./scripts/setup_mac.sh [--install-launchd] [--port 8765]
#                          [--host 127.0.0.1] [--allow-all]
#
# Security defaults:
#   * Binds to 127.0.0.1 (loopback) only. Pass --host 0.0.0.0 (or a specific
#     IP) to expose it on the LAN — the daemon grants full host control, so
#     only do this on a trusted network.
#   * Command policy is DENY-ALL by default (empty allowlist). Pass --allow-all
#     to allow every command (NOT recommended).
#
set -euo pipefail

CONFIG_DIR="${HERMES_MAC_AGENT_HOME:-$HOME/.hermes_mac_agent}"
CERT="$CONFIG_DIR/cert.pem"
KEY="$CONFIG_DIR/key.pem"
CA_CERT="$CONFIG_DIR/ca.pem"
CA_KEY="$CONFIG_DIR/ca.key"
CONFIG="$CONFIG_DIR/config.json"
HOST="127.0.0.1"
PORT=8765
INSTALL_LAUNCHD=0
ALLOW_ALL=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-launchd) INSTALL_LAUNCHD=1; shift ;;
    --port) PORT="$2"; shift 2 ;;
    --host) HOST="$2"; shift 2 ;;
    --allow-all) ALLOW_ALL=1; shift ;;
    --config-dir) CONFIG_DIR="$2"; CERT="$2/cert.pem"; KEY="$2/key.pem"; CA_CERT="$2/ca.pem"; CA_KEY="$2/ca.key"; CONFIG="$2/config.json"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done

command -v openssl >/dev/null || { echo "error: openssl not found" >&2; exit 1; }

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

# ---------------------------------------------------------------------------
# 1. TLS material: a local CA + a leaf cert it signs.
#
# The leaf is what the daemon serves; the CA is what the client verifies
# against (ca_cert=ca.pem). This lets the client do REAL certificate
# verification instead of falling back to verify=False. The CA is local and
# never leaves this machine, so it is as trustworthy as the token itself.
# ---------------------------------------------------------------------------
if [[ ! -f "$CA_CERT" || ! -f "$CA_KEY" ]]; then
  echo "==> Generating local CA ($CA_CERT)"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$CA_KEY" -out "$CA_CERT" -days 3650 \
    -subj "/CN=Hermes Mac Agent Local CA"
  chmod 600 "$CA_KEY" "$CA_CERT"
fi

if [[ -f "$CERT" && -f "$KEY" ]]; then
  echo "==> TLS leaf cert already exists at $CERT (keeping it)"
else
  echo "==> Generating leaf cert signed by the local CA"
  openssl req -newkey rsa:2048 -nodes \
    -keyout "$KEY" -out "$CONFIG_DIR/leaf.csr" \
    -subj "/CN=$(hostname)"
  openssl x509 -req -in "$CONFIG_DIR/leaf.csr" \
    -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
    -out "$CERT" -days 3650 \
    -extfile <(printf "subjectAltName=DNS:$(hostname),IP:127.0.0.1")
  rm -f "$CONFIG_DIR/leaf.csr"
  chmod 600 "$KEY" "$CERT"
fi

# ---------------------------------------------------------------------------
# 2. Random token
# ---------------------------------------------------------------------------
TOKEN="$(openssl rand -hex 32)"

# ---------------------------------------------------------------------------
# 3. config.json (secure defaults: loopback + deny-all command policy)
# ---------------------------------------------------------------------------
if [[ "$ALLOW_ALL" -eq 1 ]]; then
  ALLOWLIST_JSON='["*"]'
else
  ALLOWLIST_JSON='[]'
fi

echo "==> Writing $CONFIG"
cat > "$CONFIG" <<EOF
{
  "host": "$HOST",
  "port": $PORT,
  "cert_file": "$CERT",
  "key_file": "$KEY",
  "token": "$TOKEN",
  "allowlist": $ALLOWLIST_JSON,
  "denylist": ["sudo", "rm -rf /", "dd if=*", "mkfs*", "diskutil eraseDisk*"]
}
EOF
chmod 600 "$CONFIG"

# Security warnings for non-default (riskier) choices.
if [[ "$HOST" != "127.0.0.1" && "$HOST" != "localhost" ]]; then
  echo "WARNING: daemon will bind to $HOST (not loopback). Anyone who can reach"
  echo "         this address AND holds the token gets full control of the Mac."
  echo "         Only do this on a trusted network."
fi
if [[ "$ALLOW_ALL" -eq 1 ]]; then
  echo "WARNING: --allow-all permits EVERY shell command. The denylist is a"
  echo "         bypassable safety net, not a sandbox. Prefer an explicit"
  echo "         allowlist of the commands you actually need."
fi

# ---------------------------------------------------------------------------
# 4. TCC instructions
# ---------------------------------------------------------------------------
PYTHON_BIN="$(command -v python3)"
# Resolve the real interpreter binary (venv symlinks resolve to the parent
# interpreter). TCC keys permission to THIS executable's code-signing identity,
# not to the venv — so this is the binary to grant if you run the daemon
# directly rather than from a terminal.
PYTHON_REAL="$(readlink -f "$PYTHON_BIN" 2>/dev/null || echo "$PYTHON_BIN")"
cat <<EOF

============================================================
 Setup complete.

 Token (store this — Hermes needs it):
   $TOKEN

 Config: $CONFIG
============================================================

 NEXT STEPS — grant macOS permissions (TCC):

 macOS TCC binds Screen Recording / Accessibility to a process's code-signing
 identity — NOT to a venv. A venv's python is a symlink to its parent
 interpreter, so the grant attaches to that parent binary. Two ways to grant:

 OPTION A — grant to your terminal (easiest, recommended):
   A process launched from a terminal inherits the terminal's TCC grants.
   1. System Settings → Privacy & Security → Screen Recording → add your
      terminal (Terminal.app / iTerm / VS Code).
   2. System Settings → Privacy & Security → Accessibility → add the same.
   3. Fully quit and relaunch the terminal (TCC changes need a new process).
   4. Start the daemon from that terminal:
        $PYTHON_BIN -m hermes_mac_agent.daemon.server

 OPTION B — grant to the Python binary (for a launchd daemon):
   1. System Settings → Privacy & Security → Screen Recording → add:
        $PYTHON_REAL
   2. System Settings → Privacy & Security → Accessibility → add the same.
   3. Restart the daemon.
   NOTE: re-grant after any Python upgrade (the binary's signature changes).

 VERIFY (note: ca_cert is the CA, not the leaf):
      $PYTHON_BIN -c "from hermes_mac_agent import MacAgent; \\
a = MacAgent('127.0.0.1', $PORT, '$TOKEN', ca_cert='$CA_CERT'); \\
print(a.health())"
    → expect {'ok': True, ..., 'perms': {'screen': True, 'accessibility': True}}
    If a permission is still false, health() now returns a 'tcc' key naming the
    missing permission and how to fix it.

 TLS / CA:
   The daemon serves $CERT (a leaf). The client verifies it against
   $CA_CERT (the local CA). Pass ca_cert='$CA_CERT' to MacAgent so the
   handshake is properly verified — do NOT use verify=False.

 EDITING THE ALLOW/DENY LISTS:
   Edit "allowlist" / "denylist" in $CONFIG, then restart the daemon.
   - allowlist is DENY-ALL by default (empty = nothing is allowed).
     Add the commands/apps you need, e.g. ["ls", "echo *", "open -a Safari*"].
   - "*" in allowlist = allow everything (NOT recommended)
   - "*" in denylist  = block everything
   - denylist always wins over allowlist
   - patterns are globs matched against the full command string / app name

 SECURITY: the allow/deny policy is a safety net, not a sandbox. The real
   boundary is the token + TLS. Keep the token secret and config.json at 600.

EOF

# ---------------------------------------------------------------------------
# 5. Optional launchd install
# ---------------------------------------------------------------------------
if [[ "$INSTALL_LAUNCHD" -eq 1 ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  PLIST_SRC="$SCRIPT_DIR/../launchd/com.hermes.mac-agent.plist"
  PLIST_DST="$HOME/Library/LaunchAgents/com.hermes.mac-agent.plist"
  if [[ ! -f "$PLIST_SRC" ]]; then
    echo "error: $PLIST_SRC not found" >&2
    exit 1
  fi
  echo "==> Installing launchd agent"
  sed -e "s|__PYTHON__|$PYTHON_BIN|g" \
      -e "s|__CONFIG_DIR__|$CONFIG_DIR|g" "$PLIST_SRC" > "$PLIST_DST"
  launchctl unload "$PLIST_DST" 2>/dev/null || true
  launchctl load "$PLIST_DST"
  echo "==> launchd agent installed and loaded: $PLIST_DST"
  echo "    Logs: log stream --predicate 'process == \"python3\" AND eventMessage CONTAINS \"hermes_mac_agent\"'"
fi
