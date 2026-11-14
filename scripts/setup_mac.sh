#!/usr/bin/env bash
#
# setup_mac.sh — one-time setup for the Hermes Mac agent daemon on the MacBook.
#
#   1. Creates ~/.hermes_mac_agent/ with a local CA + a leaf TLS cert it signs
#   2. Generates a random shared token (FIRST RUN ONLY — re-runs keep it)
#   3. Writes config.json (with default allow/deny lists; re-runs preserve the
#      existing token and allow/deny lists, updating only what you pass)
#   4. Prints the exact macOS TCC permission steps
#   5. Optionally installs the launchd agent (pass --install-launchd)
#
# Usage:
#   ./scripts/setup_mac.sh [--install-launchd] [--port 8765]
#                          [--host 127.0.0.1] [--allow-all] [--regen-certs]
#
# The cert's SAN covers the machine's DNS names and its IP addresses
# (loopback + all interface IPs + --host), so clients can connect and verify
# by either. To issue a new cert (e.g. after the Mac gets a new IP), delete
# cert.pem/key.pem or pass --regen-certs.
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
HOST_SET=0
PORT_SET=0
INSTALL_LAUNCHD=0
ALLOW_ALL=0
REGEN_CERTS=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-launchd) INSTALL_LAUNCHD=1; shift ;;
    --port) PORT="$2"; PORT_SET=1; shift 2 ;;
    --host) HOST="$2"; HOST_SET=1; shift 2 ;;
    --allow-all) ALLOW_ALL=1; shift ;;
    --regen-certs) REGEN_CERTS=1; shift ;;
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
#
# SAN must cover every name/address clients dial: clients verify the leaf
# against the host they connect to, so a cert missing the LAN IP breaks the
# documented "connect by LAN IP" setup (IP address mismatch at handshake).
# ---------------------------------------------------------------------------
build_san() {
  local san ip
  san="DNS:$(hostname),DNS:$(hostname -s 2>/dev/null || hostname),DNS:localhost,IP:127.0.0.1"
  # Interface IPv4s — BSD/GNU ifconfig (macOS), then iproute2 as fallback.
  for ip in $(ifconfig 2>/dev/null | awk '$1=="inet" && $2!="127.0.0.1" {print $2}'); do
    case ",$san," in *",IP:$ip,"*) ;; *) san="$san,IP:$ip" ;; esac
  done
  if command -v ip >/dev/null 2>&1; then
    for ip in $(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1); do
      case ",$san," in *",IP:$ip,"*) ;; *) san="$san,IP:$ip" ;; esac
    done
  elif command -v python3 >/dev/null 2>&1; then
    # Last resort (no ifconfig/ip): ask the kernel which source address the
    # default route would use — sends no traffic.
    ip="$(python3 -c 'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.connect(("8.8.8.8",80));print(s.getsockname()[0])' 2>/dev/null || true)"
    [[ -n "$ip" ]] && case ",$san," in *",IP:$ip,"*) ;; *) san="$san,IP:$ip" ;; esac
  fi
  # An explicit --host <IPv4> belongs in the SAN even if it is not yet
  # assigned to an interface (e.g. a reserved static address).
  if [[ "$HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ && "$HOST" != "0.0.0.0" ]]; then
    case ",$san," in *",IP:$HOST,"*) ;; *) san="$san,IP:$HOST" ;; esac
  fi
  printf '%s' "$san"
}

SAN="$(build_san)"

if [[ ! -f "$CA_CERT" || ! -f "$CA_KEY" ]]; then
  echo "==> Generating local CA ($CA_CERT)"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$CA_KEY" -out "$CA_CERT" -days 3650 \
    -subj "/CN=Hermes Mac Agent Local CA"
  chmod 600 "$CA_KEY" "$CA_CERT"
fi

if [[ -f "$CERT" && -f "$KEY" && "$REGEN_CERTS" -eq 0 ]]; then
  echo "==> TLS leaf cert already exists at $CERT (keeping it; --regen-certs to reissue)"
  # A kept cert cannot serve addresses it was not issued for — warn if the
  # requested bind IP is missing from it.
  if [[ "$HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ && "$HOST" != "0.0.0.0" ]] \
     && ! openssl x509 -in "$CERT" -noout -text 2>/dev/null | grep -qE "IP( Address)?:$HOST"; then
    echo "WARNING: the existing cert does not list $HOST in its SAN — clients"
    echo "         connecting to $HOST will fail TLS verification."
    echo "         Re-run with --regen-certs to reissue it."
  fi
else
  echo "==> Generating leaf cert signed by the local CA (SAN: $SAN)"
  openssl req -newkey rsa:2048 -nodes \
    -keyout "$KEY" -out "$CONFIG_DIR/leaf.csr" \
    -subj "/CN=$(hostname)"
  openssl x509 -req -in "$CONFIG_DIR/leaf.csr" \
    -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
    -out "$CERT" -days 3650 \
    -extfile <(printf "subjectAltName=%s" "$SAN")
  rm -f "$CONFIG_DIR/leaf.csr"
  chmod 600 "$KEY" "$CERT"
fi

# ---------------------------------------------------------------------------
# 2. config.json — token + allow/deny lists are ONLY created fresh when no
#    config exists yet. A re-run never overwrites the token (the Hermes side
#    already has it) nor hand-edited allow/deny lists; it updates only what
#    was explicitly passed (--host/--port/--allow-all) and the cert/key paths.
# ---------------------------------------------------------------------------
find_working_python3() {
  # The macOS /usr/bin/python3 shim can point at a broken Xcode install, so
  # probe candidates for a python3 that actually runs.
  local p
  for p in "${VIRTUAL_ENV:-}/bin/python3" python3 /Library/Developer/CommandLineTools/usr/bin/python3 /usr/bin/python3; do
    [[ -n "$p" ]] || continue
    if command -v "$p" >/dev/null 2>&1 && "$p" -c 'import json' 2>/dev/null; then
      command -v "$p"
      return 0
    fi
  done
  return 1
}

TOKEN_IS_NEW=0
if [[ -f "$CONFIG" ]]; then
  echo "==> Updating existing $CONFIG — token and allow/deny lists are PRESERVED"
  PY3="$(find_working_python3 || true)"
  if [[ -z "$PY3" ]]; then
    echo "error: $CONFIG exists, and no working python3 was found to update it" >&2
    echo "       in place without clobbering your token/allowlist. Fix python3" >&2
    echo "       (or activate the project venv), or delete $CONFIG to start over." >&2
    exit 1
  fi
  MERGE_OUT="$("$PY3" - "$CONFIG" "$HOST" "$PORT" "$CERT" "$KEY" "$ALLOW_ALL" "$HOST_SET" "$PORT_SET" <<'PYEOF'
import json
import secrets
import sys

path, host, port, cert, key, allow_all, host_set, port_set = sys.argv[1:9]
try:
    with open(path) as fh:
        cfg = json.load(fh)
except (OSError, ValueError) as exc:
    print(f"unreadable config: {exc}", file=sys.stderr)
    sys.exit(1)
if not isinstance(cfg, dict):
    print("config is not a JSON object", file=sys.stderr)
    sys.exit(1)

if cfg.get("token"):
    pass  # preserve the shared secret the Hermes side already holds
else:
    cfg["token"] = secrets.token_hex(32)
    print("NEW_TOKEN")

# Policy lists: keep whatever the operator curated. --allow-all is the only
# explicit way to change the allowlist on a re-run.
cfg.setdefault("allowlist", ["*"] if allow_all == "1" else [])
cfg.setdefault("denylist", ["sudo", "rm -rf /", "dd if=*", "mkfs*", "diskutil eraseDisk*"])
cfg.setdefault("file_allowlist", [])
cfg.setdefault("file_denylist", [])
if allow_all == "1":
    cfg["allowlist"] = ["*"]

cfg["host"] = host if host_set == "1" else cfg.get("host", "127.0.0.1")
cfg["port"] = int(port) if port_set == "1" else cfg.get("port", 8765)
cfg["cert_file"] = cert
cfg["key_file"] = key

with open(path, "w") as fh:
    json.dump(cfg, fh, indent=2)
    fh.write("\n")
PYEOF
)"
  chmod 600 "$CONFIG"
  [[ "$MERGE_OUT" == *NEW_TOKEN* ]] && TOKEN_IS_NEW=1
  TOKEN="$("$PY3" -c 'import json,sys; print(json.load(open(sys.argv[1])).get("token",""))' "$CONFIG")"
else
  if [[ "$ALLOW_ALL" -eq 1 ]]; then
    ALLOWLIST_JSON='["*"]'
  else
    ALLOWLIST_JSON='[]'
  fi
  TOKEN="$(openssl rand -hex 32)"
  TOKEN_IS_NEW=1
  echo "==> Writing $CONFIG"
  cat > "$CONFIG" <<EOF
{
  "host": "$HOST",
  "port": $PORT,
  "cert_file": "$CERT",
  "key_file": "$KEY",
  "token": "$TOKEN",
  "allowlist": $ALLOWLIST_JSON,
  "denylist": ["sudo", "rm -rf /", "dd if=*", "mkfs*", "diskutil eraseDisk*"],
  "file_allowlist": [],
  "file_denylist": []
}
EOF
  chmod 600 "$CONFIG"
fi

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
if [[ "$TOKEN_IS_NEW" -eq 1 ]]; then
  TOKEN_TEXT="Token (store this — Hermes needs it):
   $TOKEN"
else
  TOKEN_TEXT="Token: kept the existing one in $CONFIG (unchanged).
  Print it with:  ${PY3:-python3} -c \"import json,sys; print(json.load(open(sys.argv[1]))['token'])\" \"$CONFIG\"
   To rotate it, delete the token field (or the file) and re-run."
fi
cat <<EOF

============================================================
 Setup complete.

 $TOKEN_TEXT

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

 VERIFY (note: ca_cert is the CA, not the leaf; token is read from the config):
      $PYTHON_BIN -c "from hermes_mac_agent import MacAgent; \\
      from hermes_mac_agent.daemon.config import Config; c = Config.load('$CONFIG'); \\
      a = MacAgent('127.0.0.1', $PORT, c.token, ca_cert='$CA_CERT'); \\
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
