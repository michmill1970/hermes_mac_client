#!/usr/bin/env bash
#
# build_app.sh — build HermesMacAgent.app (menubar host for the daemon).
#
# Produces dist/HermesMacAgent.app with PyInstaller, then ad-hoc signs it.
#
# Usage:
#   ./scripts/build_app.sh            # build into dist/
#   ./scripts/build_app.sh --install  # build + copy to /Applications
#
# Notes:
#   * Ad-hoc signing: macOS TCC keys Screen Recording / Accessibility to the
#     app's code signature. An ad-hoc signature is stable as long as you do
#     NOT rebuild — every rebuild changes the signature and macOS drops the
#     permission grants (you must re-grant them). For stable identity across
#     rebuilds, sign with a Developer ID certificate instead:
#       codesign --force --deep --sign "Developer ID Application: <Name>" \
#         dist/HermesMacAgent.app
#   * The app reads the same ~/.hermes_mac_agent/config.json as the terminal
#     daemon — run ./scripts/setup_mac.sh first.
#
set -euo pipefail

cd "$(dirname "$0")/.."

INSTALL=0
[[ "${1:-}" == "--install" ]] && INSTALL=1

command -v python3 >/dev/null || { echo "error: python3 not found" >&2; exit 1; }

# Prefer the project venv if present.
if [[ -x ".venv/bin/python" ]]; then
  PY=".venv/bin/python"
else
  PY="python3"
fi

echo "==> Installing build dependencies (pyobjc, pyinstaller)"
"$PY" -m pip install -e ".[menubar]"

echo "==> Building HermesMacAgent.app (PyInstaller)"
"$PY" -m PyInstaller --noconfirm --clean \
  --windowed \
  --name "HermesMacAgent" \
  --osx-bundle-identifier "com.hermes.mac-agent" \
  --hidden-import "websockets.asyncio.server" \
  --hidden-import "mss" \
  --hidden-import "pyautogui" \
  --hidden-import "HIServices" \
  --hidden-import "ApplicationServices" \
  --collect-submodules "hermes_mac_agent" \
  hermes_mac_agent/menubar/__main__.py

APP="dist/HermesMacAgent.app"
[[ -d "$APP" ]] || { echo "error: build did not produce $APP" >&2; exit 1; }

echo "==> Ad-hoc signing"
codesign --force --deep --sign - "$APP"

echo
echo "Built: $APP"
echo
if [[ "$INSTALL" -eq 1 ]]; then
  echo "==> Installing to /Applications"
  rm -rf "/Applications/HermesMacAgent.app"
  cp -R "$APP" /Applications/
  echo "Installed: /Applications/HermesMacAgent.app"
fi
echo
echo "Next steps:"
echo "  1. Run ./scripts/setup_mac.sh (if you haven't already) for cert/token/config."
echo "  2. Open the app:  open $APP"
echo "  3. Grant Screen Recording + Accessibility to 'HermesMacAgent' in"
echo "     System Settings → Privacy & Security, then restart the app."
echo "  4. The menu bar icon (●) shows the daemon is running."
echo
echo "NOTE: rebuilding the app changes its ad-hoc signature — macOS will drop"
echo "the TCC grants. Re-grant them after every rebuild (or sign with a"
echo "Developer ID certificate for a stable identity)."
