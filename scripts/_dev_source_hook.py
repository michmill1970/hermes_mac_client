"""PyInstaller runtime hook: optional developer source override.

Problem: TCC (Screen Recording / Accessibility) is keyed to the app bundle's
cdhash. Every rebuild changes the cdhash and macOS drops the grants —
painful during the dev/debug loop, where you want to iterate on daemon code
hundreds of times while keeping the bundle's permissions.

Solution: this hook lets a *frozen* bundle import ``hermes_mac_agent`` from
a plain source tree instead of its embedded copy. The bundle binary itself
is untouched, so its cdhash — and therefore its TCC grants — survive code
edits.

Activation is explicit and dev-only: the file ``~/.hermes_mac_agent/dev_source``
must exist and contain the absolute path of a directory that contains a
``hermes_mac_agent`` package (i.e. the repo checkout root). No marker file
=> the bundle behaves exactly like a production build.

The marker is read before anything else runs, so a broken source tree can
only fail the import of hermes_mac_agent, never silently half-override.
"""

import os
import sys


def _log(msg: str) -> None:
    # A --windowed PyInstaller bundle swallows Python-level stderr, so the
    # hook's activity is recorded to a log file next to the marker.
    try:
        with open(os.path.join(
            os.environ.get("HERMES_MAC_AGENT_HOME")
            or os.path.expanduser("~/.hermes_mac_agent"),
            "dev_source.log",
        ), "a", encoding="utf-8") as fh:
            import datetime

            fh.write(f"{datetime.datetime.now().isoformat()} {msg}\n")
    except OSError:
        pass


def _apply() -> None:
    config_dir = os.environ.get("HERMES_MAC_AGENT_HOME") or os.path.expanduser(
        "~/.hermes_mac_agent"
    )
    marker = os.path.join(config_dir, "dev_source")
    try:
        with open(marker, encoding="utf-8") as fh:
            root = fh.read().strip()
    except OSError:
        return  # no marker: production behaviour
    if not root:
        return
    pkg = os.path.join(root, "hermes_mac_agent", "__init__.py")
    if not os.path.isfile(pkg):
        _log(
            f"marker {marker} points at {root!r}, which has no "
            "hermes_mac_agent package; ignoring"
        )
        return
    if root not in sys.path:
        sys.path.insert(0, root)
    # PyInstaller's frozen (PYZ) importer can outrank sys.path on
    # sys.meta_path; re-insert PathFinder at the front so the source tree
    # wins for hermes_mac_agent and nothing else (the repo root holds only
    # repo packages, which shadow nothing from the frozen stdlib set).
    try:
        from importlib.machinery import PathFinder

        if PathFinder not in sys.meta_path or sys.meta_path[0] is not PathFinder:
            sys.meta_path.insert(0, PathFinder)
    except ImportError:
        pass
    _log(f"importing hermes_mac_agent from {root}")


_apply()
