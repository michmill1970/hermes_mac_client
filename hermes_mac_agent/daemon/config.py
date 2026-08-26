"""Daemon configuration: file layout, defaults, and the allow/deny policy.

Config lives at ``~/.hermes_mac_agent/config.json`` (override with the
``HERMES_MAC_AGENT_CONFIG`` env var, mainly for tests).

    {
      "host": "127.0.0.1",
      "port": 8765,
      "cert_file": "~/.hermes_mac_agent/cert.pem",
      "key_file":  "~/.hermes_mac_agent/key.pem",
      "token":     "<shared secret>",
      "allowlist": [],
      "denylist":  ["sudo", "rm -rf /", "dd if=*", "mkfs*", "diskutil eraseDisk*"],
      "file_allowlist": [],
      "file_denylist":  []
    }

Policy semantics (v1) — SECURE BY DEFAULT:
  * ``denylist`` is evaluated first — a match blocks the request even if the
    allowlist also matches.
  * Otherwise the request must match an ``allowlist`` entry.
  * **Default is deny-all**: an empty allowlist permits nothing. Add the
    commands/apps you actually need, or set ``"allowlist": ["*"]`` to allow
    everything (NOT recommended — see the security notes in the README).
  * ``"*"`` in the allowlist matches everything; ``"*"`` in the denylist
    blocks everything.
  * Matching is ``fnmatch`` glob on the full command string (run_command) or
    the app name / bundle path (launch_app). For commands, a pattern with no
    glob characters also matches as a **whole-word prefix of the argv** (the
    command split on whitespace), so ``"sudo"`` blocks ``"sudo ls"`` but not
    ``"sudoedit"``.
  * ``file_allowlist`` / ``file_denylist`` gate ``read_file`` / ``write_file``
    by path, using the same glob/word-prefix semantics. Default is deny-all.

The allow/deny policy is a *safety net*, not a sandbox: it is a blocklist in
front of ``shell=True`` and can be bypassed by an authenticated caller. The
real security boundary is the token + TLS. See the README "Security notes".
"""

from __future__ import annotations

import fnmatch
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CONFIG_DIR = Path(os.environ.get("HERMES_MAC_AGENT_HOME", "~/.hermes_mac_agent")).expanduser()
CONFIG_FILE = Path(os.environ.get("HERMES_MAC_AGENT_CONFIG", str(CONFIG_DIR / "config.json")))

# Bind to loopback by default. The daemon grants full host control, so it must
# not be reachable from the LAN unless the operator explicitly opts in by
# setting "host" in config.json (e.g. "0.0.0.0" or a specific interface IP).
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
# Secure by default: an empty allowlist permits nothing (deny-all). Operators
# add the commands/apps they need, or explicitly set ["*"] to allow everything.
DEFAULT_ALLOWLIST: list[str] = []
DEFAULT_DENYLIST: list[str] = [
    "sudo",
    "rm -rf /",
    "dd if=*",
    "mkfs*",
    "diskutil eraseDisk*",
]


class PolicyBlockedError(Exception):
    """Raised when a command/app is blocked by the allow/deny policy."""

    def __init__(self, kind: str, target: str, matched: str, list_name: str) -> None:
        self.kind = kind  # "command" | "app"
        self.target = target
        self.matched = matched
        self.list_name = list_name  # "allowlist" | "denylist"
        super().__init__(
            f"{kind} {target!r} blocked by {list_name} (matched pattern {matched!r})"
        )


@dataclass
class Config:
    """Resolved daemon configuration."""

    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    cert_file: str = str(CONFIG_DIR / "cert.pem")
    key_file: str = str(CONFIG_DIR / "key.pem")
    token: str = ""
    allowlist: list[str] = field(default_factory=lambda: list(DEFAULT_ALLOWLIST))
    denylist: list[str] = field(default_factory=lambda: list(DEFAULT_DENYLIST))
    # File-transfer policy (read_file / write_file). A separate namespace from
    # the command/app policy. Secure by default: an empty file_allowlist denies
    # all file access.
    file_allowlist: list[str] = field(default_factory=list)
    file_denylist: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Policy
    # ------------------------------------------------------------------

    def check_command(self, cmd: str) -> None:
        """Raise PolicyBlockedError if *cmd* is not permitted."""
        self._check(cmd, self.denylist, self.allowlist, "command")

    def check_app(self, app: str) -> None:
        """Raise PolicyBlockedError if *app* is not permitted."""
        self._check(app, self.denylist, self.allowlist, "app")

    def check_path(self, path: str) -> None:
        """Raise PolicyBlockedError if *path* is not permitted for file transfer."""
        self._check(path, self.file_denylist, self.file_allowlist, "path")

    @staticmethod
    def _matches(target: str, pattern: str) -> bool:
        """A pattern matches if the target matches it as a glob, or — when
        the pattern contains no glob characters — equals it or starts with
        it as a whole word. Word-prefix matching is what makes a bare entry
        like ``"sudo"`` block ``"sudo ls"`` without matching ``"sudoedit"``.

        Matching is case-insensitive: macOS commands and paths are
        case-insensitive in practice, so a denylist entry like ``"sudo"``
        must also block ``"SUDO ls"`` / ``"Sudo reboot"``.
        """
        target = target.lower()
        pattern = pattern.lower()
        if fnmatch.fnmatch(target, pattern):
            return True
        if any(ch in pattern for ch in "*?["):
            return False
        return target == pattern or target.startswith(pattern + " ")

    @staticmethod
    def _check(target: str, denylist: list[str], allowlist: list[str], kind: str) -> None:
        for pattern in denylist:
            if pattern == "*" or Config._matches(target, pattern):
                raise PolicyBlockedError(kind, target, pattern, "denylist")
        if "*" not in allowlist:
            for pattern in allowlist:
                if Config._matches(target, pattern):
                    return
            raise PolicyBlockedError(kind, target, "<no match>", "allowlist")

    # ------------------------------------------------------------------
    # Loading / writing
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Config":
        """Load config from *path* (default: CONFIG_FILE).

        Missing file or missing keys fall back to defaults. The token is
        never defaulted — an empty token means the daemon refuses to start
        (it must be generated by setup_mac.sh).
        """
        path = Path(path) if path else CONFIG_FILE
        data: dict[str, Any] = {}
        if path.exists():
            try:
                data = json.loads(path.read_text())
            except (json.JSONDecodeError, OSError):
                data = {}
        return cls(
            host=str(data.get("host", DEFAULT_HOST)),
            port=int(data.get("port", DEFAULT_PORT)),
            cert_file=str(Path(data.get("cert_file", str(CONFIG_DIR / "cert.pem"))).expanduser()),
            key_file=str(Path(data.get("key_file", str(CONFIG_DIR / "key.pem"))).expanduser()),
            token=str(data.get("token", "")),
            allowlist=list(data.get("allowlist", DEFAULT_ALLOWLIST)),
            denylist=list(data.get("denylist", DEFAULT_DENYLIST)),
            file_allowlist=list(data.get("file_allowlist", [])),
            file_denylist=list(data.get("file_denylist", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "cert_file": self.cert_file,
            "key_file": self.key_file,
            "token": self.token,
            "allowlist": self.allowlist,
            "denylist": self.denylist,
            "file_allowlist": self.file_allowlist,
            "file_denylist": self.file_denylist,
        }

    def save(self, path: str | Path | None = None) -> Path:
        path = Path(path) if path else CONFIG_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2) + "\n")
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return path
