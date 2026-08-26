"""Shared JSON-RPC 2.0 protocol types for the Hermes Mac agent.

Both the daemon (server) and the client import from this module so the
wire format has a single source of truth.

Wire format (one JSON object per WebSocket text frame):

    Request:  {"id": <int>, "method": "<name>", "params": {...}}
    Response: {"id": <int>, "result": {...}}
              {"id": <int>, "error": {"code": <int>, "message": "<str>"}}

Auth: the client MUST send ``{"method": "auth", "params": {"token": ...}}``
as its first frame. The server rejects every other method until the token
is verified.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# Error codes
# ---------------------------------------------------------------------------

# Standard JSON-RPC 2.0 codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# Application-specific codes
AUTH_REQUIRED = -32000
AUTH_FAILED = -32001
BLOCKED_BY_POLICY = -32002
TCC_PERMISSION_DENIED = -32003
COMMAND_TIMEOUT = -32004
PROCESS_NOT_FOUND = -32005


class Method(str, Enum):
    """All methods the daemon exposes."""

    AUTH = "auth"
    SCREENSHOT = "screenshot"
    MOUSE_MOVE = "mouse_move"
    MOUSE_CLICK = "mouse_click"
    MOUSE_DRAG = "mouse_drag"
    MOUSE_SCROLL = "mouse_scroll"
    TYPE_TEXT = "type_text"
    KEY_PRESS = "key_press"
    LAUNCH_APP = "launch_app"
    RUN_COMMAND = "run_command"
    LIST_PROCESSES = "list_processes"
    STOP_PROCESS = "stop_process"
    READ_FILE = "read_file"
    WRITE_FILE = "write_file"
    HEALTH = "health"


#: Methods that require a successful auth before they may be called.
AUTHENTICATED_METHODS: frozenset[Method] = frozenset(
    m for m in Method if m is not Method.AUTH
)

# File-transfer bounds (shared by daemon and client). Each chunk must fit in a
# single WebSocket frame under the default 1 MiB max_size; base64 inflates by
# 4/3, so 256 KiB raw (~341 KiB base64) stays well under the limit.
# MAX_FILE_SIZE caps the total size of any single file transfer.
FILE_CHUNK_SIZE = 256 * 1024
MAX_FILE_SIZE = 10 * 1024 * 1024

#: Maximum WebSocket message size (shared by daemon and client). websockets'
#: default is 1 MiB, which is too small for screenshot responses: a large
#: display's PNG can exceed 1 MiB raw, and base64 inflates it by 4/3. 16 MiB
#: covers the worst case of a MAX_FILE_SIZE (10 MiB) PNG base64-encoded
#: (~13.4 MiB) plus JSON envelope overhead.
WS_MAX_MESSAGE_SIZE = 16 * 1024 * 1024


# ---------------------------------------------------------------------------
# Message types
# ---------------------------------------------------------------------------


@dataclass
class Request:
    """A JSON-RPC 2.0 request."""

    id: int
    method: str
    params: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def parse(cls, raw: str | bytes) -> "Request":
        """Parse a raw frame into a Request.

        Raises ``ProtocolError`` on malformed input.
        """
        data = _loads(raw)
        if not isinstance(data, dict):
            raise ProtocolError("request must be a JSON object")
        req_id = data.get("id")
        method = data.get("method")
        if not isinstance(req_id, int):
            raise ProtocolError("'id' must be an integer")
        if not isinstance(method, str) or not method:
            raise ProtocolError("'method' must be a non-empty string")
        params = data.get("params", {})
        if not isinstance(params, dict):
            raise ProtocolError("'params' must be an object")
        return cls(id=req_id, method=method, params=params)

    def to_json(self) -> str:
        return json.dumps(
            {"id": self.id, "method": self.method, "params": self.params},
            separators=(",", ":"),
        )


@dataclass
class Response:
    """A JSON-RPC 2.0 response (result XOR error)."""

    id: int
    result: dict[str, Any] | None = None
    error: Error | None = None

    def to_json(self) -> str:
        payload: dict[str, Any] = {"id": self.id}
        if self.error is not None:
            payload["error"] = self.error.to_dict()
        else:
            payload["result"] = self.result if self.result is not None else {}
        return json.dumps(payload, separators=(",", ":"))

    @property
    def is_error(self) -> bool:
        return self.error is not None


@dataclass
class Error:
    """A JSON-RPC 2.0 error object."""

    code: int
    message: str
    data: Any = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            d["data"] = self.data
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Error":
        return cls(
            code=int(d.get("code", INTERNAL_ERROR)),
            message=str(d.get("message", "unknown error")),
            data=d.get("data"),
        )


class ProtocolError(Exception):
    """Raised when a frame cannot be parsed as a valid request."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _loads(raw: str | bytes) -> Any:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ProtocolError(f"invalid JSON: {exc}") from exc


def make_error_response(req_id: int, code: int, message: str, data: Any = None) -> Response:
    """Convenience constructor for an error response."""
    return Response(id=req_id, error=Error(code=code, message=message, data=data))


def make_result_response(req_id: int, result: dict[str, Any]) -> Response:
    """Convenience constructor for a result response."""
    return Response(id=req_id, result=result)
