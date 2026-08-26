"""Unit tests for the JSON-RPC protocol layer (no daemon, no GUI)."""

from __future__ import annotations

import json

import pytest

from hermes_mac_agent.protocol import (
    AUTH_REQUIRED,
    BLOCKED_BY_POLICY,
    INVALID_PARAMS,
    Method,
    ProtocolError,
    Request,
    Response,
    make_error_response,
    make_result_response,
)


class TestRequestParse:
    def test_roundtrip(self):
        req = Request(id=1, method="screenshot", params={"monitor": 1})
        parsed = Request.parse(req.to_json())
        assert parsed.id == 1
        assert parsed.method == "screenshot"
        assert parsed.params == {"monitor": 1}

    def test_bytes_input(self):
        req = Request.parse(b'{"id": 2, "method": "health", "params": {}}')
        assert req.id == 2
        assert req.method == "health"
        assert req.params == {}

    def test_params_default_empty(self):
        req = Request.parse('{"id": 3, "method": "health"}')
        assert req.params == {}

    @pytest.mark.parametrize(
        "raw",
        [
            "not json",
            "[1, 2, 3]",
            '{"id": "x", "method": "health"}',
            '{"id": 1, "method": ""}',
            '{"id": 1, "method": 5}',
            '{"id": 1, "method": "health", "params": [1]}',
            '{"method": "health"}',
        ],
    )
    def test_invalid(self, raw):
        with pytest.raises(ProtocolError):
            Request.parse(raw)


class TestResponse:
    def test_result_json(self):
        resp = make_result_response(7, {"ok": True})
        data = json.loads(resp.to_json())
        assert data == {"id": 7, "result": {"ok": True}}
        assert resp.is_error is False

    def test_result_empty_dict(self):
        resp = make_result_response(8, {})
        data = json.loads(resp.to_json())
        assert data["result"] == {}

    def test_error_json(self):
        resp = make_error_response(9, BLOCKED_BY_POLICY, "blocked", {"list": "denylist"})
        data = json.loads(resp.to_json())
        assert data["id"] == 9
        assert data["error"]["code"] == BLOCKED_BY_POLICY
        assert data["error"]["message"] == "blocked"
        assert data["error"]["data"] == {"list": "denylist"}
        assert resp.is_error is True

    def test_error_without_data_omits_key(self):
        resp = make_error_response(10, INVALID_PARAMS, "bad")
        data = json.loads(resp.to_json())
        assert "data" not in data["error"]

    def test_error_from_dict(self):
        from hermes_mac_agent.protocol import Error

        err = Error.from_dict({"code": AUTH_REQUIRED, "message": "auth first"})
        assert err.code == AUTH_REQUIRED
        assert err.message == "auth first"
        assert err.data is None


class TestMethodEnum:
    def test_all_methods_have_values(self):
        for m in Method:
            assert isinstance(m.value, str) and m.value

    def test_auth_not_in_authenticated_set(self):
        from hermes_mac_agent.protocol import AUTHENTICATED_METHODS

        assert Method.AUTH not in AUTHENTICATED_METHODS
        assert Method.HEALTH in AUTHENTICATED_METHODS
        assert len(AUTHENTICATED_METHODS) == len(Method) - 1
