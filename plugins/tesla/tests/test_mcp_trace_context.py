"""Bounded, synthetic MCP trace-context regression; no vehicle requests."""
import subprocess
import sys

import pytest
from mcp.server import _otel
from opentelemetry import propagate, trace
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
from starlette.testclient import TestClient

from tesla_plugin.server import TOOLS, create_app


TRACEPARENT = "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01"
FUTURE_PREFIX = "01" + TRACEPARENT[2:] + "-"


@pytest.fixture
def trace_context(monkeypatch):
    previous = propagate.get_global_textmap()
    propagate.set_global_textmap(TraceContextTextMapPropagator())
    observed = []
    extract = _otel.extract_trace_context

    def recording_extract(meta):
        result = extract(meta)
        observed.append(result)
        return result

    monkeypatch.setattr(_otel, "extract_trace_context", recording_extract)
    try:
        yield observed
    finally:
        propagate.set_global_textmap(previous)


def discovery(client, headers, traceparent=None):
    meta = {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {}}
    if traceparent is not None:
        meta["traceparent"] = traceparent
    return client.post("/tesla/mcp", headers={**headers, "mcp-method": "tools/list"},
                       json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": meta}})


@pytest.mark.parametrize("value,valid", [
    (None, False), (TRACEPARENT, True), ("malformed", False),
    (FUTURE_PREFIX.ljust(512, "a"), True), (FUTURE_PREFIX.ljust(513, "a"), False),
    (TRACEPARENT + "\r\ninvalid", False), (TRACEPARENT + " " * 513 + "\ninvalid", False),
])
def test_mcp_metadata_preserves_discovery_and_bounded_trace_context(settings, service, headers, trace_context, value, valid):
    with TestClient(create_app(settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        response = discovery(client, headers(), value)
        assert response.status_code == 200, response.text
        assert {item["name"] for item in response.json()["result"]["tools"]} == set(TOOLS)
        assert len(trace_context) == 1
        context = trace_context[0]
        assert (context is not None) is valid
        if valid:
            assert trace.get_current_span(context).get_span_context().trace_id == int("1234567890abcdef" * 2, 16)
        assert discovery(client, headers(), TRACEPARENT).status_code == 200
        assert len(trace_context) == 2 and trace_context[-1] is not None
    assert service.fleet.calls == []
    with service.store.db() as db:
        assert db.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM intents").fetchone()[0] == 0


@pytest.mark.parametrize("identity,status", [("missing", 401), ("owner", 401), ("client", 401), ("scope", 403)])
def test_auth_rejection_precedes_trace_context_extraction(settings, service, headers, monkeypatch, identity, status):
    def forbidden(_):
        pytest.fail("Unauthenticated or insufficient-scope metadata reached trace extraction")

    monkeypatch.setattr(_otel, "extract_trace_context", forbidden)
    authorization = ({} if identity == "missing" else headers(sub="another-owner") if identity == "owner"
                     else headers(azp="another-client") if identity == "client" else headers(scopes=[]))
    with TestClient(create_app(settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        assert discovery(client, authorization, TRACEPARENT + " " * 513 + "\ninvalid").status_code == status
    assert service.fleet.calls == []


def test_large_trace_context_finishes_in_a_bounded_subprocess():
    script = """
from mcp.shared._otel import extract_trace_context
from opentelemetry import propagate
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
propagate.set_global_textmap(TraceContextTextMapPropagator())
valid = '00-1234567890abcdef1234567890abcdef-1234567890abcdef-01'
assert extract_trace_context({'traceparent': valid + ' ' * 65536 + '\\ninvalid'}) is None
assert extract_trace_context({'traceparent': valid}) is not None
"""
    subprocess.run([sys.executable, "-I", "-c", script], check=True, capture_output=True, timeout=5)
