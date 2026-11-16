"""Bounded, synthetic MCP trace-context regression; no gateway actions."""
import subprocess
import sys

import pytest
from mcp.server import _otel
from opentelemetry import propagate, trace
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

from sally_whatsapp.server import TOOLS


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


def discovery(client, traceparent=None):
    meta = {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {}}
    if traceparent is not None:
        meta["traceparent"] = traceparent
    return client.post("/mcp", headers={"mcp-method": "tools/list"},
                       json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": meta}})


@pytest.mark.parametrize("value,valid", [
    (None, False), (TRACEPARENT, True), ("malformed", False),
    (FUTURE_PREFIX.ljust(512, "a"), True), (FUTURE_PREFIX.ljust(513, "a"), False),
    (TRACEPARENT + "\r\ninvalid", False), (TRACEPARENT + " " * 513 + "\ninvalid", False),
])
def test_mcp_metadata_preserves_discovery_and_bounded_trace_context(app_client, environment, trace_context, value, valid):
    app, client = app_client
    response = discovery(client, value)
    assert response.status_code == 200, response.text
    assert {item["name"] for item in response.json()["result"]["tools"]} == set(TOOLS)
    assert len(trace_context) == 1
    context = trace_context[0]
    assert (context is not None) is valid
    if valid:
        assert trace.get_current_span(context).get_span_context().trace_id == int("1234567890abcdef" * 2, 16)
    assert discovery(client, TRACEPARENT).status_code == 200
    assert len(trace_context) == 2 and trace_context[-1] is not None
    assert environment[2].sent == [] and environment[1].requests == []
    with app.state.service.store.db() as db:
        assert db.execute("SELECT COUNT(*) FROM sends").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM action_jobs").fetchone()[0] == 0


@pytest.mark.parametrize("identity,status", [("missing", 401), ("owner", 401), ("client", 401), ("scope", 403)])
def test_auth_rejection_precedes_trace_context_extraction(app_client, environment, monkeypatch, identity, status):
    def forbidden(_):
        pytest.fail("Unauthenticated or insufficient-scope metadata reached trace extraction")

    monkeypatch.setattr(_otel, "extract_trace_context", forbidden)
    _, client = app_client
    token = environment[3]
    if identity == "missing":
        del client.headers["Authorization"]
    else:
        claims = {"sub": "another-owner"} if identity == "owner" else {"azp": "another-client"} if identity == "client" else {"scope": ""}
        client.headers["Authorization"] = "Bearer " + token(**claims)
    assert discovery(client, TRACEPARENT + " " * 513 + "\ninvalid").status_code == status
    assert environment[2].sent == [] and environment[1].requests == []


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
