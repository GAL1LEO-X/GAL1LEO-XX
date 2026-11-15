"""Local worker failures must not starve temporary collection recovery."""
import asyncio
import json
from threading import Event

import pytest
from starlette.testclient import TestClient

from tesla_plugin.server import create_app
from tesla_plugin.worker import WorkerProgress


@pytest.mark.parametrize("failed", ["event_delivery", "telemetry_rules", "temporary_collection", "retention"])
def test_stage_errors_do_not_starve_other_work(clock, failed):
    stages = ["event_delivery", "telemetry_rules", "temporary_collection", "retention"]
    calls = []
    progress = WorkerProgress(clock, clock)

    def action(name):
        def run():
            calls.append(name)
            clock.advance(0.5)
            if name == failed:
                raise ValueError("synthetic-private-payload-must-not-be-exposed")
        return run

    asyncio.run(progress.cycle([(name, action(name)) for name in stages], asyncio.Event()))
    assert calls == stages
    assert progress.state["last_error"] == "ValueError"
    assert progress.state["vehicle_online_proven"] is False
    assert "private-payload" not in json.dumps(progress.state)
    for name, value in progress.state["stages"].items():
        assert value["status"] == ("error" if name == failed else "completed")
        assert value["duration_seconds"] == 0.5
    asyncio.run(progress.cycle([(name, lambda: None) for name in stages], asyncio.Event()))
    assert progress.state["last_error"] is None
    assert all(value["status"] == "completed" for value in progress.state["stages"].values())


def test_stop_drains_current_thread_and_does_not_start_next(clock):
    started, release = Event(), Event()
    progress = WorkerProgress(clock, clock)
    calls = []

    def blocked():
        started.set()
        assert release.wait(5)
        calls.append("drained")

    async def run():
        stop = asyncio.Event()
        task = asyncio.create_task(progress.cycle([("blocked", blocked), ("next", lambda: calls.append("next"))], stop))
        assert await asyncio.to_thread(started.wait, 5)
        assert progress.state["stages"]["blocked"]["status"] == "running"
        stop.set()
        assert not task.done()
        release.set()
        await task

    asyncio.run(run())
    assert calls == ["drained"]


def test_app_failure_still_runs_restore_stage_and_exposes_no_message(service, monkeypatch):
    from tesla_plugin.temporary_collection import TemporaryCollection
    restored = Event()
    monkeypatch.setattr(TemporaryCollection, "tick", lambda self: restored.set())
    app = create_app(service.settings, service=service)

    def fail():
        raise RuntimeError("synthetic-sensitive-remote-body")

    monkeypatch.setattr(app.state.events, "dispatch_one", fail)
    with TestClient(app, base_url="https://bridge.example") as client:
        assert restored.wait(5)
        # Retention is after restoration; await it without wall-clock polling.
        response = client.get("/tesla/healthz")
        assert response.status_code == 200
        worker = response.json()["worker"]
        assert worker["running"] is True
        assert worker["stages"]["event_delivery"]["last_error"] == "RuntimeError"
        assert worker["stages"]["temporary_collection"]["status"] in ("running", "completed")
        assert "sensitive-remote-body" not in response.text
        assert response.headers["cache-control"] == "no-store"
    assert service.fleet.closed


def test_cancellation_keeps_stage_owned_until_thread_is_drained(clock):
    started, release, finished = Event(), Event(), Event()
    progress = WorkerProgress(clock, clock)
    calls = []

    def blocked():
        started.set()
        assert release.wait(5)
        finished.set()

    async def run():
        task = asyncio.create_task(progress.cycle([("blocked", blocked), ("next", lambda: calls.append("next"))], asyncio.Event()))
        assert await asyncio.to_thread(started.wait, 5)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done() and not finished.is_set()
        stage = progress.state["stages"]["blocked"]
        assert stage["status"] == "running" and stage["completed_at"] is None
        task.cancel()  # repeated cancellation still must not abandon the thread
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert finished.is_set() and stage["status"] == "completed"
        assert progress.state["cycle_completed_at"] is None

    asyncio.run(run())
    assert calls == []
