"""Independent worker stages; local progress is not vehicle health evidence."""
import asyncio


class WorkerProgress:
    def __init__(self, clock, monotonic):
        self.clock, self.monotonic = clock, monotonic
        self.state = {"running": False, "last_error": None, "cycle_started_at": None,
                      "cycle_completed_at": None, "stages": {},
                      "basis": "local_worker_progress", "vehicle_online_proven": False}

    async def cycle(self, stages, stop):
        self.state["cycle_started_at"] = self.clock()
        errors = []
        for name, action in stages:
            if stop.is_set():
                break
            stage = self.state["stages"].setdefault(name, {})
            stage.update(status="running", started_at=self.clock(), completed_at=None,
                         duration_seconds=None, last_error=None)
            started = self.monotonic()
            pending = asyncio.create_task(asyncio.to_thread(action))
            interrupted = False
            try:
                # Cancelling an await cannot stop a thread. Keep the stage and
                # its clients owned until the actual operation has finished.
                while not pending.done():
                    try:
                        await asyncio.shield(pending)
                    except asyncio.CancelledError:
                        interrupted = True
                pending.result()
            except Exception as exc:
                # Exception messages may contain identifiers or remote payloads.
                stage.update(status="error", last_error=type(exc).__name__)
                errors.append(type(exc).__name__)
            else:
                stage.update(status="completed", last_success_at=self.clock())
            finally:
                stage.update(completed_at=self.clock(),
                             duration_seconds=round(max(0, self.monotonic()-started), 6))
            if interrupted:
                raise asyncio.CancelledError
        self.state["last_error"] = errors[0] if errors else None
        self.state["cycle_completed_at"] = self.clock()
