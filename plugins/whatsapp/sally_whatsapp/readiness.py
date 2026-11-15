"""Process readiness, bounded preparation retries and operational admission."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from functools import partial
import logging
import sqlite3
import threading

from starlette.responses import JSONResponse


log = logging.getLogger('sally_whatsapp')
PREPARATION_BACKOFF = (0.25, 0.5)  # Three attempts; SQLite keeps its own timeout.
SHUTDOWN_GRACE_SECONDS = 30
PUBLIC_ROUTES = frozenset(('/healthz', '/.well-known/oauth-protected-resource'))


def transient_database_error(error):
    code = getattr(error, 'sqlite_errorcode', None)
    return (isinstance(error, sqlite3.OperationalError) and type(code) is int
            and code & 0xff in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED))


async def _join(task):
    """Defer repeated caller cancellation until the owned work has finished."""
    cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            cancelled = True
        except Exception:
            break
    if cancelled:
        # Retrieve even a failed result, without leaking exception details or
        # replacing the caller's deferred cancellation with a worker failure.
        try:
            task.result()
        except BaseException:
            pass
        raise asyncio.CancelledError
    return task.result()


class RuntimeReadiness:
    def __init__(self, *, enabled, worker_names):
        self.enabled = enabled
        self.state = 'waiting' if enabled else 'disabled'
        self.error_code = None
        self.workers = dict.fromkeys(worker_names, False)
        self._stopping = False
        self._preparation = None
        self._repair_thread = None
        self._tasks = {}
        self._executor = None
        self._futures = set()
        self._lock = threading.Lock()
        self._on_drained = None
        self.shutdown_timed_out = threading.Event()

    async def run_sync(self, function, *args, **kwargs):
        """Own the real thread, even if its awaiting coroutine is cancelled."""
        context = copy_context()
        with self._lock:
            if self._stopping or self.state == 'failed':
                raise RuntimeError('Runtime is stopping')
            if self._executor is None:
                self._executor = ThreadPoolExecutor(thread_name_prefix='whatsapp')
            future = self._executor.submit(self._invoke, context, partial(function, *args, **kwargs))
            self._futures.add(future)
        future.add_done_callback(self._thread_finished)
        wrapped = asyncio.wrap_future(future)
        # A cancelled request no longer retrieves the shield's result. Consume
        # errors without logging provider data; the real future remains owned.
        wrapped.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        return await asyncio.shield(wrapped)

    def _invoke(self, context, function):
        # Admission is the synchronous unit's entry: units already entered are
        # in-flight, including one waiting on its own database claim/transaction.
        # Executor-queued units may not start after stop or worker failure.
        with self._lock:
            if self._stopping or self.state == 'failed':
                raise RuntimeError('Runtime is stopping')
        return context.run(function)

    def _thread_finished(self, future):
        callback = None
        with self._lock:
            self._futures.discard(future)
            if not self._futures and self._on_drained is not None:
                callback, self._on_drained = self._on_drained, None
        if callback is not None:
            callback()

    def close_when_drained(self, callback):
        """Close once after actual completion, including after event-loop exit.

        Python cannot terminate a blocked thread safely. On a grace timeout the
        resources stay owned by its concurrent future, rather than being closed
        underneath it. The final thread performs cleanup without a live loop.
        """
        with self._lock:
            self._stopping = True
            executor, self._executor = self._executor, None
            # A Future becomes done before its callbacks run. A callback can
            # still be waiting for this lock although the owned work has
            # already returned; it must not defer an otherwise drained close.
            pending = any(not future.done() for future in self._futures)
            if pending:
                self._on_drained = callback
        if executor is not None:
            executor.shutdown(wait=False)
        if not pending:
            callback()

    @property
    def ready(self):
        return self.state == 'ready' and all(self.workers.values())

    def snapshot(self):
        value = {'state': self.state, 'ready': self.ready, 'workers': dict(self.workers)}
        if self.error_code:
            value['error_code'] = self.error_code
        return value

    def _fail(self, code):
        if self._stopping or self.state == 'failed':
            return
        self.state, self.error_code = 'failed', code
        if code == 'REVOCATION_REPAIR_FAILED':
            log.error('Revocation repair failed; background workers remain stopped')
        else:
            log.error('Background worker stopped; service is not ready')
        current = asyncio.current_task()
        for task in self._tasks.values():
            if task is not current:
                task.cancel()

    async def _prepare(self, repair, activation_event):
        if activation_event is not None:
            await activation_event.wait()
        if self._stopping or self.state == 'failed':
            return False
        self.state = 'preparing'
        for attempt in range(len(PREPARATION_BACKOFF) + 1):
            if self._stopping or self.state == 'failed':
                return False
            retry = False
            self._repair_thread = asyncio.create_task(self.run_sync(repair))
            try:
                # Cancelling an await cannot stop a SQLite transaction in a
                # thread. Ownership/drain is retained by the runtime executor.
                await asyncio.shield(self._repair_thread)
            except asyncio.CancelledError:
                raise
            except Exception as error:
                retry = transient_database_error(error)
                if not retry or attempt == len(PREPARATION_BACKOFF):
                    self._fail('REVOCATION_REPAIR_FAILED')
                    return False
            else:
                return not self._stopping and self.state != 'failed'
            finally:
                self._repair_thread = None
            if self._stopping or self.state == 'failed':
                return False
            if retry:
                await asyncio.sleep(PREPARATION_BACKOFF[attempt])
        return False

    async def _activated(self, name, worker):
        try:
            if not await asyncio.shield(self._preparation) or self._stopping or self.state == 'failed':
                return
            self.workers[name] = True
            if all(self.workers.values()):
                self.state = 'ready'
            # No yield between recording entry and entering the coroutine. A
            # synchronous return/error invalidates readiness before other work.
            await worker()
            self._fail('BACKGROUND_WORKER_STOPPED')
        except asyncio.CancelledError:
            self._fail('BACKGROUND_WORKER_STOPPED')
            raise
        except Exception:
            self._fail('BACKGROUND_WORKER_STOPPED')
        finally:
            self.workers[name] = False

    def start(self, repair, workers, activation_event=None):
        if not self.enabled:
            return
        with self._lock:
            if self._futures or self._on_drained is not None or self._stopping:
                raise RuntimeError('Previous runtime has not been replaced')
        if ((self._preparation is not None and not self._preparation.done())
                or any(not task.done() for task in self._tasks.values())):
            raise RuntimeError('Runtime preparation already started')
        if set(workers) != set(self.workers):
            raise ValueError('Unexpected runtime workers')
        self._stopping = False
        self.shutdown_timed_out.clear()
        self.state, self.error_code = 'waiting', None
        self.workers = dict.fromkeys(workers, False)
        self._preparation = asyncio.create_task(self._prepare(repair, activation_event))
        self._tasks = {name: asyncio.create_task(self._activated(name, worker)) for name, worker in workers.items()}

    async def _stop(self):
        self._stopping = True
        if self.enabled:
            self.state = 'stopping'
        for task in self._tasks.values():
            task.cancel()
        if self._preparation is not None and self._repair_thread is None:
            self._preparation.cancel()  # Gate wait or retry backoff; no DB work.
        tasks = [*self._tasks.values()]
        if self._preparation is not None:
            tasks.append(self._preparation)
        # Cancellation stops the loops, never the threads executing a provider
        # request or SQLite transaction. One shared deadline bounds both waits.
        deadline = asyncio.get_running_loop().time() + SHUTDOWN_GRACE_SECONDS
        if tasks:
            await asyncio.wait(tasks, timeout=SHUTDOWN_GRACE_SECONDS)
        with self._lock:
            futures = list(self._futures)
        if futures:
            remaining = max(0, deadline - asyncio.get_running_loop().time())
            wrapped = [asyncio.wrap_future(future) for future in futures]
            for future in wrapped:
                future.add_done_callback(lambda done: None if done.cancelled() else done.exception())
            await asyncio.wait(wrapped, timeout=remaining)
        with self._lock:
            drained = all(future.done() for future in self._futures)
            if not drained:
                self.shutdown_timed_out.set()
        if not drained:
            log.error('Shutdown grace expired; resources retained until in-flight work completes')
        # A timed-out preparation waiter must not keep loop shutdown waiting;
        # its underlying concurrent future is still retained above.
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.sleep(0)
        for task in tasks:
            task.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        return drained

    async def stop(self):
        self._stopping = True
        if self.enabled:
            self.state = 'stopping'
        return await _join(asyncio.create_task(self._stop()))


class ReadinessAdmission:
    def __init__(self, app, readiness):
        self.app, self.readiness = app, readiness

    async def __call__(self, scope, receive, send):
        if self.readiness.enabled and not self.readiness.ready:
            if scope['type'] == 'websocket':
                await send({'type': 'websocket.close', 'code': 1013})
                return
            if scope['type'] == 'http' and not (
                    scope['method'] in ('GET', 'HEAD') and scope['path'] in PUBLIC_ROUTES):
                await JSONResponse({'error': 'service_not_ready'}, status_code=503,
                                   headers={'Retry-After': '1', 'Cache-Control': 'no-store'})(scope, receive, send)
                return
        await self.app(scope, receive, send)
