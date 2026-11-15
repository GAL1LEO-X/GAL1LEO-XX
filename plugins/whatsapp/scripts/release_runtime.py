"""Installed, root-owned entry point: hold requests and workers during release checks."""
import sys as _installation_sys
from pathlib import Path as _InstallationPath
import types as _installation_types
if 'installation_layout' not in _installation_sys.modules:
    _installation_source=_InstallationPath(__file__).with_name('installation_layout.py')
    _installation_module=_installation_types.ModuleType('installation_layout')
    _installation_module.__file__=str(_installation_source)
    _installation_sys.modules['installation_layout']=_installation_module
    try:
        exec(compile(_installation_source.read_bytes(),str(_installation_source),'exec'),_installation_module.__dict__)
    except BaseException:
        _installation_sys.modules.pop('installation_layout',None)
        raise
if getattr(_installation_sys.modules['installation_layout'], 'FORMAT', None) != 'whatsapp-installation-v1':
    raise ImportError('The whatsapp entry point cannot reuse another product installation layout')
from installation_layout import active as installation_profile, mapped as installation_path
import argparse
import asyncio
from pathlib import Path

def runtime_gate():
    """Resolve installed identity only when starting the operational runtime."""
    return Path(installation_path('/var/lib/develative-release-gates/whatsapp'))


class Maintenance:
    # This filesystem gate is independent of the application's readiness gate:
    # removing it permits preparation, not admission before workers are ready.
    def __init__(self, app, event, gate):
        self.app, self.event, self.gate = app, event, gate

    async def __call__(self, scope, receive, send):
        if scope['type']=='websocket' and (self.gate.exists() or not self.event.is_set()):
            await send({'type':'websocket.close','code':1013});return
        if scope['type'] == 'http' and (self.gate.exists() or not self.event.is_set()):
            if scope['path'] not in ('/healthz', '/.well-known/oauth-protected-resource') or scope['method'] not in ('GET','HEAD'):
                await send({'type':'http.response.start','status':503,'headers':[(b'retry-after',b'30')]})
                await send({'type':'http.response.body','body':b'Service maintenance'})
                return
        if scope['type'] == 'lifespan':
            async def watch():
                while self.gate.exists():
                    await asyncio.sleep(.1)
                self.event.set()
            task = asyncio.create_task(watch())
            try:
                await self.app(scope, receive, send)
            finally:
                task.cancel()
                try: await task
                except asyncio.CancelledError: pass
            return
        return await self.app(scope, receive, send)


def main():
    import uvicorn
    from sally_whatsapp.config import Settings
    from sally_whatsapp.server import create_app
    parser=argparse.ArgumentParser()
    parser.add_argument('--config',required=True)
    args=parser.parse_args()
    gate=runtime_gate()
    settings=Settings.load(args.config)
    event=asyncio.Event()
    # Ordinary restarts retain the application's recovery of interrupted work.
    # A release starts from frozen, idle databases and must not change them here.
    app=create_app(settings,recover_inflight=not gate.exists(),activation_event=event,maintenance_gate=gate)
    uvicorn.run(Maintenance(app,event,gate),host='127.0.0.1',port=settings.listen_port,
                workers=1,proxy_headers=False,access_log=False,log_level='warning')


if __name__ == '__main__':
    main()
