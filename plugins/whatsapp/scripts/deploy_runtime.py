#!/usr/bin/env python3
"""Installed entrypoint for a pinned wheel release; ingress and workers share one gate.

This file is installed separately as reviewed administrative code. It is not
selected from the application package and does not change credentials or data.
"""
import argparse
import asyncio
import json
from pathlib import Path
import re
import sys


class ReleaseAdmission:
    def __init__(self, app, event, gate, commit):
        self.app, self.event, self.gate, self.commit = app, event, gate, commit

    async def __call__(self, scope, receive, send):
        gated = self.gate.exists() or not self.event.is_set()
        if scope['type'] == 'websocket' and gated:
            await send({'type': 'websocket.close', 'code': 1013}); return
        if scope['type'] == 'http':
            if gated and (scope['path'] not in ('/healthz', '/.well-known/oauth-protected-resource')
                          or scope['method'] not in ('GET', 'HEAD')):
                await send({'type': 'http.response.start', 'status': 503, 'headers': [(b'retry-after', b'30')]})
                await send({'type': 'http.response.body', 'body': b'Service maintenance'}); return
            if scope['path'] == '/healthz' and scope['method'] in ('GET', 'HEAD'):
                async def pinned_send(message):
                    if message['type'] == 'http.response.start':
                        message = {**message, 'headers': [*message.get('headers', []),
                                                        (b'x-whatsapp-release-commit', self.commit.encode('ascii'))]}
                    await send(message)
                return await self.app(scope, receive, pinned_send)
        if scope['type'] == 'lifespan':
            async def release_workers():
                while self.gate.exists():
                    await asyncio.sleep(.1)
                self.event.set()
            task = asyncio.create_task(release_workers())
            try:
                await self.app(scope, receive, send)
            finally:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            return
        await self.app(scope, receive, send)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    parser.add_argument('--gate', required=True)
    parser.add_argument('--metadata', required=True)
    args = parser.parse_args()
    metadata_path = Path(args.metadata).resolve(strict=True)
    if Path(sys.prefix).resolve() != metadata_path.parent.parent / 'runtime/venv':
        raise ValueError('Runtime interpreter does not belong to the selected release')
    metadata = json.loads(metadata_path.read_bytes())
    if not re.fullmatch('[0-9a-f]{40}', metadata.get('commit', '')):
        raise ValueError('Invalid release metadata')
    import uvicorn
    import sally_whatsapp
    from sally_whatsapp.config import Settings
    from sally_whatsapp.server import create_app
    if metadata['version'] != sally_whatsapp.__version__:
        raise ValueError('Installed application version differs from release')
    gate, event = Path(args.gate), asyncio.Event()
    settings = Settings.load(args.config)
    app = create_app(settings, recover_inflight=not gate.exists(), activation_event=event, maintenance_gate=gate)
    uvicorn.run(ReleaseAdmission(app, event, gate, metadata['commit']), host='127.0.0.1',
                port=settings.listen_port, workers=1, proxy_headers=False, access_log=False, log_level='warning')


if __name__ == '__main__':
    main()
