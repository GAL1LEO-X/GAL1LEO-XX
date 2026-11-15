import argparse
import json
from pathlib import Path
import uvicorn
from .config import Settings
from .store import Store


def main():
    parser = argparse.ArgumentParser(description="Sally WhatsApp bridge")
    parser.add_argument("--config", required=True)
    actions = parser.add_subparsers(dest="action",required=True)
    actions.add_parser("serve")
    backup = actions.add_parser("backup")
    backup.add_argument("destination",type=Path)
    actions.add_parser("check")
    actions.add_parser('register-state-identity', help='Offline administrative enrollment of an existing technical database; stop writers first')
    reconcile=actions.add_parser('reconcile-recovery',help='Acknowledge one reviewed diagnostic issue; does not recover data or events')
    reconcile.add_argument('--reason',required=True)
    reconcile.add_argument('--last-seen',required=True,help='Exact last_seen from connection_status; use unknown for legacy issues')
    recovery=actions.add_parser('event-recovery',help='Preview or explicitly retry retained transiently failed callbacks; never reconstruct events')
    recovery_actions=recovery.add_subparsers(dest='recovery_action',required=True)
    for name in ('preview','execute'):
        command=recovery_actions.add_parser(name)
        command.add_argument('--subscription',required=True)
        command.add_argument('--delivery-id',required=True,type=int,action='append',help='Explicit delivery ID, repeat for up to 20 rows')
        if name=='execute':
            command.add_argument('--fingerprint',required=True,help='Fingerprint from an eligible preview')
            command.add_argument('--request-id',required=True,help='Unique administrative request ID, retained for idempotency')
    recovery_audit=recovery_actions.add_parser('audit')
    recovery_audit.add_argument('--request-id',required=True)
    args = parser.parse_args()
    settings = Settings.load(args.config)
    def existing_store():
        from .state_continuity import StateContinuity
        guard = StateContinuity(settings, allow_bootstrap=False)
        return Store(settings.database, recover_inflight=False, migrate_schema=False, continuity=guard)
    if args.action == 'register-state-identity':
        from .state_continuity import register_external_identity
        register_external_identity(settings)
        print('Technical state identity registered. No account action or data recovery performed.')
    elif args.action=="serve":
        from .server import create_app
        from .installation import mapped
        gate = Path(mapped('/var/lib/develative-release-gates/whatsapp'))
        uvicorn.run(create_app(settings,maintenance_gate=gate),host="127.0.0.1",port=settings.listen_port,workers=1,
                    proxy_headers=False,access_log=False,log_level="warning")
    elif args.action=="backup":
        existing_store().backup(args.destination)
        print("SQLite backup verified. Back up the separate encryption key and WAHA session consistently.")
    elif args.action=='reconcile-recovery':
        existing_store().reconcile_recovery(
            args.reason,None if args.last_seen=='unknown' else args.last_seen)
        print('Diagnostic issue reconciled explicitly. No messages, events or account state recovered or changed.')
    elif args.action=='event-recovery':
        from .event_recovery import EventRecovery
        recovery=EventRecovery(existing_store(),settings)
        if args.recovery_action=='audit': result=recovery.audit(args.request_id)
        elif args.recovery_action=='preview': result=recovery.preview(args.subscription,args.delivery_id)
        else: result=recovery.execute(args.subscription,args.delivery_id,fingerprint=args.fingerprint,request_id=args.request_id)
        print(json.dumps(result,sort_keys=True))
    else:
        from .server import create_app
        app = create_app(settings,start_worker=False,recover_inflight=False)
        app.state.service.gateway.close()
        if app.state.link_portal: app.state.link_portal.close()
        app.state.service.diagnostics.close()
        print("Configuration, database, encryption and token-verifier configuration valid; no network/account action performed.")


if __name__ == "__main__":
    main()

