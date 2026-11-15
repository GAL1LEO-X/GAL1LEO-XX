"""Periodic/boot recovery of interrupted releases. Host installed, never from a tag."""
import json
import os
from pathlib import Path
import subprocess
import sys


def is_automatic_box_plan(plan):
    return (plan.get('state') in ('applying','rollback-failed') and
            plan.get('githubRelease') == {'repository':'example-owner/example-project',
                                         'sourceCommit':plan.get('sourceCommit')})


def recover_project(project):
    import fcntl
    sys.path.insert(0,str(Path('/usr/local/lib/develative-deploy')/project))
    from github_release_common import STATE, run
    import github_release as release
    with (STATE/'publication.lock').open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return
        if project=='box':
            config=json.loads(Path('/etc/develative-deploy/box.json').read_text())
            controller=release.load_controller(config)
            for path in sorted((controller.STATE/'plans').glob('*.json')):
                plan=json.loads(path.read_text())
                if is_automatic_box_plan(plan):
                    run(['/usr/bin/python3','-I',config['controller'],'recover','--plan',plan['id']],timeout=300)
        else:
            import release_transaction as transaction
            if not transaction.JOURNAL.exists():return
            plan=json.loads(transaction.JOURNAL.read_text())
            if plan['phase'] in ('published','rolled-back'):return
            with (release.ROOT/'private/tenant-admin.lock').open('a') as tenant_lock:
                try:fcntl.flock(tenant_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:return
                transaction.recover(plan,release.wait_health)


if __name__=='__main__':
    if os.geteuid()!=0:raise SystemExit('Root required')
    if len(sys.argv)==2:
        if sys.argv[1] not in ('box','whatsapp'):raise SystemExit('Invalid project')
        recover_project(sys.argv[1])
    else:
        failed=False
        for project in ('box','whatsapp'):
            result=subprocess.run(['/usr/bin/python3','-I',__file__,project],capture_output=True,text=True,timeout=360)
            if result.returncode:
                print(project+': recovery requires inspection of the private deployment journal',flush=True)
                failed=True
        raise SystemExit(1 if failed else 0)
