"""QA174 qualification attempt 2; same assembled image and original sealed inputs."""
from pathlib import Path
import argparse, hashlib, json, os, re, runpy, secrets, time

ROOT = Path('/var/tmp/qa174-provider-81f98a4')
LABEL = 'org.plugins.whatsapp.qualification'
PROXIES = ('HTTP_PROXY','HTTPS_PROXY','FTP_PROXY','ALL_PROXY','NO_PROXY','http_proxy','https_proxy','ftp_proxy','all_proxy','no_proxy')

def require(ok, message):
    if not ok: raise RuntimeError(message)

def observe(run, identifier, check=True):
    # Only candidate metadata; never inspect production Config or Env.
    fmt = '{"id":{{json .ID}},"image":{{json .Image}},"state":{{json .State}},"user":{{json .Config.User}},"labels":{{json .Config.Labels}},"environment":{{json .Config.Env}},"host":{{json .HostConfig}},"mounts":{{json .Mounts}},"effective_caps":{{json .EffectiveCaps}},"bounding_caps":{{json .BoundingCaps}}}'
    result = run('inspect', '--format', fmt, identifier, check=check)
    return json.loads(result.stdout) if result.returncode == 0 else None

def owned(observed, nonce, image):
    require(observed and observed['labels'].get(LABEL) == nonce and observed['image'].removeprefix('sha256:') == image[7:], 'Container ownership/image mismatch; do not remove')
    require(re.fullmatch('[a-f0-9]{64}', observed['id']), 'Unexpected container identity')

def isolation(observed, root, expected_env):
    host = observed['host']
    require(host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] is True and not host.get('Privileged') and not host.get('PortBindings'), 'Network/rootfs isolation failed')
    require(observed['user'] == '1000:1000' and host['Memory'] == 1073741824 and host['PidsLimit'] == 256, 'Runtime user/resource limit changed')
    require(not observed['effective_caps'] and not observed['bounding_caps'] and not host.get('CapAdd'), 'Capabilities remain enabled')
    require('no-new-privileges' in host['SecurityOpt'] and not host.get('Devices'), 'Runtime privilege isolation changed')
    require(host.get('PidMode') != 'host' and host.get('IpcMode') != 'host', 'Host process namespace requested')
    require(host.get('NanoCpus') == 2000000000 or (host.get('CpuPeriod', 0) > 0 and host.get('CpuQuota') == 2 * host['CpuPeriod']), 'CPU limit differs from two cores')
    tmpfs = host.get('Tmpfs') or {}
    require(set(tmpfs) == {'/run/qualification'}, 'Unexpected writable tmpfs')
    require({'rw','nosuid','nodev','size=536870912','mode=1777'} <= set(tmpfs['/run/qualification'].split(',')), 'Scratch tmpfs options changed')
    mounts = observed['mounts'] or []
    binds = [m for m in mounts if m['Type'] == 'bind']
    require(len(binds) == 1 and binds[0]['Source'] == str(root / 'offline') and binds[0]['Destination'] == '/opt/offline' and binds[0]['RW'] is False, 'Unexpected host mount')
    require(all(m['Type'] == 'bind' or (m['Type'] == 'tmpfs' and m['Destination'] == '/run/qualification') for m in mounts), 'Unexpected runtime volume')
    actual_env = dict(value.split('=', 1) for value in observed['environment'])
    require(all(actual_env.get(key) == value for key, value in expected_env.items()), 'Qualification environment override changed')
    return {'network': 'none', 'read_only_root': True, 'user': observed['user'], 'memory': host['Memory'], 'pids_limit': host['PidsLimit'], 'capabilities': [], 'tmpfs': tmpfs, 'fixture_mount_read_only': True}

def cleanup(run, identifier, nonce, image, started):
    current = observe(run, identifier, check=False)
    require(current is not None, 'Owned candidate missing during cleanup; reconcile before retry')
    owned(current, nonce, image); container = current['id']; failed = []
    if started and not current['state']['Running']:
        failed.append('Candidate exited before expected cleanup')
    if current['state']['Running']:
        stopped = run('stop', '--time', '20', container, timeout=35, check=False)
        if stopped.returncode != 0: failed.append('Graceful stop failed')
    state = observe(run, container); owned(state, nonce, image)
    if state['state'].get('OOMKilled') or state['state']['Running'] or (started and state['state']['ExitCode'] not in (0, 143)):
        failed.append('OOM, forced stop or abnormal exit')
    # A forced cleanup is allowed only for our nonce; it can never pass qualification.
    removed = run('rm', '--force', container, timeout=120, check=False)
    exists = run('container', 'exists', container, check=False)
    require(removed.returncode == 0 and exists.returncode == 1, 'Owned candidate not removed')
    return {'container_removed': True, 'graceful_stop': not failed, 'exit_code': state['state']['ExitCode'], 'oom_killed': state['state'].get('OOMKilled', False), 'failures': failed}

def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--manifest-sha256', required=True); args = parser.parse_args()
    os.umask(0o077)
    require(Path(__file__).resolve().parent == ROOT and not ROOT.is_symlink(), 'Wrong staging path')
    require(re.fullmatch('[a-f0-9]{64}', args.manifest_sha256), 'Reviewed manifest digest required')
    manifest_path = ROOT / 'input-manifest.json'
    require(hashlib.sha256(manifest_path.read_bytes()).hexdigest() == args.manifest_sha256, 'Input manifest changed')
    manifest = json.loads(manifest_path.read_text()); shared = ROOT / 'server-build.py'
    require(not shared.is_symlink() and hashlib.sha256(shared.read_bytes()).hexdigest() == manifest['files']['server-build.py']['sha256'], 'Assembly helper changed')
    common = runpy.run_path(str(shared))
    manifest, runtime = common['validate_inputs'](ROOT, args.manifest_sha256)
    held = common['acquire_locks'](); profile = common['host_profile']()
    metadata = json.loads((ROOT / 'runtime-metadata.json').read_text())
    build = json.loads((ROOT / 'build-result.json').read_text())
    require(build['passed'] is True and build['manifest_sha256'] == metadata['input_manifest_sha256'] == args.manifest_sha256, 'Assembly gate failed')
    image = metadata['config_digest']; require(re.fullmatch('sha256:[a-f0-9]{64}', image), 'Invalid candidate image')
    archive = ROOT / common['ARCHIVE_NAME']
    require(not archive.is_symlink() and archive.stat().st_size == metadata['archive_bytes'] and common['sha'](archive) == metadata['archive_sha256'], 'Candidate archive changed')
    production_before = common['production_snapshot'](profile)
    require(production_before == json.loads((ROOT / 'build-intent.json').read_text())['production_before'], 'Production changed since assembly')
    script_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    results = []
    for instance in profile['instances']:
        slug = instance['slug']; nonce = secrets.token_hex(12); name = 'qa174-offline-' + nonce
        out = ROOT / ('qualification-v2-' + slug); out.mkdir(mode=0o700)
        token = secrets.token_urlsafe(32); container = None; started = False
        result = {'slug': slug, 'image': image, 'passed': False, 'live_whatsapp': False, 'production_sessions_mounted': False}
        def run(*command, **options): return common['podman'](instance, *command, **options)
        common['save'](out / 'intent.json', {'name': name, 'nonce': nonce, 'image': image, 'manifest_sha256': args.manifest_sha256, 'qualification_script_sha256': script_sha256})
        try:
            run('load', '--input', str(archive), timeout=600)
            candidate = common['image_snapshot'](instance, image)
            require(candidate['layers'][:12] == production_before[slug]['image']['layers'], 'Imported base chain changed')
            scratch = '/run/qualification'
            env = {'GOMAXPROCS':'2','UV_THREADPOOL_SIZE':'4','NODE_OPTIONS':'--require=/opt/offline/lifecycle-guard.cjs','WAHA_API_KEY':token,'WHATSAPP_API_KEY':'','OFFLINE_EXPECTED_GOWS_SHA256':metadata['gows_sha256'],'OFFLINE_EXPECTED_UID':'1000','OFFLINE_MARKER_ROOT':scratch+'/markers','TMPDIR':scratch,'WAHA_GOWS_SOCKET':scratch+'/gows.sock','WAHA_LOCAL_STORE_BASE_DIR':scratch+'/sessions','WHATSAPP_FILES_FOLDER':scratch+'/media','WHATSAPP_START_SESSION':'','WHATSAPP_RESTART_ALL_SESSIONS':'false','WAHA_WORKER_RESTART_SESSIONS':'false','WAHA_DASHBOARD_ENABLED':'false','WHATSAPP_SWAGGER_ENABLED':'false','WAHA_APPS_ENABLED':'false','WAHA_PRINT_QR':'false','WAHA_RUN_XVFB':'false','OTEL_SDK_DISABLED':'true','OTEL_TRACES_EXPORTER':'none','OTEL_METRICS_EXPORTER':'none','OTEL_LOGS_EXPORTER':'none'}
            env.update({key: '' for key in PROXIES})
            create = ['create','--log-driver=k8s-file','--name',name,'--label',LABEL+'='+nonce,'--pull=never','--network=none','--read-only','--read-only-tmpfs=false','--user','1000:1000','--cap-drop=ALL','--security-opt=no-new-privileges','--memory=1073741824','--pids-limit=256','--cpus=2','--tmpfs='+scratch+':rw,nosuid,nodev,size=536870912,mode=1777','--mount','type=bind,source='+str(ROOT/'offline')+',target=/opt/offline,readonly']
            for key, value in env.items(): create += ['--env', key + '=' + value]
            container = run(*create, image, timeout=300).stdout.strip()
            observed = observe(run, container); owned(observed, nonce, image)
            result['isolation'] = isolation(observed, ROOT, env)
            started = True; run('start', container)
            for attempt in range(60):
                ping = run('exec',container,'node','-e',"fetch('http://127.0.0.1:3000/api/sessions',{signal:AbortSignal.timeout(1000)}).then(r=>process.exit(r.status===401?0:1)).catch(()=>process.exit(1))",timeout=5,check=False)
                require(observe(run, container)['state']['Running'], 'Premature runtime exit')
                if ping.returncode == 0: break
                time.sleep(1)
            else: raise RuntimeError('Readiness timeout')
            tests = run('exec', container, 'node', '--test-reporter=tap', '/opt/offline/run-compiled-tests.cjs', timeout=90, check=False)
            tap = (tests.stdout + tests.stderr).replace(token, '[synthetic-key]')
            (out / 'compiled-tests.tap').write_text(tap)
            require(tests.returncode == 0 and re.search(r'^# pass 7\s*$', tap, re.M) and re.search(r'^# fail 0\s*$', tap, re.M), 'Actual-image compiled regressions did not pass all seven tests')
            result['compiled_tests'] = {'passed': 7, 'failed': 0, 'tap_sha256': common['sha'](out / 'compiled-tests.tap')}
            probe = run('exec', container, 'node', '/opt/offline/probe-candidate.cjs', timeout=120)
            (out / 'probe.stdout').write_text(probe.stdout.replace(token, '[synthetic-key]'))
            evidence = json.loads(probe.stdout.strip().splitlines()[-1])
            require(evidence['scope'] == 'isolated-no-account-runtime' and evidence['liveWhatsApp'] is False and evidence['sessions'] == [], 'Probe account boundary changed')
            require(evidence['authenticatedStatus'] == 200 and evidence['unauthenticatedStatus'] == 401 and evidence['uid'] == 1000, 'Authentication/UID probe failed')
            require(evidence['gows']['sha256'] == metadata['gows_sha256'] and evidence['lifecycleGuard']['attempts'] == 0 and evidence['audio']['decoded'] is True, 'Native/lifecycle/audio probe failed')
            require(evidence['candidate']['distInventoryVerified'] is True and evidence['candidate']['distFiles'] == len(runtime), 'Final dist inventory differs; possible base residual')
            result.update(passed=True, probe=evidence)
        except Exception as error: result['error'] = str(error).replace(token, '[synthetic-key]')[:2048]
        finally:
            try:
                found = observe(run, container or name, check=False)
                if found is not None:
                    owned(found, nonce, image)
                    try:
                        logs = run('logs', '--tail', '200', found['id'], check=False)
                        (out / 'startup.log').write_text((logs.stdout + logs.stderr).replace(token, '[synthetic-key]')[-65536:])
                    except Exception as error: result['log_capture_error'] = str(error).replace(token, '[synthetic-key]')[:2048]
                    result['cleanup'] = cleanup(run, found['id'], nonce, image, started)
                    if not result['cleanup']['graceful_stop']: result['passed'] = False
                elif container is not None or started: raise RuntimeError('Candidate missing; cannot attest cleanup')
            except Exception as error: result.update(passed=False, cleanup_error=str(error).replace(token, '[synthetic-key]')[:2048])
            try:
                require(common['host_profile']() == profile and common['production_snapshot'](profile) == production_before, 'Production/profile changed during qualification')
                result['production_containers_and_images_unchanged'] = True
            except Exception as error: result.update(passed=False, preservation_error=str(error)[:2048])
            common['save'](out / 'result.json', result)
        results.append(result); print(json.dumps(result), flush=True)
        if not result['passed']: break
    final = {'passed': len(results) == 2 and all(r['passed'] for r in results), 'source_commit': manifest['source_commit'], 'manifest_sha256': args.manifest_sha256, 'config_digest': image, 'archive_sha256': metadata['archive_sha256'], 'results': results, 'qualification_script_sha256': script_sha256, 'deploy_performed': False, 'live_whatsapp': False}
    common['save'](ROOT / 'qualification-v2-result.json', final)
    require(final['passed'], 'Qualification failed; inspect receipts before retry')

if __name__ == '__main__': main()
