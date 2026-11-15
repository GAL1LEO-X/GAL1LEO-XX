"""Pure rendering/validation for the optional local worker; no host mutation."""
import re
import tomllib


def enable_config(content, uid):
    if type(uid) is not int or uid < 1:
        raise ValueError('A dedicated non-root worker UID is required')
    before = tomllib.loads(content)
    expected = {'transcription_socket': '/run/whatsapp-transcriber/worker.sock',
                'transcription_server_uid': uid}
    bridge = before['bridge']
    if any(key in bridge for key in expected):
        if all(bridge.get(key) == value for key, value in expected.items()):
            return content
        raise ValueError('Existing transcription configuration requires explicit reconciliation')
    replacement = '[bridge]\ntranscription_socket = "/run/whatsapp-transcriber/worker.sock"\n'
    replacement += f'transcription_server_uid = {uid}\n'
    result, count = re.subn(r'^\[bridge\][ \t]*(?:#.*)?$', replacement.rstrip(), content, flags=re.MULTILINE)
    if count != 1:
        raise ValueError('Expected one explicit bridge section')
    after = tomllib.loads(result)
    for key, value in expected.items():
        if after['bridge'].pop(key) != value:
            raise ValueError('Transcription configuration differs')
    if after != before:
        raise ValueError('Unrelated configuration changed')
    return result


def unit(release, model, uids, threads=8):
    for path in (release, model):
        if not isinstance(path, str) or not re.fullmatch(r'/opt/whatsapp-transcriber/[a-zA-Z0-9/_.-]+', path) or '..' in path.split('/'):
            raise ValueError('Expected immutable paths below /opt/whatsapp-transcriber')
    if not uids or any(type(uid) is not int or uid < 1 for uid in uids) or len(set(uids)) != len(uids):
        raise ValueError('Expected distinct non-root tenant UIDs')
    if type(threads) is not int or not 1 <= threads <= 16:
        raise ValueError('Invalid CPU thread limit')
    allowed = ' '.join(f'--allow-uid {uid}' for uid in uids)
    return f'''[Unit]
Description=WhatsApp local Whisper large-v3 transcription
After=local-fs.target

[Service]
Type=simple
User=whatsapp-transcriber
Group=whatsapp-transcription
RuntimeDirectory=whatsapp-transcriber
RuntimeDirectoryMode=0750
UMask=0007
Environment=PYTHONPATH={release}/source
Environment=HF_HUB_OFFLINE=1
Environment=HF_HUB_DISABLE_TELEMETRY=1
Environment=DO_NOT_TRACK=1
Environment=OMP_NUM_THREADS={threads}
Environment=OPENBLAS_NUM_THREADS=1
ExecStart={release}/venv/bin/python -m sally_whatsapp.transcriber --socket /run/whatsapp-transcriber/worker.sock --model-directory {model} {allowed} --device cpu --compute-type float32 --threads {threads}
Restart=on-failure
RestartSec=5
TimeoutStopSec=15
KillMode=control-group
CPUQuota={threads * 100}%
MemoryMax=20G
MemorySwapMax=0
LimitCORE=0
TasksMax=128
NoNewPrivileges=yes
PrivateTmp=yes
PrivateNetwork=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX
ReadWritePaths=/run/whatsapp-transcriber

[Install]
WantedBy=multi-user.target
'''


def backend_dropin():
    # Only the bridge unit gets the socket group; provider and other services
    # do not inherit a new supplementary group through account membership.
    return '[Service]\nSupplementaryGroups=whatsapp-transcription\n'
