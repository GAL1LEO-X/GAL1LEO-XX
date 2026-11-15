"""Bounded, authenticated local transport to the separately admitted host broker.

Only public operation references cross this socket. The bridge never receives
credentials, paths, command lines, or privileges from the broker.
"""
import json
import os
from pathlib import Path
import re
import socket
import struct
import stat
import time
from datetime import datetime


MAX_FRAME = 65536
HOST_ACTIONS = ('instance.allocate', 'instance.prepare', 'instance.activate', 'instance.cancel',
                'release.preview', 'release.activate', 'backup.create', 'backup.restore')
IDENTIFIER = re.compile(r'[a-f0-9]{32}')
TARGET = re.compile(r'[A-Za-z0-9_.:-]{1,128}')


class BrokerError(Exception):
    def __init__(self, code='ADMIN_BROKER_UNAVAILABLE', *, uncertain=False):
        self.code, self.uncertain = code, uncertain
        super().__init__(code)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON field')
        result[key] = value
    return result


def _identifier(value):
    return isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None


def receipt(value, expected):
    """Bind every observation to the recorded operation before publishing it."""
    if not isinstance(value, dict) or any(value.get(key) != expected[key] for key in ('id', 'operation', 'target')):
        raise BrokerError('ADMIN_BROKER_INVALID_RESPONSE', uncertain=True)
    expected_approval = expected.get('approval', expected.get('arguments', {}).get('approval'))
    if not _identifier(value.get('approval')) or (expected_approval is not None and value['approval'] != expected_approval):
        raise BrokerError('ADMIN_BROKER_INVALID_RESPONSE', uncertain=True)
    if value.get('state') not in ('completed', 'failed_before_execution', 'uncertain'):
        raise BrokerError('ADMIN_BROKER_INVALID_RESPONSE', uncertain=True)
    result = {key: value[key] for key in ('id', 'operation', 'target', 'state')}
    result['approval'] = value['approval']
    if 'scope' in value or 'affected_instances' in value:
        affected = value.get('affected_instances')
        if (value.get('scope') not in ('instance', 'installation') or not isinstance(affected, list)
                or not 1 <= len(affected) <= 128 or any(not isinstance(item, str) or TARGET.fullmatch(item) is None for item in affected)
                or len(set(affected)) != len(affected)
                or (value['scope'] == 'instance' and affected != [value['target']])):
            raise BrokerError('ADMIN_BROKER_INVALID_RESPONSE', uncertain=True)
        result.update(scope=value['scope'], affected_instances=affected)
    if 'reconciled_by' in value:
        if not _identifier(value['reconciled_by']):
            raise BrokerError('ADMIN_BROKER_INVALID_RESPONSE', uncertain=True)
        result['reconciled_by'] = value['reconciled_by']
    for key in ('created_at', 'updated_at'):
        if key in value:
            timestamp = value[key]
            try:
                if (not isinstance(timestamp, str) or len(timestamp) > 40
                        or datetime.fromisoformat(timestamp.replace('Z', '+00:00')).tzinfo is None):
                    raise ValueError
            except ValueError:
                raise BrokerError('ADMIN_BROKER_INVALID_RESPONSE', uncertain=True) from None
            result[key] = timestamp
    # Never expose arbitrary broker diagnostic output or host paths to the web.
    code = value.get('error_code')
    if isinstance(code, str) and re.fullmatch(r'[A-Z][A-Z0-9_]{0,79}', code):
        result['error_code'] = code
    if value['state'] == 'failed_before_execution':
        if (value.get('execution_phase') != 'before_intent' or 'error_code' not in result
                or 'result' in value):
            raise BrokerError('ADMIN_BROKER_INVALID_RESPONSE', uncertain=True)
        result['execution_phase'] = 'before_intent'
    evidence = value.get('result')
    if value['state'] == 'completed':
        if (not isinstance(evidence, dict) or type(evidence.get('exit_code')) is not int
                or evidence['exit_code'] != 0 or not isinstance(evidence.get('receipt_sha256'), str)
                or re.fullmatch('[a-f0-9]{64}', evidence['receipt_sha256']) is None):
            raise BrokerError('ADMIN_BROKER_INVALID_RESPONSE', uncertain=True)
        result['result'] = {'exit_code': 0, 'receipt_sha256': evidence['receipt_sha256']}
        if value['operation'] == 'instance.cancel':
            preserved = {'allocation_released': False, 'instance_reusable': False,
                         'administrative_records_retained': True}
            if any(evidence.get(key) is not flag for key, flag in preserved.items()):
                raise BrokerError('ADMIN_BROKER_INVALID_RESPONSE', uncertain=True)
            result['result'].update(preserved)
    return result


def observed_receipt(value, identifier=None):
    if (not isinstance(value, dict) or not _identifier(value.get('id'))
            or (identifier is not None and value['id'] != identifier)
            or value.get('operation') not in HOST_ACTIONS or not isinstance(value.get('target'), str)
            or TARGET.fullmatch(value['target']) is None):
        raise BrokerError('ADMIN_BROKER_INVALID_RESPONSE', uncertain=True)
    return receipt(value, value)


class AdminBrokerClient:
    def __init__(self, path, owner, instance, *, expected_uid=0, timeout=5):
        # expected_uid/timeout are constructor-only dependency injection for
        # synthetic socket tests; no configuration or HTTP input can set them.
        self.path, self.owner, self.instance = str(path), owner, instance
        self.expected_uid, self.timeout = expected_uid, timeout

    def _socket_identity(self):
        path = Path(self.path)
        for parent in reversed(path.parents):
            info = os.lstat(parent)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.expected_uid
                    or info.st_mode & 0o022):
                raise BrokerError('ADMIN_BROKER_PATH_REJECTED')
        info = os.lstat(path)
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != self.expected_uid
                or info.st_mode & 0o007):
            raise BrokerError('ADMIN_BROKER_PATH_REJECTED')
        return info.st_dev, info.st_ino

    def call(self, method, request):
        sent = False
        payload = json.dumps({'version': 1, 'method': method, 'owner': self.owner,
                              'instance': self.instance, 'request': request},
                             separators=(',', ':'), allow_nan=False).encode() + b'\n'
        if len(payload) > MAX_FRAME:
            raise BrokerError('ADMIN_BROKER_INPUT_TOO_LARGE')
        try:
            identity = self._socket_identity()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
                channel.settimeout(self.timeout)
                channel.connect(self.path)
                _, uid, _ = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if uid != self.expected_uid:
                    raise BrokerError('ADMIN_BROKER_PEER_REJECTED')
                if self._socket_identity() != identity:
                    raise BrokerError('ADMIN_BROKER_PATH_REJECTED')
                # A sendall error may follow a partially or fully sent request.
                sent = True
                channel.sendall(payload)
                deadline, data = time.monotonic() + self.timeout, bytearray()
                while b'\n' not in data:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError
                    channel.settimeout(remaining)
                    chunk = channel.recv(min(4096, MAX_FRAME + 1 - len(data)))
                    if not chunk:
                        raise ValueError('Incomplete broker response')
                    data.extend(chunk)
                    if len(data) > MAX_FRAME:
                        raise ValueError('Oversized broker response')
                line, trailing = bytes(data).split(b'\n', 1)
                if trailing:
                    raise ValueError('Multiple broker responses')
                value = json.loads(line, object_pairs_hook=_object)
                if not isinstance(value, dict) or type(value.get('ok')) is not bool:
                    raise ValueError('Invalid broker envelope')
                if not value['ok']:
                    code = value.get('error_code', '')
                    if not isinstance(code, str) or re.fullmatch('[A-Z][A-Z0-9_]{0,79}', code) is None:
                        code = 'ADMIN_BROKER_REJECTED'
                    raise BrokerError(code, uncertain=method == 'execute')
                if set(value) != {'ok', 'result'} or not isinstance(value['result'], dict):
                    raise ValueError('Invalid broker envelope')
                return value['result']
        except BrokerError:
            raise
        except (OSError, ValueError, TypeError, OverflowError):
            raise BrokerError(uncertain=sent and method == 'execute') from None

    def capabilities(self):
        value = self.call('capabilities', {})
        actions = value.get('actions')
        if value.get('scope') != 'delegated_only' or not isinstance(actions, list) or len(actions) > 512:
            raise BrokerError('ADMIN_BROKER_INVALID_RESPONSE')
        result = []
        for action in actions:
            if (not isinstance(action, dict) or action.get('operation') not in HOST_ACTIONS
                    or not isinstance(action.get('target'), str) or TARGET.fullmatch(action['target']) is None
                    or not _identifier(action.get('approval')) or type(action.get('available')) is not bool
                    or not isinstance(action.get('description'), str) or not action['description'].strip()
                    or len(action['description']) > 256
                    or action.get('scope') not in ('instance', 'installation')
                    or not isinstance(action.get('affected_instances'), list)
                    or not 1 <= len(action['affected_instances']) <= 128
                    or any(not isinstance(item, str) or TARGET.fullmatch(item) is None
                           for item in action['affected_instances'])
                    or len(set(action['affected_instances'])) != len(action['affected_instances'])
                    or (action['scope'] == 'instance' and action['affected_instances'] != [action['target']])):
                raise BrokerError('ADMIN_BROKER_INVALID_RESPONSE')
            item = {key: action[key] for key in ('operation', 'target', 'approval', 'available', 'scope', 'affected_instances', 'description')}
            if 'request_id' in action:
                if not _identifier(action['request_id']):
                    raise BrokerError('ADMIN_BROKER_INVALID_RESPONSE')
                item['request_id'] = action['request_id']
            result.append(item)
        receipts = value.get('receipts', [])
        if not isinstance(receipts, list) or len(receipts) > 100:
            raise BrokerError('ADMIN_BROKER_INVALID_RESPONSE')
        observations = [observed_receipt(row) for row in receipts]
        if len({row['id'] for row in observations}) != len(observations):
            raise BrokerError('ADMIN_BROKER_INVALID_RESPONSE')
        for field in ('actions_truncated', 'receipts_truncated'):
            if type(value.get(field, False)) is not bool:
                raise BrokerError('ADMIN_BROKER_INVALID_RESPONSE')
        return {'actions': result, 'receipts': observations,
                'actions_truncated': value.get('actions_truncated', False),
                'receipts_truncated': value.get('receipts_truncated', False)}

    def execute(self, request):
        return receipt(self.call('execute', request), request)

    def status(self, record):
        identifier = record if isinstance(record, str) else record['id']
        value = self.call('status', {'id': identifier})
        return observed_receipt(value, identifier) if isinstance(record, str) else receipt(value, record)
