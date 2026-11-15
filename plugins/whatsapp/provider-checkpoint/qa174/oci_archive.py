"""Offline Docker-save -> OCI archive, verifying every layer's digest/diff-ID.

Keeps layer bytes (compressed or uncompressed) and image config unchanged.
The new transport manifest is measured; it is not the historical base manifest.
No subprocess, daemon, extraction, image load or filesystem deletion occurs.
"""
import gzip
import hashlib
import io
import json
from pathlib import PurePosixPath
import tarfile
import zlib


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def safe_name(name):
    path = PurePosixPath(name)
    require(name and not path.is_absolute() and '..' not in path.parts and '\\' not in name,
            'Unsafe archive name')


def add_bytes(archive, name, data):
    item = tarfile.TarInfo(name)
    item.size, item.mode, item.mtime = len(data), 0o644, 0
    archive.addfile(item, io.BytesIO(data))


class LayerReader:
    """Hash raw bytes and the uncompressed stream, with bounded decompression."""
    def __init__(self, source, compressed):
        self.source = source
        self.raw = hashlib.sha256()
        self.diff = hashlib.sha256()
        self.decoder = zlib.decompressobj(16 + zlib.MAX_WBITS) if compressed else None
        self.count = 0

    def read(self, size=-1):
        require(0 <= size <= 16 * 1024 * 1024, 'Unbounded layer read')
        data = self.source.read(size)
        self.raw.update(data)
        self.count += len(data)
        if self.decoder:
            remaining = data
            while remaining:
                expanded = self.decoder.decompress(remaining, 1024 * 1024)
                self.diff.update(expanded)
                remaining = self.decoder.unconsumed_tail
            require(not self.decoder.unused_data, 'Trailing compressed layer data')
        else:
            self.diff.update(data)
        return data

    def finish(self, digest, diff_id, size):
        require(self.count == size and self.raw.hexdigest() == digest, 'Layer bytes changed')
        if self.decoder:
            require(self.decoder.eof, 'Truncated compressed layer')
            self.diff.update(self.decoder.flush())
        require('sha256:' + self.diff.hexdigest() == diff_id, 'Layer diff-ID mismatch')


def convert(saved, output, expected_config, expected_diff_ids):
    """Two streaming passes; at most a few MiB of metadata are held in memory."""
    records, metadata = {}, {}
    with tarfile.open(saved, 'r|*') as archive:
        for item in archive:
            safe_name(item.name)
            require(item.isfile() or item.isdir(), 'Special Docker-save member')
            require(item.name not in records and len(records) < 2048, 'Duplicate/excessive archive members')
            if item.isdir():
                records[item.name] = None
                continue
            digest = hashlib.sha256()
            small = bytearray() if item.size <= 4 * 1024 * 1024 else None
            first = b''
            stream = archive.extractfile(item)
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                if not first:
                    first = block[:2]
                digest.update(block)
                if small is not None:
                    small.extend(block)
            records[item.name] = {'sha256': digest.hexdigest(), 'size': item.size, 'gzip': first == b'\x1f\x8b'}
            # Keep only the Docker manifest and exact expected config. Small
            # layer/extra members are hashed then discarded, not accumulated.
            if small is not None and (item.name == 'manifest.json' or 'sha256:' + digest.hexdigest() == expected_config):
                metadata[item.name] = bytes(small)
    require('manifest.json' in metadata, 'Missing or oversized Docker manifest')
    saved_manifest = json.loads(metadata['manifest.json'])
    require(isinstance(saved_manifest, list) and len(saved_manifest) == 1, 'Exactly one saved image required')
    entry = saved_manifest[0]
    require(entry['Config'] in metadata, 'Image config mismatch or oversized config')
    config_bytes = metadata[entry['Config']]
    config = json.loads(config_bytes)
    require('sha256:' + hashlib.sha256(config_bytes).hexdigest() == expected_config, 'Image config mismatch')
    require(config.get('os') == 'linux' and config.get('architecture') == 'amd64', 'Wrong image architecture')
    require(config['rootfs']['diff_ids'] == expected_diff_ids, 'Saved rootfs differs from inspected image')
    names = entry['Layers']
    require(len(names) == len(expected_diff_ids), 'Layer count mismatch')
    require(len(set(names)) == len(names), 'Repeated layer paths unsupported')
    layers = []
    selected = {}
    for name, diff_id in zip(names, expected_diff_ids):
        record = records.get(name)
        require(record is not None, 'Missing layer')
        media = 'application/vnd.oci.image.layer.v1.tar' + ('+gzip' if record['gzip'] else '')
        layers.append({'mediaType': media, 'digest': 'sha256:' + record['sha256'], 'size': record['size']})
        selected[name] = (record, diff_id)
    manifest = {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                'config': {'mediaType': 'application/vnd.oci.image.config.v1+json',
                           'digest': expected_config, 'size': len(config_bytes)}, 'layers': layers}
    manifest_bytes = canonical(manifest)
    manifest_digest = 'sha256:' + hashlib.sha256(manifest_bytes).hexdigest()
    index = {'schemaVersion': 2, 'manifests': [{'mediaType': manifest['mediaType'],
             'digest': manifest_digest, 'size': len(manifest_bytes),
             'platform': {'os': 'linux', 'architecture': 'amd64'}}]}
    config_name = 'blobs/sha256/' + expected_config[7:]
    seen = set()
    with output.open('xb') as raw, gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as zipped, \
            tarfile.open(fileobj=zipped, mode='w|') as target:
        add_bytes(target, 'oci-layout', canonical({'imageLayoutVersion': '1.0.0'}))
        add_bytes(target, 'index.json', canonical(index))
        add_bytes(target, config_name, config_bytes)
        add_bytes(target, 'blobs/sha256/' + manifest_digest[7:], manifest_bytes)
        # Compatibility entry allows Docker load without changing the OCI identity.
        add_bytes(target, 'manifest.json', canonical([{'Config': config_name, 'RepoTags': [],
                  'Layers': ['blobs/sha256/' + layer['digest'][7:] for layer in layers]}]))
        with tarfile.open(saved, 'r|*') as source:
            for item in source:
                if item.name not in selected:
                    continue
                record, diff_id = selected[item.name]
                reader = LayerReader(source.extractfile(item), record['gzip'])
                blob = tarfile.TarInfo('blobs/sha256/' + record['sha256'])
                blob.size, blob.mode = record['size'], 0o644
                target.addfile(blob, reader)
                reader.finish(record['sha256'], diff_id, record['size'])
                seen.add(item.name)
    require(seen == set(names), 'Not all layers exported')
    return {'config_digest': expected_config, 'manifest_digest': manifest_digest,
            'layers_verified': len(layers), 'base_transport_manifest_reconstructed': False}
