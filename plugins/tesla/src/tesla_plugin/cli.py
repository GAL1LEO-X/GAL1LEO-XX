"""Explicit local/operator entrypoints. No deployment or account discovery."""
import argparse
import fcntl
import getpass
import hashlib
import json
import logging
import os
from pathlib import Path
import signal
import sys
import time

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import __version__
from .config import Settings, secret
from .errors import TeslaError
from .portal import password_hash
from .store import Store, canonical
from .telemetry import Telemetry, consume_record


def write_new(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def initialize(directory, password):
    directory = Path(directory)
    targets = [directory/name for name in ("encryption.key", "owner.hash", "vehicle-private.pem", "vehicle-public.pem")]
    if any(p.exists() or p.is_symlink() for p in targets):
        raise ValueError("Initialization preserves existing files; choose an empty private directory")
    hashed = password_hash(password)
    key = ec.generate_private_key(ec.SECP256R1())
    write_new(targets[0], Fernet.generate_key()+b"\n")
    write_new(targets[1], hashed.encode()+b"\n")
    write_new(targets[2], key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    write_new(targets[3], key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo), 0o644)
    return {"initialized": True, "virtual_key_paired": False, "public_key": str(targets[3])}


def process_batch(consumer, telemetry, records):
    """Commit exactly one consumed offset after durable data or rejection metadata.

    Authentication/storage/transient failures stop the consumer without committing
    the affected record. Invalid frames are quarantined by digest, never raw data.
    """
    from kafka.structs import OffsetAndMetadata, TopicPartition
    count = 0
    for record in records:
        try:
            consume_record(telemetry, record)
        except (ValueError, TypeError, KeyError) as exc:
            reason = "INVALID_TELEMETRY"
        except TeslaError as exc:
            if exc.code not in ("INVALID_TELEMETRY", "VEHICLE_ACCESS_REQUIRED"):
                raise
            reason = exc.code
        else:
            reason = None
        if reason:
            identity = hashlib.sha256(f"{record.topic}:{record.partition}:{record.offset}".encode()).hexdigest()
            with telemetry.store.db() as db:
                db.execute("INSERT OR IGNORE INTO ingestion_errors VALUES(?,?,?)", (identity, reason, telemetry.store.clock()))
        offset = OffsetAndMetadata(record.offset+1, "", -1)
        consumer.commit({TopicPartition(record.topic, record.partition): offset})
        count += 1
    return count


def consume_step(store, consumer, telemetry, fleet, checked):
    from .collection import collection_enabled
    from .diagnostics import consumer_heartbeat
    if not collection_enabled(store):
        # Paused/unconfigured acquisition must not keep polling Tesla.
        # Kafka retains any buffered records for a later checked read.
        consumer_heartbeat(store, "paused")
        time.sleep(1)
        return checked
    batches = consumer.poll(timeout_ms=1000)
    if batches:
        fleet.oauth.access_token()
        if checked is None or time.monotonic()-checked >= 240:
            fleet.discover()
            checked = time.monotonic()
    for records in batches.values():
        process_batch(consumer, telemetry, records)
    telemetry.tick()
    consumer_heartbeat(store, "running")
    return checked


def consume(settings):
    from kafka import KafkaConsumer
    from .fleet import Fleet
    if not settings.live_enabled or not settings.telemetry_bootstrap_servers:
        raise ValueError("Telemetry consumption requires explicit live mode and private broker configuration")
    store, stop = Store(settings), False
    telemetry, fleet = Telemetry(store), Fleet(store)
    consumer = None
    lock = open(str(store.path)+".consumer.lock", "a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    def halt(*unused):
        nonlocal stop
        stop = True
    signal.signal(signal.SIGTERM, halt)
    signal.signal(signal.SIGINT, halt)
    try:
        # Fail closed before fetching records if the owner's authorization cannot
        # be renewed. Re-check membership periodically, with no vehicle wake.
        checked = None
        consumer = KafkaConsumer(*settings.telemetry_topics,
            bootstrap_servers=list(settings.telemetry_bootstrap_servers), group_id="tesla-personal-v1",
            client_id="tesla-personal", enable_auto_commit=False, auto_offset_reset="earliest",
            max_poll_records=100, fetch_max_bytes=2_000_000, max_partition_fetch_bytes=1_000_000,
            request_timeout_ms=30000, consumer_timeout_ms=1000,
            security_protocol="SSL" if settings.telemetry_broker_ca else "PLAINTEXT",
            ssl_cafile=str(settings.telemetry_broker_ca) if settings.telemetry_broker_ca else None)
        while not stop:
            checked = consume_step(store, consumer, telemetry, fleet, checked)
    finally:
        from .diagnostics import consumer_heartbeat
        try:
            consumer_heartbeat(store, "stopped")
        finally:
            if consumer:
                consumer.close(autocommit=False)
            fleet.close()
            lock.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="Generate private local keys and an owner password hash; never overwrite")
    init.add_argument("--directory", type=Path, required=True)
    for name in ("check-config", "status", "serve", "consume"):
        command = sub.add_parser(name)
        command.add_argument("--config", type=Path, required=True)
        if name == "serve":
            command.add_argument("--port", type=int, default=8018)
    args = parser.parse_args(argv)
    # Default HTTP access logs can contain OAuth callback codes. Provider bodies
    # and exception strings never go to logs from these entrypoints.
    logging.basicConfig(level=logging.WARNING)
    try:
        if args.command == "init":
            password = getpass.getpass('Owner panel passphrase (at least 16 characters): ')
            if password != getpass.getpass('Repeat the passphrase: '):
                raise ValueError("Passphrases do not match")
            print(canonical(initialize(args.directory, password)))
            return 0
        settings = Settings.load(args.config)
        if args.command == "check-config":
            secret(settings.encryption_key_file)
            if settings.owner_password_file:
                secret(settings.owner_password_file)
            if settings.live_enabled:
                secret(settings.tesla_client_secret_file)
            print(canonical({"configuration_valid": True, "live_enabled": settings.live_enabled,
                             "network_checked": False, "vehicle_qualified": False}))
        elif args.command == "status":
            from .service import Service
            service = Service(settings)
            try:
                print(canonical(service.connection_status()))
            finally:
                service.fleet.close()
        elif args.command == "consume":
            consume(settings)
        else:
            import uvicorn
            from .server import create_app
            uvicorn.run(create_app(settings), host="127.0.0.1", port=args.port, workers=1,
                        access_log=False, proxy_headers=False, server_header=False, log_level="warning")
        return 0
    except (TeslaError, ValueError, OSError) as exc:
        code = exc.code if isinstance(exc, TeslaError) else type(exc).__name__
        print(canonical({"error": code, "message": "Operation stopped; check private configuration and service prerequisites"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
