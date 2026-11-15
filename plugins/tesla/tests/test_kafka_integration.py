"""Opt-in real broker test. Only an ephemeral local container and synthetic VIN."""
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import uuid

import pytest
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaConnectionError, KafkaTimeoutError
from kafka.structs import TopicPartition

from tesla_plugin.cli import process_batch
from tesla_plugin.triggers import Triggers
from tesla_plugin.config import SCOPES
from tesla_plugin.store import canonical
from tesla_plugin.telemetry import Telemetry
from test_telemetry_events import payload, kinds
from conftest import VIN

pytestmark = [pytest.mark.integration, pytest.mark.skipif(os.environ.get("TESLA_TEST_KAFKA") != "1", reason="Opt-in isolated Docker broker test")]


def test_real_broker_replay_and_manual_offset_commit(store, vehicle_ref, clock):
    env = {k: v for k, v in os.environ.items() if k not in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")}
    docker = ["docker", "--host=unix:///var/run/docker.sock"]
    subprocess.run(docker+["info", "--format", "{{.ServerVersion}}"], env=env, check=True, capture_output=True)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    image = json.loads((Path(__file__).resolve().parents[1]/"deploy/components.lock.json").read_text())["kafka_image"]
    name = "tesla-synthetic-"+uuid.uuid4().hex[:12]
    options = {"KAFKA_NODE_ID": "1", "KAFKA_PROCESS_ROLES": "broker,controller", "KAFKA_LISTENERS": "PLAINTEXT://:9092,CONTROLLER://:9093",
        "KAFKA_ADVERTISED_LISTENERS": f"PLAINTEXT://127.0.0.1:{port}", "KAFKA_CONTROLLER_LISTENER_NAMES": "CONTROLLER",
        "KAFKA_LISTENER_SECURITY_PROTOCOL_MAP": "CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT", "KAFKA_CONTROLLER_QUORUM_VOTERS": "1@localhost:9093",
        "KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR": "1", "KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR": "1", "KAFKA_TRANSACTION_STATE_LOG_MIN_ISR": "1",
        "KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS": "0", "KAFKA_NUM_PARTITIONS": "1", "KAFKA_HEAP_OPTS": "-Xms256m -Xmx512m",
        "KAFKA_OFFSETS_TOPIC_NUM_PARTITIONS": "1", "KAFKA_LOG_SEGMENT_BYTES": "16777216", "KAFKA_LOG_RETENTION_BYTES": "33554432"}
    args = docker+["run", "--detach", "--name", name, "--memory=1g", "-p", f"127.0.0.1:{port}:9092"]
    for key, value in options.items():
        args += ["-e", key+"="+value]
    args.append(image)
    producer, consumer = None, None
    subprocess.run(args, check=True, env=env, capture_output=True)
    try:
        deadline = time.monotonic()+60
        while True:
            try:
                producer = KafkaProducer(bootstrap_servers=f"127.0.0.1:{port}", bootstrap_timeout_ms=2000)
                break
            except (KafkaConnectionError, KafkaTimeoutError):
                state = subprocess.check_output(docker+["inspect", name, "--format", "{{.State.Running}}"], env=env, text=True).strip()
                if state != "true":
                    pytest.fail("Synthetic Kafka container exited")
                if time.monotonic() >= deadline:
                    pytest.fail("Synthetic Kafka did not become ready")
                time.sleep(0.5)
        telemetry = Telemetry(store)
        # Exercise the default rule instead of adding a second identical rule.
        manager = Triggers(store)
        manager.update(vehicle_ref, [{"trigger_id": "field:BatteryLevel", "enabled": True}], SCOPES,
                       expected_revision=manager.view(vehicle_ref, SCOPES)["revision"], batch_seconds=10)
        for value in (25, 10):
            producer.send("tesla_V", key=VIN.encode(), value=canonical(payload(clock, {"BatteryLevel": value})).encode(),
                          headers=[("vin", VIN.encode()), ("txtype", b"V")]).get(timeout=20)
            clock.advance(1)
        consumer = KafkaConsumer(bootstrap_servers=f"127.0.0.1:{port}", group_id="tesla-synthetic", enable_auto_commit=False, auto_offset_reset="earliest")
        partition = TopicPartition("tesla_V", 0)
        consumer.assign([partition])
        consumer.seek_to_beginning(partition)
        records = []
        deadline = time.monotonic()+20
        while len(records)<2 and time.monotonic()<deadline:
            records.extend(consumer.poll(timeout_ms=500).get(partition, []))
        assert len(records) == 2
        assert process_batch(consumer, telemetry, records) == 2
        assert consumer.committed(partition) == records[-1].offset+1
        assert kinds(store) == ["battery_low"]
        process_batch(consumer, Telemetry(store), records)
        assert kinds(store) == ["battery_low"]
        with store.db() as db:
            assert db.execute("SELECT count(*) FROM samples").fetchone()[0] == 2
        clock.advance(10)
        Telemetry(store).tick()
        Telemetry(store).tick()
        assert kinds(store) == ["battery_low", "telemetry_changed"]
        with store.db() as db:
            data = json.loads(db.execute("SELECT data FROM events WHERE name='telemetry_changed'").fetchone()[0])
        assert data["changes"]["BatteryLevel"]["count"] == 2
        assert data["changes"]["BatteryLevel"]["after"]["value"] == 10
    except BaseException:
        # This container contains synthetic test data only.
        print(subprocess.check_output(docker+["logs", "--tail", "30", name], env=env, stderr=subprocess.STDOUT, text=True))
        raise
    finally:
        if producer:
            producer.close(timeout=5)
        if consumer:
            consumer.close(autocommit=False)
        subprocess.run(docker+["rm", "-f", "-v", name], env=env, check=True, capture_output=True)
