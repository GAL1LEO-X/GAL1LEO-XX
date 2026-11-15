"""Exercise the existing plugin against an explicitly synthetic loopback bridge."""
import argparse
import importlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from urllib.parse import urlsplit

import httpx
from cryptography.fernet import Fernet

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
gateway_module = importlib.import_module("sally_whatsapp.gateway")
operations = importlib.import_module("sally_whatsapp.operations")


def fixture_url(value):
    url = urlsplit(value)
    if (url.scheme != "http" or url.hostname != "127.0.0.1" or not url.port
            or url.username or url.password or url.path not in ("", "/")
            or url.query or url.fragment):
        raise argparse.ArgumentTypeError("only an explicit http://127.0.0.1:PORT fixture is accepted")
    return value.rstrip("/")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    transport = parser.add_mutually_exclusive_group(required=True)
    transport.add_argument("--offline-fixture", type=fixture_url)
    transport.add_argument("--offline-unix-socket", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.offline_unix_socket is not None:
        import stat
        if not args.offline_unix_socket.is_absolute() or not stat.S_ISSOCK(args.offline_unix_socket.stat().st_mode):
            parser.error("--offline-unix-socket must identify an existing absolute fixture socket")
    settings = SimpleNamespace(waha_url=args.offline_fixture or "http://fixture", waha_key_file=None,
                               session="fixture-a", live_account_enabled=True)
    gateway = gateway_module.Waha(settings)
    if args.offline_unix_socket is not None:
        gateway.client.close()
        gateway.client = httpx.Client(base_url=settings.waha_url, trust_env=False,
            transport=httpx.HTTPTransport(uds=str(args.offline_unix_socket)))
    results = []
    try:
        assert gateway.ab_operations() == operations.ab_operations.OPERATIONS
        variants = [("1@c.us", "fixture-about-✓"), ("2@c.us", ""), ("3@c.us", None)]
        for contact, expected in variants:
            arguments = {"path": {}, "query": {"contactId": contact}, "body": {}}
            value = operations.execute(gateway, settings, operations.OPERATIONS["contacts_get_about"], arguments)
            assert value == {"about": expected}, "About value/presence was not preserved"
            results.append({"operation": "contacts_get_about", "fixture_contact": contact,
                            "result": value, "passed": True})
        for contact in ("4@c.us",):
            try:
                operations.execute(gateway, settings, operations.OPERATIONS["contacts_get_about"],
                                   {"path": {}, "query": {"contactId": contact}, "body": {}})
            except gateway_module.GatewayUnavailable:
                results.append({"operation": "contacts_get_about", "fixture_contact": contact,
                                "expected_error": True, "passed": True})
            else:
                raise AssertionError("provider error must not become About null")
        # This path exercises the actual persistent queue/worker and source
        # checks, while the provider backend remains entirely synthetic.
        from sally_whatsapp.config import Settings
        from sally_whatsapp.server import OperationAction, Service
        with tempfile.TemporaryDirectory(prefix="whatsapp-ab-vertical-") as temporary:
            root = Path(temporary)
            webhook = root / "fixture-webhook.key"
            webhook.write_text("synthetic-offline-fixture-only-not-a-real-key")
            encryption = root / "fixture-encryption.key"
            encryption.write_bytes(Fernet.generate_key())
            full = Settings(database=root / "fixture.sqlite", public_url="https://fixture.example",
                issuer="https://issuer.fixture.example", owner_subject="fixture-owner",
                webhook_secret_file=webhook, encryption_key_file=encryption,
                jwks_url="https://issuer.fixture.example/jwks", oauth_client_ids=["fixture-client"],
                waha_url=settings.waha_url, waha_key_file=webhook, session=settings.session, live_account_enabled=True,
                send_enabled=True, account_actions_enabled=True, allow_all_destinations=True,
                diagnostics_enabled=False)
            service = Service(full, gateway=gateway)
            chat = "15550001111@c.us"
            identifier = "false_" + chat + "_SOURCE"
            cases = [
                ("contacts_block", {"body": {"contactId": "1@c.us"}}),
                ("contacts_unblock", {"body": {"contactId": "1@c.us"}}),
                ("chats_archive_chat", {"path": {"chatId": chat}}),
                ("chats_unarchive_chat", {"path": {"chatId": chat}}),
                ("messages_set_star", {"body": {"chatId": chat, "messageId": identifier, "star": True}}),
                ("messages_set_star", {"body": {"chatId": chat, "messageId": identifier, "star": False}}),
                ("chats_pin_message", {"path": {"chatId": chat, "messageId": identifier}, "body": {"duration": 86400}}),
                ("chats_unpin_message", {"path": {"chatId": chat, "messageId": identifier}}),
            ]
            try:
                for index, (name, arguments) in enumerate(cases):
                    key = "synthetic-ab-vertical-" + str(index).zfill(3)
                    action = OperationAction(operation=name, arguments=arguments, idempotency_key=key)
                    assert service.operation(action, full.owner_subject)["state"] == "queued"
                    assert service.process_action()
                    status = service.store.send_status(key, owner=full.owner_subject)
                    assert status["state"] == "submitted", (name, status["state"])
                    assert service.operation(action, full.owner_subject)["state"] == "submitted"
                    assert not service.process_action(), "deduplicated action was dispatched twice"
                    results.append({"operation": name, "variant": arguments.get("body", {}).get("star"),
                                    "queue_worker": True, "state": "submitted", "deduplicated": True, "passed": True})
                uncertain = OperationAction(operation="contacts_block", arguments={"body": {"contactId": "5@c.us"}},
                    idempotency_key="synthetic-ab-vertical-uncertain")
                service.operation(uncertain, full.owner_subject)
                assert service.process_action()
                assert service.store.send_status(uncertain.idempotency_key, owner=full.owner_subject)["state"] == "uncertain"
                assert not service.process_action()
                results.append({"operation": "contacts_block", "expected_uncertain": True,
                                "automatic_retry": False, "passed": True})
            finally:
                service.diagnostics.close()
    finally:
        gateway.client.close()
    summary = {"offline_only": True, "real_whatsapp_calls": 0,
               "chain": ["PLUGINS Service/SQLite queue/worker and Waha HTTP client", "fixture HTTP router",
                         "compiled WAHA AB adapter", "generated gRPC client", "Go fake backend"],
               "limits": ["fixture HTTP router is not Nest controller integration",
                          "no WhatsApp session, privacy or device behavior is qualified",
                          "MCP authorization is qualified separately by regression tests",
                          "old providers remain unavailable until a compatible contract is verified"],
               "results": results}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"passed": len(results), "offline_only": True}))


if __name__ == "__main__":
    main()
