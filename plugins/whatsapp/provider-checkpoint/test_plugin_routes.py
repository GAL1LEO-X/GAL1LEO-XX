"""Offline contracts; the eight actions require a verified provider handshake."""
import copy
import importlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

from jsonschema import Draft202012Validator

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
operations = importlib.import_module("sally_whatsapp.operations")
ab_operations = importlib.import_module("sally_whatsapp.ab_operations")
CASES = json.loads((HERE / "fixture-requests.json").read_text())
EXPECTED = {
    "contacts_get_about", "contacts_block", "contacts_unblock",
    "chats_archive_chat", "chats_unarchive_chat", "messages_set_star",
    "chats_pin_message", "chats_unpin_message",
}


class RecordingGateway:
    def __init__(self):
        self.calls = []

    def request(self, method, path, **kwargs):
        self.calls.append((method, path, copy.deepcopy(kwargs)))
        return {"about": "fixture-about-✓"} if method == "GET" else {"success": True}


class PluginABContracts(unittest.TestCase):
    def test_exactly_eight_operations_with_star_both_values(self):
        self.assertEqual({case["operation"] for case in CASES}, EXPECTED)
        self.assertEqual(
            {case["arguments"]["body"]["star"] for case in CASES
             if case["operation"] == "messages_set_star"}, {True, False})

    def test_every_fixture_fits_the_existing_public_schema(self):
        for case in CASES:
            with self.subTest(operation=case["operation"]):
                Draft202012Validator(operations.OPERATIONS[case["operation"]]["schema"]).validate(case["arguments"])

    def test_qualified_runtime_remains_fail_closed_for_all_eight(self):
        for case in CASES:
            with self.subTest(operation=case["operation"]):
                op = operations.OPERATIONS[case["operation"]]
                self.assertEqual(op["capability"], ab_operations.CAPABILITY)
                with self.assertRaisesRegex(ValueError, "qualified GOWS"):
                    operations.validate_operation(case["operation"], case["arguments"], readonly=op["readonly"])

    def test_existing_executor_routes_and_injects_the_configured_session(self):
        settings = SimpleNamespace(session="fixture-a")
        for case in CASES:
            with self.subTest(operation=case["operation"], arguments=case["arguments"]):
                args = copy.deepcopy(case["arguments"])
                saved = copy.deepcopy(args)
                op = operations.OPERATIONS[case["operation"]]
                gateway = RecordingGateway()
                operations.execute(gateway, settings, op, args,
                    intent=ab_operations.durable_intent('fixture-owner','fixture-key',1700000000))
                self.assertEqual(args, saved, "dispatch must preserve stored intent")
                self.assertEqual(len(gateway.calls), 1)
                method, path, kwargs = gateway.calls[0]
                self.assertEqual((method, path), (case["method"], case["path"]))
                for location in op["inject_session"]:
                    if location == "query":
                        self.assertEqual(kwargs["params"]["session"], settings.session)
                    elif location == "body":
                        self.assertEqual(kwargs["json"]["session"], settings.session)
                if not op["readonly"]:
                    self.assertEqual(kwargs["timeout"], 120)

    def test_dispatch_does_not_trust_a_caller_supplied_session(self):
        for name in ("contacts_get_about", "contacts_block", "contacts_unblock", "messages_set_star"):
            case = next(case for case in CASES if case["operation"] == name)
            args = copy.deepcopy(case["arguments"])
            op = operations.OPERATIONS[name]
            location = "query" if op["readonly"] else "body"
            args[location]["session"] = "other-tenant"
            gateway = RecordingGateway()
            operations.execute(gateway, SimpleNamespace(session="fixture-a"), op, args,
                intent=ab_operations.durable_intent('fixture-owner','fixture-key',1700000000))
            wire = gateway.calls[0][2]["params" if location == "query" else "json"]
            self.assertEqual(wire["session"], "fixture-a")


if __name__ == "__main__":
    unittest.main()
