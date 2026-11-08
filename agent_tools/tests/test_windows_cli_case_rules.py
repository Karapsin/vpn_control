"""The disconnected and streaming case modules against the product's own CLI rules.

Each rule below was observed on the real 2.2.15 packaged CLI with a private
temporary --state-dir, where it stopped the unchanged modules (provenance.json).
An in-memory product answers in the recorded shapes; nothing here starts a
process. Every oracle is RED on the preserved module and GREEN on the current one.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
import uuid

from agent_tools import windows_disconnected_cli_cases as disconnected_cases
from agent_tools import windows_streaming_cli_cases as streaming_cases

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / "fixtures/windows_cli_case_rules"
# The owner's guarded writes, as capabilities lists them in revisionGuardOperations.
GUARDED = {"settings set", "settings apply", "ssh key", "subscriptions add", "subscriptions update", "subscriptions delete",
           "locations add", "locations update", "locations select", "locations delete", "locations benchmark", "locations import",
           "source set", "routing set", "routing import", "quit", "updates install"}
PARSER_REFUSAL = "INVALID_ARGUMENT: invalid state directory or command.\n"


def load_harness():
    spec = importlib.util.spec_from_file_location("_case_rules_packaged_cli_harness", ROOT / "scripts/test_packaged_cli.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.__dict__


class Reached(Exception):
    """The oracle's goal: the case got past the rule to a command it may legally send."""


class Product:
    """In-memory owners keyed by workspace, answering in the recorded output shapes."""

    def __init__(self, stops):
        self.workspaces = {}
        self.stops = set(stops)

    def serve(self, workspace, mode="subscription"):
        self.workspaces[str(workspace)] = {"id": str(uuid.uuid4()), "revision": 0, "mode": mode, "settings": {"validation.batch-size": 0},
                                           "locations": []}
        return self.workspaces[str(workspace)]

    @staticmethod
    def envelope(code, owner, revision, data, warnings=()):
        return {"schemaVersion": 1, "controllerId": owner, "requestId": str(uuid.uuid4()), "ok": code == "OK", "code": code,
                "message": code if code != "OK" else "", "messageKey": None, "messageArgs": [], "final": True, "operationId": None,
                "configurationRevision": revision, "restartRequired": False, "data": data, "warnings": list(warnings)}

    def reply(self, json_mode, exit_code, code, owner=None, revision=0, data=None):
        if json_mode:
            warnings = () if owner else ("OWNER_METADATA_UNAVAILABLE",)
            return subprocess.CompletedProcess([], exit_code, json.dumps(self.envelope(code, owner, revision, data or {}, warnings)) + "\n", "")
        lines = [code, "Controller: " + (owner or "unknown"), "Request: " + str(uuid.uuid4()),
                 "Revision: " + (str(revision) if owner else "unknown"), "Completion: final", "Restart required: no"]
        text = "\n".join(lines) + "\n"
        return subprocess.CompletedProcess([], exit_code, text if exit_code == 0 else "", "" if exit_code == 0 else text)

    def invoke(self, workspace, *arguments, timeout=30):
        argv = list(arguments)
        json_mode = "--json" in argv
        argv = [item for item in argv if item != "--json"]
        guards = {}
        for name in ("--controller-id", "--if-revision"):
            if name in argv:
                index = argv.index(name)
                guards[name] = argv[index + 1]
                del argv[index:index + 2]
        if argv == ["--help"]:
            return subprocess.CompletedProcess([], 0, "Usage: vpn-control [options] <command>\n", "")
        if argv == ["--version"]:
            return subprocess.CompletedProcess([], 0, "2.2.15\n", "")
        command = " ".join(argv[:2])
        if "--unknown" in argv or ("--if-revision" in guards and command not in GUARDED):
            # Both are refused before dispatch: an unknown option and a revision guard on a read.
            if json_mode:
                return self.reply(True, 1, "INVALID_ARGUMENT")
            return subprocess.CompletedProcess([], 1, "", PARSER_REFUSAL)
        if argv == ["capabilities"]:
            return self.reply(json_mode, 0, "OK", data={"runtimeReadinessChecked": False}) if json_mode else \
                subprocess.CompletedProcess([], 0, "OK\nController: unknown\nData:\n  runtimeReadinessChecked: false\n", "")
        state = self.workspaces.get(str(workspace))
        if state is None:
            return self.reply(json_mode, 2, "UNAVAILABLE")
        if (guards.get("--controller-id") not in (None, state["id"])
                or "--if-revision" in guards and int(guards["--if-revision"]) != state["revision"]):
            return self.reply(json_mode, 1, "CONFLICT", state["id"], state["revision"])
        if command in self.stops and not (command in {"locations add", "locations import"} and state["mode"] != "current-locations"):
            raise Reached(command)
        if argv == ["status"]:
            return self.reply(json_mode, 0, "OK", state["id"], state["revision"], {"runtimeRunning": False})
        if argv == ["source", "show"]:
            return self.reply(json_mode, 0, "OK", state["id"], state["revision"], {"mode": state["mode"], "subscriptionId": ""})
        if argv == ["source", "set", "current-locations"]:
            if state["mode"] != "current-locations":
                state["mode"], state["revision"] = "current-locations", state["revision"] + 1
            return self.reply(json_mode, 0, "OK", state["id"], state["revision"], {"id": "current-locations"})
        if argv == ["settings", "show"]:
            return self.reply(json_mode, 0, "OK", state["id"], state["revision"], dict(state["settings"]))
        if argv == ["locations", "list"]:
            return self.reply(json_mode, 0, "OK", state["id"], state["revision"], {"locations": list(state["locations"])})
        if command in {"locations add", "locations import"}:
            # Subscription mode is read-only for locations: the owner answers, the revision stays.
            return self.reply(json_mode, 1, "READ_ONLY_SOURCE", state["id"], state["revision"])
        raise AssertionError("unmodelled command: " + " ".join(argv))


class Child:
    def __init__(self, owner, label, argv):
        self.owner, self.label, self.argv = owner, label, argv
        self.process = types.SimpleNamespace(poll=lambda: None, _handle=7)
        self.pid, self.birth, self.ordinal = 4100 + len(owner.children), "1", len(owner.children)

    def observe(self):
        return None


class Owner:
    def __init__(self, product, root):
        self.product, self.root = product, Path(root)
        self.cli = "/opt/vpn-control/vpn-control-cli.exe"
        self.request = {"action": "streaming-client-interrupt", "cliPath": self.cli, "productVersion": "2.2.15",
                        "treePins": [{"role": "installed-app", "root": "/opt/vpn-control", "files": ["vpn-control-cli.exe"]}],
                        "context": {"ordinarySessionId": 2}}
        self.by_path = {str(Path(self.cli)).casefold(): types.SimpleNamespace(record={"path": self.cli})}
        self.native = types.SimpleNamespace(birth=lambda handle: "1")
        self.children, self.events = [], []

    def guard(self):
        pass

    def event(self, kind, value):
        self.events.append(kind)

    def invoke(self, workspace, *arguments, timeout=30):
        return self.product.invoke(workspace, *arguments)

    def child(self, label, argv, new_console=False):
        if argv[-1] != "serve":
            raise Reached("child:" + label)
        self.product.serve(argv[2])
        self.children.append(Child(self, label, argv))
        return self.children[-1]


class CaseRuleTests(unittest.TestCase):
    BEFORE = {"disconnected": ("disconnected-cases.before.source", "586b2ad33459348535fd655fa6cc9db001708f83eb346291b27e32d1b6c55510"),
              "streaming": ("streaming-cases.before.source", "f40b207f5b482df9cd3061fddadde3e4f6002ec3d8321cdaeadb1d6c5d152462")}

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.harness = load_harness()

    def before(self, name):
        fixture, digest = self.BEFORE[name]
        raw = (FIXTURES / fixture).read_bytes()
        self.assertEqual(digest, hashlib.sha256(raw).hexdigest())
        provenance = json.loads((FIXTURES / "provenance.json").read_bytes())["fixtures"][fixture]
        self.assertEqual((digest, len(raw)), (provenance["sha256"], provenance["sizeBytes"]))
        module = types.ModuleType("_case_rules_before_" + name)
        module.__file__ = str(FIXTURES / fixture)
        sys.modules[module.__name__] = module
        self.addCleanup(sys.modules.pop, module.__name__, None)
        exec(compile(raw, module.__file__, "exec"), module.__dict__)
        return module

    def cases(self, module, product):
        base = Path(tempfile.mkdtemp(dir=self.root))  # One fresh owner root per run: case files are create-only.
        owner = Owner(product, base)
        workspace = base / "workspace"
        identity = product.serve(workspace)["id"]
        root = base / "fixture files"
        root.mkdir()
        case = module.Cases(owner, workspace, identity, self.harness, root)
        case.initial_settings = {"validation.batch-size": 0}
        return case

    # Oracles: each returns normally only when the case got past the product rule.
    def static_oracle(self, module):
        module.static_cases(self.cases(module, Product(())))

    def location_oracle(self, module):
        with self.assertRaisesRegex(Reached, "locations add"):
            module.location_cases(self.cases(module, Product({"locations add"})))

    def transfer_oracle(self, module):
        case = self.cases(module, Product({"locations import"}))
        document = case.root / "locations export.json"
        document.write_bytes(b'{"type":"vpn_control_locations","locations":[]}')
        with self.assertRaisesRegex(Reached, "locations import"):
            module.independent_transfer(case, document, case.output(document))

    def diagnostics_oracle(self, module):
        case = self.cases(module, Product({"diagnostics export"}))
        with self.assertRaisesRegex(Reached, "diagnostics export"):
            module.diagnostics_cases(case, case.root)

    def streaming_oracle(self, module):
        product = Product(())
        base = Path(tempfile.mkdtemp(dir=self.root))
        owner = Owner(product, base)
        workspace = base / "workspace"
        serve = owner.child("serve", [owner.cli, "--state-dir", str(workspace), "serve"])
        with self.assertRaisesRegex(Reached, "child:stream-status-json"):
            module.run(owner, workspace, product.workspaces[str(workspace)]["id"], self.harness)
        self.assertEqual("current-locations", product.workspaces[str(workspace)]["mode"])
        self.assertIs(serve, owner.children[0])

    def red_then_green(self, name, current, oracles):
        before = self.before(name)
        for oracle, reason in oracles:
            with self.subTest(oracle=oracle.__name__):
                # The preserved module stops on the product's answer, exactly where the real CLI stopped it.
                with self.assertRaisesRegex(AssertionError, reason):
                    oracle(before)
                oracle(current)

    def test_disconnected_cases_follow_the_product_rules(self):
        self.red_then_green("disconnected", disconnected_cases,
                            ((self.static_oracle, "human-static-streams"), (self.location_oracle, "human-exit-code"),
                             (self.transfer_oracle, "human-exit-code"), (self.diagnostics_oracle, "CLI exit 1, expected 0")))

    def test_streaming_cases_select_current_locations_once_on_a_fresh_workspace(self):
        self.red_then_green("streaming", streaming_cases, ((self.streaming_oracle, "fresh-current-locations-before-streams"),))

    def test_the_human_refusal_shapes_are_the_recorded_ones(self):
        self.assertTrue(disconnected_cases.human_error_is(PARSER_REFUSAL, "INVALID_ARGUMENT"))
        self.assertTrue(disconnected_cases.human_error_is("READ_ONLY_SOURCE\nController: x\n", "READ_ONLY_SOURCE"))
        for stderr, code in (("INVALID_ARGUMENTS\n", "INVALID_ARGUMENT"), ("", "UNAVAILABLE"), ("OK\n", "UNAVAILABLE"),
                             ("x INVALID_ARGUMENT: y\n", "INVALID_ARGUMENT")):
            self.assertFalse(disconnected_cases.human_error_is(stderr, code), stderr)


if __name__ == "__main__":
    unittest.main()
