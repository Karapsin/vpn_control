"""Host-only plan tests; native Windows acceptance stays a separate gate."""
from dataclasses import FrozenInstanceError
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock

from agent_tools import ssh_program_windows as owner


FIXTURES = Path(__file__).parent / "fixtures" / "windows_program_v5"
OPERATION = "77f8563d-b16d-4116-bad1-167841bcd343"
SID = "S-1-5-21-4099058025-2437077614-260217637-1001"


def program():
    return {
        "language": "powershell-scriptblock", "source": owner.HELD_PARAMETER_HEADER + "[Console]::WriteLine('infrastructure')\n",
        "args": [], "cwd": None,
        "targetContext": {
            "kind": "windows-deployment", "executionPrincipal": "system",
            "deploymentId": "d493a373-1d2c-4ab0-bfd4-e93575019dce",
            "hostBootId": "25515f23-b966-4c3a-ae63-d38452375578",
            "qemuPid": 4321, "qemuStartTicks": 9876543,
            "guestBootTime": "2026-10-19T00:00:00.0000000Z",
            "ordinarySid": SID, "ordinarySessionId": 2,
            "workspace": r"C:\ProgramData\VpnControlProgram-77f8563d-b16d-4116-bad1-167841bcd343",
            "credentialPath": "/private/windows-program/credential.bytes",
        },
    }


def capabilities(value):
    expected = {key: item for key, item in value["targetContext"].items() if key != "credentialPath"}
    expected.update(host="archlinux", workspaceSddl=owner.parent_sddl(SID))
    return mock.Mock(guard=mock.Mock()), mock.Mock(guard=mock.Mock(return_value=expected))


class WindowsProgramPlanTest(unittest.TestCase):
    def test_exact_proven_bootstrap_and_wire_measurements(self):
        source = (FIXTURES / "held_program.proven.source").read_bytes()
        original = (FIXTURES / "bootstrap.proven.source").read_bytes()
        provenance = json.loads((FIXTURES / "provenance.json").read_text())
        self.assertEqual(hashlib.sha256(original).hexdigest(), provenance["bootstrap"]["sha256"])
        self.assertEqual(hashlib.sha256(source).hexdigest(), provenance["heldSource"]["sha256"])
        workspace = r"C:\ProgramData\VpnControlOrdinaryTask-d907f7a0-725b-40f1-8bf8-d9c76439e33a"
        bootstrap = owner.render_bootstrap(source, path=workspace + "\\continuation-" + OPERATION + ".ps1",
                                           workspace=workspace, ordinary_sid=SID, phase_id=OPERATION)
        self.assertEqual(bootstrap, original)
        encoded = base64.b64encode(bootstrap.decode("utf-8-sig").encode("utf-16le")).decode("ascii")
        arguments, bounds = owner.command_bounds(owner.POWERSHELL,
            ("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded), source)
        self.assertEqual(bounds["commandUtf16UnitsIncludingNul"], provenance["commandUtf16UnitsIncludingNul"])
        self.assertEqual(bounds["serializedRequestBytes"], provenance["serializedRequestBytes"])
        self.assertEqual(base64.b64decode(arguments["input-data"], validate=True), source)

    def test_effect_free_immutable_plan_requires_both_live_capabilities(self):
        value = program()
        source, binding = capabilities(value)
        with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("no child")), \
                mock.patch.object(Path, "read_bytes", side_effect=AssertionError("no source reopen")), \
                mock.patch.object(Path, "mkdir", side_effect=AssertionError("no filesystem effects")):
            plan = owner.build_plan("unused-root", "archlinux", OPERATION, value, source, binding)
        self.assertEqual(source.guard.call_count, 2)
        self.assertEqual(binding.guard.call_count, 2)
        self.assertEqual(plan.source_bytes, b"\xef\xbb\xbf" + value["source"].encode())
        self.assertIn(b"SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18'))", plan.bootstrap_bytes)
        self.assertIn(b"& $program -ExpectedSourceSha256 $expected -HeldSource $reader -SourcePath $path", plan.bootstrap_bytes)
        arguments = plan.guest_exec_arguments()
        self.assertEqual(arguments["path"], owner.POWERSHELL)
        self.assertEqual(base64.b64decode(arguments["input-data"]), plan.source_bytes)
        arguments["path"] = "changed"
        self.assertEqual(plan.guest_exec_arguments()["path"], owner.POWERSHELL)
        with self.assertRaises(FrozenInstanceError):
            plan.operation_id = "changed"
        public = plan.public_record()
        self.assertEqual(public["executionPrincipal"], "system")
        self.assertEqual(public["executionSemantics"], "held-saved-file-scriptblock-v5")
        self.assertNotIn(value["targetContext"]["credentialPath"], json.dumps(public))
        self.assertNotIn(value["targetContext"]["credentialPath"].encode(), plan.bootstrap_bytes)

    def test_binding_or_source_changes_refuse_before_plan(self):
        value = program()
        source, binding = capabilities(value)
        expected = binding.guard.return_value
        for field, changed in (("qemuPid", 987), ("ordinarySid", SID + "0"),
                               ("guestBootTime", "2026-10-18T00:00:00.0000000Z"),
                               ("workspaceSddl", "O:BA"), ("host", "other-host")):
            with self.subTest(field=field):
                binding.guard.side_effect = [expected, {**expected, field: changed}]
                with self.assertRaisesRegex(ValueError, "target_changed"):
                    owner.build_plan(None, "archlinux", OPERATION, value, source, binding)
        binding.guard.side_effect = None
        source.guard.side_effect = RuntimeError("source_changed")
        with self.assertRaisesRegex(RuntimeError, "source_changed"):
            owner.build_plan(None, "archlinux", OPERATION, value, source, binding)
        with self.assertRaisesRegex(ValueError, "admission_capability"):
            owner.build_plan(None, "archlinux", OPERATION, value, {}, {})

    def test_schema_does_not_widen_proven_semantics(self):
        changes = (
            ("language", "powershell-file"), ("args", ["argument"]),
            ("args", ()), ("cwd", r"C:\Windows\System32"),
            ("source", "Write-Output arbitrary"), ("source", owner.HELD_PARAMETER_HEADER + "\0"),
        )
        for key, value in changes:
            with self.subTest(key=key, value=value):
                sample = program(); sample[key] = value
                with self.assertRaises(ValueError):
                    owner.validate(sample)
        for key, value in (("executionPrincipal", "ordinary"), ("executionPrincipal", None),
                           ("qemuPid", True), ("ordinarySessionId", 0), ("ordinarySid", "S-1-5-18"),
                           ("workspace", r"C:\ProgramData\..\Windows"),
                           ("credentialPath", "/private/../credential"),
                           ("guestBootTime", "unknown")):
            with self.subTest(context=key, value=value):
                sample = program(); sample["targetContext"][key] = value
                with self.assertRaises(ValueError):
                    owner.validate(sample)
        for scope in ("program", "context"):
            sample = program()
            (sample if scope == "program" else sample["targetContext"])["ready"] = True
            with self.assertRaises(ValueError):
                owner.validate(sample)
        sample = program(); del sample["targetContext"]["executionPrincipal"]
        with self.assertRaises(ValueError):
            owner.validate(sample)

    def test_windows_argv_uses_list2cmdline_and_utf16_with_nul(self):
        argv = [owner.POWERSHELL, "space quote\"", "Ж😀", "trailing\\"]
        _, observed = owner.command_bounds(argv[0], argv[1:])
        rendered = subprocess.list2cmdline(argv).encode("utf-16le")
        self.assertEqual(observed["commandUtf16UnitsIncludingNul"], len(rendered) // 2 + 1)
        self.assertEqual(observed["commandSha256Utf16le"], hashlib.sha256(rendered).hexdigest())
        with self.assertRaisesRegex(ValueError, "command_chars"):
            owner.command_bounds("p", ["😀" * 16383])
        _, maximum = owner.command_bounds("p", ["x" * 32764])
        self.assertEqual(maximum["commandUtf16UnitsIncludingNul"], 32767)
        with self.assertRaisesRegex(ValueError, "command_chars"):
            owner.command_bounds("p", ["x" * 32765])

    def test_complete_json_outer_bound_is_independent_from_windows_limit(self):
        # Short argv can still exceed the outer budget after exact input-data
        # serialization; no fallback can turn this into launch authorization.
        with self.assertRaisesRegex(ValueError, "transport_bytes"):
            owner.command_bounds("p", ["x" * 20000], b"x" * 32768)
        with self.assertRaisesRegex(ValueError, "input_bound"):
            owner.command_bounds("p", [], b"x" * 32769)
        for path, args in (("p\0", []), ("p", ["x\0"]), ("p", [1])):
            with self.assertRaisesRegex(ValueError, "windows_argv"):
                owner.command_bounds(path, args)

    def test_render_rejects_provider_escape_encoding_and_source_bounds(self):
        sample = program(); context = sample["targetContext"]
        arguments = dict(path=context["workspace"] + "\\program-" + OPERATION + ".ps1",
                         workspace=context["workspace"], ordinary_sid=SID, phase_id=OPERATION)
        raw = b"\xef\xbb\xbf" + sample["source"].encode()
        for changed in (b"source", b"\xef\xbb\xbf\xff", b"\xef\xbb\xbf" + b"x" * 32768):
            with self.assertRaises((ValueError, UnicodeError)):
                owner.render_bootstrap(changed, **arguments)
        for path in (context["workspace"] + "\\..\\escape.ps1", context["workspace"] + "\\source.ps1:ads",
                     context["workspace"] + "\\source'quote.ps1", r"C:\Windows\source.ps1"):
            with self.assertRaisesRegex(ValueError, "source_path"):
                owner.render_bootstrap(raw, **{**arguments, "path": path})


if __name__ == "__main__":
    unittest.main()
