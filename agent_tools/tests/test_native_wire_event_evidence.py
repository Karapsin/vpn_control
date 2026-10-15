"""Causal controls for explicit wire-event evidence admission.

Synthetic fixed evidence has no dependency on a native attempt. Tests never
start processes or contact SSH/VMs. The preserved collector reads only temporary
synthetic files.
"""
from __future__ import annotations

import copy
import fnmatch
import hashlib
import json
from pathlib import Path
import unittest

from agent_tools.tests import native_wire_event_evidence as subject


FIXTURE = Path(__file__).with_name("fixtures") / "native_wire_event_evidence"


def synthetic_trace():
    kinds = ("stage", "execute", "verify")
    codes = {kind: hashlib.sha256(("PUBLIC_CODE_" + kind).encode()).hexdigest() for kind in kinds}
    context = {
        "expected_qualification_id": "12345678-1234-4123-8123-123456789abc",
        "expected_correlation": "0123456789abcdef0123456789abcdef",
        "current_uid": 1900, "expected_code_sha256": codes,
        "expected_pids": {"stage": 4101, "execute": 4102, "verify": 4103},
        "expected_parent_pid": 4000, "expected_carrier_bytes": 70001,
        "expected_carrier_sha256": hashlib.sha256(b"PUBLIC_CARRIER").hexdigest(),
        "expected_argv": ["PUBLIC argument", "Ω ' quote"], "expected_principal": "fixture-user",
    }
    authority = {
        "qualificationId": context["expected_qualification_id"],
        "automaticCorrelation": context["expected_correlation"],
        "allowedCodeSha256": dict(codes), "carrierBytes": context["expected_carrier_bytes"],
        "carrierSha256": context["expected_carrier_sha256"],
        "expectedArgv": list(context["expected_argv"]), "expectedPrincipal": context["expected_principal"],
    }
    events = {}
    for index, kind in enumerate(kinds, 1):
        name = "wire-" + format(index, "032x") + ".json"
        events[name] = {
            "argvSha256": hashlib.sha256(("PUBLIC_ARGV_" + kind).encode()).hexdigest(),
            "automaticCorrelation": context["expected_correlation"],
            "commandBytes": 12000 + index, "controlMaster": False, "forwarding": False,
            "freshOneShot": True, "kind": kind, "localUid": context["current_uid"],
            "maxArgumentBytes": 11000 + index, "parentPid": context["expected_parent_pid"],
            "pid": context["expected_pids"][kind], "qualificationId": context["expected_qualification_id"],
            "remoteCarrierCodeSha256": codes[kind], "replayAllowed": False, "sshExecutable": "/usr/bin/ssh",
        }
    return authority, events, context


class _SyntheticEntry:
    def __init__(self, name, body):
        self.name, self.body = name, body

    def __lt__(self, other):
        return self.name < other.name

    def read_bytes(self):
        return self.body


class _SyntheticRun:
    entry_type = _SyntheticEntry

    def __init__(self, bodies):
        self.entries = {name: self.entry_type(name, body) for name, body in bodies.items()}

    def glob(self, pattern):
        return [entry for name, entry in self.entries.items() if fnmatch.fnmatchcase(name, pattern)]


class _SyntheticPins:
    def __init__(self, run):
        self.run = run

    def read(self, path, expected, mode):
        # This fixture models the caller's declared IO contract. Native source
        # custody is tested separately with the platform's real file handles.
        if (type(mode) is not int or mode != 0o600
                or self.run.entries.get(path.name) is not path
                or hashlib.sha256(path.read_bytes()).hexdigest() != expected):
            raise AssertionError("Synthetic source pin changed")


def original_collector(authority, events, *, _run_factory=_SyntheticRun, **_context):
    """Execute the exact owner fragment on explicit in-memory synthetic entries."""
    raw = (FIXTURE / "original_collector.before.fragment").read_bytes()
    provenance = json.loads((FIXTURE / "provenance.json").read_bytes())
    if hashlib.sha256(raw).hexdigest() != provenance["fragmentSha256"]:
        raise AssertionError("Preserved original collector changed")
    namespace = {"json": json, "sha": lambda value: hashlib.sha256(value).hexdigest()}
    source = "def collect(run,pins):\n" + raw.decode() + "        return wire\n"
    exec(compile(source, str(FIXTURE / "original_collector.before.fragment"), "exec"), namespace)
    bodies = {name: json.dumps(value, sort_keys=True).encode()
              for name, value in {**events, "wire-authority.private.json": authority}.items()}
    run = _run_factory(bodies)
    wire = namespace["collect"](run, _SyntheticPins(run))
    return {"state": "validated", "eventCount": len(wire), "wireRecords": wire, "replayAllowed": False}


class NativeWireEventEvidenceTests(unittest.TestCase):
    collector = staticmethod(subject.validate_wire_evidence)

    def assert_trace_accepted(self, collector):
        authority, events, context = synthetic_trace()
        result = collector(authority, events, **context)
        self.assertEqual("validated", result["state"])
        self.assertEqual(3, result["eventCount"])
        self.assertEqual(["stage", "execute", "verify"], [event["kind"] for event in result["wireRecords"]])
        self.assertIs(False, result["replayAllowed"])
        return result

    def test_explicit_trace_survives_authority_filename_collision(self):
        self.assert_trace_accepted(self.collector)

    def test_exact_preserved_collector_demonstrates_authority_collision(self):
        with self.assertRaisesRegex(ValueError, "actual_wire_command_admission_mismatch"):
            self.assert_trace_accepted(original_collector)
        stat_calls = []
        class WindowsEntry(_SyntheticEntry):
            def stat(self):
                stat_calls.append(self.name)
                return type("WritableWindowsMode", (), {"st_mode": 0o100666})()
        class WindowsRun(_SyntheticRun):
            entry_type = WindowsEntry
        def windows_collector(authority, events, **context):
            return original_collector(authority, events, _run_factory=WindowsRun, **context)
        with self.assertRaisesRegex(ValueError, "actual_wire_command_admission_mismatch"):
            self.assert_trace_accepted(windows_collector)
        self.assertEqual([], stat_calls)
        run = WindowsRun({"wire-" + "1" * 32 + ".json": b"PUBLIC_SYNTHETIC_SOURCE"})
        entry = next(iter(run.entries.values())); pins = _SyntheticPins(run)
        digest = hashlib.sha256(entry.read_bytes()).hexdigest()
        pins.read(entry, digest, 0o600)
        for mode in (0o400, 0o666, True):
            with self.subTest(requested_mode=mode), self.assertRaises(AssertionError):
                pins.read(entry, digest, mode)
        with self.assertRaises(AssertionError):
            pins.read(entry, "0" * 64, 0o600)
        self.assertEqual([], stat_calls)

    def test_authority_never_becomes_an_event_name_or_an_extra_event(self):
        for replace_one in (False, True):
            authority, events, context = synthetic_trace()
            if replace_one:
                events.pop(next(iter(events)))
            events["wire-authority.private.json"] = authority
            with self.subTest(replace_one=replace_one), self.assertRaises(subject.WireEvidenceError):
                subject.validate_wire_evidence(authority, events, **context)

    def test_event_filename_and_exact_schemas_refuse_tampering(self):
        cases = ("wrong-name", "uppercase-id", "extra-field", "missing-field", "not-object")
        for case in cases:
            authority, events, context = synthetic_trace()
            name = next(iter(events))
            if case == "wrong-name":
                events["wire-../event.json"] = events.pop(name)
            elif case == "uppercase-id":
                events["wire-" + "A" * 32 + ".json"] = events.pop(name)
            elif case == "extra-field":
                events[name]["approval"] = True
            elif case == "missing-field":
                events[name].pop("parentPid")
            else:
                events[name] = []
            with self.subTest(case=case), self.assertRaises(subject.WireEvidenceError):
                subject.validate_wire_evidence(authority, events, **context)

    def test_identity_pid_uid_code_and_safety_tampering_refuse(self):
        changes = {
            "qualificationId": "87654321-4321-4321-8321-cba987654321",
            "automaticCorrelation": "f" * 32, "kind": "unexpected", "localUid": True,
            "parentPid": 4999, "pid": 4102, "remoteCarrierCodeSha256": "0" * 64,
            "argvSha256": "A" * 64, "sshExecutable": "ssh", "freshOneShot": 1,
            "controlMaster": 0, "forwarding": True, "replayAllowed": True,
        }
        for field, value in changes.items():
            authority, events, context = synthetic_trace()
            events[next(iter(events))][field] = value
            with self.subTest(field=field), self.assertRaises(subject.WireEvidenceError):
                subject.validate_wire_evidence(authority, events, **context)

    def test_command_size_bound_uses_positive_integers_and_includes_60000(self):
        for field in ("commandBytes", "maxArgumentBytes"):
            for value in (False, 0, -1, 60001, 1.0, "60000"):
                authority, events, context = synthetic_trace()
                events[next(iter(events))][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(subject.WireEvidenceError):
                    subject.validate_wire_evidence(authority, events, **context)
        authority, events, context = synthetic_trace()
        for event in events.values():
            event["commandBytes"] = 60000
            event["maxArgumentBytes"] = 60000
        self.assertEqual(3, subject.validate_wire_evidence(authority, events, **context)["eventCount"])

    def test_duplicate_kinds_or_process_identity_refuse(self):
        for field in ("kind", "pid"):
            authority, events, context = synthetic_trace()
            first, second, _ = events.values()
            second[field] = first[field]
            with self.subTest(field=field), self.assertRaises(subject.WireEvidenceError):
                subject.validate_wire_evidence(authority, events, **context)

    def test_authority_and_explicit_expected_context_refuse_tampering(self):
        cases = ("authority-extra", "authority-missing", "authority-carrier", "authority-argv",
                 "authority-principal", "authority-code", "expected-parent", "expected-pids", "expected-codes")
        for case in cases:
            authority, events, context = synthetic_trace()
            if case == "authority-extra": authority["kind"] = "stage"
            elif case == "authority-missing": authority.pop("expectedPrincipal")
            elif case == "authority-carrier": authority["carrierBytes"] += 1
            elif case == "authority-argv": authority["expectedArgv"].append("changed")
            elif case == "authority-principal": authority["expectedPrincipal"] = "another-user"
            elif case == "authority-code": authority["allowedCodeSha256"]["stage"] = "0" * 64
            elif case == "expected-parent": context["expected_parent_pid"] = True
            elif case == "expected-pids": context["expected_pids"]["verify"] = context["expected_pids"]["stage"]
            else: context["expected_code_sha256"].pop("verify")
            with self.subTest(case=case), self.assertRaises(subject.WireEvidenceError):
                subject.validate_wire_evidence(authority, events, **context)

    def test_result_does_not_expose_mutable_input_aliases(self):
        authority, events, context = synthetic_trace()
        original = copy.deepcopy(events)
        result = subject.validate_wire_evidence(authority, events, **context)
        result["wireRecords"][0]["kind"] = "changed"
        result["eventNames"]["stage"] = "changed"
        self.assertEqual(original, events)


if __name__ == "__main__":
    unittest.main()
