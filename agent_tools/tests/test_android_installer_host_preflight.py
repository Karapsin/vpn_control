"""Exercise the actual source factory without retaining private native proofs.

The renderer test replaces ONLY the two original-admission checksum roots with
the digest of an explicitly owned synthetic proof. Every actual reader/function
body, complete consumed bundle module and generated import namespace is retained.
The native Linux root/proc/effect-plane scenario is a separate required gate.
"""
import ast
import base64
import hashlib
import json
from pathlib import Path
import types
import unittest

from agent_tools import android_component_successor as successor

FIXTURES = Path(__file__).parent / "fixtures/android_component_successor"
ORIGINAL = "0dd55704-1e80-4d62-8d9d-2f0a123e0c3b"
ADMISSION = "6b616c2f-6c36-4ac0-836e-4465c78bfc92"
ORIGINAL_PROOF_SHA = "93ff56ef99d2496aef690ea1ae44e0e7ff4136386e6718fa81e8f0ff21e2e6ed"


class InstallerHostPreflightTests(unittest.TestCase):
    def fixture(self):
        root = "/home/kardinal/.vpn-control-mcp-fixtures"
        parents = {"/": [1, 2, 0o40755, 0, 0], "/home": [1, 3, 0o40755, 0, 0],
                   "/home/kardinal": [1, 4, 0o40700, 1000, 1000],
                   root: [1, 5, 0o40700, 1000, 1000]}
        pin = {"principal": "historical-worker", "format": "descriptor9",
               "generation": [1, 20, 0o100600, 1000, 1000, 1, 121, 30, 30],
               "sha256": "44f2b1d325cbd0dedda6d6af5b1bf856792edf327accad99475e8cde6e4e865a"}
        proof = {"originalCorrelationId": ORIGINAL, "retirementCorrelationId": ADMISSION,
                 "worker": {"pid": 901, "startTicks": 90},
                 "fixture": {"pid": 902, "startTicks": 91},
                 "files": {"remote-lease.json": pin, "output/fixture-identity.json": dict(pin)}}
        digest = hashlib.sha256(successor._canonical(proof)).hexdigest()
        paths = {"global-admission-intent": root + "/android-installer-" + ORIGINAL + "/output/component-retained-retirement-admission-intent.json",
                 "admitted-proof": root + "/android-installer-component-baseline-" + ADMISSION + "/component-retirement-admission/component-admitted-proof.json",
                 "admitted-result": root + "/android-installer-component-baseline-" + ADMISSION + "/component-retirement-admission/component-admitted.json"}
        metadata = {}
        for role, path in paths.items():
            raw = successor._canonical(proof if role == "admitted-proof" else {"fixture": role})
            metadata[role] = {"path": path, "state": "present", "parents": parents,
                              "generation": [1, 30, 0o100600, 0, 0, 1, len(raw), 30, 30],
                              "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                              "rawBase64": base64.b64encode(raw).decode()}
        bundle = (FIXTURES / "bundle.before.source").read_bytes()
        self.assertEqual(hashlib.sha256(bundle).hexdigest(), "6d2ff26ae551d1d7c3b2b7ba7428b02fdd1e28e91beb760a4a4ee12de7738a85")
        readers = (FIXTURES / "installer-host-readers.source").read_bytes()
        provenance = json.loads((FIXTURES / "provenance.json").read_text())
        self.assertEqual(hashlib.sha256(readers).hexdigest(), provenance["installerHostReaders"]["sha256"])
        tables = {"binding": {}, "processSource": "", "boundarySource": "", "validatorSource": "",
                  "paths": [], "priorPass": []}
        original = ("COMPONENT_RELEASE_ADMITTED_PROOF=" + repr(proof) + "\n"
                    "COMPONENT_RELEASE_METADATA=" + repr(metadata) + "\n"
                    "LAUNCH=" + repr({"observation": {"bootId": "00000000-0000-4000-8000-000000000001"}}) + "\n"
                    "EFFECT_PLANE_FIXED=" + repr(tables) + "\n"
                    "CURRENT1E15_EFFECT_PLANE_FIXED=" + repr(tables) + "\n"
                    "exec(compile(" + repr(bundle) + ",'owned-bundle-fixture','exec'),{})\n" + readers.decode()).encode()
        return original, digest

    def renderer_with_fixture_trust_root(self, fixture_sha):
        path = Path(successor.__file__)
        tree = ast.parse(path.read_bytes())
        changed = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and node.value == ORIGINAL_PROOF_SHA:
                node.value = fixture_sha
                changed += 1
        self.assertEqual(changed, 2)
        ast.fix_missing_locations(tree)
        namespace = {"__file__": str(path), "__name__": "owned_host_factory_fixture"}
        exec(compile(tree, str(path), "exec"), namespace)
        return namespace["installer_host_preflight_capsule"]

    def test_actual_renderer_closes_namespace_and_refuses_unsupported_platform(self):
        source, proof_sha = self.fixture()
        render = self.renderer_with_fixture_trust_root(proof_sha)
        capsule = render(source, hashlib.sha256(source).hexdigest())
        self.assertEqual(hashlib.sha256(capsule["source"]).hexdigest(), capsule["sha256"])
        namespace = {"__name__": "owned_generated_host_guard"}
        exec(compile(capsule["source"], "owned-generated-host-guard", "exec"), namespace)
        self.assertIs(namespace["installer_host_preflight"].__globals__, namespace)
        # Explicit OS capability seam only; standard imports come from the
        # complete actual renderer, not globals supplied by the test harness.
        namespace["sys"] = types.SimpleNamespace(platform="unsupported")
        with self.assertRaisesRegex(ValueError, "installer_host_linux_root_required"):
            namespace["installer_host_preflight"]()

    def test_source_checksum_mismatch_refuses_before_generation(self):
        source, proof_sha = self.fixture()
        render = self.renderer_with_fixture_trust_root(proof_sha)
        with self.assertRaisesRegex(ValueError, "installer_host_original_source_changed"):
            render(source + b"\n", hashlib.sha256(source).hexdigest())

    def test_production_factory_does_not_accept_a_caller_authored_proof(self):
        source, _ = self.fixture()
        with self.assertRaisesRegex(ValueError, "installer_host_original_admission_changed"):
            successor.installer_host_preflight_capsule(source, hashlib.sha256(source).hexdigest())


if __name__ == "__main__":
    unittest.main()
