"""One lexical whole-caller pair using the retained QGA/native-I/O peers.

Only the authenticated IntakeReply peer class is extracted from its qualifier.
Both callers execute complete, unmodified Python-c namespaces. The existing
lost-ACK control retains the original wire and namespace until inert cleanup.
"""
import ast
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import uuid

HERE = Path(__file__).resolve().parent
BEFORE_SHA = "495b28e31c71faba29e31cc61bd57c869f88f72cf5b1c32c7d102d6cdceddbc6"
AFTER_SHA = "aa3b9c6d1928829a8bb703f1a9369c10a153cc43f42be4af999d7625122f6b7c"
sha = lambda raw: hashlib.sha256(raw).hexdigest()


def _positive(receipt, world):
    assert receipt["error"] is None, receipt["originalFailure"]
    value = json.loads(receipt["stdout"])
    assert value["query"] == "initial-system-intake"
    assert len(value["result"]["filePins"]) == 4 and len(value["result"]["directoryPins"]) == 9
    assert value["sourceClosing"] and not receipt["retainedOriginalHostDescriptors"]
    assert len(world.executions) == 1
    assert not any(row["command"].startswith("guest-file-") for row in world.rpc)
    return value


def run_lexical_pair(before, after, output_root):
    assert sha(before) == BEFORE_SHA and sha(after) == AFTER_SHA
    provenance = json.loads((HERE.parent / "system_intake_caller/provenance.json").read_bytes())
    originals = {}
    for relative, pin in provenance["fixturePins"].items():
        raw = (HERE / relative).read_bytes()
        assert len(raw) == pin["bytes"] and sha(raw) == pin["sha256"]
        originals[relative] = raw
    assert originals["caller.before.source"] == before
    qualifier = originals["qualifier.before.source"].decode()
    tree = ast.parse(qualifier)
    peer_class = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "IntakeReply")
    peer_class_source = ast.get_source_segment(qualifier, peer_class)
    aliases = ("harness", "_bf05_whole_protocol_boundary", "_bf05_whole_producer_boundary")
    missing = object()
    prior_aliases = {name: sys.modules.get(name, missing) for name in aliases}
    prior_path = list(sys.path)
    prior_modules = dict(sys.modules)
    common_name = "_system_intake_lexical_common_" + uuid.uuid4().hex
    results = {}
    own_modules = {common_name}
    try:
        # Force the exact sibling harness instead of accepting an unrelated cache.
        sys.modules.pop("harness", None)
        common_path = HERE / "private/post-program-adoption-prerequisite-preparation-v1/qualification/qualify_current.py"
        spec = importlib.util.spec_from_file_location(common_name, common_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[common_name] = module
        spec.loader.exec_module(module)
        # This caller never streams an artifact. Declare no physical transfer
        # assets in its retained peer; logical host/receipt data remain intact.
        module.peer.LOCAL_ARTIFACTS = {}
        globals()["common"] = module
        exec(compile(peer_class_source, str(HERE / "qualifier.before.source"), "exec"), globals(), globals())

        class World(module.BoundaryMixin, IntakeReply):
            pass

        declarations = module.peer.literals(before.decode())
        assert declarations["QGA_MODULE_SHA"] == sha(declarations["QGA_MODULE_SOURCE"]) == "bf05c8f08c1e5210ba79ffb59186206e80dc13fef057748dab3596df8ab6f022"
        assert declarations["EMITTER_SHA256"] == sha(declarations["EMITTER_SOURCE"]) == "2938a7c6c25d23adc9683ced126fe2d3c0a88614dab59a7b134a624d6f8b0ee8"
        for label, source, mode in (("before", before, None), ("after", after, None), ("unknown", after, "deadline")):
            destination = output_root / label
            destination.mkdir(mode=0o700)
            caller = destination / "whole-caller.source"
            caller.write_bytes(source)
            world = World(declarations, destination, fault="python-c", seed_endpoint_receipt=False)
            world.prepare(mode, "guest-exec")
            decoder_calls = {}

            def profile(frame, event, arg):
                name = frame.f_globals.get("__name__", "")
                if event == "call" and name.startswith(("_initial_system_intake_decoder_", "_private_initial_system_emitter_")):
                    registered = sys.modules.get(name)
                    assert registered is not None and registered.__dict__ is frame.f_globals
                    own_modules.add(name)
                    if name.startswith("_initial_system_intake_decoder_"):
                        decoder_calls[frame.f_code.co_name] = decoder_calls.get(frame.f_code.co_name, 0) + 1

            prior_profile = sys.getprofile()
            try:
                sys.setprofile(profile)
                receipt = module.peer.execute(caller, world, "whole-namespace")
                sys.setprofile(prior_profile)
                assert receipt["initialGlobals"] == ["__name__", "__builtins__"] and receipt["pythonCWithoutFile"]
                assert receipt["sourceUnmodified"] and not receipt["partialNamespaceExecution"]
                assert receipt["canonicalQgaRegistered"] and receipt["canonicalModuleRegistered"]
                assert not receipt["postExecFunctionReplacement"]
                assert world.physical_source is None and world.read_bytes == 0
                if label in ("before", "after"):
                    try:
                        value = _positive(receipt, world)
                    except AssertionError as positive_failure:
                        assert label == "before", receipt["originalFailure"]
                        assert receipt["originalFailure"]["class"] == "AttributeError"
                        assert "has no attribute '__name__not'" in receipt["originalFailure"]["message"]
                        assert len(world.executions) == 0 and not decoder_calls
                        assert not any(row["command"] == "guest-exec" for row in world.rpc)
                        receipt["samePositiveOraclePassed"] = False
                        receipt["actualPositiveAssertion"] = str(positive_failure)
                    else:
                        assert label == "after"
                        assert decoder_calls.get("<module>") == 1 and decoder_calls.get("decode_result") == 1
                        receipt["samePositiveOraclePassed"] = True
                else:
                    assert receipt["originalFailure"]["class"] == "ValueError"
                    assert "retained_rpc_deadline" in receipt["originalFailure"]["message"]
                    assert len(world.executions) == 1 and len(world.park_snapshots) == 3
                    assert receipt["retainedOriginalHostDescriptors"]
                    assert receipt["outboundFrames"] == receipt["outboundFramesAtUnknown"]
                    assert not any(row["command"] == "guest-exec-status" for row in world.rpc)
                receipt["decoderRegisteredWholeModuleCalls"] = decoder_calls
                receipt["guestExecCount"] = len(world.executions)
                receipt["declaredNativeIoPeerOnly"] = True
                receipt["nativeOrNetworkActions"] = False
                results[label] = receipt
                (destination / "causal-receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
            finally:
                sys.setprofile(prior_profile)
                for name, candidate in list(sys.modules.items()):
                    origin = getattr(candidate, "__file__", "")
                    if name not in prior_modules and isinstance(origin, str) and origin.startswith(declarations["SPEC"]["root"] + "/"):
                        own_modules.add(name)
                world.harness_cleanup()
                assert not world.fds and world.guest_file.closed
        assert all((HERE / relative).read_bytes() == raw for relative, raw in originals.items())
    finally:
        sys.path[:] = prior_path
        for name in own_modules:
            if name in prior_modules:
                sys.modules[name] = prior_modules[name]
            else:
                sys.modules.pop(name, None)
        for name, prior in prior_aliases.items():
            if prior is missing:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = prior
        assert all(sys.modules.get(name, missing) is prior for name, prior in prior_aliases.items())
        assert not any(name not in prior_modules and name.startswith(("_initial_system_intake_decoder_", "_private_initial_system_emitter_"))
                       for name in sys.modules)
    return dict(before=results["before"], after=results["after"], unknown=results["unknown"],
                samePositiveOracle=True, authenticQualifierPeerClassUnchanged=True,
                allOriginalFixtureBytesUnchanged=True, moduleAliasesAndImportPathRestored=True,
                nativeOrNetworkActions=False)
