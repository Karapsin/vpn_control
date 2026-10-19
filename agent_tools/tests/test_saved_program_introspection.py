"""Preserved complete-caller introspection failures and the current loader consumer.

The unregistered saved-capsule failure is historical: current program execution
accepts snapshotted source directly and never needs to inspect its classes.
Its active carrier and request-order prevention checks are recorded in metadata.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


FIXTURES = Path(__file__).with_name("fixtures") / "saved_program_introspection"
PINS = {
    "import-registration.before.source": (26191, "ec552271162155f5f331be97882321590da91a5b18823fc81b41c2a50d09bc39"),
    "import-registration.qualifier.before.source": (9130, "518901db9f3a6fefa04199f240b24ae9a12bbea29308ee1fe8dfa034520c96c3"),
    "saved-capsule.before.source": (29399, "66abcafe85a76995c71b358d61b28a2e42a5a5cf97f0c9f665e1c1ea5a416752"),
    "metadata.public.json": (2653, "77e475260759dc90a6d4b27a7aca58c2d16e2c30d11266ba13308dc3e4ebc054"),
}


def fixture(name):
    size, digest = PINS[name]
    with (FIXTURES / name).open("rb") as stream:
        raw = stream.read(size + 1)
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("saved_program_fixture_pin")
    return raw


WORKER = r'''
from pathlib import Path
import hashlib,importlib.util,inspect,json,os,shutil,sys,tempfile
repository,fixture_path,expected,mode=sys.argv[1:]
sys.path.insert(0,repository)
def deny_effect(event,args):
    if event.startswith(('subprocess.','socket.')) or event in ('os.system','os.exec','os.posix_spawn','os.fork'):
        raise AssertionError('unexpected_external_effect:'+event)
sys.addaudithook(deny_effect)
from agent_tools.source_module_loader import SourceSession
source=Path(fixture_path).read_bytes()
assert hashlib.sha256(source).hexdigest()==expected
specification={'hostRoot':'/tmp/inert-never-created','hostUser':'inert','fileName':'inert.bin','sizeBytes':1,'sha256':'0'*64,'sourceSha':'0'*40,'correlationId':'1'*32}
receipt={'path':'/tmp/inert-never-executed.py','sha256':'0'*64,'bytes':1}
dependencies=('native_review_source_closure.py','ssh_source_file_stage.py','ssh_source_file_stage_direct.py','ssh_direct_nested_channel.py','ssh_transport.py','android_qualified_cli_observation.py','ssh_source_file_gateway.source')
with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve()) as temporary:
    # Keep the original programme's unchanged parents[5] computation valid.
    root=Path(temporary)/'a/b/c/d/e'
    root.mkdir(parents=True)
    sources=root/'agent_tools'
    sources.mkdir(mode=0o700)
    for name in dependencies:
        shutil.copyfile(Path(repository)/'agent_tools'/name,sources/name)
        (sources/name).chmod(0o600)
    original=sources/'stage_before.py'
    original.write_bytes(source)
    original.chmod(0o600)
    session=None
    if mode=='current-loader':
        paths=tuple(sys.path)
        session=SourceSession(sources,'stage_before')
        module=session.module
        prefix=session.prefix
        assert sys.modules[module.__name__] is module
        # This deliberately uses stdlib inspect, independently of the current
        # loader's captured-source inspect view used inside render_gateway.
        inspected=inspect.getsource(module.HeldFile)
        assert 'class HeldFile:' in inspected
        renderer=module.render_gateway
    elif mode=='import-registration-red':
        imported=importlib.util.spec_from_file_location('private_raw_stage',original)
        module=importlib.util.module_from_spec(imported)
        assert imported.name not in sys.modules
        imported.loader.exec_module(module)
        renderer=module.render_gateway
    elif mode=='saved-capsule-red':
        namespace={'__name__':'saved_fixture_unregistered','__file__':str(original)}
        assert namespace['__name__'] not in sys.modules
        exec(compile(source,str(original),'exec'),namespace)
        renderer=namespace['render_gateway']
    else:
        raise AssertionError('unknown_mode')
    try:
        try:
            gateway=renderer(specification,receipt)
        except TypeError as error:
            if mode=='current-loader':raise
            result={'state':'RED','errorClass':type(error).__name__,'message':str(error)}
        else:
            assert mode=='current-loader'
            compile(gateway,'complete-generated-gateway','exec')
            gateway_path=root/'gateway.py'
            gateway_path.write_bytes(gateway)
            gateway_path.chmod(0o600)
            rendered={'__name__':'generated_gateway_fixture','__file__':str(gateway_path)}
            exec(compile(gateway,str(gateway_path),'exec'),rendered)
            assert rendered['SPEC']==specification and rendered['RECEIPT']==receipt
            tiny=root/'tiny-input'
            tiny.write_bytes(b'plain\x00binary\xff\n')
            tiny.chmod(0o600)
            with rendered['HeldFile'](tiny) as held:
                assert held.sha256==hashlib.sha256(tiny.read_bytes()).hexdigest()
                held.guard(rehash=True)
            assert held.fd is None
            session.guard()
            result={'state':'GREEN','actualStdlibInspect':True,'gatewayBytes':len(gateway),'generatedHeldFileGuardAndClosure':True}
    finally:
        if session is not None:session.close()
    assert original.read_bytes()==source
    if mode=='current-loader':
        assert tuple(sys.path)==paths
        assert not any(name==prefix or name.startswith(prefix+'.') for name in sys.modules)
        assert session.finder not in sys.meta_path
        result['currentNamespaceClosed']=True
    result.update(sourceSha256=expected,externalEffects=0,nativeClaim=False)
    print(json.dumps(result,sort_keys=True))
'''


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "requires POSIX source custody")
class SavedProgramIntrospectionTests(unittest.TestCase):
    def control(self, name, mode):
        raw = fixture(name)
        repository = Path(__file__).resolve().parents[2]
        value = subprocess.run(
            [sys.executable, "-I", "-B", "-c", WORKER, str(repository),
             str(FIXTURES / name), hashlib.sha256(raw).hexdigest(), mode],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=15,
        )
        self.assertEqual(0, value.returncode, value.stderr.decode("utf-8", "replace"))
        self.assertFalse(value.stderr)
        self.assertLess(len(value.stdout), 4096)
        result = json.loads(value.stdout)
        self.assertEqual(0, result["externalEffects"])
        self.assertIs(result["nativeClaim"], False)
        return result

    def test_original_import_registration_failure_reaches_real_class_inspection(self):
        qualifier = fixture("import-registration.qualifier.before.source").decode()
        self.assertIn("module_from_spec(spec)", qualifier)
        self.assertNotIn("sys.modules[spec.name]", qualifier)
        result = self.control("import-registration.before.source", "import-registration-red")
        self.assertEqual("RED", result["state"])
        self.assertEqual("TypeError", result["errorClass"])
        self.assertEqual("<class 'private_raw_stage.HeldFile'> is a built-in class", result["message"])

    def test_current_source_session_inspects_and_generates_complete_original_gateway(self):
        result = self.control("import-registration.before.source", "current-loader")
        self.assertEqual("GREEN", result["state"])
        self.assertIs(result["actualStdlibInspect"], True)
        self.assertGreater(result["gatewayBytes"], 20000)
        self.assertIs(result["generatedHeldFileGuardAndClosure"], True)
        self.assertIs(result["currentNamespaceClosed"], True)

    def test_original_unregistered_saved_capsule_failure_remains_contextual_red(self):
        result = self.control("saved-capsule.before.source", "saved-capsule-red")
        self.assertEqual("RED", result["state"])
        self.assertEqual("TypeError", result["errorClass"])
        self.assertEqual("<class 'saved_fixture_unregistered.HeldFile'> is a built-in class", result["message"])
        metadata = json.loads(fixture("metadata.public.json"))
        self.assertIs(metadata["nativeClaim"], False)
        self.assertIs(metadata["hostSubmitted"], False)
        self.assertIs(metadata["containsCredentialValues"], False)
        self.assertIs(metadata["rawTracebackExported"], False)
        self.assertIn("test_ssh_program_execution", metadata["B"]["greenConsumer"])
        self.assertIn("test_ssh_program_execution", metadata["C"]["greenConsumer"])


if __name__ == "__main__":
    unittest.main()
