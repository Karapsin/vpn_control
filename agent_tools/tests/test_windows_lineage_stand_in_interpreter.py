"""Whole-before RED/GREEN for the lineage actors' stand-in executable under a world-writable interpreter.

Fast Checks run 40187427911 (ubuntu-latest) errored the unfixed
test_actual_held_binary_firmware_and_original_actors_without_any_RPC after
0.22 s. Its qemu/swtpm stand-ins ran sys.executable, the runner's CPython under
/opt/hostedtoolcache, which the runner image makes world-writable
(configure-system.sh: chmod -R 777 /opt). The generated lineage packet pins each
actor's executable with windows_vm_instance's pin, which refuses a group- or
world-writable file, so the packet returned blocked and validate_lineage
raised. The portable half runs that exact production pin; the Linux half runs
the whole before and current cases with a world-writable private copy of this
interpreter as sys.executable. No VM, QMP/QGA RPC or guest is involved.
"""
import ast,hashlib,inspect,json,os,shutil,stat,subprocess,sys,tempfile,types,unittest,uuid
from pathlib import Path
from unittest import mock

from agent_tools import windows_vm_instance as instance
from agent_tools.tests import test_readiness_windows_lifecycle as current

FIXTURES=Path(__file__).parent/'fixtures/windows_lineage_stand_in_interpreter'
BEFORE=FIXTURES/'test_readiness_windows_lifecycle.py.before.source'
PROVENANCE=FIXTURES/'provenance.json'
BEFORE_SHA256='79816d7959a2bd92970bb98417768e2e09d12c5a677405d08f0d547487be5347'
ORIGINAL='test_actual_held_binary_firmware_and_original_actors_without_any_RPC'


def production_pin():
    """The exact executable pin the lineage packet inlines from windows_vm_instance._vm_main."""
    source=inspect.getsource(instance._vm_main);function=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef))
    nodes=[n for n in function.body if isinstance(n,ast.Import)or isinstance(n,ast.FunctionDef)and n.name in('require','generation','pin')]
    scope={'held':[],'pins':[]};exec(compile(ast.Module(body=nodes,type_ignores=[]),'production instance pin','exec'),scope)
    return scope


def world_writable(path):
    path.chmod(0o777);return path


class StandInInterpreterRegression(unittest.TestCase):
    def before(self):
        provenance=json.loads(PROVENANCE.read_bytes());raw=BEFORE.read_bytes()
        self.assertEqual((BEFORE_SHA256,len(raw),False),(provenance['sourceSha256'],provenance['sourceBytes'],provenance['nativeFailureClaimed']))
        self.assertEqual(BEFORE_SHA256,hashlib.sha256(raw).hexdigest())
        self.assertEqual(current.__name__+'.CompleteWindowsLineageTests.'+ORIGINAL,provenance['originalFailureTestId'])
        module=types.ModuleType('_windows_lifecycle_before_'+uuid.uuid4().hex);module.__file__=current.__file__
        exec(compile(raw,str(BEFORE),'exec',dont_inherit=True),module.__dict__)
        return module

    def test_production_pin_refuses_world_writable_stand_in_and_admits_the_selected_one(self):
        scope=production_pin()
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve()
            for name in ('runner-tool-cache-python','system-python'):
                path=root/name;path.write_bytes(b'#!/bin/sh\nexit 0\n');path.chmod(0o755)
            runner=world_writable(root/'runner-tool-cache-python');system=root/'system-python'
            try:
                # What the unfixed stand-in is on the hosted runner: refused by the production pin.
                with self.assertRaisesRegex(ValueError,'^instance_source$'):scope['pin'](str(runner),executable=True)
                # The fixed choice skips it for the first admitted candidate, and never
                # returns an executable that the pin refuses.
                selected=current.endpoint_interpreter((str(runner),str(system)))
                self.assertEqual(str(system),selected)
                fd,digest=scope['pin'](selected,executable=True)
                self.assertEqual(hashlib.sha256(system.read_bytes()).hexdigest(),digest)
                self.assertIsNone(current.endpoint_interpreter((str(runner),str(root/'absent'))))
            finally:
                for fd in scope['held']:os.close(fd)

    @unittest.skipUnless(sys.platform=='linux','actual Linux executable generations and Unix socket FD ownership')
    def test_linux_unfixed_red_and_fixed_green_with_world_writable_interpreter(self):
        if current.endpoint_interpreter(('/usr/bin/python3',)) is None:
            self.skipTest('no admitted system interpreter for the fixed stand-in')
        unfixed=self.before()
        with tempfile.TemporaryDirectory(prefix='vc-lineage-python-',dir='/tmp') as temporary:
            # A private copy of this interpreter with the tool cache's mode.
            copy=Path(temporary)/'python3';shutil.copy2(os.path.realpath(sys.executable),copy);world_writable(copy)
            probe=subprocess.run([str(copy),'-I','-B','-c','import json,selectors,socket'],capture_output=True,timeout=20)
            if probe.returncode!=0:self.skipTest('world-writable interpreter copy cannot start: %r'%(probe.stderr[-500:],))
            with mock.patch.object(sys,'executable',str(copy)):
                old=unittest.TestResult();unfixed.CompleteWindowsLineageTests(ORIGINAL).run(old)
                new=unittest.TestResult();current.CompleteWindowsLineageTests(ORIGINAL).run(new)
        details='\n'.join(text for _,text in old.failures+old.errors+new.failures+new.errors)
        # Unfixed: the packet refuses the world-writable actor executable and the case
        # errors in validate_lineage, as in run 40187427911.
        self.assertEqual((1,0,1,0),(old.testsRun,len(old.failures),len(old.errors),len(old.skipped)),details)
        self.assertIn('windows_lifecycle_lineage_invalid',old.errors[0][1],details)
        # Fixed: the stand-in is an admitted interpreter and the whole lineage closes.
        self.assertEqual((1,0,0,0),(new.testsRun,len(new.failures),len(new.errors),len(new.skipped)),details)

    def test_retained_whole_before_and_ci_evidence_custody(self):
        provenance=json.loads(PROVENANCE.read_bytes())
        self.assertFalse(provenance['nativeFailureClaimed'])
        self.assertEqual(BEFORE_SHA256,hashlib.sha256(BEFORE.read_bytes()).hexdigest())
        event=provenance['originalFailureEvent']
        self.assertEqual(('finished','error',provenance['originalFailureTestId']),(event['event'],event['outcome'],event['publicTestId']))
        self.assertEqual(provenance['originalFailureEventSha256'],hashlib.sha256(json.dumps(event,sort_keys=True,separators=(',',':')).encode()).hexdigest())


if __name__=='__main__':unittest.main()
