"""Actual bounded private pipes project public facts before hashing or storage."""
import hashlib
import inspect
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

from agent_tools import ssh_tmux_mcp_adapter as adapter
from agent_tools import ssh_tmux_privileged_terminal_closure as privileged
from agent_tools import ssh_tmux_resource_admission as resources

FIXTURE=Path(__file__).parent/'fixtures/tmux_private_reply_projection'


@unittest.skipUnless(os.name=='posix','actual nonblocking private pipes')
class PrivateReplyTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.root.chmod(0o700)
        self.secret=secrets.token_hex(32).encode();self.prefix=self.secret[:12]
        self.authority={'phase':'status','snapshot':None,'sources':{},'transport':{},'local':{},'argvSha256':'a'*64}

    def before(self):
        path=FIXTURE/'ssh_tmux_mcp_adapter.before.source';raw=path.read_bytes()
        pin=json.loads((FIXTURE/'provenance.json').read_bytes())['files'][path.name]
        self.assertEqual(pin,{'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)})
        module=types.ModuleType('agent_tools._private_reply_before');module.__package__='agent_tools';module.__file__=str(path)
        exec(compile(raw,str(path),'exec'),module.__dict__);return module

    def capture(self,module,body,*,timeout=3):
        source='import json,sys,time\nv=sys.stdin.buffer.readline().strip()\nsys.stdin.buffer.read()\n'+body
        kwargs={'public_reply':privileged.validate_carrier_diagnostic} if module is adapter else {}
        result,path=module._capture(self.root,authority=self.authority,
            launch=lambda:subprocess.Popen([sys.executable,'-I','-B','-c',source],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE),
            payload=self.secret+b'\n{}',guard=lambda:None,timeout_seconds=timeout,private_payload=True,**kwargs)
        return result,path,json.loads((path/'receipt.json').read_bytes())

    def test_complete_before_valid_json_echo_is_retained_and_hashed_red(self):
        digest=hashlib.sha256;seen=[]
        def observed(raw=b'',*args,**kwargs):
            if self.prefix in raw:seen.append(True)
            return digest(raw,*args,**kwargs)
        with mock.patch.object(hashlib,'sha256',side_effect=observed):
            result,path,_=self.capture(self.before(),"print(json.dumps({'unexpected':v[:12].decode()}))")
        self.assertEqual('captured',result['state']);self.assertIn(self.prefix,(path/'stdout').read_bytes());self.assertTrue(seen)

    def test_valid_json_nested_escaped_duplicate_and_partial_echo_never_retained_green(self):
        cases=["print(json.dumps({'unexpected':v[:12].decode()}))",
               "print(json.dumps({'unexpected':{'nested':[v[:12].decode()]}}))",
               "print('{\"unexpected\":\"'+''.join('\\\\u%04x'%x for x in v[:12])+'\"}')",
               "print('{\"state\":\"a\",\"state\":'+json.dumps(v[:12].decode())+'}')",
               "print(json.dumps({'state':v[:12].decode()}))",
               "sys.stdout.buffer.write(v[:12]);sys.stdout.flush()",
               "print('{}');sys.stderr.buffer.write(v[:12])",
               "sys.stdout.buffer.write(v[:12]);sys.stdout.flush();time.sleep(2)",
               "sys.stdout.buffer.write(b'X'*2200000)"]
        digest=hashlib.sha256
        def guarded(raw=b'',*args,**kwargs):
            self.assertNotIn(self.prefix,raw,'private reply reached a digest')
            return digest(raw,*args,**kwargs)
        for index,body in enumerate(cases):
            with self.subTest(index=index),mock.patch.object(hashlib,'sha256',side_effect=guarded):
                result,path,receipt=self.capture(adapter,body,timeout=.1 if 'sleep' in body else 3)
            self.assertEqual('unknown',result['state']);self.assertIsNotNone(receipt['failure'])
            self.assertEqual(b'',(path/'stdout').read_bytes());self.assertEqual(b'',(path/'stderr').read_bytes())
            for file in path.iterdir():self.assertNotIn(self.prefix,file.read_bytes())
            self.assertNotIn('stdinBytesWritten',receipt)
            intent=json.loads((path/'intent.json').read_bytes());self.assertNotIn('payloadBytes',intent);self.assertNotIn('payloadSha256',intent)

    def test_fixed_public_validator_retains_canonical_facts_only(self):
        value={'state':'root-census-failed','correlationId':privileged.CORRELATION,'phase':'root-child-unknown','childExit':1,'errno':None,'workspaceProof':False,'nativeActionAllowed':False,'replayAllowed':False}
        result,path,receipt=self.capture(adapter,'print('+repr(json.dumps(value))+')')
        self.assertEqual('captured',result['state']);self.assertEqual(adapter.session.canonical(value),(path/'stdout').read_bytes())
        self.assertIs(True,receipt['privateInputComplete']);self.assertNotIn('stdinBytesWritten',receipt)

    def test_missing_public_validator_stops_before_launch_or_journal(self):
        launch=mock.Mock()
        with mock.patch.object(adapter,'_capsule') as capsule:
            with self.assertRaisesRegex(ValueError,'capture_private_reply_validator_required'):
                adapter._capture(self.root,authority=self.authority,launch=launch,payload=self.secret,guard=lambda:None,private_payload=True)
            capsule.assert_not_called();launch.assert_not_called()

    def test_both_real_private_callers_supply_closed_validators(self):
        self.assertIn('public_reply=validator',inspect.getsource(privileged._observe))
        self.assertIn('public_reply=_public_resource_reply',inspect.getsource(resources.fixed_resource_query))
        from agent_tools.tests.test_ssh_tmux_resource_admission import ResourceTests
        fixture=ResourceTests('runTest');fixture.setUp();self.addCleanup(fixture.doCleanups)
        value=fixture.host();self.assertIs(value,resources._public_resource_reply(value))
        for mutate in (lambda v:v.update(extra=self.prefix.decode()),
                       lambda v:v['samples'][0]['vmstat'].update(extra=self.prefix.decode()),
                       lambda v:v['samples'][0].update(psi=self.prefix.decode()),
                       lambda v:v['samples'][0].update(availableMemoryBytes=self.prefix.decode())):
            value=fixture.host();mutate(value)
            with self.assertRaises((ValueError,TypeError)):resources._public_resource_reply(value)


if __name__=='__main__':unittest.main()
