"""Actual complete phase.program fork/provider dispatch against kernel QMP/QGA."""
import ast
import base64
import zlib
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import types
import unittest
from uuid import uuid4
from unittest import mock
from agent_tools import readiness_windows_display_phase as phase,readiness_windows_login as login,readiness_windows_login_continuation as continuation

FIXTURE=Path(__file__).parent/'fixtures/windows_display_phase'
BEFORE=Path(__file__).parent/'fixtures/windows_display_phase_effect_self'
COMPLETE_EVIDENCE=[]


def before_module():
    raw=(BEFORE/'before.source').read_bytes();provenance=json.loads((BEFORE/'provenance.json').read_bytes())
    if hashlib.sha256(raw).hexdigest()!=provenance['sourceSha256']:raise ValueError('display_phase_before_changed')
    module=types.ModuleType('agent_tools._display_phase_before');module.__package__='agent_tools';module.__file__=str(BEFORE/'before.source');sys.modules[module.__name__]=module
    exec(compile(raw,module.__file__,'exec'),module.__dict__);return module


@unittest.skipUnless(sys.platform.startswith('linux'),'actual QMP/QGA process/socket/FD fixture')
class CompleteDisplayPhase(unittest.TestCase):
    def incident(self,producer):
        from agent_tools.tests import test_readiness_windows_sockets as sockets
        fixture=sockets.CompleteWindowsSocketTests('test_healthy_background_and_interactive_observation_no_unnecessary_recovery')
        self.addCleanup(fixture.doCleanups)
        locked=sockets.facts();locked['session']['Flags']=0
        with mock.patch.object(sockets,'ENDPOINT',FIXTURE/'endpoint.py'),mock.patch.object(sockets,'facts',lambda:locked):fixture.setUp()
        root=fixture.root
        seed=login.program(fixture.binding,'login-probe',str(uuid4()),expected_sid=locked['expectedSid'],profile={},expected={})
        declared={}
        for node in ast.parse(seed).body:
            if isinstance(node,ast.Assign)and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)and node.targets[0].id in {'SESSION_SCRIPT','LOGIN_ACCOUNT_SCRIPT'}:declared[node.targets[0].id]=ast.literal_eval(node.value)
        getter_sources={'session':declared['SESSION_SCRIPT'],'account':declared['LOGIN_ACCOUNT_SCRIPT'],'combined':phase.observation_source(fixture.binding)}
        getter_path=root/'getter-sources.json';getter_path.write_text(json.dumps(getter_sources));getter_path.chmod(0o600)
        before=fixture.run_packet();expected={k:before[k]for k in ('actor','hostBoot','controlConnection')};session=before['sessionFacts'];expected.update(boot=session['boot'],console=session['console'],logon=session['session']['Logon'],user=session['session']['User'])
        operation=str(uuid4());sid=session['expectedSid'];profile={'width':320,'height':200,'crops':[{'rect':[0,0,1,1],'sha256':hashlib.sha256(b'AAA').hexdigest()}]}
        original=login.program(fixture.binding,'login-submit',operation,expected_sid=sid,profile=profile,expected=expected)
        original_path=root/'original-public-producer.py';original_path.write_bytes(original);original_sha=hashlib.sha256(original).hexdigest()
        # Harmless fixture marker is framed stdin, never generated source. This
        # complete canonical original MUST stop at its native screenshot gate.
        result=subprocess.run([sys.executable,'-I','-B',str(original_path),original_sha,original_sha,'30','{}'],input=b'\0\0\0\3A!9',capture_output=True,timeout=35)
        self.assertEqual(0,result.returncode,result.stderr);rejected=json.loads(result.stdout);self.assertEqual('instance_login_screen_unrecognized',rejected['reason']);self.assertEqual(0,json.loads((root/'counters.json').read_bytes())['inputCount'])
        identity={'operationId':operation,'binding':fixture.binding,'expectedSid':sid,'profile':profile,'expected':expected};native_identity={'expected':expected,'profile':profile,'account':sid,'machine':fixture.machine,'hostBoot':fixture.binding['context']['hostBootId'],'user':'recovery'}
        import fcntl
        lock=os.open(root/'intent.json',os.O_RDONLY|os.O_NOFOLLOW)
        try:
            fcntl.flock(lock,fcntl.LOCK_EX)
            catalog=next(ast.literal_eval(n.value)for n in ast.parse(original).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='LOGIN_PUBLIC_REASONS'for t in n.targets))
            with mock.patch.object(login,'LOGIN_PUBLIC_REASONS',catalog,create=True):barrier=continuation._original_phase(root,operation,native_identity,original_sha,lock)
        finally:os.close(lock)
        original_terminal=(root/('login-owner-'+operation+'.terminal.json')).read_bytes()
        source=producer.program(continuation._AuthenticatedOriginal(original,identity,lambda:None),barrier,budget_seconds=30)
        path=root/'phase-complete.py';path.write_bytes(source)
        result=subprocess.run([sys.executable,'-I','-B',str(path),'start'],stdin=subprocess.DEVNULL,capture_output=True,timeout=35)
        self.assertEqual(0,result.returncode,result.stderr);value=json.loads(result.stdout);counts=json.loads((root/'counters.json').read_bytes())
        self.assertEqual(original_terminal,(root/('login-owner-'+operation+'.terminal.json')).read_bytes());self.assertFalse((root/('login-credential-'+operation+'.intent.json')).exists())
        status=subprocess.run([sys.executable,'-I','-B',str(path),'status'],stdin=subprocess.DEVNULL,capture_output=True,timeout=5);self.assertEqual(0,status.returncode,status.stderr);self.assertEqual(value,json.loads(status.stdout));self.assertEqual(counts,json.loads((root/'counters.json').read_bytes()))
        COMPLETE_EVIDENCE.append({'producer':'before'if producer is not phase else'current','originalOperationId':operation,'phaseOperationId':phase.relation(operation)['operationId'],'originalCallerSha256':original_sha,'phaseCallerSha256':hashlib.sha256(source).hexdigest(),'phaseCallerZlibBase64':base64.b64encode(zlib.compress(source)).decode(),'originalCallerZlibBase64':base64.b64encode(zlib.compress(original)).decode(),'result':value,'counters':counts,'originalTerminalUnchanged':True,'credentialIntentAbsent':True,'samePhaseStatusNoNewGuestOrPointer':True})
        return value,counts
    def test_complete_before_self_effect_refusal_RED_current_once_awake_GREEN(self):
        old,counts=self.incident(before_module());self.assertEqual('terminal',old['state']);self.assertEqual('blocked',old['packet']['state']);self.assertEqual('instance_display_wake_prior_unresolved',old['packet']['reason']);self.assertEqual(0,counts['inputCount'])
        current,counts=self.incident(phase);self.assertEqual('terminal',current['state']);self.assertEqual('awake',current['packet']['state']);self.assertEqual(1,counts['inputCount']);self.assertFalse(current['packet']['inputFieldAuthority']);self.assertEqual(1,current['packet']['displayState'])

if __name__=='__main__':unittest.main()
