"""A changed physical guest-agent socket invalidates partial readiness facts."""
import ast
import hashlib
import inspect
import json
import os
import socket
import stat
import struct
import tempfile
import time
import textwrap
import types
import unittest
import sys
from pathlib import Path
from agent_tools import windows_vm_instance as instance
from agent_tools import windows_vm_deploy_remote as producer
from agent_tools.native_vm_spec import FreshWindowsVmSpec
from agent_tools.tests.test_native_vm_spec import request


@unittest.skipUnless(sys.platform=='linux','actual Linux Unix socket descriptor census')
class ListeningSocketTests(unittest.TestCase):
    def source(self):
        source=inspect.getsource(instance._vm_main)
        node=next(n for n in ast.walk(ast.parse(source)) if isinstance(n,ast.FunctionDef) and n.name=='owns')
        return ast.get_source_segment(source,node)

    def test_connected_stream_keeps_path_but_listener_still_has_exact_owner(self):
        from agent_tools.tests.connected_socket_causal import prove
        folder=Path(__file__).parent/'fixtures/connected_tpm_socket'
        raw=(folder/'before.source').read_bytes()
        metadata=json.loads((folder/'provenance.json').read_bytes())
        self.assertEqual(metadata['fragmentSha256'],hashlib.sha256(raw).hexdigest())
        result=prove(raw.decode(),self.source())
        self.assertEqual('GREEN',result['after'])
        self.assertTrue(result['foreignOwnerRejected'])


@unittest.skipUnless(os.name=='posix' and hasattr(socket,'AF_UNIX'),'owned Unix socket fixtures')
class GuestAgentClosingTests(unittest.TestCase):
    def test_physical_dirty_stream_before_red_fixed_delimited_nonce_green(self):
        from agent_tools.tests.guest_agent_sync_causal import observe
        folder=Path(__file__).parent/'fixtures/guest_agent_sync';raw=(folder/'before.source').read_bytes()
        metadata=json.loads((folder/'provenance.json').read_bytes())
        self.assertEqual(metadata['fragmentSha256'],hashlib.sha256(raw).hexdigest())
        before,queries=observe(raw.decode());self.assertFalse(before['guestAgentReady']);self.assertEqual([],queries)
        after,queries=observe(self.current_source())
        self.assertTrue(after['guestAgentReady']);self.assertTrue(after['ordinarySessionObserved'])
        self.assertEqual(['guest-ping','guest-get-osinfo','guest-get-users'],queries)
        for case in ('wrong','marker-missing','bound'):
            value,queries=observe(self.current_source(),case=case)
            self.assertFalse(value['guestAgentReady']);self.assertEqual([],queries)
        value,_=observe(self.current_source(),exchange=True);self.assertFalse(value['guestAgentReady'])

    def observe(self,source,exchange):
        with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve()) as temporary:
            root=Path(temporary);server=socket.socket(socket.AF_UNIX)
            self.addCleanup(server.close);server.bind(str(root/'qga.sock'))
            replacement=socket.socket(socket.AF_UNIX);self.addCleanup(replacement.close)
            replacement.bind(str(root/'replacement.sock'))
            class Stream:
                def write(self,raw):
                    request=json.loads(raw.lstrip(b'\xff'));command=request['execute'];self.delimited=command=='guest-sync-delimited'
                    self.response={'return':request['arguments']['id'] if command=='guest-sync-delimited' else
                                   {'pretty-name':'Windows fixture'} if command=='guest-get-osinfo' else
                                   [{'user':'ordinary'}] if command=='guest-get-users' else None}
                    if command=='guest-get-users' and exchange:os.replace(root/'replacement.sock',root/'qga.sock')
                def readline(self,limit):return (b'\xff'if self.delimited else b'')+(json.dumps(self.response)+'\n').encode()
            class Client:
                closed=False
                def settimeout(self,_):pass
                def connect(self,_):pass
                def getsockopt(self,*_):return struct.pack('3i',31415,os.geteuid(),os.getegid())
                def makefile(self,*_,**__):return Stream()
                def close(self):self.closed=True
            client=Client()
            def require(value,reason):
                if not value:raise ValueError(reason)
            def owns(pid,path,is_socket):
                require(pid==31415 and is_socket and stat.S_ISSOCK(path.lstat().st_mode),'fixture_socket')
            namespace={'os':os,'json':json,'struct':struct,'root':root,'SETUP':{'user':'ordinary'},
                       'require':require,'owns':owns,'time':time,'socket':types.SimpleNamespace(
                           socket=lambda *_:client,AF_UNIX=1,SOL_SOCKET=1,SO_PEERCRED=1)}
            exec(compile(textwrap.dedent(source),'actual guest-state function','exec'),namespace)
            value=namespace['guest_state'](31415)
            self.assertTrue(client.closed)
            return value

    def current_source(self):
        source=inspect.getsource(instance._vm_main);tree=ast.parse(source)
        node=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='guest_state')
        return ast.get_source_segment(source,node)

    def test_retained_beforeimage_leaks_partial_ready_but_fix_invalidates_changed_socket(self):
        folder=Path(__file__).parent/'fixtures/guest_agent_socket_closing'
        raw=(folder/'before.source').read_bytes();provenance=json.loads((folder/'provenance.json').read_bytes())
        self.assertEqual(provenance['fragmentSha256'],hashlib.sha256(raw).hexdigest())
        self.assertTrue(self.observe(raw.decode(),True)['guestAgentReady'])
        self.assertEqual({'guestAgentReady':False,'ordinarySessionObserved':False,'osName':None},
                         self.observe(self.current_source(),True))

    def test_unchanged_socket_retains_actual_agent_and_ordinary_session_facts(self):
        self.assertEqual({'guestAgentReady':True,'ordinarySessionObserved':True,'osName':'Windows fixture'},
                         self.observe(self.current_source(),False))


@unittest.skipUnless(os.name=='posix','POSIX-only instance producer')
class InstanceDiagnosticTests(unittest.TestCase):
    def test_complete_producer_keeps_unknown_and_emits_only_bounded_diagnostic(self):
        import contextlib,io
        from unittest import mock
        namespace={'SPEC':{'root':'/unused-owned-root','deploymentId':'inert'},'MODE':'status'}
        exec(compile(inspect.getsource(instance._vm_main),'complete instance observer','exec'),namespace)
        for error,category,check in ((ValueError('instance_socket_identity'),'ValueError','instance_socket_identity'),
                                     (PermissionError('PRIVATE_INPUT_MUST_NOT_LEAK'),'OSError',None)):
            output=io.StringIO()
            with mock.patch.object(os,'geteuid',side_effect=error),contextlib.redirect_stdout(output):
                namespace['_vm_main']()
            value=json.loads(output.getvalue())
            self.assertEqual('unknown',value['state']);self.assertFalse(value['replayAllowed'])
            self.assertEqual('resources',value['failurePhase']);self.assertEqual(category,value['failureClass'])
            self.assertEqual(check,value['failureCheck']);self.assertNotIn('PRIVATE_INPUT',output.getvalue())

    def test_decoder_rejects_unbounded_diagnostic_data(self):
        spec=FreshWindowsVmSpec.parse(request())
        value={'schemaVersion':1,'deploymentId':spec.deployment_id,'mode':'status','state':'unknown',
               'reason':'instance_effect_or_observation_unknown','nativeActionAllowed':False,'replayAllowed':False,
               'failurePhase':'observation','failureClass':'ValueError','failureCheck':'instance_socket_identity'}
        self.assertEqual(value,producer.validate_result(spec,'status',value))
        for key,invalid in (('failurePhase','arbitrary'),('failureClass','arbitrary'),('failureCheck','PRIVATE INPUT')):
            with self.assertRaises(ValueError):producer.validate_result(spec,'status',{**value,key:invalid})


if __name__=='__main__':unittest.main()
