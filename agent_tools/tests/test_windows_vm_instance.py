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


REPLACED=Path(__file__).parent/'fixtures/instance_executable_replaced'
# The native shape of 2026-11-17 (instance order dev,ino,mode,uid,gid,nlink,size,mtime,ctime):
# a package upgrade unlinked the running QEMU, so only nlink and ctime changed.
NATIVE_RECORDED=[66306,1234700,33261,0,0,1,28940536,1789559094000000000,1790008459287925436]
NATIVE_OBSERVED=[66306,1234700,33261,0,0,0,28940536,1789559094000000000,1794928875234735109]


def current_definitions(*names):
    source=inspect.getsource(instance._vm_main)
    nodes={n.name:n for n in ast.walk(ast.parse(source)) if isinstance(n,ast.FunctionDef)}
    return '\n'.join(textwrap.dedent('    '+ast.get_source_segment(source,nodes[name])) for name in names)+'\n'


class FakeProc:
    """Only the /proc facts process() reads: birth ticks, cmdline, exe inode and owner."""
    def __init__(self,pid,start,argv,exe):
        self.pid,self.start,self.argv,self.exe=pid,start,list(argv),list(exe)
        self.cmdline=b'\0'.join(os.fsencode(x) for x in argv)+b'\0'

    def stat(self,path):
        fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        if path=='/proc/'+str(self.pid)+'/exe':return types.SimpleNamespace(**dict(zip(fields,self.exe)))
        if path=='/proc/'+str(self.pid):return types.SimpleNamespace(st_uid=1000)
        raise FileNotFoundError(path)

    def open(self,path,mode='r'):
        import io
        if path!='/proc/'+str(self.pid)+'/cmdline' or mode!='rb':raise FileNotFoundError(path)
        return io.BytesIO(self.cmdline)

    def namespace(self,rows=None):
        def require(value,reason):
            if not value:raise ValueError(reason)
        def birth(pid):
            if pid!=self.pid:raise FileNotFoundError(pid)
            return self.start
        fake_os=types.SimpleNamespace(stat=self.stat,geteuid=lambda:1000,fsencode=os.fsencode)
        return {'os':fake_os,'open':self.open,'hashlib':hashlib,'require':require,'birth':birth,
                'read':lambda name:json.loads(json.dumps(rows[name]))}


class ExecutableReplacedOnDiskTests(unittest.TestCase):
    """A package upgrade that unlinks a running QEMU leaves the same instance (2026-11-17)."""
    def setUp(self):
        self.argv=['/proc/self/fd/9','-name','fixture','-uuid','7fb3fd62-699e-4478-9bd0-498a61efb91c']
        raw=b'\0'.join(os.fsencode(x) for x in self.argv)+b'\0'
        self.row={'pid':1387336,'startTicks':50405618,'argv':self.argv,'commandSha256':hashlib.sha256(raw).hexdigest(),
                  'executableGeneration':list(NATIVE_RECORDED)}

    def process(self,source,proc):
        namespace=proc.namespace()
        exec(compile(source,'instance process identity','exec'),namespace)
        return namespace['process']

    def before(self):
        raw=(REPLACED/'before.source').read_bytes();provenance=json.loads((REPLACED/'provenance.json').read_bytes())
        self.assertEqual(provenance['fragmentSha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual([NATIVE_RECORDED,NATIVE_OBSERVED],[provenance['nativeShape']['recorded'],provenance['nativeShape']['observed']])
        return raw.decode()

    def test_native_unlinked_executable_before_red_fixed_green(self):
        from agent_tools.tests import red_gate
        replaced=FakeProc(self.row['pid'],self.row['startTicks'],self.argv,NATIVE_OBSERVED)
        if red_gate.red_required(self,REPLACED/'before.source'):
            with self.assertRaisesRegex(ValueError,'^instance_process_changed$'):
                self.process(self.before(),replaced)(self.row)
        self.assertEqual(self.row['pid'],self.process(current_definitions('generation','process'),replaced)(self.row))

    def test_every_other_identity_change_still_refuses_exactly_as_before(self):
        before,after=self.before(),current_definitions('generation','process')
        changes=[('dev',0),('ino',1),('mode',2),('uid',3),('gid',4),('size',6),('mtime',7)]
        cases=[('exe-'+name,{'exe':[v+1 if i==index else v for i,v in enumerate(NATIVE_OBSERVED)]}) for name,index in changes]
        cases+=[('startTicks',{'start':self.row['startTicks']+1}),('cmdline',{'argv':self.argv+['-S']})]
        for name,change in cases:
            proc=FakeProc(self.row['pid'],change.get('start',self.row['startTicks']),change.get('argv',self.argv),change.get('exe',NATIVE_OBSERVED))
            for label,source in (('before',before),('after',after)):
                with self.subTest(change=name,source=label),self.assertRaisesRegex(ValueError,'^instance_process_changed$'):
                    self.process(source,proc)(self.row)
        unchanged=FakeProc(self.row['pid'],self.row['startTicks'],self.argv,NATIVE_RECORDED)
        for name,value in (('digest',{**self.row,'commandSha256':'0'*64}),('pid',{**self.row,'pid':self.row['pid']+1})):
            with self.subTest(receipt=name),self.assertRaises((ValueError,FileNotFoundError)):self.process(after,unchanged)(value)
        for value in (None,NATIVE_RECORDED[:8],[str(x) for x in NATIVE_RECORDED],tuple(NATIVE_RECORDED)):
            with self.subTest(recorded=value),self.assertRaisesRegex(ValueError,'^instance_process_receipt$'):
                self.process(after,unchanged)({**self.row,'executableGeneration':value})
        self.assertEqual(self.row['pid'],self.process(after,unchanged)(self.row))

    def test_replacement_is_reported_only_for_an_admitted_actor(self):
        source=current_definitions('generation','process','replacements')
        def evidence(exe,rows):
            proc=FakeProc(self.row['pid'],self.row['startTicks'],self.argv,exe);namespace=proc.namespace(rows)
            exec(compile(source,'instance replacement evidence','exec'),namespace)
            return namespace['replacements']()
        tpm={**self.row,'pid':self.row['pid']+7}
        self.assertEqual({'executableReplacedOnDisk':{'qemu':{'nlink':0,'ctimeNs':NATIVE_OBSERVED[8]}}},
                         evidence(NATIVE_OBSERVED,{'qemu-started.json':self.row,'swtpm-started.json':tpm}))
        self.assertEqual({},evidence(NATIVE_RECORDED,{'qemu-started.json':self.row,'swtpm-started.json':tpm}))
        moved=[v+1 if i==1 else v for i,v in enumerate(NATIVE_OBSERVED)]
        self.assertEqual({},evidence(moved,{'qemu-started.json':self.row,'swtpm-started.json':tpm}))

    def test_status_and_stop_results_carry_only_bounded_evidence(self):
        spec=FreshWindowsVmSpec.parse(request())
        base={'schemaVersion':1,'deploymentId':spec.deployment_id,'reason':None,'nativeActionAllowed':False,'replayAllowed':False,
              'qemu':{'pid':1387336,'startTicks':50405618},'swtpm':{'pid':1387330,'startTicks':50405600},'productReady':False}
        booted={**base,'mode':'status','state':'booted-observed','qemuStatus':'running','guestAgentReady':True,
                'ordinarySessionObserved':True,'osName':None}
        stopped={**base,'mode':'stop','state':'stopped-observed','positiveAbsence':True}
        evidence={'executableReplacedOnDisk':{'qemu':{'nlink':0,'ctimeNs':NATIVE_OBSERVED[8]}}}
        for value in (booted,stopped,{**booted,**evidence},{**stopped,**evidence}):
            self.assertEqual(value,producer.validate_result(spec,value['mode'],value))
        invalid=({},{'qemu':{'nlink':0}},{'other':{'nlink':0,'ctimeNs':1}},{'qemu':{'nlink':-1,'ctimeNs':1}},{'qemu':{'nlink':True,'ctimeNs':1}},[])
        for rows in invalid:
            for value in (booted,stopped):
                with self.subTest(rows=rows,state=value['state']),self.assertRaises(ValueError):
                    producer.validate_result(spec,value['mode'],{**value,'executableReplacedOnDisk':rows})
        with self.assertRaises(ValueError):
            producer.validate_result(spec,'status',{**stopped,'mode':'status',**evidence})
        from agent_tools import windows_vm_deploy as deploy
        response={'mode':'start','deploymentId':spec.deployment_id,'operationId':None,'checks':()}
        started={**booted,'mode':'start','osName':'Windows'}
        self.assertEqual({**started,**evidence,'osName':None},deploy._gateway_payload_result({**started,**evidence},response))
        with self.assertRaises(ValueError):
            deploy._gateway_payload_result({**started,'executableReplacedOnDisk':{'qemu':{'nlink':0}}},response)


@unittest.skipUnless(sys.platform=='linux','actual Linux /proc/<pid>/exe of an unlinked running executable')
class PhysicalExecutableReplacementTests(unittest.TestCase):
    """The OS shape itself: replace a running program's file the way a package upgrade does."""
    def test_running_child_survives_replacement_of_its_file(self):
        import shutil,subprocess
        from agent_tools.tests import red_gate
        sleep=shutil.which('sleep',path='/usr/bin:/bin');self.assertIsNotNone(sleep)
        with tempfile.TemporaryDirectory() as temporary:
            path=os.path.join(temporary,'qemu-system-x86_64');shutil.copy(os.path.realpath(sleep),path);os.chmod(path,0o755)
            exe=os.open(path,os.O_RDONLY)
            child=subprocess.Popen([path,'30'],close_fds=True,start_new_session=True)
            try:
                namespace={'os':os,'hashlib':hashlib,'json':json,'time':time}
                def require(value,reason):
                    if not value:raise ValueError(reason)
                namespace['require']=require
                exec(compile(current_definitions('generation','birth','record','process'),'actual instance identity','exec'),namespace)
                for _ in range(100):
                    try:row=namespace['record'](child,[path,'30'],exe);break
                    except (FileNotFoundError,ValueError):time.sleep(.02)
                else:self.fail('child identity was not recorded')
                os.close(exe);exe=-1
                self.assertEqual(1,row['executableGeneration'][5])
                # pacman extracts the new file beside the old one and renames it over the path.
                time.sleep(.05);shutil.copy(path,path+'.new');os.replace(path+'.new',path)
                observed=os.stat('/proc/'+str(child.pid)+'/exe')
                self.assertEqual((0,row['executableGeneration'][1]),(observed.st_nlink,observed.st_ino))
                if red_gate.red_required(self,REPLACED/'before.source'):
                    old={'os':os,'hashlib':hashlib,'require':require,'birth':namespace['birth']}
                    exec(compile((REPLACED/'before.source').read_text(),'preserved instance identity','exec'),old)
                    with self.assertRaisesRegex(ValueError,'^instance_process_changed$'):old['process'](row)
                self.assertEqual(child.pid,namespace['process'](row))
            finally:
                if exe>=0:os.close(exe)
                child.kill();child.wait(timeout=5)


if __name__=='__main__':unittest.main()
