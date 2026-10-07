"""No SSH/native invocation. Actual held local guards plus real binary children.

Remote Linux process/kernel identity is a declared separate native gate. The
whole source programme is compiled and its launch/observe methods inspected;
local DTO fixtures do not claim a Linux native channel ready.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock
from agent_tools import ssh_fresh_nested_channel as channel
from agent_tools.tests import test_ssh_connection_session as fixtures

@unittest.skipUnless(os.name=='posix' and hasattr(os,'O_NOFOLLOW'),'POSIX protected channel custody')
class FreshChannelTests(unittest.TestCase):
    def setUp(self):
        # Private fixture base avoids shared macOS T directory link churn.
        real_temporary=tempfile.TemporaryDirectory
        private_base=real_temporary(prefix='vcf-',dir=Path('/tmp').resolve())
        self.addCleanup(private_base.cleanup);base=Path(private_base.name)
        with mock.patch.object(tempfile,'TemporaryDirectory',side_effect=lambda *a,**kw:real_temporary(*a,**{**kw,'dir':base})):
            self.f=fixtures.SessionTests(methodName='runTest');self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.config['hosts']['archlinux']['password']='inert private sentinel';self.f.write_config();self.f.ready()
        self.root=self.f.root;self.corr='b'*32;self.raw={};self.calls=[];self.real_popen=subprocess.Popen
        self.stdout=json.dumps({'state':'unknown','correlationId':self.corr}).encode();self.stderr=b'';self.rc=3
    def consumer(self,argv,**kw):
        self.assertEqual(['-F','/dev/null'],argv[1:3]);self.assertIn('-T',argv);self.assertIn('ProxyCommand=false',argv)
        remote=shlex.split(argv[-1]);self.assertEqual(['python3','-I','-B','-c'],remote[:4]);self.assertEqual(channel._REMOTE,remote[4])
        self.assertNotIn('inert private sentinel',repr(argv));self.calls.append(remote)
        # Consume real private stdin, emit bounded fixture transport response.
        code='import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]));sys.stderr.buffer.write(bytes.fromhex(sys.argv[2]));sys.exit(int(sys.argv[3]))'
        return self.real_popen([sys.executable,'-I','-B','-c',code,self.stdout.hex(),self.stderr.hex(),str(self.rc)],**kw)
    def invoke(self,prepare=True,corr=None,retainer=None):
        function=channel.prepare if prepare else channel.status
        with mock.patch.object(channel.subprocess,'Popen',side_effect=self.consumer):
            return function(self.root,'archlinux',corr or self.corr,_private_capture=retainer or self.raw.update)
    def test_lost_launch_reply_keeps_once_intent_and_only_observes_original(self):
        before=self.f.config_path.read_bytes()
        self.assertEqual('unknown',self.invoke()['state']);self.assertEqual('prepare',self.calls[-1][6])
        self.assertTrue(self.raw['complete']);self.assertEqual(3,self.raw['returnCode'])
        self.assertEqual('unknown',self.invoke()['state']);self.assertEqual('status',self.calls[-1][6])
        self.assertEqual(before,self.f.config_path.read_bytes());self.assertEqual(1,len(self.f.spawns))
        self.assertEqual('unknown',self.invoke(corr='c'*32)['state']);self.assertEqual(2,len(self.calls))
    def ready_fixture(self):
        namespace,table,header,row=self.remote_snapshot_fixture()
        master=namespace['snapshot']()
        return {'state':'ready','correlationId':self.corr,'master':master,
                'arch':{'uid':channel.EXPECTED_UID,'boot':channel.EXPECTED_BOOT},
                'controlPath':'/tmp/vpn-channel-'+self.corr+'/m'}

    def test_lost_local_readiness_reply_reconciles_existing_master_without_launch(self):
        remote=self.ready_fixture();self.invoke() # Once launch retained UNKNOWN.
        self.stdout=json.dumps(remote).encode();self.rc=0
        value=self.invoke(False)
        self.assertEqual('ready',value['state']);self.assertEqual('status',self.calls[-1][6])
        self.assertEqual('ready',self.invoke()['state']);self.assertEqual('status',self.calls[-1][6])
        self.assertEqual('prepare',self.calls[0][6]);self.assertEqual(3,len(self.calls))

    def test_positive_idle_end_allows_one_new_connection_without_job_replay(self):
        remote=self.ready_fixture();self.stdout=json.dumps(remote).encode();self.rc=0
        self.assertEqual('ready',self.invoke()['state'])
        self.stdout=json.dumps({'state':'ended','correlationId':self.corr,'prior':remote,'gatewayBoot':remote['master']['gatewayBoot']}).encode()
        self.assertEqual('ended',self.invoke(False)['state'])
        self.stdout=json.dumps({'state':'unknown','correlationId':'c'*32}).encode();self.rc=3
        self.assertEqual('unknown',self.invoke(corr='c'*32)['state']);self.assertEqual('prepare',self.calls[-1][6])
        self.assertEqual(2,sum(call[6]=='prepare' for call in self.calls))

    def test_positive_unseen_pending_end_allows_new_connection(self):
        self.invoke();self.stdout=json.dumps({'state':'ended','correlationId':self.corr,'prior':None,'gatewayBoot':channel.EXPECTED_BOOT}).encode();self.rc=0
        self.assertEqual('ended',self.invoke(False)['state'])
        self.stdout=b'{}';self.rc=3
        self.invoke(corr='c'*32);self.assertEqual('prepare',self.calls[-1][6])

    def test_readonly_route_metadata_never_launches_and_rejects_stale_receipt(self):
        self.stdout=json.dumps(self.ready_fixture()).encode();self.rc=0
        admitted=self.invoke()
        with mock.patch.object(channel.subprocess,'Popen',side_effect=self.consumer):
            metadata=channel.route_options(self.root,'archlinux',self.corr,admitted['receiptSha256'])
            self.assertEqual({'correlationId','receiptSha256','outerReceiptSha256','outerOptions','innerOptions'},set(metadata))
            self.assertEqual(self.corr,metadata['correlationId'])
            self.assertEqual('ProxyCommand=false',metadata['outerOptions'][-1])
            self.assertEqual('ProxyCommand=false',metadata['innerOptions'][-1])
            with self.assertRaises(ValueError):channel.route_options(self.root,'archlinux',self.corr,'0'*64)
        self.assertEqual(1,sum(call[6]=='prepare' for call in self.calls))

    def test_explicit_ensure_unknown_observes_once_and_bad_receipt_has_no_effect(self):
        with mock.patch.object(channel.subprocess,'Popen',side_effect=self.consumer):
            self.assertEqual('unknown',channel.ensure_channel(self.root,'archlinux',self.corr)['state'])
            self.assertEqual('unknown',channel.ensure_channel(self.root,'archlinux',self.corr)['state'])
            count=len(self.calls)
            self.assertEqual('unknown',channel.ensure_channel(self.root,'archlinux',self.corr,'0'*64)['state'])
            self.assertEqual(count,len(self.calls))
        self.assertEqual(['prepare','status'],[call[6] for call in self.calls])

    def test_explicit_ensure_positive_expiry_renews_connection_only(self):
        remote=self.ready_fixture();self.stdout=json.dumps(remote).encode();self.rc=0
        admitted=self.invoke();old_intent=(self.root/'.rag_index/ssh-fresh-nested-channel'/(self.corr+'.intent.json')).read_bytes()
        new_id='c'*32;original_consumer=self.consumer
        def sequence(argv,**kw):
            call=shlex.split(argv[-1]);identity=call[5]
            if identity==self.corr:
                self.stdout=json.dumps({'state':'ended','correlationId':self.corr,'prior':remote,'gatewayBoot':remote['master']['gatewayBoot']}).encode()
            else:
                self.stdout=json.dumps({**remote,'correlationId':new_id,'controlPath':'/tmp/vpn-channel-'+new_id+'/m'}).encode()
            return original_consumer(argv,**kw)
        with mock.patch.object(channel.uuid,'uuid4',return_value=types.SimpleNamespace(hex=new_id)),mock.patch.object(channel.subprocess,'Popen',side_effect=sequence):
            metadata=channel.ensure_channel(self.root,'archlinux',self.corr,admitted['receiptSha256'])
        self.assertEqual(new_id,metadata['correlationId']);self.assertEqual(old_intent,(self.root/'.rag_index/ssh-fresh-nested-channel'/(self.corr+'.intent.json')).read_bytes())
        self.assertEqual(['prepare','status','prepare','status'],[call[6] for call in self.calls])

    def test_actual_local_gate_failures_expose_finite_phase_before_submission(self):
        channel._journal(self.root,True)
        self.root.chmod(0o777)
        try:self.assertEqual('inventory',self.invoke(False).get('failurePhase'))
        finally:self.root.chmod(0o700)
        # Real synthetic managed receipt corruption reaches the exact _read
        # parser; no credentials/error strings are projected and no SSH runs.
        ready=channel.session._journal(self.root,'archlinux',False)/'ready.json'
        saved=ready.read_bytes();ready.write_bytes(b'{private invalid sentinel')
        try:
            value=self.invoke(False)
            self.assertEqual('outer_receipt',value.get('failurePhase'));self.assertNotIn('sentinel',json.dumps(value))
        finally:ready.write_bytes(saved)
        self.assertEqual([],self.calls)

    def test_actual_ended_reviewed_source_handoff_refuses_unknown_or_foreign(self):
        # Only the old source identity is a declared fixture seam. Actual
        # producer/terminal receipts, protected FD guards and real children run.
        previous=channel._REVIEWED_ENDED_PREDECESSOR
        remote=self.ready_fixture();self.stdout=json.dumps(remote).encode();self.rc=0
        with mock.patch.object(channel,'_source',return_value=previous):
            self.assertEqual('ready',self.invoke()['state'])
            self.stdout=json.dumps({'state':'ended','correlationId':self.corr,'prior':remote,'gatewayBoot':remote['master']['gatewayBoot']}).encode()
            self.assertEqual('ended',self.invoke(False)['state'])
        group=self.root/'.rag_index/ssh-fresh-nested-channel'
        intent=group/(self.corr+'.intent.json');terminal=group/(self.corr+'.terminal.json')
        old_intent=intent.read_bytes();old_terminal=terminal.read_bytes();count=len(self.calls)
        data=json.loads(old_terminal);data['state']='unknown';terminal.write_text(json.dumps(data))
        self.assertEqual('unknown',self.invoke(corr='c'*32)['state']);self.assertEqual(count,len(self.calls))
        terminal.write_bytes(old_terminal)
        data=json.loads(old_intent);data['sourceSha256']='0'*64;intent.write_text(json.dumps(data))
        self.assertEqual('unknown',self.invoke(corr='c'*32)['state']);self.assertEqual(count,len(self.calls))
        intent.write_bytes(old_intent)
        self.stdout=b'{}';self.rc=3
        self.invoke(corr='c'*32);self.assertEqual('prepare',self.calls[-1][6])
        self.assertEqual(old_intent,intent.read_bytes());self.assertEqual(old_terminal,terminal.read_bytes())

    def test_private_remote_diagnostic_never_projects_raw_or_extra_fields(self):
        capture={'state':'unknown','correlationId':self.corr,'failurePhase':'launch','launchCapture':{'private':'secret sentinel'}}
        self.stdout=json.dumps(capture).encode();self.rc=3
        result=self.invoke();self.assertEqual('launch',result['failurePhase']);self.assertNotIn('sentinel',json.dumps(result))
        for wrong in ({**capture,'failurePhase':'secret sentinel'},{**capture,'extra':'sentinel'}):
            self.stdout=json.dumps(wrong).encode()
            self.assertNotIn('failurePhase',self.invoke(False));self.assertNotIn('sentinel',json.dumps(self.invoke(False)))

    def test_finite_private_refusal_tuple_projects_only_validated_fields(self):
        failure={'state':'unknown','correlationId':self.corr,'failurePhase':'master_snapshot','launchCapture':{'private':'sentinel'},'failureReason':'fd_changed','exceptionClass':'FileNotFoundError','errno':2}
        self.stdout=json.dumps(failure).encode();self.rc=3
        result=self.invoke();self.assertEqual('fd_changed',result['failureReason']);self.assertEqual(2,result['errno']);self.assertEqual('FileNotFoundError',result['exceptionClass']);self.assertNotIn('sentinel',json.dumps(result))
        for key,value in (('failureReason','secret sentinel'),('exceptionClass','secret sentinel'),('errno',True),('errno',256),('errno',-1)):
            with self.subTest(key=key,value=value):
                self.stdout=json.dumps({**failure,key:value}).encode();result=self.invoke(False)
                self.assertNotIn('failureReason',result);self.assertNotIn('exceptionClass',result);self.assertNotIn('errno',result);self.assertNotIn('sentinel',json.dumps(result))
        self.stdout=json.dumps({k:v for k,v in failure.items() if k!='errno'}).encode();self.assertNotIn('failureReason',self.invoke(False))

    def test_actual_9a_ended_handoff_requires_original_remote_sha(self):
        # Exact old programme bytes are reconstructed from the two stated
        # diagnostic-only deltas. Historical source identity is an explicit
        # fixture seam; actual protected producer/terminal/child guards run.
        remote_source=channel._REMOTE
        # Reconstruct the prior pin solely from a fixed literal; no ignored
        # evidence dependency belongs in routine tests.
        current_pin=next(n for n in ast.parse(remote_source).body if isinstance(n,ast.FunctionDef) and n.name=='pin')
        old_literal="def pin(path):\n before=os.lstat(path)\n fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)\n try:\n  body=os.read(fd,65537)\n  if len(body)>65536 or gen(before)!=gen(os.fstat(fd)) or gen(before)!=gen(os.lstat(path)):raise ValueError('changed')\n finally:os.close(fd)\n return body,gen(before)\n"
        source_lines=remote_source.splitlines(keepends=True)
        remote_source=''.join(source_lines[:current_pin.lineno-1])+old_literal+''.join(source_lines[current_pin.end_lineno:])
        root=ast.parse(remote_source);refusal=next(n for n in root.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_REFUSALS' for t in n.targets))
        lines=remote_source.splitlines(keepends=True);old_remote=''.join(lines[:refusal.lineno-1]+lines[refusal.end_lineno:])
        old_remote=old_remote[:old_remote.rindex('except (OSError,ValueError,KeyError,subprocess.SubprocessError) as failure:')]+"except (OSError,ValueError,KeyError,subprocess.SubprocessError):\n print(json.dumps({'state':'unknown','correlationId':corr,'failurePhase':phase,'launchCapture':launch_capture(launch)},sort_keys=True));raise SystemExit(3)\n"
        self.assertEqual(channel._REVIEWED_ENDED_REMOTE_9A,hashlib.sha256(old_remote.encode()).hexdigest())
        remote=self.ready_fixture();self.stdout=json.dumps(remote).encode();self.rc=0
        with mock.patch.object(channel,'_source',return_value=channel._REVIEWED_ENDED_PREDECESSOR_9A),mock.patch.object(channel,'_REMOTE',old_remote):
            self.assertEqual('ready',self.invoke()['state'])
            self.stdout=json.dumps({'state':'ended','correlationId':self.corr,'prior':remote,'gatewayBoot':remote['master']['gatewayBoot']}).encode();self.assertEqual('ended',self.invoke(False)['state'])
        group=self.root/'.rag_index/ssh-fresh-nested-channel';intent=group/(self.corr+'.intent.json');terminal=group/(self.corr+'.terminal.json');saved=intent.read_bytes();ended=terminal.read_bytes();count=len(self.calls)
        data=json.loads(saved);data['remoteSourceSha256']='0'*64;intent.write_text(json.dumps(data))
        end=json.loads(ended);end['intentSha256']=hashlib.sha256(intent.read_bytes()).hexdigest();terminal.write_text(json.dumps(end))
        self.assertEqual('unknown',self.invoke(corr='c'*32)['state']);self.assertEqual(count,len(self.calls))
        intent.write_bytes(saved);terminal.write_bytes(ended);self.stdout=b'{}';self.rc=3
        self.invoke(corr='c'*32);self.assertEqual('prepare',self.calls[-1][6]);self.assertEqual(saved,intent.read_bytes());self.assertEqual(ended,terminal.read_bytes())

    def test_actual_9527_ended_handoff_requires_original_remote_sha(self):
        # Exact old programme bytes are reconstructed from the two stated
        # diagnostic-only deltas. Historical source identity is an explicit
        # fixture seam; actual protected producer/terminal/child guards run.
        remote_source=channel._REMOTE
        # Reconstruct the prior pin solely from a fixed literal; no ignored
        # evidence dependency belongs in routine tests.
        current_pin=next(n for n in ast.parse(remote_source).body if isinstance(n,ast.FunctionDef) and n.name=='pin')
        old_literal="def pin(path):\n before=os.lstat(path)\n fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)\n try:\n  body=os.read(fd,65537)\n  if len(body)>65536 or gen(before)!=gen(os.fstat(fd)) or gen(before)!=gen(os.lstat(path)):raise ValueError('changed')\n finally:os.close(fd)\n return body,gen(before)\n"
        source_lines=remote_source.splitlines(keepends=True)
        remote_source=''.join(source_lines[:current_pin.lineno-1])+old_literal+''.join(source_lines[current_pin.end_lineno:])
        old_remote=remote_source
        self.assertEqual(channel._REVIEWED_ENDED_REMOTE_9527,hashlib.sha256(old_remote.encode()).hexdigest())
        remote=self.ready_fixture();self.stdout=json.dumps(remote).encode();self.rc=0
        with mock.patch.object(channel,'_source',return_value=channel._REVIEWED_ENDED_PREDECESSOR_9527),mock.patch.object(channel,'_REMOTE',old_remote):
            self.assertEqual('ready',self.invoke()['state'])
            self.stdout=json.dumps({'state':'ended','correlationId':self.corr,'prior':remote,'gatewayBoot':remote['master']['gatewayBoot']}).encode();self.assertEqual('ended',self.invoke(False)['state'])
        group=self.root/'.rag_index/ssh-fresh-nested-channel';intent=group/(self.corr+'.intent.json');terminal=group/(self.corr+'.terminal.json');saved=intent.read_bytes();ended=terminal.read_bytes();count=len(self.calls)
        data=json.loads(saved);data['remoteSourceSha256']='0'*64;intent.write_text(json.dumps(data))
        end=json.loads(ended);end['intentSha256']=hashlib.sha256(intent.read_bytes()).hexdigest();terminal.write_text(json.dumps(end))
        self.assertEqual('unknown',self.invoke(corr='c'*32)['state']);self.assertEqual(count,len(self.calls))
        intent.write_bytes(saved);terminal.write_bytes(ended);self.stdout=b'{}';self.rc=3
        self.invoke(corr='c'*32);self.assertEqual('prepare',self.calls[-1][6]);self.assertEqual(saved,intent.read_bytes());self.assertEqual(ended,terminal.read_bytes())

    def test_actual_route_unknown_retains_validated_public_cause(self):
        failure={'state':'unknown','correlationId':self.corr,'failurePhase':'master_snapshot','launchCapture':None,'failureReason':'fd_changed','exceptionClass':'FileNotFoundError','errno':2}
        self.stdout=json.dumps(failure).encode();self.rc=3;self.invoke()
        with mock.patch.object(channel.subprocess,'Popen',side_effect=self.consumer),self.assertRaises(ValueError) as caught:
            channel.route_options(self.root,'archlinux',self.corr,'0'*64)
        self.assertEqual('fd_changed',caught.exception.result['failureReason']);self.assertEqual(self.corr,caught.exception.result['correlationId']);self.assertFalse(caught.exception.result['replayAllowed'])

    def test_status_without_intent_never_submits(self):
        self.assertEqual('unknown',self.invoke(False)['state']);self.assertEqual([],self.calls)
    def test_malformed_missing_foreign_and_bool_identity_refuse(self):
        self.invoke()
        for body in (b'\xff',b'{}',b'{"state":"ready","state":"unknown"}',json.dumps({'state':'ready','correlationId':'c'*32}).encode()):
            self.stdout=body;self.rc=0
            self.assertEqual('unknown',self.invoke(False)['state']);self.assertEqual(body,self.raw['stdout'])
        self.assertFalse(channel._master_shape({'actor':{'pid':True,'startTicks':1,'uid':0}}))
    def test_cap_and_response_loss_never_offer_replay(self):
        self.stdout=b'x'*5000;self.rc=0
        value=self.invoke();self.assertEqual('unknown',value['state']);self.assertFalse(value['replayAllowed'])
        self.assertTrue(self.raw['overflow']);self.assertFalse(self.raw['complete']);self.assertEqual(5000,self.raw['counts']['stdout'])
    def test_same_inode_intent_and_config_mutation_refuse(self):
        self.invoke();intent=next((self.root/'.rag_index/ssh-fresh-nested-channel').glob('*.intent.json'))
        value=json.loads(intent.read_bytes());value['expectedUid']=False;intent.write_text(json.dumps(value));intent.chmod(0o600)
        self.assertEqual('unknown',self.invoke(False)['state']);self.assertEqual(1,len(self.calls))
    def test_raw_retention_drift_under_held_custody_refuses(self):
        def drift(value):
            self.raw.update(value);body=self.f.config_path.read_bytes();self.f.config_path.write_bytes(body)
        self.assertEqual('unknown',self.invoke(retainer=drift)['state']);self.assertTrue(self.raw['complete'])
    def test_raw_retention_exception_keeps_unknown(self):
        def refuse(value):raise OSError('private sentinel')
        value=self.invoke(retainer=refuse);self.assertEqual('unknown',value['state']);self.assertNotIn('sentinel',json.dumps(value))
    def test_bad_host_ids_and_receipts_do_not_submit(self):
        for corr in ('../x','b'*31,True,None):
            self.assertEqual('unknown',channel.prepare(self.root,'archlinux',corr)['state'])
        self.assertEqual('unknown',channel.prepare(self.root,'other',self.corr)['state'])
        with self.assertRaises(ValueError):channel.route_options(self.root,'archlinux',self.corr,'x')
        self.assertEqual([],self.calls)
    def test_remote_source_is_fixed_once_launch_and_readonly_status(self):
        compile(channel._REMOTE,'exact-channel-remote','exec');tree=ast.parse(channel._REMOTE)
        self.assertIn("os.mkdir(stage,0o700)",channel._REMOTE);self.assertIn("save('intent.json'",channel._REMOTE)
        self.assertIn("'ControlPersist=60'",channel._REMOTE);self.assertIn("'ProxyCommand=false'",channel._REMOTE)
        self.assertNotIn('os.kill(',channel._REMOTE);self.assertNotIn('unlink(',channel._REMOTE)
        self.assertIn("elif request!={}:raise ValueError('status_input')",channel._REMOTE)
    def remote_snapshot_fixture(self):
        # Exact generated CodeTypes; only Linux /proc transport facts are an
        # explicitly mapped TempFS seam. Real private Unix socket/FDs and SSH
        # binary pipes execute. This is not native gateway acceptance.
        namespace={'__builtins__':__builtins__}
        tree=ast.parse(channel._REMOTE)
        nodes=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))]
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'actual-generated-channel-functions','exec'),namespace)
        stage=self.root/'remote';stage.mkdir(mode=0o700);control=stage/'m'
        sock=socket.socket(socket.AF_UNIX);self.addCleanup(sock.close);sock.bind(str(control));control.chmod(0o600)
        pid=os.getpid();proc=self.root/'proc';proc.mkdir();actor=proc/str(pid);actor.mkdir();fdroot=actor/'fd';fdroot.mkdir()
        (actor/'stat').write_bytes(str(pid).encode()+b' (inert process seam) '+b' '.join([b'S']+[b'0']*18+[b'1']+[b'0']*10))
        inode=control.lstat().st_ino;(fdroot/'3').symlink_to('socket:['+str(inode)+']')
        net=proc/'net';net.mkdir();table=net/'unix'
        header=b'Num       RefCount Protocol Flags    Type St Inode Path\n'
        row=('0000: 00000002 00000000 00010000 0001 01 '+str(inode)+' '+str(control)+'\n').encode();table.write_bytes(header+row)
        import types
        facade=types.SimpleNamespace(**{name:getattr(os,name) for name in dir(os)})
        # Explicit host-ancestor metadata fixture seam. Unrelated TempFS
        # siblings alter shared macOS T metadata; the synthetic Linux route
        # has no authority over those host directories. All directories and
        # files within this test's private root retain actual full stat facts.
        external={(info.st_dev,info.st_ino):info for parent in self.root.resolve().parents for info in [parent.stat()]}
        def host_fact(info):
            held=external.get((info.st_dev,info.st_ino)) if stat.S_ISDIR(info.st_mode) else None
            if held is None:return info
            values={name:getattr(info,name) for name in dir(info) if name.startswith('st_')}
            values.update(st_nlink=held.st_nlink,st_size=held.st_size,
                          st_mtime_ns=held.st_mtime_ns,st_ctime_ns=held.st_ctime_ns)
            return types.SimpleNamespace(**values)
        facade.fstat=lambda fd:host_fact(os.fstat(fd))
        def translate(path):
            text=os.fspath(path)
            return str(proc)+text[len('/proc'):] if isinstance(text,str) and (text=='/proc' or text.startswith('/proc/')) else path
        for name in ('lstat','stat','open','readlink','listdir','lexists'):
            if name=='lexists':continue
            original=getattr(os,name)
            def wrapped(path,*args,_function=original,_name=name,**kwargs):
                value=_function(translate(path),*args,**kwargs)
                return host_fact(value) if _name in ('stat','lstat') else value
            setattr(facade,name,wrapped)
        executable=self.root/'check.py';executable.write_text('import sys;\nif "-G" in sys.argv:sys.stdout.write("identityfile '+str(self.f.key)+'\\n")\nelse:sys.stderr.write("Master running (pid='+str(pid)+')\\n")')
        real_run=subprocess.run
        subprocess_facade=types.SimpleNamespace(**{name:getattr(subprocess,name) for name in dir(subprocess)})
        def metadata_run(argv,**kw):
            self.assertEqual('ssh',argv[0]);self.assertIn('-G',argv)
            return real_run([sys.executable,'-I','-B',str(executable),*argv[1:]],**kw)
        subprocess_facade.run=metadata_run
        config=self.root/'remote-config';config.write_text('Host fixture\n Hostname inert.invalid\n');config.chmod(0o600)
        remote_spec={'configFile':str(config),'controlPath':str(control),'remoteHostAlias':'fixture'}
        # Install the declared host-ancestor facade before the original pins.
        # Baseline and closing observations must use the same environment;
        # private root/key/config metadata stays actual and strict.
        namespace.update(os=facade,subprocess=subprocess_facade,config_file=str(config),spec=remote_spec)
        namespace['config_pin']=namespace['file_pin'](str(config),body=True)
        namespace['route_pin']=namespace['effective_route'](remote_spec)
        namespace.update(stage=str(stage),control=str(control),boot=channel.EXPECTED_BOOT,
                         ssh=[sys.executable,'-I','-B',str(executable)],profile='fixture',_SOCKET_CAPTURE_BYTES=4096)
        namespace['_test_socket']=sock
        return namespace,table,header,row

    def test_actual_host_ancestor_churn_before_route_pin_uses_one_fixture_environment(self):
        real_run=subprocess.run;changed=[]
        sibling=self.root.parent/'host-ancestor-churn'
        def churn(argv,**kwargs):
            if not changed and '-G' in argv:
                before=self.root.parent.stat()
                sibling.mkdir(mode=0o700)
                after=self.root.parent.stat()
                self.assertNotEqual((before.st_size,before.st_mtime_ns,before.st_ctime_ns),
                                    (after.st_size,after.st_mtime_ns,after.st_ctime_ns))
                changed.append(True)
            return real_run(argv,**kwargs)
        with mock.patch.object(subprocess,'run',side_effect=churn):
            namespace,table,header,row=self.remote_snapshot_fixture()
        self.assertEqual(changed,[True])
        # Actual generated guard/snapshot with physical ancestor mutation.
        # Only explicitly external host ancestor metadata is a fixture seam.
        self.assertEqual(os.getpid(),namespace['snapshot']()['actor']['pid'])
        key=self.f.key;key.write_bytes(key.read_bytes()+b'!')
        with self.assertRaisesRegex(ValueError,'config_or_keys_changed'):
            namespace['snapshot']()

    def test_actual_owned_root_directory_churn_still_refuses(self):
        namespace,table,header,row=self.remote_snapshot_fixture()
        self.assertEqual(os.getpid(),namespace['snapshot']()['actor']['pid'])
        # The facade excludes this owned root; a real child changes its link
        # count and generation, which the unchanged production guard refuses.
        (self.root/'foreign-owned-child').mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError,'config_or_keys_changed'):
            namespace['snapshot']()

    def test_actual_remote_snapshot_private_socket_and_malformed_kernel_refusal(self):
        namespace,table,header,row=self.remote_snapshot_fixture()
        actual=namespace['snapshot']();self.assertEqual(os.getpid(),actual['actor']['pid'])
        for malformed in (b'broken header\n'+row,header+row+b'invalid row\n',header+row+row):
            table.write_bytes(malformed)
            with self.subTest(malformed=malformed),self.assertRaises(ValueError):namespace['snapshot']()

    def test_actual_openssh_randomized_listener_alias_and_foreign_refusal(self):
        namespace,table,header,row=self.remote_snapshot_fixture()
        canonical=os.fsencode(namespace['control'])
        alias=canonical+b'.aB0123456789cDeF'
        table.write_bytes(header+row.replace(canonical,alias))
        self.assertEqual(os.getpid(),namespace['snapshot']()['actor']['pid'])
        for wrong in (canonical+b'.short',canonical+b'.aB0123456789cDeF/extra',canonical+b'X.aB0123456789cDeF'):
            table.write_bytes(header+row.replace(canonical,wrong))
            with self.assertRaises(ValueError):namespace['snapshot']()
        namespace['_test_socket'].close();Path(namespace['control']).unlink();namespace['corr']=self.corr
        table.write_bytes(header+row.replace(canonical,alias))
        self.assertFalse(namespace['pending_absent']())

    def test_actual_pending_absence_refuses_live_correlated_actor_and_unknown_kernel(self):
        namespace,table,header,row=self.remote_snapshot_fixture();namespace['corr']=self.corr
        namespace['_test_socket'].close();Path(namespace['control']).unlink();table.write_bytes(header)
        self.assertTrue(namespace['pending_absent']())
        child=subprocess.Popen([sys.executable,'-I','-B','-c','import time;time.sleep(2)',self.corr],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.addCleanup(lambda:child.poll() is None and child.terminate());self.addCleanup(lambda:child.poll() is None and child.wait(timeout=3))
        fake_proc=self.root/'proc'/str(child.pid);fake_proc.mkdir();(fake_proc/'cmdline').write_bytes(b'python\0'+self.corr.encode()+b'\0')
        self.assertFalse(namespace['pending_absent']())
        child.terminate();child.wait(timeout=3);(fake_proc/'cmdline').unlink();fake_proc.rmdir()
        self.assertTrue(namespace['pending_absent']())
        table.write_bytes(b'bad kernel header\n')
        with self.assertRaises(ValueError):namespace['pending_absent']()

    def test_actual_whole_remote_status_recovers_launch_before_ready(self):
        self.whole_remote_status()

    def test_actual_whole_remote_status_proves_unseen_stage_absent(self):
        self.whole_remote_status(absent=True)

    def test_actual_whole_remote_status_kernel_timestamp_drift_keeps_master_closure(self):
        self.whole_remote_status(kernel_timestamp_drift=True)

    def test_actual_whole_ready_publication_config_drift_refuses(self):
        self.whole_remote_status(publication_drift=True)

    def test_actual_whole_remote_refusal_retains_finite_subtype(self):
        value=self.whole_remote_status(foreign_member=True)
        self.assertEqual('remote_intent',value['failurePhase'])
        self.assertEqual('directory_membership',value['failureReason'])
        self.assertEqual('ValueError',value['exceptionClass']);self.assertIsNone(value['errno'])

    def test_actual_whole_remote_failure_retains_finite_stage(self):
        self.whole_remote_status(prepare_collision=True)

    def test_actual_emitted_launch_capture_real_child_has_bounded_private_prefix(self):
        namespace={'__builtins__':__builtins__}
        nodes=[n for n in ast.parse(channel._REMOTE).body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))]
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'actual-emitted-launch-capture','exec'),namespace)
        namespace['_SOCKET_CAPTURE_BYTES']=4096
        child=namespace['inner']([sys.executable,'-I','-B','-c','import sys;sys.stdout.buffer.write(b"o"*2048);sys.stderr.buffer.write(b"private refusal"*100);sys.exit(255)'],2)
        proof=namespace['launch_capture'](child)
        self.assertEqual(255,proof['returnCode']);self.assertTrue(proof['complete']);self.assertTrue(all(proof['eof'].values()))
        self.assertEqual(2048,proof['counts']['stdout']);self.assertEqual(512,proof['streams']['stdout']['prefixBytes'])
        self.assertFalse(proof['streams']['stdout']['prefixComplete']);self.assertEqual(hashlib.sha256(child['stdout']).hexdigest(),proof['streams']['stdout']['retainedSha256'])
        self.assertLess(len(json.dumps(proof).encode()),3072)

    def whole_remote_status(self,absent=False,publication_drift=False,prepare_collision=False,foreign_member=False,kernel_timestamp_drift=False):
        # Genuine emitted complete programme. Explicit Linux /proc/path and
        # Arch UID/boot getter fixture seams; real Unix socket/private FS and
        # actual binary SSH children remain. No native readiness assertion.
        namespace,table,header,row=self.remote_snapshot_fixture()
        import builtins,contextlib,io,types
        native_stage='/tmp/vpn-channel-'+self.corr
        physical=Path(namespace['stage']);native_control=native_stage+'/m'
        table.write_bytes(header+row.replace(os.fsencode(physical/'m'),native_control.encode()))
        mapped=namespace['os'];base_functions={name:getattr(mapped,name) for name in ('open','stat','lstat','listdir','readlink','mkdir')}
        def translate(path):
            value=os.fspath(path)
            if value=='/tmp':return str(self.root)
            if isinstance(value,str) and (value==native_stage or value.startswith(native_stage+'/')):return str(physical)+value[len(native_stage):]
            return path
        for name,original in base_functions.items():
            def method(path,*args,_f=original,**kwargs):return _f(translate(path),*args,**kwargs)
            setattr(mapped,name,method)
        mapped.path=types.SimpleNamespace(**{name:getattr(os.path,name) for name in dir(os.path)})
        mapped.path.lexists=lambda path:os.path.lexists(translate(path))
        proc=self.root/'proc';bootfile=proc/'sys/kernel/random/boot_id';bootfile.parent.mkdir(parents=True);bootfile.write_text(channel.EXPECTED_BOOT+'\n')
        config=namespace['config_file']
        # Original source protocol currently binds these actual launch facts.
        (physical/'intent.json').write_text(json.dumps({'correlationId':self.corr,'gatewayBoot':channel.EXPECTED_BOOT,'gatewayUid':os.getuid()}));(physical/'intent.json').chmod(0o600)
        executable=self.root/'whole-check.py'
        executable.write_text('import sys,json\nif "-G" in sys.argv:sys.stdout.write("identityfile '+str(self.f.key)+'\\n")\nelif "-O" in sys.argv:sys.stderr.write("Master running (pid='+str(os.getpid())+')\\n")\nelse:print(json.dumps({"uid":1000,"boot":"'+channel.EXPECTED_BOOT+'"}))\n')
        real_popen=subprocess.Popen;facade=types.SimpleNamespace(**{name:getattr(subprocess,name) for name in dir(subprocess)})
        def popen(argv,**kw):
            self.assertEqual('ssh',argv[0]);self.assertIn(native_control,argv)
            return real_popen([sys.executable,'-I','-B',str(executable),*argv[1:]],**kw)
        facade.Popen=popen
        def run(argv,**kw):
            self.assertEqual('ssh',argv[0]);self.assertIn('-G',argv)
            return subprocess.run([sys.executable,'-I','-B',str(executable),*argv[1:]],**kw)
        facade.run=run
        remote_sys=types.SimpleNamespace(argv=['fixed',self.corr,'prepare' if prepare_collision else 'status',config,'fixture',channel._source()],stdin=types.SimpleNamespace(buffer=io.BytesIO(b'{"passphrase":"inert fixture"}' if prepare_collision else b'{}')))
        original_import=builtins.__import__
        def importing(name,*args,**kw):
            if name=='os':return mapped
            if name=='subprocess':return facade
            if name=='sys':return remote_sys
            return original_import(name,*args,**kw)
        # Exact updated original-intent DTO; all metadata facts come from the
        # genuine producer functions, with source SHA bound to current module.
        new_spec={'configFile':config,'controlPath':native_control,'remoteHostAlias':'fixture'}
        intent={'correlationId':self.corr,'gatewayBoot':channel.EXPECTED_BOOT,'gatewayUid':os.getuid(),
                'sourceSha256':channel._source(),'configPin':namespace['file_pin'](config,body=True),
                'effectiveRoute':namespace['effective_route'](new_spec)}
        (physical/'intent.json').write_text(json.dumps(intent));(physical/'intent.json').chmod(0o600)
        if foreign_member:(physical/'foreign').write_bytes(b'inert real foreign member')
        if absent:
            namespace['_test_socket'].close();(physical/'m').unlink();(physical/'intent.json').unlink();physical.rmdir();table.write_bytes(header)
        if kernel_timestamp_drift:
            original_read=mapped.read
            def read(fd,limit):
                body=original_read(fd,limit)
                if os.fstat(fd).st_ino==table.stat().st_ino:
                    info=table.stat();os.utime(table,ns=(info.st_atime_ns,info.st_mtime_ns+1000000))
                return body
            mapped.read=read
        if publication_drift:
            original_fsync=os.fsync;changed=[False]
            def drift(fd):
                original_fsync(fd)
                if (physical/'ready.json').exists() and not changed[0]:
                    changed[0]=True;Path(config).write_text(Path(config).read_text()+'# publication drift\n')
            mapped.fsync=drift
        scope={'__builtins__':{**vars(builtins),'__import__':importing}}
        output=io.StringIO();code=None
        with contextlib.redirect_stdout(output):
            try:exec(compile(channel._REMOTE,'actual-complete-channel-programme','exec'),scope)
            except SystemExit as ended:code=ended.code
        value=json.loads(output.getvalue())
        if foreign_member:
            self.assertEqual('unknown',value['state']);self.assertEqual(3,code)
        elif prepare_collision:
            self.assertEqual('unknown',value['state']);self.assertEqual('prepare_stage',value.get('failurePhase'));self.assertEqual(3,code)
        elif publication_drift:
            self.assertEqual('unknown',value['state']);self.assertEqual(3,code);self.assertTrue((physical/'ready.json').exists())
        elif absent:
            self.assertEqual('ended',value['state']);self.assertEqual(0,code);self.assertIsNone(value['prior']);self.assertFalse(physical.exists())
        else:
            self.assertEqual('ready',value['state'],value);self.assertIsNone(code)
            self.assertTrue((physical/'ready.json').is_file())
        return value

    def test_master_dto_uses_real_private_unix_socket_metadata(self):
        parent=self.root/'socket-fixture';parent.mkdir(mode=0o700);path=parent/'m'
        sock=socket.socket(socket.AF_UNIX);self.addCleanup(sock.close);sock.bind(str(path));path.chmod(0o600)
        info=path.lstat();directory=parent.lstat()
        gen=lambda s:[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
        value={'actor':{'pid':os.getpid(),'startTicks':1,'uid':os.getuid()},'socket':gen(info),
               'directory':[directory.st_dev,directory.st_ino,directory.st_mode,directory.st_uid,directory.st_gid],
               'listenerInode':'1','gatewayBoot':channel.EXPECTED_BOOT}
        self.assertTrue(channel._master_shape(value))
        for key,bad in (('pid',True),('startTicks',0),('uid',True)):
            altered={**value,'actor':{**value['actor'],key:bad}};self.assertFalse(channel._master_shape(altered))

@unittest.skipUnless(os.name=='posix' and hasattr(os,'O_NOFOLLOW'),'POSIX bounded pin')
class ProcUnixPinTests(unittest.TestCase):
    def emitted(self,facade):
        tree=ast.parse(channel._REMOTE)
        functions=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('gen','pin')]
        scope={'os':facade};exec(compile(ast.Module(body=functions,type_ignores=[]),'actual-emitted-pin','exec'),scope)
        return scope['pin']
    def trial(self,path,arm,change='timestamps'):
        # Explicit proc-path mapping seam; every FD/read/stat/mutation is real
        # on a private TempFS file. No claim this is native procfs acceptance.
        with tempfile.TemporaryDirectory() as tmp:
            leaf=Path(tmp)/'unix';leaf.write_bytes(b'bounded actual kernel table fixture\n')
            initial=leaf.stat();calls=[];facade=types.SimpleNamespace(**{n:getattr(os,n) for n in dir(os)})
            def drift():
                if change=='timestamps':os.utime(leaf,ns=(initial.st_atime_ns,initial.st_mtime_ns+1000000))
                elif change=='mode':leaf.chmod(0o640)
                elif change=='size':leaf.write_bytes(b'changed size')
                elif change=='inode':leaf.rename(leaf.with_suffix('.old'));leaf.write_bytes(b'bounded actual kernel table fixture\n')
            count=[0]
            def lstat(p):
                calls.append('lstat');count[0]+=1
                if arm=='name' and count[0]==2:drift()
                return os.lstat(leaf)
            def read(fd,n):
                calls.append('read');value=os.read(fd,n)
                if arm=='descriptor':drift()
                return value
            def fstat(fd):calls.append('fstat');return os.fstat(fd)
            facade.lstat=lstat;facade.open=lambda p,flags:os.open(leaf,flags)
            facade.read=read;facade.fstat=fstat
            body,generation=self.emitted(facade)(path)
            self.assertEqual(b'bounded actual kernel table fixture\n',body)
            self.assertEqual(9,len(generation));self.assertEqual(['lstat','read','fstat','lstat'],calls)
    def test_exact_proc_unix_timestamp_drift_descriptor_and_name(self):
        for arm in ('descriptor','name'):
            with self.subTest(arm=arm):self.trial('/proc/net/unix',arm)
    def test_regular_files_keep_timestamp_refusal(self):
        for path in ('/tmp/ready.json','/tmp/intent.json','/proc/1/stat','/proc/net/unix.other'):
            for arm in ('descriptor','name'):
                with self.subTest(path=path,arm=arm),self.assertRaisesRegex(ValueError,'changed'):self.trial(path,arm)
    def test_proc_unix_invariant_drift_refuses(self):
        for change in ('mode','size','inode'):
            for arm in ('descriptor','name'):
                # Replacing a path leaves the held original inode unchanged;
                # the exact named closing comparison still refuses it.
                with self.subTest(change=change,arm=arm),self.assertRaisesRegex(ValueError,'changed'):self.trial('/proc/net/unix',arm,change)

    def test_proc_unix_all_seven_invariant_fields_remain_strict(self):
        # UID/GID/device substitutions are explicit returned-stat fact seams;
        # the underlying open/read/descriptor and inode are real TempFS.
        for attribute in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size'):
            for arm in ('descriptor','name'):
                with self.subTest(attribute=attribute,arm=arm),tempfile.TemporaryDirectory() as tmp:
                    leaf=Path(tmp)/'unix';leaf.write_bytes(b'bounded fixture')
                    facade=types.SimpleNamespace(**{n:getattr(os,n) for n in dir(os)})
                    attributes=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
                    def alter(info):
                        value={name:getattr(info,name) for name in attributes};value[attribute]+=1
                        return types.SimpleNamespace(**value)
                    count=[0]
                    def lstat(path):
                        count[0]+=1;info=os.lstat(leaf)
                        return alter(info) if arm=='name' and count[0]==2 else info
                    facade.lstat=lstat;facade.open=lambda path,flags:os.open(leaf,flags)
                    facade.fstat=lambda fd:alter(os.fstat(fd)) if arm=='descriptor' else os.fstat(fd)
                    with self.assertRaisesRegex(ValueError,'changed'):self.emitted(facade)('/proc/net/unix')

    def test_actual_route_parent_sibling_churn_requires_declared_fixture_seam(self):
        # Execute unchanged emitted file_pin/parent_guard against real TempFS.
        # A sibling outside the owned fixture changes external size/times.
        nodes=[n for n in ast.parse(channel._REMOTE).body if isinstance(n,ast.FunctionDef) and n.name in ('generation','parent_guard','file_pin')]
        with tempfile.TemporaryDirectory(prefix='vcf-',dir=Path('/tmp').resolve()) as tmp:
            host=Path(tmp).resolve();owned=host/'owned';owned.mkdir(mode=0o700);leaf=owned/'config';leaf.write_bytes(b'inert config');leaf.chmod(0o600)
            sibling=host/'sibling0';sibling.write_bytes(b'unrelated host fixture')
            baseline=host.stat();index=[0]
            def scope(stabilize=False,mode_drift=False):
                facade=types.SimpleNamespace(**{n:getattr(os,n) for n in dir(os)})
                def fact(info):
                    if not stabilize or (info.st_dev,info.st_ino)!=(baseline.st_dev,baseline.st_ino):return info
                    values={name:getattr(info,name) for name in dir(info) if name.startswith('st_')}
                    values.update(st_size=baseline.st_size,st_mtime_ns=baseline.st_mtime_ns,st_ctime_ns=baseline.st_ctime_ns)
                    return types.SimpleNamespace(**values)
                facade.stat=lambda *a,**kw:fact(os.stat(*a,**kw));facade.fstat=lambda fd:fact(os.fstat(fd))
                changed=[False]
                def read(fd,n):
                    raw=os.read(fd,n)
                    if raw and not changed[0]:
                        changed[0]=True;previous=host/('sibling'+str(index[0]));index[0]+=1;previous.rename(host/('sibling'+str(index[0])))
                        if mode_drift:host.chmod(0o750)
                    return raw
                facade.read=read
                ns={'os':facade,'Path':Path,'stat':stat,'hashlib':hashlib,'re':__import__('re')}
                exec(compile(ast.Module(body=nodes,type_ignores=[]),'unchanged-emitted-route-pin-causal-control','exec'),ns)
                return ns
            with self.assertRaisesRegex(ValueError,'route_parent_changed'):scope()['file_pin'](str(leaf),body=True)
            # Only the declared external timestamp/size fixture seam differs;
            # leaf body and actual FD hash still execute and remain identical.
            value=scope(True)['file_pin'](str(leaf),body=True)
            self.assertEqual(hashlib.sha256(b'inert config').hexdigest(),value['sha256'])
            with self.assertRaisesRegex(ValueError,'route_parent_changed'):scope(True,True)['file_pin'](str(leaf),body=True)

if __name__=='__main__':unittest.main()
