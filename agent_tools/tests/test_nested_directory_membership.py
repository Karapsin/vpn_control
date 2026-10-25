"""Actual immutable route source and generated SSH/socket regressions."""
import ast
import copy
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import threading
import tempfile
import importlib.util
import py_compile
import time
import types
import unittest
from unittest import mock

if os.name=='posix':
    from agent_tools import readiness_nested_membership as proof
    from agent_tools import readiness_nested_channel as nested
    from agent_tools import readiness_transport as transport_ready
    from agent_tools import readiness
    from agent_tools import ssh_fresh_nested_channel as channel
    from agent_tools import ssh_transport as transport

FIXTURE=Path(__file__).parent/'fixtures/nested_directory_membership'

def before(name):
    if name not in {'ssh_fresh_nested_channel.py','readiness_nested_channel.py','readiness_nested_channel.proof-gap','readiness_transport.missing-capsule'}:
        raise ValueError('before_source_not_catalogued')
    path=FIXTURE/(name+'.before.source');raw=path.read_bytes()
    record=json.loads((FIXTURE/'provenance.json').read_bytes())['sources'][str(path.relative_to(Path(__file__).parents[2]))]
    if hashlib.sha256(raw).hexdigest()!=record['sha256']:raise ValueError('before_source_changed')
    module=types.ModuleType('agent_tools._membership_before_'+name.replace('.','_'))
    module.__package__='agent_tools';module.__file__=str(path)
    with mock.patch.dict(sys.modules,{module.__name__:module}):exec(compile(raw,str(path),'exec'),module.__dict__)
    return module


@unittest.skipUnless(os.name=='posix','POSIX generated SSH/ancestry sockets')
class MembershipTests(unittest.TestCase):
    def test_finite_comparison_excludes_all_nonmembership_changes(self):
        gen=[2,3,stat.S_IFDIR|0o700,os.getuid(),os.getgid(),2,4096,12,13]
        a={'gatewayBoot':'same','sourceSha256':'same','configPin':{'parents':[{'name':'home','generation':gen}],
            'generation':[3]*9,'sha256':'public-config'},'effectiveRoute':{'keyMetadata':{'key':{'parents':[{'name':'home','generation':gen}],'generation':[4]*9}},'ownedHomePins':{'home':gen}}}
        b=copy.deepcopy(a)
        b['configPin']['parents'][0]['generation'][5]+=1
        b['effectiveRoute']['keyMetadata']['key']['parents'][0]['generation'][7]+=1
        b['effectiveRoute']['ownedHomePins']['home'][8]+=1
        self.assertTrue(proof.membership_only(a,b));self.assertFalse(proof.membership_only(a,a))
        for path,index in ((('configPin','parents',0,'generation'),0),(('configPin','parents',0,'generation'),1),
             (('configPin','parents',0,'generation'),2),(('configPin','parents',0,'generation'),3),
             (('configPin','parents',0,'generation'),4),(('configPin','parents',0,'generation'),6),
             (('configPin','generation'),7),(('effectiveRoute','keyMetadata','key','generation'),8)):
            bad=copy.deepcopy(b);leaf=bad
            for key in path:leaf=leaf[key]
            leaf[index]+=1;self.assertFalse(proof.membership_only(a,bad),(path,index))
        for key in ('gatewayBoot','sourceSha256'):
            bad=copy.deepcopy(b);bad[key]='foreign';self.assertFalse(proof.membership_only(a,bad))
        bad=copy.deepcopy(b);bad['configPin']['sha256']='foreign';self.assertFalse(proof.membership_only(a,bad))
        bad=copy.deepcopy(b);bad['effectiveRoute']['ownedHomePins']['home'][2]=stat.S_IFREG|0o700
        self.assertFalse(proof.membership_only(a,bad))
        with self.assertRaisesRegex(ValueError,'original_source_unsupported'):proof.diagnostic_source('foreign source')

    def test_actual_whole_old_generated_snapshot_churn_red_new_green(self):
        from agent_tools.tests.test_ssh_fresh_nested_channel import FreshChannelTests
        old=before('ssh_fresh_nested_channel.py')
        for implementation,old_case in ((old,True),(channel,False)):
            case=FreshChannelTests('runTest');case.setUp()
            try:
                with mock.patch('agent_tools.tests.test_ssh_fresh_nested_channel.channel',implementation):
                    namespace,*_=case.remote_snapshot_fixture()
                namespace['snapshot']()
                (case.root/'unrelated-owned-fixture').mkdir(mode=0o700)
                if old_case:
                    with self.assertRaisesRegex(ValueError,'config_or_keys_changed'):namespace['snapshot']()
                else:
                    namespace['snapshot']()
                    for i in range(3):(case.root/('next-fixture-'+str(i))).mkdir(mode=0o700);namespace['snapshot']()
                    case.f.key.write_bytes(case.f.key.read_bytes()+b'!')
                    with self.assertRaisesRegex(ValueError,'config_or_keys_changed'):namespace['snapshot']()
            finally:case.doCleanups()

    def test_new_generated_ancestor_mode_replacement_and_leaf_config_refuse(self):
        from agent_tools.tests.test_ssh_fresh_nested_channel import FreshChannelTests
        for attack in ('mode','replacement','config'):
            with self.subTest(attack=attack):
                case=FreshChannelTests('runTest');case.setUp()
                try:
                    ns,*_=case.remote_snapshot_fixture();ns['snapshot']()
                    if attack=='mode':case.root.chmod(0o750)
                    elif attack=='replacement':
                        # Exact pathname ancestor replacement while retaining
                        # its original contents and modes still changes inode.
                        config=Path(ns['config_file']);saved=config.with_name('old-config')
                        config.rename(saved);config.write_bytes(saved.read_bytes());config.chmod(0o600)
                    else:Path(ns['config_file']).write_text('Host foreign\n')
                    with self.assertRaises(ValueError):ns['snapshot']()
                finally:case.doCleanups()

    def test_actual_timestamp_cached_comparator_full_original_proof_red_current_blocked(self):
        import agent_tools
        from agent_tools.tests.test_ssh_direct_nested_channel import DirectChannelTests
        original_remote=before('ssh_fresh_nested_channel.py')._REMOTE
        case=DirectChannelTests('runTest')
        with mock.patch.object(channel,'_REMOTE',original_remote):case.setUp();ready=case.invoke()
        self.addCleanup(case.doCleanups);prior=case.result;old=case.corr;real_popen=case.real_popen
        with mock.patch.object(subprocess,'Popen',side_effect=case.consumer):nested.admit(case.root,'archlinux',old,ready['receiptSha256'])
        with tempfile.TemporaryDirectory(dir=case.root)as temporary:
            folder=Path(temporary);folder.chmod(0o700);path=folder/'readiness_nested_membership.py'
            authentic=Path(proof.__file__).read_bytes();needle=b'return same(original,current)and changed'
            poisoned=authentic.replace(needle,b'return True'.ljust(len(needle)));self.assertNotEqual(authentic,poisoned)
            self.assertEqual(len(authentic),len(poisoned));path.write_bytes(poisoned);info=path.stat()
            py_compile.compile(str(path),doraise=True)
            path.write_bytes(authentic);os.utime(path,ns=(info.st_atime_ns,info.st_mtime_ns));path.chmod(0o600)
            spec=importlib.util.spec_from_file_location('agent_tools._actual_stale_membership',path)
            stale=importlib.util.module_from_spec(spec);spec.loader.exec_module(stale)
            self.assertTrue(stale.membership_only({'config':'original'},{'config':'foreign'}))
            source_key=json.loads((channel._context_journal(case.root,'archlinux',old,False,True)/(old+'.intent.json')).read_bytes())['sourceSha256']
            evidence={'state':'directory_membership_changed','correlationId':old,'gatewayBoot':prior['master']['gatewayBoot'],
                'sourceSha256':source_key,'originalIntentSha256':'a'*64,'currentIntentSha256':'b'*64}
            refused={'state':'unknown','correlationId':old,'failurePhase':'remote_intent','failureReason':'remote_intent_changed','exceptionClass':'ValueError','errno':None,'launchCapture':None}
            calls=[]
            def endpoint(argv,**kw):
                source=ast.literal_eval(ast.parse(shlex.split(argv[-1])[4],mode='eval').body.args[0]);calls.append(source)
                if source==original_remote:
                    code='import sys;sys.stdin.buffer.read();print('+repr(json.dumps(refused))+');raise SystemExit(3)'
                else:
                    self.assertEqual(stale.diagnostic_source(original_remote),source)
                    # The actual poisoned emitted comparator executes in a
                    # real child. Kernel/SSH endpoint metadata is the declared
                    # seam; a changed config hash is deliberately not allowed.
                    node=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef)and n.name=='membership_only')
                    lines=source.splitlines(keepends=True);function=''.join(lines[node.lineno-1:node.end_lineno])
                    code='import sys,stat,json;sys.stdin.buffer.read()\n'+function+'\nassert membership_only({"config":"original"},{"config":"foreign"})\nprint('+repr(json.dumps(evidence))+')'
                return real_popen([sys.executable,'-I','-B','-c',code],**kw)
            for current in (False,True):
                raw=Path(nested.__file__).read_bytes()if current else(FIXTURE/'readiness_nested_channel.before-code-guard.source').read_bytes()
                module_path=folder/('current.py'if current else'before.py');module_path.write_bytes(raw);module_path.chmod(0o600)
                module=types.ModuleType('agent_tools._whole_membership_cached_'+str(current));module.__package__='agent_tools';module.__file__=str(module_path)
                with mock.patch.object(agent_tools,'readiness_nested_membership',stale),mock.patch.dict(sys.modules,{'agent_tools.readiness_nested_membership':stale,module.__name__:module}),mock.patch.object(subprocess,'Popen',side_effect=endpoint):
                    exec(compile(raw,str(module_path),'exec',dont_inherit=True),module.__dict__)
                    count=len(calls)
                    if current:
                        with self.assertRaisesRegex(ValueError,'executing_code_changed'):
                            with module.membership_successor(case.root,'archlinux',old,ready['receiptSha256'],time.monotonic()+10):self.fail('cached code issued a proof')
                        self.assertEqual(count,len(calls))
                    else:
                        with module.membership_successor(case.root,'archlinux',old,ready['receiptSha256'],time.monotonic()+10):pass
                        self.assertEqual(count+2,len(calls))

    def test_existing_candidate_missing_capsule_whole_before_replaces_red_current_blocks(self):
        from agent_tools.tests.test_ssh_direct_nested_channel import DirectChannelTests
        for unsafe in (True,False):
            with self.subTest(unsafe=unsafe):
                case=DirectChannelTests('runTest');case.setUp()
                try:
                    module=before('readiness_transport.missing-capsule')if unsafe else transport_ready
                    source_folder=case.root/'controller-source';source_folder.mkdir(mode=0o700)
                    for name in ('readiness_transport.py','readiness_nested_channel.py','readiness_nested_membership.py','ssh_direct_nested_channel.py','ssh_fresh_nested_channel.py'):
                        source=Path(transport_ready.__file__).with_name(name).read_bytes()
                        if unsafe and name=='readiness_transport.py':source=(FIXTURE/'readiness_transport.missing-capsule.before.source').read_bytes()
                        (source_folder/name).write_bytes(source);(source_folder/name).chmod(0o600)
                    if unsafe:module.__file__=str(source_folder/'readiness_transport.py')
                    adapter=module.TransportAdapter(case.root,'archlinux');directory=adapter._campaign('archlinux')
                    pins={p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in source_folder.iterdir()}
                    rid='a'*64;candidate={'version':2,'recoveryId':rid,'host':'archlinux',
                        'correlationId':hashlib.sha256((rid+'archlinux').encode()).hexdigest()[:32],'ownerSources':pins}
                    for name in ('current.json',rid+'.intent.json'):
                        path=directory/name;path.write_text(json.dumps(candidate,sort_keys=True));path.chmod(0o600)
                    for name in pins:
                        path=directory/(rid+'.'+name+'.source');path.write_bytes((source_folder/name).read_bytes());path.chmod(0o600)
                    (directory/(rid+'.readiness_nested_membership.py.source')).unlink()
                    with transport_ready.private.Directory(directory)as opened,transport_ready.master.Lock(opened):pass
                    retained={p.name:p.read_bytes()for p in directory.iterdir()}
                    observed=readiness.Observation('archlinux',adapter.machine,transport='unavailable',trusted=True,integrity=True)
                    with mock.patch.object(subprocess,'Popen',side_effect=case.consumer):
                        if unsafe:
                            try:adapter.recover('reconnect','b'*64,observed,time.monotonic()+10)
                            except (readiness.AdapterBlocked,FileNotFoundError):pass
                            self.assertTrue(case.calls,'unfixed complete caller must actually dispatch replacement')
                            self.assertNotEqual(retained['current.json'],(directory/'current.json').read_bytes())
                        else:
                            with self.assertRaises(FileNotFoundError):adapter.recover('reconnect','b'*64,observed,time.monotonic()+10)
                            self.assertEqual([],case.calls)
                            self.assertEqual(retained,{p.name:p.read_bytes()for p in directory.iterdir()})
                finally:case.doCleanups()

    def test_candidate_semantic_drift_and_post_observer_replacement_never_grant_ready(self):
        from agent_tools.tests.test_ssh_direct_nested_channel import DirectChannelTests
        for unsafe,phase in ((True,'route'),(False,'route'),(True,'admit'),(False,'admit')):
            with self.subTest(unsafe=unsafe,phase=phase):
                case=DirectChannelTests('runTest');case.setUp()
                try:
                    module=before('readiness_transport.missing-capsule')if unsafe else transport_ready
                    adapter=module.TransportAdapter(case.root,'archlinux');folder=adapter._campaign('archlinux')
                    rid='a'*64;names=('readiness_transport.py','readiness_nested_channel.py','readiness_nested_membership.py','ssh_direct_nested_channel.py','ssh_fresh_nested_channel.py')
                    candidate={'version':2,'recoveryId':rid,'host':'archlinux','correlationId':hashlib.sha256((rid+'archlinux').encode()).hexdigest()[:32],
                        'ownerSources':{name:hashlib.sha256(('public source '+name).encode()).hexdigest()for name in names}}
                    for name in ('current.json',rid+'.intent.json'):
                        path=folder/name;path.write_text(json.dumps(candidate));path.chmod(0o600)
                    for name in names:
                        path=folder/(rid+'.'+name+'.source');path.write_text('public source '+name);path.chmod(0o600)
                    watched=folder/(rid+'.readiness_nested_membership.py.source')
                    def replace_capture(*args,**kw):
                        tmp=watched.with_name('replacement');tmp.write_bytes(watched.read_bytes());tmp.chmod(0o600);tmp.replace(watched)
                        return {'correlationId':candidate['correlationId']}if phase=='route' else{'state':'selected'}
                    observed=readiness.Observation('archlinux',adapter.machine,transport='unavailable',trusted=True,integrity=True)
                    with mock.patch.object(module.nested_ready,'present',return_value=phase=='route'),mock.patch.object(module.nested_ready,'route_options',side_effect=replace_capture),mock.patch.object(module.direct,'status',return_value={'state':'ready','receiptSha256':'f'*64}),mock.patch.object(module.nested_ready,'admit',side_effect=replace_capture):
                        if unsafe:self.assertIs(True,adapter.reconcile_recovery('reconnect',rid,observed,time.monotonic()+10,1,'a'*64))
                        else:
                            with self.assertRaises(ValueError):adapter.reconcile_recovery('reconnect',rid,observed,time.monotonic()+10,1,'a'*64)
                    # All wrong candidate meanings must be rejected before an
                    # owner/status/selection boundary, even with valid JSON.
                    current=transport_ready.TransportAdapter(case.root,'archlinux')
                    with transport_ready.private.Directory(folder)as directory:
                        for change in ('host','correlation','rid','catalog','digest','boolversion','intent'):
                            value=copy.deepcopy(candidate)
                            if change=='host':value['host']='foreign'
                            elif change=='correlation':value['correlationId']='d'*32
                            elif change=='rid':value['recoveryId']='c'*64
                            elif change=='catalog':value['ownerSources'].pop(names[0])
                            elif change=='digest':value['ownerSources'][names[0]]='g'*64
                            elif change=='boolversion':value['version']=True
                            else:value['ownerSources'][names[0]]='0'*64
                            with ExitStack()as stack,self.assertRaises(readiness.AdapterBlocked):current._candidate_guard(directory,value,'archlinux',stack)
                finally:case.doCleanups()

    def test_complete_original_caller_only_positive_membership_proof_renews_once(self):
        from agent_tools.tests.test_ssh_direct_nested_channel import DirectChannelTests
        original_remote=before('ssh_fresh_nested_channel.py')._REMOTE
        case=DirectChannelTests('runTest')
        with mock.patch.object(channel,'_REMOTE',original_remote):case.setUp();ready=case.invoke()
        self.addCleanup(case.doCleanups)
        old=case.corr;prior=case.result;actual_popen=case.real_popen
        original_source=json.loads((channel._context_journal(case.root,'archlinux',old,False,True)/(old+'.intent.json')).read_bytes())['sourceSha256']
        refusal={'state':'unknown','correlationId':old,'failurePhase':'remote_intent','failureReason':'remote_intent_changed','exceptionClass':'ValueError','errno':None,'launchCapture':None}
        evidence={'state':'directory_membership_changed','correlationId':old,'gatewayBoot':prior['master']['gatewayBoot'],
            'sourceSha256':original_source,'originalIntentSha256':'a'*64,'currentIntentSha256':'b'*64}
        old_calls=[];new_calls=[];probe_calls=[];drift=[False];recover_errors=[]
        original_prepare=transport_ready.direct.prepare
        def traced_prepare(*args,**kw):
            value=original_prepare(*args,**kw);recover_errors.append(value);return value
        original_recover=transport_ready.TransportAdapter.recover
        def traced_recover(*args,**kw):
            try:return original_recover(*args,**kw)
            except Exception as error:
                import traceback
                recover_errors.append(traceback.format_exc());raise
        diagnostic=proof.diagnostic_source(original_remote)
        def consumer(argv,**kwargs):
            remote=shlex.split(argv[-1]);body=None
            if remote[0]=='python3' and len(remote)>6:
                source=ast.literal_eval(ast.parse(remote[4],mode='eval').body.args[0]);corr=remote[5];action=remote[6]
                if corr==old:
                    self.assertEqual('status',action);self.assertIn(source,(original_remote,diagnostic));old_calls.append(source)
                    body=evidence if source==diagnostic else(refusal if drift[0] else prior)
                else:
                    self.assertEqual(channel._REMOTE,source);new_calls.append(action)
                    body={**prior,'correlationId':corr,'controlPath':'/tmp/vpn-channel-'+corr+'/m'}
                code=0 if body is not refusal else 3
            else:
                probe_calls.append(argv)
                user=transport.load_config(case.root).hosts['archlinux'].user
                body={'boot':prior['arch']['boot'],'uid':1000,'principal':user,'home':'/owned','connection':'192.0.2.1 1000 192.0.2.2 22'};code=0
            program='import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]));raise SystemExit(int(sys.argv[2]))'
            # Popen remains real: original source-bound complete callers,
            # framing, concurrent coordinator locks and schema guards run.
            return actual_popen([sys.executable,'-I','-B','-c',program,json.dumps(body).encode().hex(),str(code)],**kwargs)
        with mock.patch.object(subprocess,'Popen',side_effect=consumer),mock.patch.object(transport_ready.TransportAdapter,'recover',new=traced_recover),mock.patch.object(transport_ready.direct,'prepare',new=traced_prepare):
            # Install only the original positive ready receipt, before the
            # declared endpoint changes its public status to strict UNKNOWN.
            nested.admit(case.root,'archlinux',old,ready['receiptSha256'])
            # An expired budget may not start even the original observer.
            gap=before('readiness_nested_channel.proof-gap')
            count=len(old_calls)
            try:gap._original(case.root,'archlinux',old,ready['receiptSha256'],time.monotonic()-1)
            except gap.NestedUnknown:pass
            self.assertGreater(len(old_calls),count)
            count=len(old_calls)
            with self.assertRaises(nested.NestedUnknown):nested._original(case.root,'archlinux',old,ready['receiptSha256'],time.monotonic()-1)
            self.assertEqual(count,len(old_calls))
            drift[0]=True
            # Replace the same exact ready bytes at the actual first record-FD
            # close: the old code reopened and accepted a new generation.
            journal=channel._context_journal(case.root,'archlinux',old,False,True)
            for module,unsafe in ((gap,True),(nested,False)):
                for attack in ('ready','pointer'):
                    watch=[None];changed=[False];real_open=os.open;real_close=os.close
                    target=journal/(old+'.ready.json') if attack=='ready' else nested.directory(case.root,'archlinux')/'current.json'
                    body=target.read_bytes()
                    def opening(path,*args,**kwargs):
                        fd=real_open(path,*args,**kwargs)
                        if str(path)==old+'.ready.json' and watch[0]is None:watch[0]=fd
                        return fd
                    def closing(fd):
                        real_close(fd)
                        if fd==watch[0] and not changed[0]:
                            changed[0]=True;replacement=target.with_name(target.name+'.replacement')
                            replacement.write_bytes(body);replacement.chmod(0o600);os.replace(replacement,target)
                    with mock.patch.object(os,'open',side_effect=opening),mock.patch.object(os,'close',side_effect=closing):
                        if unsafe:
                            with module.membership_successor(case.root,'archlinux',old,ready['receiptSha256'],time.monotonic()+10):pass
                        else:
                            with self.assertRaises(ValueError):
                                with module.membership_successor(case.root,'archlinux',old,ready['receiptSha256'],time.monotonic()+10):self.fail('replaced generation issued proof')
                    self.assertTrue(changed[0])
            # Every other unresolved connection intent remains a hard fence.
            foreign=journal/('9'*32+'.intent.json')
            foreign.write_text(json.dumps({'host':'archlinux','correlationId':'9'*32}));foreign.chmod(0o600)
            new_count=len(new_calls)
            blocked=transport_ready.direct.prepare_successor(case.root,'archlinux','8'*32,old,ready['receiptSha256'],deadline=time.monotonic()+10)
            self.assertEqual('unknown',blocked['state']);self.assertEqual(new_count,len(new_calls))
            foreign.unlink()  # Synthetic unsubmitted fixture record only.

            old_reader=before('readiness_nested_channel.py')
            with self.assertRaises(old_reader.NestedUnknown):old_reader.route_options(case.root,'archlinux')
            with self.assertRaises(nested.DirectoryMembershipChanged):nested.route_options(case.root,'archlinux')
            legacy=case.root/'.rag_index/readiness-transport/archlinux'
            legacy.mkdir(mode=0o700,parents=True)
            old_campaign={'recoveryId':'c'*64,'correlationId':'d'*32,'host':'archlinux'}
            retained={}
            for name in ('current.json','legacy.intent.json'):
                path=legacy/name;path.write_text(json.dumps(old_campaign,sort_keys=True));path.chmod(0o600);retained[name]=path.read_bytes()
            results=[];errors=[];operation='b8ed214e-b76d-4e91-bda1-1344606b0109'
            operations=[operation,'fc67051b-7976-4fb5-bdad-575551021f20','76661036-58f8-4577-bd1c-de52cad0de53']
            def work(operation):
                try:
                    ctx=transport_ready.context(case.root,'archlinux',deadline=time.monotonic()+20,sleep=lambda _:None)
                    results.append(readiness.ensure_ready(ctx,readiness.Requirements(frozenset({'transport'}),frozenset({'reconnect'})),operation))
                except BaseException as error:
                    import traceback
                    errors.append((type(error).__name__,str(error),traceback.format_exc()))
            threads=[threading.Thread(target=work,args=(op,))for op in operations]
            for thread in threads:thread.start()
            for thread in threads:thread.join(25);self.assertFalse(thread.is_alive())
            self.assertEqual([],errors,(errors,recover_errors,new_calls,len(probe_calls)));self.assertEqual(3,len(results));self.assertEqual(1,new_calls.count('prepare'))
            self.assertEqual(1,len({result.connection for result in results}));self.assertTrue(probe_calls)
            self.assertEqual(set(operations),{result.operation_identity for result in results})
            self.assertEqual(retained,{path.name:path.read_bytes()for path in legacy.iterdir()})
            before_count=len(new_calls)
            ctx=transport_ready.context(case.root,'archlinux',deadline=time.monotonic()+10)
            readiness.ensure_ready(ctx,readiness.Requirements(frozenset({'transport'}),frozenset({'reconnect'})),operation)
            self.assertEqual(1,new_calls.count('prepare'));self.assertGreaterEqual(len(new_calls),before_count)
        self.assertTrue((channel._context_journal(case.root,'archlinux',old,False,True)/(old+'.ready.json')).exists())
        self.assertFalse((channel._context_journal(case.root,'archlinux',old,False,True)/(old+'.terminal.json')).exists())
        case.assert_legacy_unchanged()


if __name__=='__main__':unittest.main()
