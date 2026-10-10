"""Routine coverage for the fixed privileged AVD holder observation."""
import ast
import hashlib
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock
from agent_tools import android_avd_launch_recovery as recovery

class PrivilegedCensusTests(unittest.TestCase):
    def scope(self,*names):
        nodes=[n for n in ast.parse(recovery._CENSUS).body if isinstance(n,(ast.Import,ast.ImportFrom)) or isinstance(n,ast.FunctionDef) and n.name in set(names)|{'parent_fds','guard_parents','close_parents'}]
        scope={};exec(compile(ast.Module(body=nodes,type_ignores=[]),'<actual-privileged-avd-census>','exec'),scope)
        if 'write_capsule' in names:
            # APFS counts regular children in directory nlink; the target Linux
            # filesystem counts directory links. Model that native invariant.
            import stat
            proxy=types.SimpleNamespace(**vars(os))
            def linux_directory_links(info):
                if not stat.S_ISDIR(info.st_mode):return info
                fields=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode','st_uid','st_gid','st_nlink')
                value=types.SimpleNamespace(**{key:getattr(info,key) for key in fields});value.st_nlink=2;return value
            proxy.fstat=lambda fd:linux_directory_links(os.fstat(fd))
            proxy.stat=lambda *args,**kwargs:linux_directory_links(os.stat(*args,**kwargs))
            scope['os']=proxy
        return scope
    def test_measured_incomplete_unprivileged_census_requires_new_observation(self):
        self.assertTrue(callable(recovery.prepare_privileged_census))
        self.assertFalse(hasattr(recovery,'launch'))
    def test_actual_fd_reader_same_bytes_replacement_rejects(self):
        scope=self.scope('fp','read_fixed');real=os.read;swapped=[]
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp).resolve()/'disk';path.write_bytes(b'disk')
            def swap(fd,n):
                raw=real(fd,n)
                if not swapped:path.rename(path.with_name('old'));path.write_bytes(b'disk');swapped.append(True)
                return raw
            with mock.patch.object(scope['os'],'read',side_effect=swap),self.assertRaisesRegex(ValueError,'census_file_changed'):scope['read_fixed'](path,4)
    def test_actual_header_hash_does_not_claim_full_disk_hash(self):
        scope=self.scope('fp','read_fixed')
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp).resolve()/'disk';path.write_bytes(b'disk'*100)
            value=scope['read_fixed'](path,16)
            self.assertEqual('prefix',value['hashScope']);self.assertEqual(16,value['bytesRead'])
    def proc_fixture(self,tmp,command=b'normal\0'):
        proc=Path(tmp)/'proc';proc.mkdir();p=proc/'17';p.mkdir();(p/'fd').mkdir();(p/'cmdline').write_bytes(command)
        return proc,p
    def test_actual_privileged_census_permission_denial_is_incomplete(self):
        scope=self.scope('process_census');scope['ticks']=lambda _:10
        with tempfile.TemporaryDirectory() as tmp:
            proc,p=self.proc_fixture(tmp);scope['PROC']=proc
            real=Path.iterdir
            def denied(path):
                if path==p/'fd':raise PermissionError('fixture')
                return real(path)
            with mock.patch.object(Path,'iterdir',denied):value=scope['process_census']({})
            self.assertFalse(value['complete']);self.assertEqual(1,value['unreadableProcessCount'])
    def test_actual_pid_reuse_rejects(self):
        scope=self.scope('process_census');scope['ticks']=mock.Mock(side_effect=[10,11])
        with tempfile.TemporaryDirectory() as tmp:
            proc,p=self.proc_fixture(tmp);scope['PROC']=proc
            with self.assertRaisesRegex(ValueError,'census_pid_reused'):scope['process_census']({})
    def test_actual_qemu_and_foreign_holder_are_positive_facts(self):
        scope=self.scope('process_census');scope['ticks']=lambda _:10
        with tempfile.TemporaryDirectory() as tmp:
            proc,p=self.proc_fixture(tmp,b'/fixed/qemu-system-x86_64\0-avd\0foreign\0');scope['PROC']=proc
            disk=Path(tmp)/'disk';disk.write_bytes(b'disk');(p/'fd'/'7').symlink_to(disk);i=disk.stat()
            value=scope['process_census']({(i.st_dev,i.st_ino):['api29/disk']})
            self.assertEqual(['api29/disk'],value['holders'][0]['files']);self.assertEqual(17,value['emulators'][0]['pid'])
    def test_actual_owned_tree_rejects_symlink_descendant(self):
        scope=self.scope('fp','read_fixed','tree_facts')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'disk').symlink_to('/foreign/disk')
            normal=os.fstat
            def owned(fd):
                info=normal(fd);fields=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode','st_uid','st_gid','st_nlink');value=types.SimpleNamespace(**{key:getattr(info,key) for key in fields});value.st_uid=1000 if (info.st_dev,info.st_ino)==(root.stat().st_dev,root.stat().st_ino) else info.st_uid;return value
            # Parent named generations must agree with the controlled descriptor owner.
            guard=scope['guard_parents'];scope['guard_parents']=lambda chain:None
            with mock.patch.object(scope['os'],'fstat',side_effect=owned),self.assertRaisesRegex(ValueError,'census_tree_type'):scope['tree_facts'](root.resolve())

    def test_authority_remains_false_even_complete_stable_census(self):
        scope=self.scope('summary');value={'bootId':'boot','avds':{},'ports':[],'processes':{'complete':True,'holders':[],'emulators':[]}}
        result=scope['summary']([value,value]);self.assertTrue(result['complete']);self.assertFalse(result['lifecycleAllowed']);self.assertFalse(result['productAdmitted'])
    def test_lease_drift_is_rejected_by_actual_fixed_guard(self):
        scope=self.scope('guard_proof');proof={'observations':[{'bootId':'boot','claims':{'api29':{'present':True,'generation':[1]}}}]};scope['boot']=lambda:'boot';scope['facts']=lambda *args:{'present':True,'generation':[2]};scope['ROOT']=Path('/fixed')
        with self.assertRaisesRegex(ValueError,'census_claim_changed'):scope['guard_proof'](proof)
    def test_actual_generated_program_refuses_unprivileged_dispatch(self):
        program=recovery._CENSUS.replace('__CFG__',repr({'correlationId':'new'}))
        with mock.patch('os.getuid',return_value=1000),mock.patch('os.geteuid',return_value=1000),self.assertRaisesRegex(ValueError,'census_privileged_principal_required'):exec(compile(program,'<actual-composed-census>','exec'),{})
    def test_actual_port_reader_retains_foreign_binding(self):
        scope=self.scope('ports')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'net').mkdir();(root/'net/tcp').write_text('header\n0: 0100007F:1634 00000000:0000 0A 0:0 0:0 0 1000 0 999\n');(root/'net/tcp6').write_text('header\n');scope['PROC']=root
            self.assertEqual(5684,scope['ports']()[0]['port'])
    def test_local_claim_replacement_is_rejected_before_dispatch(self):
        from agent_tools import android_endpoint_admission as endpoint
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp).resolve()/'claim';path.write_text('{}');path.chmod(0o600);pin=endpoint._recovery_local_snapshot(path)
            prepared={'snapshots':{},'claims':{path:pin}};path.rename(path.with_name('old'));path.write_text('{}');path.chmod(0o600)
            with self.assertRaisesRegex(ValueError,'census_local_claim_changed'):recovery.guard_prepared(prepared)
    def test_actual_reader_ancestor_move_and_symlink_route_rejects(self):
        scope=self.scope('fp','read_fixed','parent_fds','guard_parents','close_parents');normal=os.read;swapped=[]
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp).resolve();route=base/'route';route.mkdir();path=route/'disk';path.write_bytes(b'disk')
            def swap(fd,n):
                raw=normal(fd,n)
                if not swapped:route.rename(base/'moved');route.symlink_to(base/'moved',target_is_directory=True);swapped.append(True)
                return raw
            with mock.patch.object(scope['os'],'read',side_effect=swap),self.assertRaisesRegex(ValueError,'census_(ancestry|file)_changed'):scope['read_fixed'](path,4)
    def test_actual_reader_parent_full_generation_drift_rejects(self):
        scope=self.scope('fp','read_fixed');normal=os.read;changed=[]
        with tempfile.TemporaryDirectory() as tmp:
            route=Path(tmp).resolve();path=route/'disk';path.write_bytes(b'disk')
            def change(fd,n):
                raw=normal(fd,n)
                if not changed:(route/'new-entry').write_bytes(b'new');changed.append(True)
                return raw
            with mock.patch.object(scope['os'],'read',side_effect=change),self.assertRaisesRegex(ValueError,'census_ancestry_changed'):scope['read_fixed'](path,4)
    def test_actual_capsule_create_uses_held_root_and_rejects_route_exchange(self):
        scope=self.scope('fp','write_capsule');real=os.open
        name='android-avd-privileged-census-11111111-1111-4111-8111-111111111111.json'
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp).resolve();route=base/'route';route.mkdir();foreign=base/'foreign';foreign.mkdir();chain,unused=scope['parent_fds'](route/'held-root');swapped=[]
            def exchange(path,flags,*args,**kwargs):
                if path==name and not swapped:route.rename(base/'moved');route.symlink_to(foreign,target_is_directory=True);swapped.append(True)
                return real(path,flags,*args,**kwargs)
            try:
                with mock.patch.object(scope['os'],'open',side_effect=exchange),self.assertRaisesRegex(ValueError,'census_ancestry_changed'):scope['write_capsule'](chain,name,b'private')
            finally:scope['close_parents'](chain)
            self.assertFalse((foreign/name).exists());self.assertEqual(b'',(base/'moved'/name).read_bytes())
    def test_actual_capsule_create_retains_named_parent_and_private_mode(self):
        scope=self.scope('fp','write_capsule');name='android-avd-privileged-census-11111111-1111-4111-8111-111111111111.json'
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();chain,unused=scope['parent_fds'](root/'held-root')
            try:scope['write_capsule'](chain,name,b'private');scope['guard_parents'](chain)
            finally:scope['close_parents'](chain)
            self.assertEqual(b'private',(root/name).read_bytes());self.assertEqual(0o600,(root/name).stat().st_mode&0o777)
    def test_actual_capsule_create_parent_permission_drift_rejects(self):
        scope=self.scope('fp','write_capsule');real=os.open;name='android-avd-privileged-census-11111111-1111-4111-8111-111111111111.json'
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();root.chmod(0o700);chain,unused=scope['parent_fds'](root/'held-root')
            def exchange(path,flags,*args,**kwargs):
                fd=real(path,flags,*args,**kwargs)
                if path==name:root.chmod(0o777)
                return fd
            try:
                with mock.patch.object(scope['os'],'open',side_effect=exchange),self.assertRaisesRegex(ValueError,'census_parent_changed'):scope['write_capsule'](chain,name,b'private')
            finally:scope['close_parents'](chain)
            self.assertEqual(b'',(root/name).read_bytes())

# Exact consumed _CENSUS.read_fixed from module SHA eb89ef4cccdb5417becd02b4116eccd10b2e4da4d9fe81f3a8c54d8f97b13fa0.
# The snapshot is routine-only causal evidence; production uses the current reader.
_LEGACY_READ_FIXED_SOURCE = "def read_fixed(path,limit):\n chain,name=parent_fds(path);fd=None\n try:\n  fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=chain[-1]['fd']);before=os.fstat(fd)\n  if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1:raise ValueError('census_file_type')\n  count=min(before.st_size,limit);raw=b''\n  while len(raw)<count:\n   part=os.read(fd,min(count-len(raw),65536))\n   if not part:break\n   raw+=part\n  if len(raw)!=count or fp(before)!=fp(os.fstat(fd)) or fp(before)!=fp(os.stat(name,dir_fd=chain[-1]['fd'],follow_symlinks=False)):raise ValueError('census_file_changed')\n  guard_parents(chain)\n  return {'generation':fp(before),'bytesRead':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'hashScope':'full' if len(raw)==before.st_size else 'prefix','raw':raw}\n finally:\n  if fd is not None:os.close(fd)\n  close_parents(chain)"


class FixedReaderAccumulationTests(unittest.TestCase):
    # A repo-local disposable subtree keeps real ancestor checks away from
    # unrelated system temp siblings. All parent/file guards remain unchanged.
    def scope(self, legacy=False):
        names={'fp','parent_fds','guard_parents','close_parents','read_fixed'}
        nodes=[n for n in ast.parse(recovery._CENSUS).body
               if isinstance(n,(ast.Import,ast.ImportFrom)) or
               isinstance(n,ast.FunctionDef) and n.name in names]
        if legacy:
            self.assertEqual(hashlib.sha256(_LEGACY_READ_FIXED_SOURCE.encode()).hexdigest(),
                             '5f57e1e31522f84b8cb327d7ae21a43f091a2549b7a649764e3822b32b2e33a2')
            old=ast.parse(_LEGACY_READ_FIXED_SOURCE).body[0]
            nodes=[old if isinstance(n,ast.FunctionDef) and n.name=='read_fixed' else n for n in nodes]
        scope={}
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'<actual-census-fd-reader>','exec',dont_inherit=True),scope)
        return scope

    def counted_read(self,scope,path):
        # Only payload subtype instrumentation: every byte comes from real
        # os.read on the actual held FD. All file/name/ancestry checks are real.
        # This counts growing immutable concatenations, not elapsed time or
        # allocator behaviour. Plain-byte semantic tests are separate below.
        class Chunk(bytes):
            prefix_bytes=0
            def __add__(self,other):
                Chunk.prefix_bytes+=len(self)+len(other)
                return Chunk(bytes(self)+bytes(other))
            def __radd__(self,other):
                Chunk.prefix_bytes+=len(other)+len(self)
                return Chunk(bytes(other)+bytes(self))
        real=os.read;reads=[]
        proxy=types.SimpleNamespace(**vars(os))
        def read(fd,count):
            raw=real(fd,count);reads.append((count,len(raw)));return Chunk(raw)
        proxy.read=read;scope['os']=proxy
        value=scope['read_fixed'](path,path.stat().st_size)
        return value,reads,Chunk.prefix_bytes

    def test_real_fd_reconstruction_has_linear_growth(self):
        size=4*1024*1024;payload=bytes(range(256))*(size//256)
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as tmp:
            path=Path(tmp).resolve()/'large';path.write_bytes(payload)
            old,old_reads,old_cost=self.counted_read(self.scope(True),path)
            current,reads,cost=self.counted_read(self.scope(),path)
            self.assertEqual(old_reads,reads)
            self.assertEqual(old,current)
            self.assertEqual(payload,current['raw'])
            self.assertEqual(hashlib.sha256(payload).hexdigest(),current['sha256'])
            self.assertEqual(64,len(reads))
            self.assertGreater(old_cost,size*16)
            self.assertLessEqual(cost,size*2)

    def test_actual_plain_bytes_full_prefix_empty_and_boundaries_match(self):
        payload=bytes(range(256))*257
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as tmp:
            path=Path(tmp).resolve()/'data';path.write_bytes(payload)
            for limit in (0,1,65535,65536,65537,len(payload),len(payload)+1):
                with self.subTest(limit=limit):
                    old=self.scope(True)['read_fixed'](path,limit)
                    current=self.scope()['read_fixed'](path,limit)
                    self.assertEqual(old,current)
                    self.assertIs(type(current['raw']),bytes)
                    self.assertEqual(payload[:limit],current['raw'])
                    self.assertEqual('full' if limit>=len(payload) else 'prefix',current['hashScope'])
            empty=path.with_name('empty');empty.write_bytes(b'')
            self.assertEqual(self.scope(True)['read_fixed'](empty,1),self.scope()['read_fixed'](empty,1))

    def test_actual_partial_reads_and_early_eof(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as tmp:
            path=Path(tmp).resolve()/'data';payload=b'abcdefgh'*1000;path.write_bytes(payload)
            for legacy in (True,False):
                scope=self.scope(legacy);proxy=types.SimpleNamespace(**vars(os))
                proxy.read=lambda fd,count:os.read(fd,min(count,7));scope['os']=proxy
                self.assertEqual(payload,scope['read_fixed'](path,len(payload))['raw'])
                calls=[]
                def eof(fd,count):
                    if calls:return b''
                    calls.append(True);return os.read(fd,min(count,7))
                proxy.read=eof
                with self.assertRaisesRegex(ValueError,'census_file_changed'):
                    scope['read_fixed'](path,len(payload))

    def test_actual_file_and_parent_drift_still_refuse(self):
        for change in ('file','parent'):
            with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as tmp:
                root=Path(tmp).resolve();path=root/'data';path.write_bytes(b'bytes'*100)
                scope=self.scope();proxy=types.SimpleNamespace(**vars(os));changed=[]
                def read(fd,count):
                    raw=os.read(fd,count)
                    if not changed:
                        changed.append(True)
                        if change=='file':path.rename(root/'original');path.write_bytes(b'bytes'*100)
                        else:(root/'new-entry').write_bytes(b'new')
                    return raw
                proxy.read=read;scope['os']=proxy
                with self.assertRaisesRegex(ValueError,'census_(file|ancestry)_changed'):
                    scope['read_fixed'](path,500)

    def test_diagnostic_deliberate_source_mismatch_refuses_before_prepare(self):
        from agent_tools import android_avd_census_diagnostic as diagnostic
        with mock.patch.object(diagnostic,'CENSUS_SHA','0'*64), \
             mock.patch.object(recovery,'prepare_privileged_census',
                               side_effect=AssertionError('source mismatch must precede prepare')):
            with self.assertRaisesRegex(ValueError,'avd_diagnostic_consumed_source_changed'):
                diagnostic.prepare_diagnostic(Path(recovery.__file__).resolve().parents[1],
                                              '11111111-1111-4111-8111-111111111111')

    def test_genuine_api35_factory_keeps_thirteen_backends_and_28_stage_checks(self):
        import copy,sys,uuid
        from agent_tools import android_installer_component_bundle as bundle
        from agent_tools.tests import test_android_installer_component_bundle as fixture
        f=fixture.BundleTests();f.setUp()
        try:
            selected,backend,args,_,log,_,_=f.api35_fixture()
            from agent_tools import android_api35_coldboot_product_observation as getter
            from agent_tools import android_component_command_transport as command
            from agent_tools import android_device_availability as availability
            import tempfile
            from agent_tools.tests.fixtures.android_api35_historical_context import Context
            from agent_tools.tests.fixtures.android_remaining_hermetic import component_command
            temporary=tempfile.TemporaryDirectory(prefix='api35-complete-factory-')
            self.addCleanup(temporary.cleanup)
            history=Context(Path(temporary.name));self.addCleanup(history.close)
            command=component_command(history,command)
            owned=history.prepare()
            actual,_=command.prepare(history.root,owned,'android-api35')
            code=compile(command.namespace_source(actual),'<complete-existing-api35-factory>',
                         'exec',dont_inherit=True)
            # The historical command prefix retains its getter. Bind the one
            # API35 stage function from the authenticated component selection.
            bundle._selected_modules(f.receipt,selected)
            staged=ast.parse(selected['getter_api35']._GETTER.replace('__GETTER__',repr({})))
            stage=next(node for node in staged.body
                       if isinstance(node,ast.FunctionDef) and node.name=='getter_stage')
            staged_code=compile(selected['adapter'].production_imports('api35')+
                                ast.unparse(ast.Module(body=[stage],type_ignores=[])),
                                '<staged-api35-getter>','exec',dont_inherit=True)
            stage_code=next(value for value in staged_code.co_consts
                            if isinstance(value,types.CodeType) and value.co_name=='getter_stage')
            names={'component_command','command_binary','command_request','command_host_identity',
                   'command_host_guard','command_bounded','getter_stage','child_identity',
                   'session_guest','qemu_fact','external_file','external_jdk','external_jdk_guard'}
            found=set()
            for value in code.co_consts:
                if isinstance(value,types.CodeType) and value.co_name in names:
                    if value.co_name=='getter_stage':value=stage_code
                    backend[value.co_name]=types.FunctionType(value,backend,
                                                             argdefs=backend[value.co_name].__defaults__)
                    found.add(value.co_name)
            self.assertEqual(names,found)
            request={'host':'archlinux','device':'android-api35','correlationId':str(uuid.uuid4()),
                     'sourceSha':bundle._PRODUCT_SHA,'expectedOwner':fixture.OWNER,'expectedRevision':0,
                     'expectedAvd':'owned-fixture','expectedApi':35,
                     'packageSha256':backend['GETTER']['packageSha256'],
                     'reservation':copy.deepcopy(backend['LAUNCH']['intent']['reservation'])}
            code=backend['getter_stage'].__code__;calls=[];prior=sys.getprofile()
            def trace(frame,event,arg):
                if event=='call' and frame.f_code is code:calls.append(True)
            try:
                sys.setprofile(trace)
                guard=bundle.BaselineGuard(f.receipt,bundle.modules(f.receipt),backend,request)
                guard()
            finally:sys.setprofile(prior)
            self.assertEqual(28,len(calls))
            self.assertIs(sys.getprofile(),prior)
            self.assertFalse(any('updates' in line or 'root' in line or 'unroot' in line
                                 for line in log.read_text().splitlines()))
        finally:f.tearDown()
