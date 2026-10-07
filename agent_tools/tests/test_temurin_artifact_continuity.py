"""Routine real TempFS extraction-origin and final held/named closure regressions. No SSH/download/JDK execution."""
import ast, hashlib, io, os, sys, stat, struct, tarfile, tempfile, time, unittest
from pathlib import Path
from agent_tools.tests.fixtures import temurin_artifact_continuity as fixture

def namespace(source):
    import posixpath
    if os.name!='posix':raise unittest.SkipTest('POSIX FD metadata required')
    import resource
    ns={'os':os,'stat':stat,'hashlib':hashlib,'time':time,'struct':struct,'tarfile':tarfile,'posixpath':posixpath,'pathlib':__import__('pathlib'),'resource':resource,'JDK_ROOT_NAME':'jdk-17.0.20.1+1'}
    tree=ast.parse(source)
    for node in tree.body:
        for n in ast.walk(node):
            if isinstance(n,ast.Constant)and n.value=='/proc/self/fd'and sys.platform=='darwin':n.value='/dev/fd'
            if isinstance(n,ast.Compare)and isinstance(n.left,ast.Attribute)and n.left.attr in ('st_uid','st_gid')and len(n.comparators)==1 and isinstance(n.comparators[0],ast.Constant)and n.comparators[0].value==1000:
                n.comparators[0].value=os.getuid()if n.left.attr=='st_uid'else os.getgid()
    exec(compile(ast.fix_missing_locations(tree),'authenticated-extractor-observations','exec'),ns)
    return ns

def helpers():return namespace(fixture.FIXED_SOURCE)

class SnapshotIdentityTests(unittest.TestCase):
    def test_full_authenticated_snapshots_and_no_native_entrypoints(self):
        for source,digest in ((fixture.OLD_SOURCE,fixture.OLD_SOURCE_SHA256),(fixture.FIXED_SOURCE,fixture.FIXED_SOURCE_SHA256)):
            self.assertEqual(hashlib.sha256(source.encode()).hexdigest(),digest)
            tree=ast.parse(source);self.assertTrue(all(isinstance(n,ast.FunctionDef)for n in tree.body))
            self.assertFalse(any(isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr in ('execve','Popen','run','extractall','setrlimit','urlopen')for n in ast.walk(tree)))
        self.assertEqual({n.name for n in ast.parse(fixture.FIXED_SOURCE).body},set(fixture.FUNCTION_NAMES))

@unittest.skipUnless(os.name=='posix','POSIX FD metadata required')
class ExtractionTests(unittest.TestCase):

    def setUp(self):
        self.ns = helpers()

    def member(self, name, kind=tarfile.REGTYPE, data=b'', link=''):
        x = tarfile.TarInfo(name)
        x.type = kind
        x.size = len(data)
        x.mode = 493 if kind in (tarfile.REGTYPE, tarfile.DIRTYPE) else 511
        x.linkname = link
        return (x, data)

    def extract(self, items):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t).resolve()
            raw = io.BytesIO()
            with tarfile.open(fileobj=raw, mode='w:gz') as a:
                for item, data in items:
                    a.addfile(item, io.BytesIO(data) if item.isreg() else None)
            (p / 'archive').write_bytes(raw.getvalue())
            (p / 'out').mkdir(mode=448)
            fd = os.open(p / 'archive', os.O_RDONLY)
            dest = os.open(p / 'out', os.O_RDONLY | os.O_DIRECTORY)
            try:
                result = self.ns['extract_checked'](fd, dest, time.monotonic() + 2)
                return (result, {str(q.relative_to(p / 'out')): q.read_bytes() if q.is_file() else None for q in (p / 'out').rglob('*') if not q.is_symlink()})
            finally:
                os.close(fd)
                os.close(dest)

    def valid(self):
        root = self.ns['JDK_ROOT_NAME']
        return [self.member(root, tarfile.DIRTYPE), self.member(root + '/bin', tarfile.DIRTYPE), self.member(root + '/bin/java', data=b'harmless executable bytes')]

    def test_actual_valid_archive_strict_private_output(self):
        (records, entries, total), outputs = self.extract(self.valid())
        self.assertEqual(records[0]['sha256'], hashlib.sha256(b'harmless executable bytes').hexdigest())
        self.assertEqual(outputs[self.ns['JDK_ROOT_NAME'] + '/bin/java'], b'harmless executable bytes')

    def test_escape_special_duplicate_parent_and_setid_refusals(self):
        root = self.ns['JDK_ROOT_NAME']
        for extra in (self.member('../escaped'), self.member('/escaped'), self.member(root + '/../escape'), self.member(root + '/device', tarfile.CHRTYPE), self.member(root + '/bin/java'), self.member(root + '/missing/file')):
            with self.subTest(name=extra[0].name), self.assertRaises(ValueError):
                self.extract(self.valid() + [extra])
        items = self.valid()
        items[-1][0].mode = 2541
        with self.assertRaisesRegex(ValueError, 'artifact_member_type'):
            self.extract(items)

    def test_internal_links_and_escape_cycle_refusal(self):
        root = self.ns['JDK_ROOT_NAME']
        items = self.valid() + [self.member(root + '/alias', tarfile.SYMTYPE, link='bin/java'), self.member(root + '/copy', tarfile.LNKTYPE, link=root + '/bin/java')]
        (records, entries, total), outputs = self.extract(items)
        self.assertEqual(outputs[root + '/copy'], b'harmless executable bytes')
        for target in ('../../outside', '/outside', 'missing', 'cycle'):
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.extract(self.valid() + [self.member(root + '/cycle', tarfile.SYMTYPE, link=target)])

    def test_actual_deadline_and_digest_eof(self):
        items = [self.member(self.ns['JDK_ROOT_NAME'], tarfile.DIRTYPE)]
        members = [i for i, d in items]
        with tempfile.TemporaryFile() as f:
            f.write(b'full bytes')
            f.flush()
            count, digest, pin = self.ns['file_digest'](f.fileno(), time.monotonic() + 1)
            self.assertEqual(count, 10)
            self.assertEqual(digest, hashlib.sha256(b'full bytes').hexdigest())
            with self.assertRaisesRegex(ValueError, 'artifact_deadline'):
                self.ns['file_digest'](f.fileno(), 0)

@unittest.skipUnless(os.name == 'posix', 'POSIX FD metadata required')
class ContinuityTests(ExtractionTests):

    def inventory_namespace(self, old=False, prior=False):
        return namespace(fixture.PRIOR_FINAL_TREE_SOURCE if prior else fixture.OLD_SOURCE if old else fixture.FIXED_SOURCE)

    def scenario(self, drift, old=False, prior=False):
        ns = self.inventory_namespace(old, prior)
        root = ns['JDK_ROOT_NAME']
        with tempfile.TemporaryDirectory() as t:
            path = Path(t).resolve()
            (path / 'jdk-tree').mkdir(mode=448)
            raw = io.BytesIO()
            with tarfile.open(fileobj=raw, mode='w:gz') as a:
                for item, data in self.valid() + [self.member(root + '/alias', tarfile.SYMTYPE, link='bin/java'), self.member(root + '/copy', tarfile.LNKTYPE, link=root + '/bin/java')]:
                    a.addfile(item, io.BytesIO(data) if item.isreg() else None)
            (path / 'archive').write_bytes(raw.getvalue())
            fd = os.open(path / 'archive', os.O_RDONLY)
            dest = os.open(path / 'jdk-tree', os.O_RDONLY | os.O_DIRECTORY)
            try:
                origin, entries, total = ns['extract_checked'](fd, dest, time.monotonic() + 2)
            finally:
                os.close(fd)
                os.close(dest)
            ns['result_dir'] = path
            ns['SOURCE_TREE_DIR'] = path
            target = path / 'jdk-tree' / root / 'bin/java'
            if drift == 'bytes':
                target.write_bytes(b'foreign-content')
            elif drift == 'inode':
                data = target.read_bytes()
                target.unlink()
                target.write_bytes(data)
                target.chmod(448)
            elif drift == 'mode':
                target.chmod(384)
            elif drift == 'missing':
                target.unlink()
            elif drift == 'extra':
                target.with_name('unlisted').write_bytes(b'unlisted')
            elif drift == 'link':
                link = path / 'jdk-tree' / root / 'alias'
                link.unlink()
                link.symlink_to('copy')
            elif drift == 'directory':
                directory = target.parent
                directory.rename(directory.with_name('old-bin'))
                directory.mkdir(mode=448)
                target.write_bytes(b'harmless executable bytes')
                target.chmod(448)
            if drift in ('closing-bytes', 'closing-inode', 'closing-extra', 'closing-late'):
                fn = ns['inventory_jdk']
                fn(entries, time.monotonic() + 2, origin)
                held = ns['hold_tree'](entries, origin, time.monotonic() + 2)
                try:
                    if drift == 'closing-late':
                        original_digest = ns['file_digest']
                        later_fd = held[root + '/bin/java']['fd']
                        victim = path / 'jdk-tree' / root / 'copy'

                        def late_digest(fd, deadline):
                            value = original_digest(fd, deadline)
                            if fd == later_fd:
                                victim.write_bytes(b'foreign-content')
                            return value
                        ns['file_digest'] = late_digest
                    elif drift == 'closing-bytes':
                        target.write_bytes(b'foreign-content')
                    elif drift == 'closing-inode':
                        data = target.read_bytes()
                        target.unlink()
                        target.write_bytes(data)
                        target.chmod(448)
                    else:
                        target.with_name('unlisted').write_bytes(b'extra')
                    guard_result = ns['guard_tree'](held, time.monotonic() + 2)
                    return {'guardResult': guard_result, 'victimBytes': (path / 'jdk-tree' / root / 'copy').read_bytes()}
                finally:
                    ns['close_tree'](held)
            fn = ns['inventory_jdk']
            if 'origin' in __import__('inspect').signature(fn).parameters:
                return fn(entries, time.monotonic() + 2, origin)
            return fn(entries, time.monotonic() + 2)

    def test_actual_extraction_origin_inventory_same_path_drift_refusal(self):
        for drift in ('bytes', 'inode', 'mode', 'missing', 'extra', 'link', 'directory', 'closing-bytes', 'closing-inode', 'closing-extra', 'closing-late'):
            with self.subTest(drift=drift), self.assertRaises((ValueError, OSError)):
                self.scenario(drift)

    def test_actual_unmodified_origin_inventory_passes(self):
        result = self.scenario(None)
        self.assertEqual(result['fileCount'], 2)
        self.assertEqual(result['linkCount'], 1)

    def test_actual_consumed_old_producer_relabels_foreign_bytes(self):
        value = self.scenario('bytes', old=True)
        row = next((row for row in value['files'] if row['path'].endswith('/bin/java')))
        self.assertEqual(row['sha256'], hashlib.sha256(b'foreign-content').hexdigest())

    def test_actual_prior_final_scan_accepts_late_foreign_content_current_refuses(self):
        self.assertEqual(hashlib.sha256(fixture.PRIOR_FINAL_TREE_SOURCE.encode()).hexdigest(), fixture.PRIOR_FINAL_TREE_SOURCE_SHA256)
        old = self.scenario('closing-late', prior=True)
        self.assertIsNone(old['guardResult'])
        self.assertEqual(old['victimBytes'], b'foreign-content')
        with self.assertRaisesRegex(ValueError, 'artifact_origin_changed'):
            self.scenario('closing-late')



@unittest.skipUnless(os.name=='posix','POSIX held-directory metadata required')
class OwnedParentTransitionTests(unittest.TestCase):
    def ns(self,old=False):
        source=fixture.OLD_PARENT_SOURCE if old else fixture.FIXED_PARENT_SOURCE
        digest=fixture.OLD_PARENT_SOURCE_SHA256 if old else fixture.FIXED_PARENT_SOURCE_SHA256
        self.assertEqual(hashlib.sha256(source.encode()).hexdigest(),digest)
        ns=namespace(source);ns['identity_host']={'uid':os.getuid(),'gid':os.getgid()};return ns

    def test_actual_old_own_mkdir_red_fixed_exact_delta_green(self):
        for old in (True,False):
            ns=self.ns(old)
            with tempfile.TemporaryDirectory()as temp:
                parent=Path(temp).resolve()/'parent';parent.mkdir(mode=0o700);(parent/'existing').write_bytes(b'unchanged')
                child=parent/'fresh';chain,name=ns['parent_fds'](child);fd=None
                try:
                    if old:
                        os.mkdir(name,0o700,dir_fd=chain[-1]['fd']);fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY,dir_fd=chain[-1]['fd']);pin=ns['fp'](os.fstat(fd));ns.update(result_dir=child,result_fd=fd,result_chain=chain,result_identity=pin[:2]+pin[5:8])
                        with self.assertRaisesRegex(ValueError,'census_ancestry_changed'):ns['output_guard']()
                    else:
                        ancestor=[row['pin'][:]for row in chain[:-1]]
                        fd,proof=ns['create_owned_leaf'](chain,name);ns['guard_parents'](chain)
                        self.assertEqual(proof['oldEntryCount'],1);self.assertEqual(proof['newEntryCount'],2);self.assertTrue(proof['exactOneChildDelta']);self.assertEqual(ancestor,[row['pin']for row in chain[:-1]])
                        self.assertEqual((parent/'existing').read_bytes(),b'unchanged');self.assertEqual(os.listdir(fd),[])
                finally:
                    if fd is not None:os.close(fd)
                    ns['close_parents'](chain)

    def test_actual_transition_refuses_foreign_catalogue_child_name_inode_mode_and_link(self):
        from unittest.mock import patch
        for drift in ('extra','existing-bytes','child-mode','child-name','child-symlink','parent-mode','parent-inode'):
            with self.subTest(drift=drift),tempfile.TemporaryDirectory()as temp:
                parent=Path(temp).resolve()/'parent';parent.mkdir(mode=0o700);(parent/'existing').write_bytes(b'original');child=parent/'fresh';ns=self.ns();chain,name=ns['parent_fds'](child);original=os.mkdir
                def mutate(name,mode=0o777,*,dir_fd=None):
                    original(name,mode,dir_fd=dir_fd)
                    if drift=='extra':(parent/'foreign').write_bytes(b'foreign')
                    elif drift=='existing-bytes':(parent/'existing').write_bytes(b'foreign')
                    elif drift=='child-mode':child.chmod(0o755)
                    elif drift=='child-name':child.rename(parent/'unexpected')
                    elif drift=='child-symlink':child.rmdir();child.symlink_to('existing')
                    elif drift=='parent-mode':parent.chmod(0o755)
                    elif drift=='parent-inode':parent.rename(parent.with_name('old'));original(parent,0o700)
                try:
                    with patch.object(os,'mkdir',side_effect=mutate),self.assertRaises((ValueError,OSError)):ns['create_owned_leaf'](chain,name)
                finally:ns['close_parents'](chain)

    def test_actual_transition_refuses_observed_foreign_child_owner_and_existing_name(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory()as temp:
            parent=Path(temp).resolve();ns=self.ns();child=parent/'fresh';chain,name=ns['parent_fds'](child);original=os.fstat
            def observed(fd):
                info=original(fd)
                if child.exists()and info.st_ino==child.stat().st_ino:
                    values={key:getattr(info,key)for key in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode','st_uid','st_gid','st_nlink')};values['st_uid']+=1;return SimpleNamespace(**values)
                return info
            try:
                with patch.object(os,'fstat',side_effect=observed),self.assertRaisesRegex(ValueError,'artifact_parent_transition'):ns['create_owned_leaf'](chain,name)
            finally:ns['close_parents'](chain)
            chain,name=ns['parent_fds'](child)
            try:
                with self.assertRaisesRegex(ValueError,'artifact_parent_transition'):ns['create_owned_leaf'](chain,name)
            finally:ns['close_parents'](chain)



@unittest.skipUnless(os.name=='posix','POSIX real FD closure required')
class CleanupOwnershipTests(unittest.TestCase):
    def test_actual_retainer_old_tuple_cleanup_red_and_all_fixed_contexts_close(self):
        self.assertEqual(hashlib.sha256(fixture.RETAINER_SOURCE.encode()).hexdigest(),fixture.RETAINER_SOURCE_SHA256)
        for old in (True,False):
            source=fixture.OLD_CLEANUP_SOURCE if old else fixture.FIXED_CLEANUP_SOURCE
            digest=fixture.OLD_CLEANUP_SOURCE_SHA256 if old else fixture.FIXED_CLEANUP_SOURCE_SHA256
            self.assertEqual(hashlib.sha256(source.encode()).hexdigest(),digest)
            with tempfile.TemporaryDirectory()as temp:
                root=Path(temp).resolve();stage=root/'android-cli-stage-inert';stage.mkdir(mode=0o700);tree=stage/'tree';tree.mkdir(mode=0o700)
                paths={'intent.json':stage/'intent.json','receipt.json':stage/'receipt.json'};paths.update({'file-'+str(i):tree/('file-'+str(i))for i in range(153)})
                for path in paths.values():path.write_bytes(b'harmless')
                ns=namespace(fixture.FIXED_PARENT_SOURCE+'\n'+fixture.RETAINER_SOURCE+'\n'+fixture.CLOSE_TREE_SOURCE);ns.update(ROOT=root,GETTER={'stageId':'inert'},held=[],parent_cache={})
                pins={name:{'generation':ns['fp'](path.stat())}for name,path in paths.items()};ns['retain_stage'](pins)
                self.assertEqual(len(ns['held']),155);self.assertTrue(all(type(item)is tuple and len(item)==4 for item in ns['held']));self.assertTrue(all(type(row)is dict and type(row['fd'])is int for row in ns['parent_cache'].values()))
                ns['tree_fd']=os.open(tree,os.O_RDONLY|os.O_DIRECTORY)if old else None;ns['archive_fd']=os.open(stage/'intent.json',os.O_RDONLY);ns['result_fd']=os.open(stage,os.O_RDONLY|os.O_DIRECTORY);ns['result_chain'],_=ns['parent_fds'](stage/'intent.json');ns['archive_chain'],_=ns['parent_fds'](stage/'intent.json')if not old else ([],None)
                finalchain,_=ns['parent_fds'](stage/'intent.json');ns['final_tree']={'owned':{'fd':os.open(stage/'intent.json',os.O_RDONLY),'rootChain':finalchain}}
                fds={item[2]for item in ns['held']}|{row['fd']for row in ns['parent_cache'].values()}|{row['fd']for row in ns['result_chain']}|{row['fd']for row in finalchain}|{row['fd']for row in ns['archive_chain']}|{fd for fd in (ns['tree_fd'],ns['archive_fd'],ns['result_fd'],ns['final_tree']['owned']['fd'])if fd is not None}
                try:
                    if old:
                        with self.assertRaises(TypeError):exec(compile(source,'actual-old-all-cleanup','exec'),ns)
                        os.fstat(ns['held'][0][2])
                        self.assertEqual(ns['final_tree'],{})
                    else:
                        exec(compile(source,'actual-fixed-all-cleanup','exec'),ns)
                        self.assertEqual(ns['final_tree'],{})
                        for fd in fds:
                            with self.subTest(fd=fd),self.assertRaises(OSError):os.fstat(fd)
                finally:
                    for fd in fds:
                        try:os.close(fd)
                        except OSError:pass



@unittest.skipUnless(os.name=='posix','POSIX FD source identity required')
class OfficialToolIdentityTests(unittest.TestCase):
    def tool(self,name):
        import base64,zlib
        raw=zlib.decompress(base64.b64decode(fixture.OFFICIAL_TOOL_ELF_ZLIB_BASE64[name],validate=True));record=fixture.OFFICIAL_TOOL_RECORDS[name]
        self.assertEqual(len(raw),record['bytes']);self.assertEqual(hashlib.sha256(raw).hexdigest(),record['sha256']);return raw,record
    def ns(self):
        self.assertEqual(hashlib.sha256(fixture.FIXED_TOOL_IDENTITY_SOURCE.encode()).hexdigest(),fixture.FIXED_TOOL_IDENTITY_SOURCE_SHA256)
        ns=namespace(fixture.FIXED_SOURCE+'\n'+fixture.FIXED_TOOL_IDENTITY_SOURCE);ns.update(ARTIFACT_SHA=fixture.OFFICIAL_TOOL_ARCHIVE_SHA256,ARTIFACT_SIZE=193252603,re=__import__('re'));return ns
    def invoke(self,name,mutate=None,late=None,foreign_asset=False):
        ns=self.ns();raw,source=self.tool(name)
        with tempfile.TemporaryDirectory()as temp:
            parent=Path(temp).resolve();path=parent/name;path.write_bytes(raw);path.chmod(0o700)
            if mutate:mutate(path,raw)
            fd=os.open(path,os.O_RDONLY);directory=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
            row=dict(source,type='file',elf=True,generation=ns['fp'](path.stat()),buildIds=[]);item={'record':row,'fd':fd,'parent':directory,'leaf':name};holds={source['path']:item}
            if late:
                digest=ns['file_digest']
                def changed(*args):
                    result=digest(*args);late(path,raw);return result
                ns['file_digest']=changed
            if foreign_asset:ns['ARTIFACT_SHA']='0'*64
            try:return ns['fixed_tool_identity'](holds,name),row
            finally:os.close(fd);os.close(directory)
    def test_actual_five_official_elfs_old_gate_red_exact_asset_green(self):
        for name in fixture.OFFICIAL_TOOL_RECORDS:
            with self.subTest(name=name):
                admitted,row=self.invoke(name)
                with self.assertRaisesRegex(ValueError,'artifact_tool_missing'):exec(compile(fixture.OLD_TOOL_GATE_SOURCE,'actual-consumed-buildid-gate','exec'),{'row':row})
                self.assertEqual(admitted['buildIds'],[]);self.assertEqual(admitted['gnuBuildIdPresence'],'absent-in-authenticated-asset');self.assertEqual(admitted['elfMachine'],'EM_X86_64');self.assertEqual(admitted['sha256'],row['sha256'])
    def test_exact_source_replacement_nonelf_wrongarch_truncation_and_private_modes_refuse(self):
        def machine(path,raw):
            data=bytearray(raw);struct.pack_into('<H',data,18,183);path.write_bytes(data)
        for mutate in (lambda p,r:p.write_bytes(b'foreign'),lambda p,r:p.write_bytes(b'XXXX'+r[4:]),machine,lambda p,r:p.write_bytes(r[:40]),lambda p,r:p.chmod(0o600),lambda p,r:p.chmod(0o755),lambda p,r:os.link(p,p.with_name('second-link'))):
            with self.subTest(mutate=mutate),self.assertRaisesRegex(ValueError,'artifact_tool_identity'):self.invoke('java',mutate=mutate)
        with self.assertRaisesRegex(ValueError,'artifact_tool_identity'):self.invoke('java',foreign_asset=True)
        ns=self.ns()
        with self.assertRaisesRegex(ValueError,'artifact_tool_missing'):ns['fixed_tool_identity']({},'java')
    def test_actual_post_hash_wrongarch_truncated_elf_and_malformed_present_note_refuse(self):
        def machine(path,raw):
            data=bytearray(raw);struct.pack_into('<H',data,18,183);path.write_bytes(data)
        def note(path,raw):
            data=bytearray(raw);struct.pack_into('<I',data,708,5000);path.write_bytes(data)
        for mutation in (machine,note,lambda p,r:p.write_bytes(r[:40]),lambda p,r:p.write_bytes(r[:4]+b'\x01'+r[5:]),lambda p,r:p.write_bytes(r[:5]+b'\x02'+r[6:])):
            with self.subTest(mutation=mutation),self.assertRaisesRegex(ValueError,'artifact_tool_elf'):self.invoke('java',late=mutation)



@unittest.skipUnless(os.name=='posix','POSIX archive metadata required')
class ArchivePublicationTests(unittest.TestCase):
    def run_boundary(self,old,mutation):
        ns=namespace(fixture.FIXED_PARENT_SOURCE+'\n'+fixture.ARCHIVE_PUBLICATION_WRITER_SOURCE+(''if old else'\n'+fixture.FIXED_ARCHIVE_CLOSURE_SOURCE));ns['json']=__import__('json')
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp).resolve();path=root/'temurin.tar.gz';path.write_bytes(b'original source');path.chmod(0o600);out=root/'output';out.mkdir(mode=0o700)
            archive=os.open(path,os.O_RDONLY);result=os.open(out,os.O_RDONLY|os.O_DIRECTORY);chain,name=ns['parent_fds'](path);pin=ns['fp'](path.stat());reopened=[]
            def scan(held,deadline):
                if mutation=='chmod':path.chmod(0o644)
                elif mutation=='replace':path.rename(root/'old');path.write_bytes(b'replacement');path.chmod(0o600)
                elif mutation=='wrong-fd':ns['archive_fd']=result
                elif mutation=='null':ns['archive_fd']=None
                elif mutation=='reopened':ns['archive_fd']=os.open(path,os.O_RDONLY);reopened.append(ns['archive_fd'])
                elif mutation=='null-pin':ns['archive_pin']=None
            ns.update(archive_fd=archive,archive_open_fd=archive,archive_pin=pin,SOURCE_ARCHIVE_PIN=pin,archive_chain=chain,archive_name=name,result_fd=result,proof={'failure':None,'fullHeldNamedTreeClosure':True},failure=None,final_tree={},guard_tree=scan)
            source=fixture.OLD_ARCHIVE_PUBLICATION_SOURCE if old else fixture.FIXED_ARCHIVE_PUBLICATION_SOURCE
            try:
                exec(compile(source,'actual-archive-final-publication','exec'),ns)
                emitted=(out/'terminal-proof.json').read_bytes()if(out/'terminal-proof.json').exists()else None
                return ns['proof'],emitted
            finally:
                for fd in reopened:os.close(fd)
                os.close(archive);os.close(result);ns['close_parents'](chain)
    def test_actual_old_final_tree_late_chmod_false_acceptance_red(self):
        self.assertEqual(hashlib.sha256(fixture.OLD_ARCHIVE_PUBLICATION_SOURCE.encode()).hexdigest(),fixture.OLD_ARCHIVE_PUBLICATION_SOURCE_SHA256)
        proof,raw=self.run_boundary(True,'chmod');self.assertIsNone(proof['failure']);self.assertTrue(proof['fullHeldNamedTreeClosure']);self.assertIsNotNone(raw)
    def test_actual_fixed_publication_late_archive_drift_and_wrong_handles_refuse(self):
        self.assertEqual(hashlib.sha256(fixture.FIXED_ARCHIVE_CLOSURE_SOURCE.encode()).hexdigest(),fixture.FIXED_ARCHIVE_CLOSURE_SOURCE_SHA256)
        self.assertEqual(hashlib.sha256(fixture.FIXED_ARCHIVE_PUBLICATION_SOURCE.encode()).hexdigest(),fixture.FIXED_ARCHIVE_PUBLICATION_SOURCE_SHA256)
        for mutation in ('chmod','replace','wrong-fd','null','reopened','null-pin'):
            with self.subTest(mutation=mutation):
                proof,raw=self.run_boundary(False,mutation);self.assertIsNotNone(proof['failure']);self.assertFalse(proof['fullHeldNamedTreeClosure']);self.assertIsNone(raw)
        proof,raw=self.run_boundary(False,None);self.assertIsNone(proof['failure']);self.assertTrue(proof['fullHeldNamedTreeClosure']);self.assertIsNotNone(raw)


@unittest.skipIf(os.name == 'nt', 'POSIX descriptor identity fixture')
class ProducerJournalParentTests(unittest.TestCase):
    def scenario(self, fixed, expect_refusal=False, audit_drift=None):
        from agent_tools.tests.fixtures import temurin_artifact_continuity as fixture
        import struct, json, sys
        source = fixture.PRODUCER_JOURNAL_CURRENT_SOURCE if fixed else fixture.PRODUCER_JOURNAL_OLD_SOURCE
        prefix = fixture.PRODUCER_JOURNAL_CURRENT_PREFIX if fixed else fixture.PRODUCER_JOURNAL_OLD_PREFIX
        ns = {'os': os, 'pathlib': __import__('pathlib'), 'stat': stat, 'time': time, 'hashlib': hashlib, 'struct': struct, 'json': json, 're': __import__('re')}
        module = ast.parse(source)
        for node in ast.walk(module):
            if isinstance(node, ast.Compare) and isinstance(node.left, ast.Attribute) and node.left.attr in ('st_uid', 'st_gid'):
                for index, value in enumerate(node.comparators):
                    if isinstance(value, ast.Constant) and value.value == 1000:
                        node.comparators[index] = ast.Constant(os.getuid() if node.left.attr == 'st_uid' else os.getgid())
        # APFS counts regular directory entries in nlink; Linux admission stays two.
        if sys.platform == 'darwin':
            for value in ast.walk(module):
                if isinstance(value, ast.Compare) and isinstance(value.left, ast.Attribute) and value.left.attr == 'st_nlink':
                    for index, constant in enumerate(value.comparators):
                        if isinstance(constant, ast.Constant) and constant.value == 2: value.comparators[index] = ast.parse('2 + len(os.listdir(audit_fd))', mode='eval').body
        exec(compile(ast.fix_missing_locations(module), 'actual-producer-image-and-writer', 'exec'), ns)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            build = root / 'tmp' / 'vpn-control-jpackage-launcher-abcdefgh'
            image = build / 'image' / 'launcher-preflight'
            (image / 'bin').mkdir(parents=True)
            (image / 'lib').mkdir()
            (root / 'audit').mkdir(mode=0o700)
            import base64, zlib
            elf = zlib.decompress(base64.b64decode(fixture.OFFICIAL_TOOL_ELF_ZLIB_BASE64['java']))
            for relative in ('bin/launcher-preflight', 'lib/libapplauncher.so'):
                (image / relative).write_bytes(elf)
                (image / relative).chmod(0o700)
            result_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            audit_fd = os.open(root / 'audit', os.O_RDONLY | os.O_DIRECTORY)
            ns.update(result_fd=result_fd, audit_fd=audit_fd, role_index=4, command_records=[], image_holds=[], build_root=build, build_tmp=root / 'tmp', SOURCE_TREE_DIR=root / 'source', JDK_ROOT_NAME='jdk-17.0.20.1+1', ROLE_NAMES=('java-version','javac','jar','jpackage','hello-launcher'), command=[str(image / 'bin' / 'launcher-preflight')], kwargs={'check':False,'capture_output':True,'text':True,'timeout':60}, producer_guards=lambda: None)
            before = ns['fp'](os.fstat(result_fd))
            audit_pin = ns['fp'](os.fstat(audit_fd))
            ns['audit_identity'] = audit_pin[:2] + audit_pin[5:8]
            try:
                exec(compile(prefix, 'actual-producer-pre-release-prefix', 'exec'), ns)
                if expect_refusal:
                    with self.assertRaisesRegex(ValueError, 'census_ancestry_changed'):
                        ns['generated_image_guard']()
                else:
                    ns['generated_image_guard']()
                    ns['producer_audit_guard']()
                    if audit_drift is not None:
                        if audit_drift == 'mode': (root / 'audit').chmod(0o755)
                        elif audit_drift == 'replacement':
                            (root / 'audit').rename(root / 'old-audit'); (root / 'audit').mkdir(mode=0o700)
                        elif audit_drift == 'symlink':
                            (root / 'audit').rename(root / 'old-audit'); (root / 'audit').symlink_to('old-audit')
                        with self.assertRaisesRegex(ValueError, 'producer_audit_changed'): ns['producer_audit_guard']()
                        return
                    # Actual physical chunk writer and terminal record create
                    # remain confined to the mutable audit sibling.
                    ns['retain_raw'](audit_fd, 'command-4-stdout', b'JPACKAGE_LAUNCHER_OK\n')
                    ns['write_record'](audit_fd, 'command-4-terminal.json', b'{"returncode":0}')
                    ns['generated_image_guard']()
                    self.assertEqual(ns['fp'](os.fstat(result_fd)), before)
                    originals = [item[2] for item in ns['image_holds']]
                    ns['close_image_holds']()
                    for descriptor in originals:
                        with self.assertRaises(OSError): os.fstat(descriptor)
                    # Actual final writer runs only after owned image pins close.
                    ns['write_record'](result_fd, 'terminal-proof.json', b'{"returncode":0}')
                    self.assertEqual(ns['image_holds'], [])
                return [p.name for p in root.iterdir()], [p.name for p in (root / 'audit').iterdir()]
            finally:
                ns['close_image_holds']()
                os.close(audit_fd)
                os.close(result_fd)

    def test_current_actual_producer_logging_preserves_held_image_ancestors(self):
        self.scenario(True)

    def test_actual_audit_private_identity_refuses_drift(self):
        for drift in ('mode','replacement','symlink'):
            with self.subTest(drift=drift): self.scenario(True, audit_drift=drift)

    def test_consumed9438_actual_journal_write_invalidates_image_parent(self):
        self.scenario(False, expect_refusal=True)


if __name__=='__main__':unittest.main()
