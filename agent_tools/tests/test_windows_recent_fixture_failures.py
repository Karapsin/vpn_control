"""Causal public caller controls. Native product/SSH authority is never exercised."""
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
from types import SimpleNamespace, ModuleType
from contextlib import contextmanager
import inspect
import errno
from unittest.mock import patch
import unittest
import uuid

HERE = Path(__file__).resolve().parent
VARIANT = os.environ.get('FIXTURE_VARIANT', 'fixed')
ROOT = Path(os.environ.get('FIXTURE_REPOSITORY', str(HERE.parents[1])))
PWSH = Path(os.environ.get('FIXTURE_PWSH') or
            (shutil.which('powershell.exe') if os.name=='nt' else shutil.which('pwsh')) or
            str(ROOT/'.runtime/windows-order-pwsh/portable/pwsh'))
BUNDLE = json.loads((HERE/'fixtures/windows_recent_fixture_sources.json').read_text())

def source(name):
    record = BUNDLE['files'][name]
    raw = record['utf8'].encode()
    if len(raw) != record['bytes'] or hashlib.sha256(raw).hexdigest() != record['sha256']:
        raise ValueError('public_fixture_source_changed')
    return record['utf8']

def callable_nodes(nodes, arguments, namespace):
    # Real AST nodes from the preserved caller; runtime dependencies are explicit.
    fn = ast.FunctionDef(name='assembled', args=ast.arguments(posonlyargs=[],
        args=[ast.arg(arg=name) for name in arguments], kwonlyargs=[],
        kw_defaults=[], defaults=[]), body=nodes, decorator_list=[])
    module = ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[]))
    exec(compile(module, '<authentic-caller-fragment>', 'exec'), namespace)
    return namespace['assembled']

def route_admit():
    tree = ast.parse(source('route.'+VARIANT+'.py'))
    nodes = [n for n in tree.body if isinstance(n, ast.Assert) and
             'sel' in ast.unparse(n.test) and 'route' in ast.unparse(n.test)]
    if len(nodes) != 1:
        raise RuntimeError('authentic-route-selector')
    return callable_nodes(nodes, ('sel','route'), {'uuid':uuid})

def load_closure():
    namespace = {'__name__':'preserved_closure'}
    exec(compile(source('closure.before.py'), '<preserved-source-classifier>', 'exec'),namespace)
    return SimpleNamespace(**namespace)

CLOSURE = load_closure()

def prepare_admit():
    tree = ast.parse(source('name.caller.'+VARIANT+'.py'))
    start = next(i for i,n in enumerate(tree.body) if isinstance(n,ast.Assert)
                 and ast.unparse(n.test) == "mode == 'run'")
    with_node = next(n for n in tree.body[start:] if isinstance(n,ast.With))
    # End after the authentic intent publication; then execute the real held-read loop.
    end = next(i for i in range(start,len(tree.body)) if tree.body[i] is with_node)
    body = tree.body[start:end]
    # Use the preserved classifier module; do not import a later canonical epoch.
    body = [n for n in body if not isinstance(n,ast.ImportFrom)]
    loop = with_node.body[0]
    return callable_nodes(body+[loop], ('P','B','route','save','held','mode'),
                          {'json':json,'uuid':uuid,'hashlib':hashlib,
                           'source_closure':CLOSURE})

def send_decision():
    tree = ast.parse(source('key-chain.'+VARIANT+'.py'))
    branch = next(n for n in ast.walk(tree) if isinstance(n,ast.If) and
                  isinstance(n.test,ast.Compare) and
                  'FRESH_CHAIN_FRAME' in ast.unparse(n.test))
    index = next(i for i,n in enumerate(branch.body) if isinstance(n,ast.Expr) and
                 isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Name) and
                 n.value.func.id == 'save' and 'operator-decision-' in ast.unparse(n))
    body = branch.body[index:]+[ast.Return(value=ast.Name(id='index',ctx=ast.Load()))]
    return callable_nodes(body, ('child','save','index','decision'), {})

class RouteDomain(unittest.TestCase):
    def test_compact_selected_uuid_matches_authenticated_hyphenated_uuid(self):
        corr = uuid.UUID('f27a140d-81af-4d0b-9ebf-0ded43f11f7b')
        try:
            route_admit()({'correlationId':corr.hex},{'correlationId':str(corr)})
        except (ValueError,AssertionError) as exc:
            self.fail('same UUID identity refused: '+type(exc).__name__)

    def test_foreign_uuid_still_refused(self):
        with self.assertRaises((ValueError,AssertionError)):
            route_admit()({'correlationId':uuid.UUID(int=1).hex},
                          {'correlationId':str(uuid.UUID(int=2))})

    def test_canonical_identity_remains_accepted(self):
        corr = str(uuid.UUID(int=1))
        route_admit()({'correlationId':corr},{'correlationId':corr})

@unittest.skipUnless(os.name=='posix' and hasattr(os,'O_NOFOLLOW'), 'actual POSIX held-file contract')
class PublicNamePreflight(unittest.TestCase):
    def attempt(self, parent, name):
        payload = source('owner-facts.public.json').encode()
        candidate = parent/name
        candidate.write_bytes(payload)
        candidate.chmod(0o600)
        seal = {'pins':[{'path':str(candidate),'sha256':hashlib.sha256(payload).hexdigest()}]}
        (parent/'prepared-seal.json').write_text(json.dumps(seal))
        (parent/'recovery.remote.final.py').write_text('print("inert")\n')
        holder = CLOSURE._Held()
        def save(name, body):
            raw = json.dumps(body,sort_keys=True).encode()
            fd = os.open(parent/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            try:
                os.write(fd,raw)
                os.fsync(fd)
            finally:
                os.close(fd)
        try:
            prepare_admit()(parent,{'headSha':'a'*40},
                {'correlationId':str(uuid.UUID(int=1))},save,
                SimpleNamespace(held=holder),'run')
            holder.finish()
        finally:
            holder.close()
        return candidate

    def test_protected_name_refuses_before_any_mutation_intent(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp).resolve()
            with self.assertRaisesRegex(ValueError,'outside source scope'):
                self.attempt(parent,'owner-binding.json')
            self.assertFalse((parent/'recovery.intent.json').exists(),
                             'protected public name consumed intent before classifier')

    def test_actual_byte_equal_rename_admits_and_classifier_stays_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent=Path(tmp).resolve()
            old=parent/'owner-binding.json'
            old.write_bytes(source('owner-facts.public.json').encode())
            before=hashlib.sha256(old.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError,'outside source scope'):
                CLOSURE._path(str(old))
            renamed=parent/'owner-facts.public.json'
            old.rename(renamed)
            self.assertEqual(before,hashlib.sha256(renamed.read_bytes()).hexdigest())
            self.attempt(parent,renamed.name)
            self.assertTrue((parent/'recovery.intent.json').exists())
            for name in ('credentials.json','binding.json.bak','owner-binding.json'):
                with self.subTest(name=name),self.assertRaises(ValueError):
                    CLOSURE._path(str(parent/name))

@unittest.skipUnless(PWSH.is_file(), 'real PowerShell interpreter required')
class CheckAcknowledgement(unittest.TestCase):
    def run_case(self, *, status_owner='owner', version='2.2.5', malformed=False):
        task = source('ack.'+VARIANT+'.ps1')
        begin = task.index('function Public(')
        end = task.index('\n$cache=',begin)
        fragment = task[begin:end]
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp).resolve()
            def packet(data, owner='owner'):
                return json.dumps({'schemaVersion':1,'code':'OK','final':True,
                   'controllerId':owner,'configurationRevision':17,'data':data})
            (parent/'check.json').write_text(packet({}))
            (parent/'status.json').write_text('broken {' if malformed else
                packet({'availableVersion':version,'phase':'available'},status_owner))
            (parent/'download.json').write_text(packet({}))
            cli = parent/'inert-cli.ps1'
            cli.write_text("$command=$args[-1];[IO.File]::AppendAllText((Join-Path $PSScriptRoot 'calls.txt'),$command+\"`n\");$global:LASTEXITCODE=0;Write-Output ([IO.File]::ReadAllText((Join-Path $PSScriptRoot ($command+'.json'))))")
            script = parent/'control.ps1'
            quote=lambda v:"'"+str(v).replace("'","''")+"'"
            script.write_text("$ErrorActionPreference='Stop';$root="+quote(parent)+
                ";$state='inert-state';$ep=[pscustomobject]@{controllerId='owner'};$cli="+quote(cli)+
                "\ntry{\n"+fragment+"\n[Console]::Out.WriteLine('OBSERVED')}catch{[Console]::Error.WriteLine($_.Exception.Message);exit 1}")
            result=subprocess.run([str(PWSH),'-NoLogo','-NoProfile','-NonInteractive','-File',str(script)],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={k:v for k,v in os.environ.items()if not k.startswith('DYLD_')},timeout=20)
            calls=(parent/'calls.txt').read_text().splitlines() if (parent/'calls.txt').exists() else []
            return result,calls

    def test_empty_command_ack_uses_separate_status_without_resubmission(self):
        result,calls=self.run_case()
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(calls,['check','status','download','status'])
        self.assertEqual(calls.count('check'),1)
        self.assertEqual(calls.count('download'),1)

    def test_foreign_status_owner_refused_before_download(self):
        result,calls=self.run_case(status_owner='foreign')
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('download',calls)

    def test_wrong_target_version_refused_before_download(self):
        result,calls=self.run_case(version='2.2.4')
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('download',calls)

    def test_malformed_status_refused_without_mutation_replay(self):
        result,calls=self.run_case(malformed=True)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(calls.count('check'),1)
        self.assertNotIn('download',calls)

@unittest.skipUnless(os.name=='posix', 'real inherited control pipe requires POSIX')
class OriginalPipeObservation(unittest.TestCase):
    def run_child(self, mode):
        read_fd,write_fd=os.pipe()
        # Child read-end closure is positively observed before the write; an
        # independent release pipe keeps it alive for the BrokenPipe race case.
        program="import os,sys\n"
        if mode=='broken': program+='os.close(0)\n'
        program+="print('READY',flush=True)\nos.read("+str(read_fd)+",1)\n"
        child=subprocess.Popen([sys.executable,'-B','-c',program],stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(read_fd,))
        os.close(read_fd)
        records={};error=None;index=None
        try:
            self.assertEqual(child.stdout.readline(),b'READY\n')
            if mode=='terminal':
                os.write(write_fd,b'x');child.wait(timeout=5)
            if mode=='closed':child.stdin.close()
            def save(name,value):records[name]=value
            try:index=send_decision()(child,save,0,b'{"action":"finish"}\n')
            except (BrokenPipeError,OSError,ValueError) as exc:error=exc
            if mode!='terminal':os.write(write_fd,b'x')
            rc=child.wait(timeout=5)
            return child.pid,rc,records,error,index
        finally:
            os.close(write_fd)
            if child.poll() is None:
                child.wait(timeout=5)
            for stream in (child.stdin,child.stdout,child.stderr):
                try:stream.close()
                except (BrokenPipeError,OSError):pass

    def assert_unknown(self,mode):
        pid,rc,records,error,index=self.run_child(mode)
        self.assertIsNone(error,'original pipe delivery raised '+repr(error))
        self.assertEqual(rc,0)
        self.assertEqual(index,1)
        value=records.get('operator-undelivered-0.json')
        self.assertIsNotNone(value)
        self.assertEqual(value['originalPid'],pid)
        self.assertEqual(value['state'],'unknown')
        self.assertEqual(value['productOutcome'],'unknown')
        self.assertFalse(value['replayAllowed'])
        self.assertEqual(len([k for k in records if k.startswith('operator-decision-')]),1)

    def test_live_original_with_closed_peer_read_end_keeps_unknown(self):
        self.assert_unknown('broken')

    def test_observed_original_terminal_skips_write_and_keeps_unknown(self):
        self.assert_unknown('terminal')

    def test_closed_original_stdin_skips_write_and_keeps_unknown(self):
        self.assert_unknown('closed')

    def test_live_readable_original_accepts_one_decision(self):
        _pid,rc,records,error,index=self.run_child('live')
        self.assertIsNone(error)
        self.assertEqual(rc,0)
        self.assertEqual(index,1)
        self.assertEqual(list(records),['operator-decision-0.json'])

class ExistingImageTransfer(unittest.TestCase):
    def emit(self,path):
        # The native UID/custody observations remain separate. Execute the exact
        # preserved transfer statements and size predicate with a real file and
        # real stdout pipe; no QMP command or new capture is part of this control.
        script=('import os,sys,json,gzip,hashlib,base64\n'
                'fd=os.open(sys.argv[1],os.O_RDONLY);s=os.fstat(fd)\n'
                'try:\n raw=os.read(fd,s.st_size+1)\nfinally:os.close(fd)\n'+
                source('image.'+VARIANT+'.fragment.py'))
        return subprocess.run([sys.executable,'-B','-c',script,str(path)],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)

    def assert_transfer(self,raw):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'existing-public.ppm';path.write_bytes(raw)
            result=self.emit(path)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        rows=[json.loads(line)for line in result.stdout.splitlines()]
        self.assertEqual(rows[0],{'state':'EXISTING_RETURN_DISPLAY_BEGIN',
            'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
        chunks=rows[1:]
        self.assertEqual(len(chunks),(len(raw)+49151)//49152)
        recovered=bytearray()
        for index,row in enumerate(chunks):
            self.assertEqual(set(row),{'state','offset','base64'})
            self.assertEqual(row['state'],'EXISTING_RETURN_DISPLAY_CHUNK')
            self.assertEqual(row['offset'],index*49152)
            block=base64.b64decode(row['base64'],validate=True)
            self.assertEqual(block,raw[index*49152:(index+1)*49152])
            recovered.extend(block)
        self.assertEqual(bytes(recovered),raw)

    def test_over_historical_gzip_cap_preserves_exact_bytes_hash_and_chunk_order(self):
        public_path=os.environ.get('FIXTURE_IMAGE_FILE')
        raw=Path(public_path).read_bytes()if public_path else hashlib.shake_256(
            b'inert public image transfer regression').digest(3072016)
        self.assert_transfer(raw)

    def test_partial_final_chunk_retains_byte_count_and_order(self):
        self.assert_transfer(hashlib.shake_256(b'partial public image').digest(49152+17))

    def test_original_16mib_raw_cap_remains_strict(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'oversize.ppm'
            with path.open('wb')as f:f.truncate(16777216)
            result=self.emit(path)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(result.stdout,b'')

def project_task_result():
    tree=ast.parse(source('projection.'+VARIANT+'.py'))
    if VARIANT=='before':
        loop=next(n for n in tree.body if isinstance(n,ast.For) and
                  isinstance(n.target,ast.Tuple))
        selector=next(n for n in loop.body if isinstance(n,ast.Assign)and
                      any(isinstance(t,ast.Name)and t.id=='terminal'for t in n.targets))
        selected=next(n for n in loop.body if isinstance(n,ast.Assign)and
                      any(isinstance(t,ast.Name)and t.id=='result'for t in n.targets))
        nodes=[selector,selected]
    else:
        holder=next(n for n in tree.body if isinstance(n,ast.Try))
        start=next(i for i,n in enumerate(holder.body)if isinstance(n,ast.Assign)and
                   any(isinstance(t,ast.Name)and t.id=='index'for t in n.targets))
        nodes=holder.body[start:start+3]
    return callable_nodes(nodes+[ast.Return(value=ast.Name(id='result',ctx=ast.Load()))],
                          ('rows','label'),{})

@contextmanager
def projection_pair(variant='fixed'):
    # Before is the actual prior candidate, not a missing-API surrogate. The
    # fixed routine reads real owners; isolated proposals specify those paths.
    if variant=='before':
        owner_text=source('resource.projection.before.py')
        closure_text=source('resource.closure.before.py')
    else:
        owner=Path(os.environ.get('FIXTURE_PREFLIGHT_SOURCE',str(ROOT/'agent_tools/native_fixture_preflight.py')))
        closure_owner=Path(os.environ.get('FIXTURE_CLOSURE_SOURCE',str(ROOT/'agent_tools/native_review_source_closure.py')))
        owner_text=owner.read_text();closure_text=closure_owner.read_text()
    package_name='_windows_public_projection_'+uuid.uuid4().hex
    package=ModuleType(package_name);package.__path__=[]
    closure_name=package_name+'.native_review_source_closure'
    closure=ModuleType(closure_name)
    sys.modules[package_name]=package;sys.modules[closure_name]=closure
    try:
        exec(compile(closure_text,'<actual-source-closure-owner>','exec'),closure.__dict__)
        node=next(n for n in ast.parse(owner_text).body
                  if isinstance(n,ast.FunctionDef)and n.name=='read_only_return_projection')
        namespace={'os':os,'json':json,'__package__':package_name}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[])),
                     '<actual-projection-owner>','exec'),namespace)
        holders=[];original_init=closure._Held.__init__
        def observed_original_init(held):
            original_init(held);holders.append(held)
        closure._Held.__init__=observed_original_init
        try:yield namespace['read_only_return_projection'],closure
        finally:
            opened=[];count=0
            for held in holders:
                for fd in held.fds:
                    count+=1
                    try:os.fstat(fd)
                    except OSError as exc:
                        if exc.errno!=errno.EBADF:raise
                    else:opened.append(fd)
            RESOURCE_HOLDER_CLOSURES.append({'holders':len(holders),'fds':count,'closed':not opened})
            if opened:raise AssertionError('actual source holders leaked')
    finally:
        del sys.modules[closure_name];del sys.modules[package_name]

def future_projection(rows,expected,mutate=False):
    with tempfile.TemporaryDirectory()as tmp:
        path=Path(tmp).resolve()/'joined-public.ndjson'
        path.write_bytes(b''.join((json.dumps(row)+'\n').encode()for row in rows))
        digest=hashlib.sha256(path.read_bytes()).hexdigest()
        if VARIANT=='before':
            parsed=[json.loads(line)for line in path.read_bytes().splitlines()]
            if mutate:path.write_bytes(b'changed source stream')
            try:return {'state':'observed','result':project_task_result()(parsed,'automatic-return-full209')}
            except (StopIteration,AssertionError,KeyError):return {'state':'unknown'}
        with projection_pair()as(function,actual_closure):
            if not mutate:return function(path,digest,expected)
            original=actual_closure._read_all;fired=[]
            def change_after_actual_read(fd,*args):
                raw=original(fd,*args)
                if raw==path.read_bytes()and not fired:
                    fired.append(True);path.write_bytes(b'changed source stream')
                return raw
            with patch.object(actual_closure,'_read_all',side_effect=change_after_actual_read):
                return function(path,digest,expected)

@unittest.skipUnless(os.name=='posix'and hasattr(os,'O_NOFOLLOW'),'actual source closure requires POSIX')
class SemanticTaskProjection(unittest.TestCase):
    def public_rows(self):
        original=json.loads(source('projection-qga.public.json'))
        actual=json.loads(source('projection-task.public.json'))
        rows=original[:3]+[actual]+original[3:]
        history=actual['result']['matchingHistory'][0]
        expected={k:history[k]for k in ('originControllerId','originRequestId','jobId','operationId')}
        expected['controllerId']=actual['result']['controllerId']
        return rows,actual,expected

    def test_later_semantic_task_row_wins_over_first_exited_bootstrap(self):
        rows,actual,expected=self.public_rows()
        selected=future_projection(rows,expected)
        self.assertEqual(selected.get('state'),'observed')
        self.assertEqual(selected.get('result'),actual['result'])

    def test_bootstrap_exit_without_observed_task_never_becomes_full_return(self):
        rows,_actual,expected=self.public_rows()
        rows=[r for r in rows if r['state']!='ORDINARY_STATUS_RESULT_OBSERVED']
        self.assertEqual(future_projection(rows,expected).get('state'),'unknown')

    def test_observed_task_with_wrong_image_count_is_refused(self):
        rows,actual,expected=self.public_rows();actual['result']['imageFiles']=208
        self.assertEqual(future_projection(rows,expected).get('state'),'unknown')

    def test_every_foreign_original_or_current_identity_is_refused(self):
        for key in ('controllerId','originControllerId','originRequestId','jobId','operationId'):
            rows,_actual,expected=self.public_rows();expected[key]='foreign'
            with self.subTest(key=key):
                self.assertEqual(future_projection(rows,expected).get('state'),'unknown')

    def test_duplicate_semantic_completion_is_refused(self):
        rows,actual,expected=self.public_rows();rows.append(actual)
        self.assertEqual(future_projection(rows,expected).get('state'),'unknown')

    def test_actual_stream_change_during_closure_is_unknown(self):
        rows,_actual,expected=self.public_rows()
        self.assertEqual(future_projection(rows,expected,mutate=True).get('state'),'unknown')

    def test_cleanup_observation_stays_distinct_from_scenario_acceptance(self):
        for present,cleanup in ((True,'gap'),(None,'unknown'),(False,'observed-absent')):
            rows,actual,expected=self.public_rows();actual['result']['inputPresent']=present
            value=future_projection(rows,expected)
            with self.subTest(present=present):
                self.assertEqual(value.get('state'),'observed')
                self.assertEqual(value.get('inputPresent'),present)
                self.assertEqual(value.get('cleanupCode'),'OK')
                self.assertEqual(value.get('cleanupState'),cleanup)
                self.assertIs(value.get('scenarioComplete'),False)
                self.assertIs(value.get('productAcceptance'),False)
                self.assertIs(value.get('nativeActionAllowed'),False)
                self.assertIs(value.get('replayAllowed'),False)

RESOURCE_VARIANT=os.environ.get('FIXTURE_RESOURCE_VARIANT','fixed')
RESOURCE_READ_MEASUREMENTS=[]
RESOURCE_HOLDER_CLOSURES=[]

@unittest.skipUnless(os.name=='posix'and hasattr(os,'O_NOFOLLOW'),'actual bounded source closure requires POSIX')
class BoundedProjectionSource(unittest.TestCase):
    CAP=262143

    def public_rows(self):
        return SemanticTaskProjection().public_rows()

    @contextmanager
    def actual_file(self,raw):
        with tempfile.TemporaryDirectory()as tmp:
            path=Path(tmp).resolve()/'public-stream.ndjson'
            path.write_bytes(raw);path.chmod(0o600)
            yield path,hashlib.sha256(raw).hexdigest()

    @contextmanager
    def measured_reads(self,closure,path,after_first=None):
        original=os.read;inode=path.stat().st_ino;device=path.stat().st_dev
        ledger=[]
        def syscall(fd,count):
            info=os.fstat(fd)
            raw=original(fd,count)
            if (info.st_dev,info.st_ino)==(device,inode):
                ledger.append((count,len(raw)))
                if len(ledger)==1 and after_first is not None:after_first()
            return raw
        # Every returned byte and requested size comes from a real os.read.
        try:
            with patch.object(closure.os,'read',side_effect=syscall):yield ledger
        finally:
            RESOURCE_READ_MEASUREMENTS.append({'test':self.id(), 'syscalls':
                [{'requested':request,'returned':size}for request,size in ledger],
                'returnedBytes':sum(size for _request,size in ledger)})

    def capped_read(self,held,path,digest,cap,gen=None):
        # Historical callers had no optional bound. Exercise their real read,
        # then assert resource behavior; a missing parameter is never RED.
        if 'max_bytes' in inspect.signature(held.read).parameters:
            return held.read(str(path),digest,gen,max_bytes=cap)
        return held.read(str(path),digest,gen)

    def test_initial_oversize_refuses_before_any_read_syscall(self):
        raw=b'x'*(2*1024*1024)
        with self.actual_file(raw)as(path,digest),projection_pair(RESOURCE_VARIANT)as(fn,closure):
            with self.measured_reads(closure,path)as ledger:
                result=fn(path,digest,self.public_rows()[2])
            self.assertEqual(result['state'],'unknown')
            self.assertEqual(ledger,[], 'oversize file allocated/read before refusal')

    def test_growth_during_read_has_exact_cap_plus_one_returned_byte_ceiling(self):
        raw=b'x'*4096
        with self.actual_file(raw)as(path,digest),projection_pair(RESOURCE_VARIANT)as(fn,closure):
            def grow():
                with path.open('ab')as f:f.write(b'y'*(2*1024*1024))
            with self.measured_reads(closure,path,grow)as ledger:
                result=fn(path,digest,self.public_rows()[2])
            self.assertEqual(result['state'],'unknown')
            self.assertEqual(ledger,[(self.CAP+1,len(raw)),(self.CAP+1-len(raw),self.CAP+1-len(raw))])

    def test_growth_before_finish_refuses_without_rehash_read(self):
        rows,_actual,expected=self.public_rows()
        raw=b''.join((json.dumps(r)+'\n').encode()for r in rows)
        with self.actual_file(raw)as(path,digest),projection_pair(RESOURCE_VARIANT)as(fn,closure):
            original=closure._Held.finish;calls=[]
            def grow_before_real_finish(held):
                calls.append(True)
                with path.open('ab')as f:f.write(b'x'*(2*1024*1024))
                return original(held)
            with self.measured_reads(closure,path)as ledger,patch.object(closure._Held,'finish',grow_before_real_finish):
                result=fn(path,digest,expected)
            self.assertEqual(calls,[True])
            self.assertEqual(result['state'],'unknown')
            self.assertEqual(sum(size for _request,size in ledger),len(raw))
            self.assertEqual(ledger,[(self.CAP+1,len(raw)),(self.CAP+1-len(raw),0)])

    def test_growth_during_finish_rehash_is_bounded_and_refused(self):
        rows,_actual,expected=self.public_rows()
        raw=b''.join((json.dumps(r)+'\n').encode()for r in rows)
        with self.actual_file(raw)as(path,digest),projection_pair(RESOURCE_VARIANT)as(fn,closure):
            original=closure._Held.finish
            def growth_during_real_finish(held):
                def grow():
                    with path.open('ab')as f:f.write(b'y'*(2*1024*1024))
                with self.measured_reads(closure,path,grow)as closing_ledger:
                    try:return original(held)
                    finally:ledger.extend(closing_ledger)
            ledger=[]
            with patch.object(closure._Held,'finish',growth_during_real_finish):
                result=fn(path,digest,expected)
            self.assertEqual(result['state'],'unknown')
            self.assertEqual(ledger,[(self.CAP+1,len(raw)),(self.CAP+1-len(raw),self.CAP+1-len(raw))])

    def test_cached_read_enforces_new_smaller_bound_without_reading(self):
        raw=b'x'*4096
        with self.actual_file(raw)as(path,digest),projection_pair(RESOURCE_VARIANT)as(_fn,closure):
            held=closure._Held()
            try:
                held.read(str(path),digest)
                with self.measured_reads(closure,path)as ledger:
                    with self.assertRaises(ValueError):self.capped_read(held,path,digest,128)
                self.assertEqual(ledger,[])
            finally:held.close()

    def test_cached_read_retains_prior_bound_when_omitted_and_file_grows(self):
        raw=b'x'*4096
        with self.actual_file(raw)as(path,digest),projection_pair(RESOURCE_VARIANT)as(_fn,closure):
            held=closure._Held()
            try:
                self.capped_read(held,path,digest,4096)
                with path.open('ab')as f:f.write(b'y')
                with self.measured_reads(closure,path)as ledger:
                    with self.assertRaises(ValueError):held.read(str(path),digest)
                self.assertEqual(ledger,[])
            finally:held.close()

    def test_cached_strengthened_bound_remains_on_finish_after_growth(self):
        raw=b'x'*4096
        with self.actual_file(raw)as(path,digest),projection_pair(RESOURCE_VARIANT)as(_fn,closure):
            held=closure._Held()
            try:
                self.capped_read(held,path,digest,8192)
                self.capped_read(held,path,digest,4096)
                self.capped_read(held,path,digest,8192)
                with path.open('ab')as f:f.write(b'y'*8192)
                with self.measured_reads(closure,path)as ledger:
                    with self.assertRaises(ValueError):held.finish()
                self.assertEqual(ledger,[])
            finally:held.close()

    def test_default_read_preserves_four_tuple_and_generation9_interfaces(self):
        raw=b'x'*(2*1024*1024)
        with self.actual_file(raw)as(path,digest),projection_pair(RESOURCE_VARIANT)as(_fn,closure):
            held=closure._Held()
            try:
                gen=closure.generation(path.stat())
                self.assertEqual(held.read(str(path),digest,gen),raw)
                self.assertEqual(len(held.files[str(path)]),4)
                self.assertEqual(len(held.files[str(path)][1]),9)
                self.assertEqual(held.read(str(path),digest,gen),raw)
                held.finish()
            finally:held.close()

    def test_exact_integer_image_count_required(self):
        rows,actual,expected=self.public_rows();actual['result']['imageFiles']=209.0
        with self.actual_file(b''.join((json.dumps(r)+'\n').encode()for r in rows))as(path,digest),projection_pair(RESOURCE_VARIANT)as(fn,_closure):
            self.assertEqual(fn(path,digest,expected)['state'],'unknown')

    def test_exact_integer_image_bytes_required(self):
        rows,actual,expected=self.public_rows();actual['result']['imageBytes']=200349547.0
        with self.actual_file(b''.join((json.dumps(r)+'\n').encode()for r in rows))as(path,digest),projection_pair(RESOURCE_VARIANT)as(fn,_closure):
            self.assertEqual(fn(path,digest,expected)['state'],'unknown')

    def test_bound_includes_exact_limit_and_refuses_limit_plus_one(self):
        for count,accepted in ((4096,True),(4097,False)):
            with self.subTest(count=count),self.actual_file(b'x'*count)as(path,digest),projection_pair(RESOURCE_VARIANT)as(_fn,closure):
                held=closure._Held()
                try:
                    if accepted:
                        self.assertEqual(self.capped_read(held,path,digest,4096),b'x'*count);held.finish()
                    else:
                        with self.measured_reads(closure,path)as ledger:
                            with self.assertRaises(ValueError):self.capped_read(held,path,digest,4096)
                        self.assertEqual(ledger,[])
                finally:held.close()

    def test_fixed_optional_bound_rejects_nonpositive_or_noninteger_values(self):
        # New argument validation is GREEN coverage, not an old missing-API RED.
        with self.actual_file(b'x')as(path,digest),projection_pair('fixed')as(_fn,closure):
            for cap in (0,-1,True,1.0,'1'):
                held=closure._Held()
                try:
                    with self.subTest(cap=cap),self.assertRaises(ValueError):held.read(str(path),digest,max_bytes=cap)
                    self.assertEqual(held.fds,[])
                finally:held.close()

if __name__=='__main__':unittest.main(verbosity=2)
