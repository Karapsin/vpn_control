"""Two hosted-runner races that failed real cases on 529cc610 stay closed.

Fast Checks run 42656925414, Agent Tools Shard 5: Linux, CPython 3.12, the
shard's one serial worker. Each causal case runs the actual case of the peer's
whole unfixed 529cc610 beforeimage and of the current module, with their real
fixtures and local children. Only the moment of one real event is chosen:

- pending descriptors: real config/key PrivateConfigCustody owners that only a
  reference cycle reaches are pending when the high-FD case starts, as earlier
  serial modules leave them, and one full collection runs right before the case
  creates its second child, where CPython 3.12 collects after
  inspect.getsource() has parsed the whole module;
- stalled budget: that child's first poll takes longer than the unfixed .08 s;
- growing free space: a real file of the case's own filesystem is deleted
  before every observer sample after the first.

The unfixed case must fail with the hosted trace itself. No SSH, VM, guest or
network.
"""
import contextlib,gc,hashlib,io,json,os,re,subprocess,tempfile,time,types,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools import private_config_custody,windows_parallel_vm_source_inventory as inventory
from agent_tools.tests import test_ssh_owned_channel_retirement as retirement
from agent_tools.tests import test_windows_parallel_vm_source_inventory as source_inventory

FIXTURE=Path(__file__).parent/'fixtures/hosted_environment_races'
PROVENANCE=FIXTURE/'provenance.json'
HIGH_FD='Fixed546RetirementTests.test_whole_high_fd_reader_writer_red_and_scalable_outer_inner_green'
LOW_DISK='SourceInventoryTest.test_actual_destination_and_low_disk_refuse_without_hash'
DIAGNOSTIC=re.compile(r'descriptor window: pre-baseline collection finalized (\d+) earlier descriptors (\{.*\})\n')
BEFOREIMAGES={'test_ssh_owned_channel_retirement.py':'test_ssh_owned_channel_retirement.py.before.source',
              'test_windows_parallel_vm_source_inventory.py':'test_windows_parallel_vm_source_inventory.py.before.source'}


def provenance():
    value=json.loads(PROVENANCE.read_bytes())
    if value['nativeFailureClaimed'] is not False or any(
            record['traceSha256']!=hashlib.sha256(('\n'.join(record['trace'])+'\n').encode()).hexdigest()
            for record in value['originalFailures'].values()):
        raise ValueError('hosted_environment_races_provenance_changed')
    return value


def before(current):
    """The peer's whole unfixed beforeimage, executed as its own module beside the current one."""
    name=BEFOREIMAGES[Path(current.__file__).name];raw=(FIXTURE/name).read_bytes()
    record=provenance()['sources']['agent_tools/tests/'+Path(current.__file__).name]
    if (hashlib.sha256(raw).hexdigest(),len(raw),record['beforeimage'])!=(record['sourceSha256'],record['sourceBytes'],name):
        raise ValueError('hosted_environment_races_beforeimage_changed')
    module=types.ModuleType('agent_tools.tests._hosted_environment_races_before_'+uuid.uuid4().hex)
    module.__file__=current.__file__;module.__package__='agent_tools.tests'
    exec(compile(raw,str(FIXTURE/name),'exec'),module.__dict__)
    return module


def frames(text):
    """A unittest trace without its header, checkout paths and position markers."""
    lines=text[text.index('Traceback (most recent call last):'):].splitlines()
    return [re.sub(r'File "[^"]*/(test_[a-z0-9_]+\.py)(?:\.before\.source)?"',r'File "\1"',line)
            for line in lines if not re.fullmatch(r'\s*[~^]+\s*',line)]


def hosted(name):
    return frames('\n'.join(provenance()['originalFailures'][name]['trace']))


def failures(result):
    return ''.join(text for _,text in result.failures+result.errors+[(None,'skipped: '+reason) for _,reason in result.skipped])


def plant(root,pairs):
    """Real config/key custody owners reachable only from a cycle, as earlier serial
    modules leave BoundInlineArgv plans in traceback, frame and mock cycles."""
    owners=[]
    for index in range(pairs):
        for name in ('planted-config-%d.json','planted-key-%d'):
            path=Path(root).resolve()/(name%index);path.write_bytes(b'inert planted bytes\n');path.chmod(0o600)
            owners.append(private_config_custody.PrivateConfigCustody(path))
    held=sum(len(owner._fds) for owner in owners)
    owners.append(owners)
    return held


def run_high_fd(module,*,pairs=0,collect_before_child=0,stall_child=0,stall_seconds=0):
    """One actual high-FD case with its real children.

    Chosen: the child before whose creation one full collection runs, and the
    child whose first poll is slow. Planted owners stay pending only while
    automatic collection is off; with pairs=0 it stays on outside the case.
    """
    owner,method=HIGH_FD.split('.')
    enabled=gc.isenabled();gc.collect()
    if pairs:gc.disable()
    created=[];released=[];stalled=[];diagnostics=io.StringIO()
    class Child(subprocess.Popen):
        def __init__(child,*args,**kwargs):
            created.append(child)
            if len(created)==collect_before_child:
                count=len(os.listdir('/dev/fd'));gc.collect();released.append(count-len(os.listdir('/dev/fd')))
            super().__init__(*args,**kwargs)
        def poll(child):
            if created.index(child)+1==stall_child and not stalled:
                stalled.append(None);time.sleep(stall_seconds)
            return super().poll()
    try:
        with tempfile.TemporaryDirectory() as temporary:
            held=plant(temporary,pairs);result=unittest.TestResult()
            with mock.patch.object(subprocess,'Popen',Child),contextlib.redirect_stderr(diagnostics):
                getattr(module,owner)(method).run(result)
            return types.SimpleNamespace(result=result,held=held,children=len(created),released=released,stalled=len(stalled),
                                         restored=gc.isenabled(),diagnostics=diagnostics.getvalue())
    finally:
        # A failed unfixed case leaves its last harmless child unowned: close and reap it here.
        for child in created:
            for stream in (getattr(child,name,None) for name in ('stdin','stdout','stderr')):
                if stream is not None and not stream.closed:stream.close()
            if getattr(child,'_child_created',False):child.wait(timeout=30)
        gc.collect()
        if enabled:gc.enable()


def run_low_disk(module,*,files=3,size=1<<20):
    """One actual low-disk case while its filesystem really gains space.

    A real file beside the case's root is deleted before every observer sample
    after the first, as any other process of the runner can do between two
    samples. The gain is measured with the unprojected statvfs.
    """
    owner,method=LOW_DISK.split('.')
    sample=os.statvfs;observer=inventory.observe_source;entries=[];grown=[];devices=[];result=unittest.TestResult()
    with tempfile.TemporaryDirectory() as temporary:
        ballast=[Path(temporary)/('ballast-%d'%index) for index in range(files)]
        for path in ballast:path.write_bytes(b'\xa5'*size)
        def observed(source,root,*args,**kwargs):
            entries.append(None)
            if len(entries)>1 and ballast:
                devices.append((os.stat(temporary).st_dev,os.stat(root).st_dev))
                first=sample(root);ballast.pop().unlink();last=sample(root)
                grown.append(last.f_bavail*last.f_frsize-first.f_bavail*first.f_frsize)
            return observer(source,root,*args,**kwargs)
        with mock.patch.object(inventory,'observe_source',observed):
            getattr(module,owner)(method).run(result)
    return types.SimpleNamespace(result=result,entries=len(entries),grown=grown,devices=devices)


@unittest.skipUnless(os.name=='posix' and Path('/dev/fd').is_dir(),'POSIX descriptor table required')
class HighDescriptorCaseTests(unittest.TestCase):
    def assert_hosted_failure(self,run):
        text=failures(run.result)
        if run.result.skipped:self.skipTest(text)
        self.assertEqual((1,1,0),(run.result.testsRun,len(run.result.failures),len(run.result.errors)),text)
        self.assertEqual(hosted('highDescriptor'),frames(text),text)

    def test_unfixed_case_fails_when_a_collection_returns_low_descriptors_and_the_current_case_passes(self):
        unfixed=before(retirement)
        quiet=run_high_fd(unfixed,collect_before_child=2);text=failures(quiet.result)+quiet.diagnostics
        if quiet.result.skipped:self.skipTest(text)
        # Control: the same unfixed case and the same collection, with nothing pending, stay green.
        self.assertTrue(quiet.result.wasSuccessful(),text);self.assertEqual((1,4,[0]),(quiet.result.testsRun,quiet.children,quiet.released),text)
        old=run_high_fd(unfixed,pairs=1,collect_before_child=2)
        # At least the null device and both pipes of the second child fit below the table again.
        self.assertGreaterEqual(old.held,4);self.assertEqual(([old.held],2,[]),(old.released,old.children,DIAGNOSTIC.findall(old.diagnostics)))
        self.assert_hosted_failure(old)
        new=run_high_fd(retirement,pairs=1,collect_before_child=2);text=failures(new.result)+new.diagnostics
        self.assertTrue(new.result.wasSuccessful(),text);self.assertEqual((1,4,[0]),(new.result.testsRun,new.children,new.released),text)
        # The current case finalized the planted owners itself, before it filled the table.
        noticed=DIAGNOSTIC.findall(new.diagnostics);self.assertEqual(1,len(noticed),text)
        self.assertEqual((new.held,new.held),(int(noticed[0][0]),sum(json.loads(noticed[0][1]).values())),text)
        self.assertEqual((old.held,False,False),(new.held,old.restored,new.restored))

    def test_unfixed_case_fails_when_its_budget_ends_before_the_first_step_and_the_current_case_passes(self):
        old=run_high_fd(before(retirement),stall_child=2,stall_seconds=.1)
        self.assert_hosted_failure(old);self.assertEqual((1,2),(old.stalled,old.children))
        new=run_high_fd(retirement,stall_child=2,stall_seconds=.1);text=failures(new.result)+new.diagnostics
        self.assertTrue(new.result.wasSuccessful(),text);self.assertEqual((1,1,4,True),(new.result.testsRun,new.stalled,new.children,new.restored),text)

    def test_the_beforeimages_are_the_hosted_generations(self):
        value=provenance();self.assertEqual({'agent_tools/tests/'+name for name in BEFOREIMAGES},set(value['sources']))
        for current in (retirement,source_inventory):
            module=before(current);self.assertEqual(current.__file__,module.__file__)
        self.assertEqual({'highDescriptor','lowDisk'},set(value['originalFailures']))


@unittest.skipUnless(os.name=='posix','POSIX statvfs required')
class LowDiskCaseTests(unittest.TestCase):
    def test_unfixed_case_fails_when_the_filesystem_gains_space_between_samples_and_the_current_case_passes(self):
        old=run_low_disk(before(source_inventory));text=failures(old.result)
        if not old.grown or min(old.grown)<=0:
            self.skipTest('this filesystem did not return a deleted megabyte before the next sample: %r'%old.grown)
        self.assertEqual((1,1,0,2),(old.result.testsRun,len(old.result.failures),len(old.result.errors),old.entries),text)
        self.assertEqual(hosted('lowDisk'),frames(text),text)
        new=run_low_disk(source_inventory);text=failures(new.result)
        self.assertTrue(new.result.wasSuccessful(),text);self.assertEqual(1,new.result.testsRun,text)
        for run in (old,new):
            # The same real gain reached both cases: one deleted megabyte before each later sample.
            self.assertTrue(run.grown and all(gain>0 for gain in run.grown),run.grown)
            self.assertTrue(all(ballast==root for ballast,root in run.devices),run.devices)
        self.assertGreater(len(new.grown),len(old.grown))


if __name__=='__main__':
    unittest.main()
