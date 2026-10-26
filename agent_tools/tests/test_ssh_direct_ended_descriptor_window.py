"""Unrelated deferred custody finalizers cannot counterfeit the direct-ended FD gate.

Actual provider/TempFS cases of the whole unfixed beforeimage and of the current
module; only when one real cyclic PrivateConfigCustody owner is finalized is
controlled. No SSH, VM, guest or network.
"""
import contextlib,gc,hashlib,io,json,os,re,tempfile,types,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools import private_config_custody
from agent_tools.tests import test_ssh_direct_ended_source_transition as current

FIXTURE=Path(__file__).parent/'fixtures/ssh_direct_ended_descriptor_window'
BEFORE=FIXTURE/'test_ssh_direct_ended_source_transition.py.before.source'
PROVENANCE=FIXTURE/'provenance.json'
ORIGINAL='ProviderEndedClosureHistoryTests.test_actual_equal_source_ended_then_new_intent'
# Every measured FD window of the module: ready, refusal, provider/MCP transition,
# closure transition and checkpoint-74 population admission.
SITES=(ORIGINAL,'ProviderEndedHistoryTests.test_refuses_live','ProviderEndedHistoryTests.test_actual_old_provider_and_mcp_transition',
       'ProviderEndedClosureHistoryTests.test_actual_b1a_closure_only_transition_preserves_every_saved_byte',
       'Checkpoint74EndedPopulationTests.test_actual_a78_full_population_to_checkpoint74')
CHANGED='operation FD table changed: '
DIAGNOSTIC=re.compile(r'descriptor window: pre-baseline collection finalized (\d+) earlier descriptors (\{.*\})\n')


def before():
    raw=BEFORE.read_bytes();provenance=json.loads(PROVENANCE.read_bytes())
    if ((hashlib.sha256(raw).hexdigest(),len(raw),provenance['sourcePath'],provenance['nativeFailureClaimed'])!=
            (provenance['sourceSha256'],provenance['sourceBytes'],'agent_tools/tests/test_ssh_direct_ended_source_transition.py',False)):
        raise ValueError('descriptor_window_beforeimage_changed')
    module=types.ModuleType('agent_tools.tests._descriptor_window_before_'+uuid.uuid4().hex)
    module.__file__=current.__file__;module.__package__='agent_tools.tests'
    exec(compile(raw,str(BEFORE),'exec'),module.__dict__)
    return module


def plant(root,pairs=3):
    """Real config/key custody owners reachable only from a cycle, as earlier serial
    modules leave BoundInlineArgv plans in traceback, frame and mock cycles."""
    owners=[]
    for index in range(pairs):
        for name in ('.vm-hosts.local.json','inert-key'):
            path=Path(root).resolve()/('%s-%d'%(name,index));path.write_bytes(b'inert private bytes\n');path.chmod(0o600)
            owners.append(private_config_custody.PrivateConfigCustody(path))
    held=sum(len(owner._fds) for owner in owners)
    owners.append(owners)
    return held


def failures(result):
    return ''.join(text for _,text in result.failures+result.errors)


def report(text):
    """The complete JSON diagnostic of the fixed window's failure."""
    return json.loads(text.split('AssertionError: '+CHANGED,1)[1].strip())


@unittest.skipUnless(current.fixture_owner.COORDINATOR_CAPABLE,'POSIX private TempFS provider required')
class DescriptorWindowTests(unittest.TestCase):
    def replay(self,module,name,*,pairs=3,effect=None,automatic=False):
        """Run one actual case; one full collection starts its measured invoke.

        The owners are planted when the case's seed returns, after the case's own
        garbage is collected, so the measured baseline holds them pending. They
        stay pending only while automatic collection is off; with it on, nothing
        is planted and the window alone must stop the collector.
        """
        if automatic and pairs:raise ValueError('planted_owner_needs_manual_collection')
        enabled=gc.isenabled();gc.collect()
        if not automatic:gc.disable()
        held=[];collected=[];inside=[];diagnostics=io.StringIO()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                original_seed,original_invoke=module.ProviderEndedHistoryTests.seed,module.ProviderEndedHistoryTests.invoke
                def seed(case,*args,**kwargs):
                    value=original_seed(case,*args,**kwargs)
                    gc.collect();held.append(plant(temporary,pairs))
                    return value
                def invoke(case,*args,**kwargs):
                    if kwargs.get('corr') is not None and kwargs.get('corr')==getattr(case,'new',None):
                        # CI: an allocation-triggered full collection inside the invoke.
                        count=len(os.listdir('/dev/fd'));gc.collect();collected.append(count-len(os.listdir('/dev/fd')))
                        inside.append(gc.isenabled())
                        if effect is not None:effect()
                    return original_invoke(case,*args,**kwargs)
                group,method=name.split('.');result=unittest.TestResult()
                with mock.patch.object(module.ProviderEndedHistoryTests,'seed',seed),mock.patch.object(module.ProviderEndedHistoryTests,'invoke',invoke),contextlib.redirect_stderr(diagnostics):
                    getattr(module,group)(method).run(result)
                if len(held)!=1:raise AssertionError('case must seed exactly once: %r'%held)
                return result,held[0],collected,inside,gc.isenabled(),diagnostics.getvalue()
        finally:
            gc.collect()
            if enabled:gc.enable()

    def test_unfixed_counts_deferred_custody_finalizer_red_fixed_window_green(self):
        provenance=json.loads(PROVENANCE.read_bytes());trace=provenance['originalFailureTrace']
        self.assertEqual(provenance['originalFailureTraceSha256'],hashlib.sha256(('\n'.join(trace)+'\n').encode()).hexdigest())
        self.assertEqual(current.__name__+'.'+ORIGINAL,provenance['originalFailureTestId'])
        self.assertEqual('AssertionError: 43 != 7',trace[-1])
        old=before()
        for name in SITES:
            with self.subTest(site=name):
                result,held,collected,_,_,diagnostics=self.replay(old,name)
                text=failures(result)
                self.assertEqual((1,1,0,''),(result.testsRun,len(result.failures),len(result.errors),diagnostics),text)
                # That collection finalized exactly the planted owners, inside the measured invoke.
                self.assertEqual([held],collected,text)
                counts=re.fullmatch(r'AssertionError: (\d+) != (\d+)',text.rstrip('\n').splitlines()[-1])
                self.assertIsNotNone(counts,text);self.assertEqual(held,int(counts[1])-int(counts[2]),text)
                if name==ORIGINAL:
                    # The same line-103 statement as the CI trace; 43 - 7 there, planted held here.
                    self.assertIn('  File "%s", %s'%(BEFORE,trace[4].split('", ',1)[1]),text.splitlines(),text)
                    self.assertIn(trace[5],text.splitlines(),text)
                result,held,collected,_,_,diagnostics=self.replay(current,name)
                # Fixed: the window finalized them before its baseline and said so in one line;
                # none remained for the in-window collection and the operation's own FD table is unchanged.
                self.assertTrue(result.wasSuccessful(),failures(result)+diagnostics)
                self.assertEqual((1,[0]),(result.testsRun,collected),failures(result)+diagnostics)
                line=DIAGNOSTIC.fullmatch(diagnostics);self.assertIsNotNone(line,diagnostics);self.assertEqual(held,int(line[1]),diagnostics)

    def test_fixed_window_reports_kept_deferred_and_foreign_descriptors_completely(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();kept=[];owned=[];released=[]
            foreign=os.open(str(root/'foreign-preexisting'),os.O_RDWR|os.O_CREAT,0o600)
            def keep():kept.append(os.open(str(root/'owned-unclosed'),os.O_RDWR|os.O_CREAT,0o600))
            def defer():
                path=root/'deferred-owner';path.write_bytes(b'inert private bytes\n');path.chmod(0o600)
                custody=private_config_custody.PrivateConfigCustody(path);owned.append(len(custody._fds));cycle=[custody];cycle.append(cycle)
            def close_foreign():os.close(foreign);released.append(foreign)
            try:
                for label,effect in (('kept',keep),('deferred',defer),('foreign',close_foreign)):
                    with self.subTest(effect=label):
                        # Automatic collection stays on outside: only the window may stop it.
                        result,_,collected,inside,restored,diagnostics=self.replay(current,ORIGINAL,pairs=0,effect=effect,automatic=True)
                        text=failures(result)
                        self.assertEqual((1,1,0,[0],[False],True,''),(result.testsRun,len(result.failures),len(result.errors),collected,inside,restored,diagnostics),text)
                        value=report(text)
                        self.assertEqual({'opened','closed','before','after','threads','gcEnabled','finalizedBeforeBaseline'},set(value),text)
                        self.assertTrue(value['before'] and all(len(row)==4 for table in ('before','after') for row in value[table].values()),text)
                        # Collector state and threads are recorded inside the window, before it is restored.
                        self.assertEqual((False,{},True),(value['gcEnabled'],value['finalizedBeforeBaseline'],'MainThread' in value['threads']),text)
                        if label=='kept':
                            self.assertEqual(({str(kept[0])},{}),(set(value['opened']),value['closed']),text)
                            self.assertTrue(value['opened'][str(kept[0])][3].endswith('owned-unclosed'),text)
                        elif label=='deferred':
                            # The collector cannot run inside the window: a release left to it fails.
                            self.assertEqual((owned[0],{}),(len(value['opened']),value['closed']),text)
                            self.assertTrue(any(row[3].endswith('deferred-owner') for row in value['opened'].values()),text)
                        else:
                            self.assertEqual(({},[str(foreign)]),(value['opened'],list(value['closed'])),text)
                            self.assertTrue(value['closed'][str(foreign)][3].endswith('foreign-preexisting'),text)
            finally:
                for fd in kept+([] if released else [foreign]):os.close(fd)
                gc.collect()


if __name__=='__main__':
    unittest.main()
