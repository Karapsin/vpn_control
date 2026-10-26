"""Earlier serial cases' deferred finalizers cannot counterfeit exact FD windows.

Every peer that compared a global FD count around its measurement now uses
descriptor_window. Each causal case runs one actual case of the peer's whole
unfixed 005852a2 beforeimage and of the current module. Only when one full
collection runs is controlled: real config/key PrivateConfigCustody owners that
only a reference cycle reaches are pending when the case starts, as earlier
serial modules leave them, and that collection runs at one call of a seam inside
the measured window, as an allocation-triggered one did on the hosted runner.
No SSH, VM, guest or network.
"""
import contextlib,gc,hashlib,io,json,os,re,tempfile,types,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools import private_config_custody,readiness_tart_macos_registry as registry,ssh_direct_nested_channel as direct
from agent_tools.tests import test_readiness_tart_macos_registry as tart
from agent_tools.tests import test_ssh_direct_ended_inventory_successor as successor
from agent_tools.tests import test_ssh_direct_nested_channel as nested
from agent_tools.tests import test_ssh_direct_original6b_observation as original6b
from agent_tools.tests import test_ssh_direct_retained_delivery_transition as delivery
from agent_tools.tests import test_ssh_direct_retained_wrapper_transition as wrapper
from agent_tools.tests import test_windows_census_child_imports as census
from agent_tools.tests import test_windows_direct_readonly_checkpoint as readonly

FIXTURE=Path(__file__).parent/'fixtures/descriptor_window'
PROVENANCE=FIXTURE/'provenance.json'
# (current peer, its whole beforeimage, one measured case, seam whose call `at` runs inside that case's window)
CASES=(
    (successor,'test_ssh_direct_ended_inventory_successor.py.before.source','EndedInventorySuccessorTests.test_authentic_matcher_exact_predecessor_and_current_tuple',
     lambda m:(m.EndedInventorySuccessorTests,'old_history',1)),
    (census,'test_windows_census_child_imports.py.before.source','WindowsCensusChildImportsTests.test_exact_one_import_fix_completes_entire_main_JSON',
     lambda m:(m.WindowsCensusChildImportsTests,'control',1)),
    (readonly,'test_windows_direct_readonly_checkpoint.py.before.source','WindowsDirectReadonlyCheckpointTests.test_changed_product_refuses',
     lambda m:(m.WindowsDirectReadonlyCheckpointTests,'git',1)),
    # Both prepare_lease_namespace calls and the enrollment admission load the namespace before the 20 measured loads.
    (tart,'test_readiness_tart_macos_registry.py.before.source','MacProductionCustodyBoundariesTests.test_lease_enrollment_host_admission_precedes_guest_write_and_healthy_repeat_has_no_dispatch',
     lambda m:(registry.MacCustody,'load_lease_namespace',4)),
    (delivery,'test_ssh_direct_retained_delivery_transition.py.before.source','RetainedDeliveryTransitionTests.test_new_connection_has_actual_working_direct_route_only',
     lambda m:(direct,'route_options',1)),
    (wrapper,'test_ssh_direct_retained_wrapper_transition.py.before.source','RetainedWrapperTransitionTests.test_retained_status_reports_only_original_positive_end_without_child_or_writes',
     lambda m:(m.RetainedWrapperTransitionTests,'observe',1)),
    (wrapper,'test_ssh_direct_retained_wrapper_transition.py.before.source','RetainedWrapperTransitionTests.test_missing_original_ready_refuses',
     lambda m:(m.RetainedWrapperTransitionTests,'observe',1)),
    (original6b,'test_ssh_direct_original6b_observation.py.before.source','Original6bObservationTests.test_actual_original_ended_status_appends_terminal_only',
     lambda m:(m.Original6bObservationTests,'invoke',1)),
    (original6b,'test_ssh_direct_original6b_observation.py.before.source','Original6bObservationTests.test_missing_ready_refuses',
     lambda m:(m.Original6bObservationTests,'invoke',1)),
    (original6b,'test_ssh_direct_original6b_observation.py.before.source','Original6bObservationTests.test_ready_reply_never_promotes_usable_selection',
     lambda m:(m.Original6bObservationTests,'invoke',1)),
    (nested,'test_ssh_direct_nested_channel.py.before.source','DirectChannelTests.test_closing_key_mutation_refuses_and_closes_holders',
     lambda m:(direct,'prepare',1)),
)
DIAGNOSTIC=re.compile(r'descriptor window: pre-baseline collection finalized (\d+) earlier descriptors (\{.*\})\n')


def provenance():
    value=json.loads(PROVENANCE.read_bytes())
    if value['nativeFailureClaimed'] is not False or value['originalFailureTraceSha256']!=hashlib.sha256(('\n'.join(value['originalFailureTrace'])+'\n').encode()).hexdigest():
        raise ValueError('descriptor_window_provenance_changed')
    return value


def before(current,name):
    """The peer's whole unfixed beforeimage, executed as its own module beside the current one."""
    raw=(FIXTURE/name).read_bytes();record=provenance()['sources']['agent_tools/tests/'+Path(current.__file__).name]
    if (hashlib.sha256(raw).hexdigest(),len(raw),record['beforeimage'])!=(record['sourceSha256'],record['sourceBytes'],name):
        raise ValueError('descriptor_window_beforeimage_changed')
    module=types.ModuleType('agent_tools.tests._descriptor_window_before_'+uuid.uuid4().hex)
    module.__file__=current.__file__;module.__package__='agent_tools.tests'
    exec(compile(raw,str(FIXTURE/name),'exec'),module.__dict__)
    return module


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


def replay(module,test,seam,*,pairs=3,effect=None):
    """Run one actual case; one full collection starts at seam call `at`, inside its window.

    Planted owners stay pending only while automatic collection is off. With
    pairs=0 it stays on outside the case, so only the window may stop it.
    """
    owner,method=test.split('.');target,name,at=seam(module)
    enabled=gc.isenabled();gc.collect()
    if pairs:gc.disable()
    calls=[];collected=[];inside=[];diagnostics=io.StringIO()
    try:
        with tempfile.TemporaryDirectory() as temporary:
            held=plant(temporary,pairs);original=getattr(target,name)
            def seam_call(*args,**kwargs):
                calls.append(None)
                if len(calls)==at:
                    count=len(os.listdir('/dev/fd'));gc.collect();collected.append(count-len(os.listdir('/dev/fd')));inside.append(gc.isenabled())
                    if effect is not None:effect()
                return original(*args,**kwargs)
            result=unittest.TestResult()
            with mock.patch.object(target,name,seam_call),contextlib.redirect_stderr(diagnostics):
                getattr(module,owner)(method).run(result)
            return types.SimpleNamespace(result=result,held=held,calls=len(calls),collected=collected,inside=inside,
                                         restored=gc.isenabled(),diagnostics=diagnostics.getvalue())
    finally:
        gc.collect()
        if enabled:gc.enable()


def failures(result):
    return ''.join(text for _,text in result.failures+result.errors+[(None,'skipped: '+reason) for _,reason in result.skipped])


def report(text,label):
    """The complete JSON diagnostic of a failing descriptor window."""
    return json.loads(text.split('AssertionError: '+label+' FD table changed: ',1)[1].strip())


@unittest.skipUnless(os.name=='posix' and Path('/dev/fd').is_dir(),'POSIX descriptor table required')
class DescriptorWindowPeerTests(unittest.TestCase):
    def test_unfixed_global_counts_red_shared_window_green(self):
        value=provenance();self.assertEqual({'agent_tools/tests/'+Path(m.__file__).name for m,*_ in CASES},set(value['sources']))
        for current,name,test,seam in CASES:
            with self.subTest(peer=current.__name__,case=test):
                quiet=replay(before(current,name),test,seam,pairs=0);text=failures(quiet.result)+quiet.diagnostics
                if quiet.result.skipped:self.skipTest(text)
                # Control: the same unfixed case and in-window collection with nothing pending stays green.
                self.assertTrue(quiet.result.wasSuccessful(),text);self.assertEqual((1,[0]),(quiet.result.testsRun,quiet.collected),text)
                old=replay(before(current,name),test,seam);text=failures(old.result)
                # RED: the in-window collection finalized exactly the pending owners and
                # the global count changed by exactly what that collection closed.
                self.assertEqual((1,1,0,[old.held],''),(old.result.testsRun,len(old.result.failures),len(old.result.errors),old.collected,old.diagnostics),text)
                counts=re.fullmatch(r'AssertionError: (\d+) != (\d+)',text.rstrip('\n').splitlines()[-1])
                self.assertIsNotNone(counts,text);self.assertEqual(old.held,abs(int(counts[1])-int(counts[2])),text)
                new=replay(current,test,seam);text=failures(new.result)+new.diagnostics
                # GREEN: the window finalized them before its baseline and said so in one line;
                # none remained for the in-window collection.
                self.assertTrue(new.result.wasSuccessful(),text)
                self.assertEqual((1,[0],old.calls),(new.result.testsRun,new.collected,new.calls),text)
                line=DIAGNOSTIC.fullmatch(new.diagnostics)
                self.assertIsNotNone(line,text);self.assertEqual(old.held,int(line[1]),text)

    def test_fixed_case_window_reports_kept_deferred_foreign_and_replaced_descriptors_completely(self):
        test='WindowsCensusChildImportsTests.test_exact_one_import_fix_completes_entire_main_JSON'
        seam=lambda m:(m.WindowsCensusChildImportsTests,'control',1)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();kept=[];owned=[];released=[]
            foreign=os.open(str(root/'foreign-preexisting'),os.O_RDWR|os.O_CREAT,0o600)
            swapped=os.open(str(root/'swapped-preexisting'),os.O_RDWR|os.O_CREAT,0o600)
            def keep():kept.append(os.open(str(root/'owned-unclosed'),os.O_RDWR|os.O_CREAT,0o600))
            def defer():
                path=root/'deferred-owner';path.write_bytes(b'inert planted bytes\n');path.chmod(0o600)
                custody=private_config_custody.PrivateConfigCustody(path);owned.append(len(custody._fds));cycle=[custody];cycle.append(cycle)
            def close_foreign():os.close(foreign);released.append(foreign)
            def replace():
                # Same number and the same count, another file: only the identity changes.
                other=os.open(str(root/'swapped-replacement'),os.O_RDWR|os.O_CREAT,0o600);os.dup2(other,swapped);os.close(other)
            try:
                for label,effect in (('kept',keep),('deferred',defer),('foreign',close_foreign),('replaced',replace)):
                    with self.subTest(effect=label):
                        # Automatic collection stays on outside: only the case's window may stop it.
                        run=replay(census,test,seam,pairs=0,effect=effect);text=failures(run.result)
                        if run.result.skipped:self.skipTest(text)
                        self.assertEqual((1,1,0,[0],[False],True,''),(run.result.testsRun,len(run.result.failures),len(run.result.errors),run.collected,run.inside,run.restored,run.diagnostics),text)
                        value=report(text,'test')
                        self.assertEqual({'opened','closed','before','after','threads','gcEnabled','finalizedBeforeBaseline'},set(value),text)
                        self.assertTrue(value['before'] and all(len(row)==4 for table in ('before','after') for row in value[table].values()),text)
                        self.assertEqual((False,{},True),(value['gcEnabled'],value['finalizedBeforeBaseline'],'MainThread' in value['threads']),text)
                        if label=='kept':
                            self.assertEqual(({str(kept[0])},{}),(set(value['opened']),value['closed']),text)
                            self.assertTrue(value['opened'][str(kept[0])][3].endswith('owned-unclosed'),text)
                        elif label=='deferred':
                            # The collector cannot run inside the window: a release left to it fails.
                            self.assertEqual((owned[0],{}),(len(value['opened']),value['closed']),text)
                            self.assertTrue(any(row[3].endswith('deferred-owner') for row in value['opened'].values()),text)
                        elif label=='foreign':
                            self.assertEqual(({},[str(foreign)]),(value['opened'],list(value['closed'])),text)
                            self.assertTrue(value['closed'][str(foreign)][3].endswith('foreign-preexisting'),text)
                        else:
                            self.assertEqual(([str(swapped)],[str(swapped)],len(value['before'])),(list(value['opened']),list(value['closed']),len(value['after'])),text)
                            self.assertEqual((True,True),(value['opened'][str(swapped)][3].endswith('swapped-replacement'),value['closed'][str(swapped)][3].endswith('swapped-preexisting')),text)
            finally:
                for fd in kept+([] if released else [foreign])+[swapped]:os.close(fd)
                gc.collect()


if __name__=='__main__':
    unittest.main()
