"""A neighbour of the live filesystem cannot fail or silence the free-space regression.

Found by reviewing the fix of Fast Checks run 42656925414 at 68d59e2a, not on a
hosted runner: test_hosted_environment_races proved its real free-space gain
with two statvfs samples around each deleted megabyte, the comparison of two
samples of a live filesystem that it was written to remove from its peers. A
neighbour that took the megabyte back in between failed the current-case arm,
skipped the unfixed arm, or let the unfixed case pass and failed that arm.

Each causal case runs the actual low-disk regression case of the current module
while one real neighbour file, larger than the deleted megabyte, is written
once at one chosen moment. Nothing is projected and no sample is compared here:
the regression case must run both of its arms and pass. A last case puts the
unfixed 529cc610 case in place of the current one: repeating an attempt must
never excuse a case, so the regression case must still fail. No SSH, VM, guest
or network.
"""
import contextlib,io,os,tempfile,unittest
from pathlib import Path
from unittest import mock
from agent_tools import windows_parallel_vm_source_inventory as inventory
from agent_tools.tests import test_hosted_environment_races as subject

CASE='LowDiskCaseTests.test_unfixed_case_fails_when_the_filesystem_gains_space_between_samples_and_the_current_case_passes'
NEIGHBOUR=4<<20
REPEATS=4


def run_beside_a_neighbour(moment=None,ordinal=0):
    """The actual regression case while one real neighbour file is written once.

    'between': right after the ordinal-th deleted megabyte, before the next sample.
    'after': before the ordinal-th observer entry, after both samples around its deletion.
    """
    owner,method=CASE.split('.')
    deleted=[];entered=[];written=[];result=unittest.TestResult();notices=io.StringIO()
    unlink=Path.unlink;observe=inventory.observe_source
    with tempfile.TemporaryDirectory() as neighbourhood:
        def write():
            path=Path(neighbourhood)/('neighbour-%d'%len(written));path.write_bytes(b'\x5a'*NEIGHBOUR);written.append(path)
        def unlinked(path,*args,**kwargs):
            unlink(path,*args,**kwargs)
            if path.name.startswith('ballast-'):
                deleted.append(path)
                if moment=='between' and len(deleted)==ordinal:write()
        def observed(*args,**kwargs):
            entered.append(None)
            if moment=='after' and len(entered)==ordinal:write()
            return observe(*args,**kwargs)
        with mock.patch.object(Path,'unlink',unlinked),mock.patch.object(inventory,'observe_source',observed), \
                contextlib.redirect_stderr(notices):
            getattr(subject,owner)(method).run(result)
    return result,len(written),notices.getvalue()


@unittest.skipUnless(os.name=='posix','POSIX statvfs required')
class NeighbourCaseTests(unittest.TestCase):
    def assert_both_arms_ran_and_passed(self,moment,ordinal):
        # Control: without a neighbour the case runs here at all; a filesystem that never
        # returns a deleted megabyte skips it, and then no neighbour can be told apart.
        result,written,notices=run_beside_a_neighbour()
        text=subject.failures(result)+notices
        if result.skipped:self.skipTest(text)
        self.assertEqual((1,[],[],0),(result.testsRun,result.failures,result.errors,written),text)
        result,written,notices=run_beside_a_neighbour(moment,ordinal)
        text=subject.failures(result)+notices
        # The neighbour really wrote once, and the case neither failed nor skipped an arm.
        self.assertEqual((1,[],[],[],1),(result.testsRun,result.failures,result.errors,result.skipped,written),text)
        # It passed because the harness named the attempt its neighbour changed and repeated it.
        repeated=subject.REPEATED.findall(notices)
        if not repeated:self.skipTest('this filesystem did not show the neighbour file to the harness')
        self.assertEqual(('1',str(subject.ATTEMPTS)),repeated[0][:2],text)

    def test_a_neighbour_between_the_samples_of_the_current_arm_does_not_fail_the_regression(self):
        self.assert_both_arms_ran_and_passed('between',2)

    def test_a_neighbour_between_the_samples_of_the_unfixed_arm_does_not_skip_the_regression(self):
        self.assert_both_arms_ran_and_passed('between',1)

    def test_a_neighbour_before_the_unfixed_observer_sample_does_not_fail_the_regression(self):
        self.assert_both_arms_ran_and_passed('after',2)

    def test_an_unfixed_case_in_place_of_the_current_one_still_fails_the_regression(self):
        owner,method=CASE.split('.');stand_in=subject.before(subject.source_inventory)
        for _ in range(REPEATS):
            result=unittest.TestResult()
            with mock.patch.object(subject,'source_inventory',stand_in),contextlib.redirect_stderr(io.StringIO()):
                getattr(subject,owner)(method).run(result)
            text=subject.failures(result)
            if result.skipped:self.skipTest(text)
            self.assertEqual((1,1,0),(result.testsRun,len(result.failures),len(result.errors)),text)
            # The stand-in failed the way the hosted case did and that ended the regression case.
            if text.rstrip('\n').splitlines()[-1]=='AssertionError: ValueError not raised':return
            # Otherwise a neighbour kept the gain from the stand-in, which passed: nothing was excused, so run again.
        self.fail(text)


if __name__=='__main__':
    unittest.main()
