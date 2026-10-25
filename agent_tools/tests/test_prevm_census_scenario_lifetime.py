"""Whole-before RED/GREEN for real-procfs census scenarios whose holders outlived them.

Fast Checks run 40187427911 (ubuntu-latest) failed the unfixed
test_linux_real_procfs_holder_census_regressions after 3.6 s. The hosted runner
allows 65536 descriptors (configure-limits.sh), so scenario (b) really ran its
8200-descriptor holder, and every holder lived until the whole case ended. The
exact census refuses any scan with actor_descriptor_limit while one same-account
process holds more than 8192 descriptors, so the later cwd-only, map-only and
zombie scenarios were refused for scenario (b)'s holder instead of observing
their own. Developer hosts whose hard limit is below 8300 skip (b) and passed.
The portable half runs the exact embedded census over the module's procfs
double; the Linux half runs the whole before and current cases on the real
procfs. No VM, root census or native creator is involved.
"""
import hashlib,json,os,sys,types,unittest,uuid
from pathlib import Path

from agent_tools.tests import test_windows_creator_prevm_refusal_recovery as current

FIXTURES=Path(__file__).parent/'fixtures/prevm_census_scenario_lifetime'
BEFORE=FIXTURES/'test_windows_creator_prevm_refusal_recovery.py.before.source'
PROVENANCE=FIXTURES/'provenance.json'
BEFORE_SHA256='097826ef1351938b5e6993063de7259ebf06731d361185a745311646ce25f919'
ORIGINAL='test_linux_real_procfs_holder_census_regressions'
JOB='/fake/creators/'+current.MACHINE+'/'+current.OP


def descriptor_capacity():
    import resource
    hard=resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    return hard==resource.RLIM_INFINITY or hard>=8300


class ScenarioLifetimeRegression(unittest.TestCase):
    def before(self):
        provenance=json.loads(PROVENANCE.read_bytes());raw=BEFORE.read_bytes()
        self.assertEqual((BEFORE_SHA256,len(raw),False),(provenance['sourceSha256'],provenance['sourceBytes'],provenance['nativeFailureClaimed']))
        self.assertEqual(BEFORE_SHA256,hashlib.sha256(raw).hexdigest())
        self.assertEqual(current.__name__+'.CreatorPreVmClosure.'+ORIGINAL,provenance['originalFailureTestId'])
        module=types.ModuleType('_prevm_census_before_'+uuid.uuid4().hex);module.__file__=current.__file__
        exec(compile(raw,str(BEFORE),'exec',dont_inherit=True),module.__dict__)
        return module

    def test_exact_census_refuses_later_scenarios_while_an_earlier_holder_lives(self):
        if current.WRITER is None:self.fail('no embedded census source exists')
        paths=[JOB,'/fake/creators/'+current.MACHINE,'/fake/vc-lw-a3aec884']
        # Scenario (b)'s holder still alive while scenario (c)'s cwd-only holder is scanned.
        proc=current.FakeProc(self)
        proc.process(100,start=5,fds=['/dev/null']*8200)
        proc.process(101,start=6,cwd=JOB)
        census=proc.census(paths)
        self.assertEqual((census.get('reason'),census.get('detail',{}).get('substep'),census.get('detail',{}).get('pid')),
                         ('actor_descriptor_limit','descriptor-limit',100),census)
        # Scenario (b) ended before (c) began: (c) observes exactly its own holder.
        proc=current.FakeProc(self)
        proc.process(101,start=6,cwd=JOB)
        census=proc.census(paths)
        self.assertEqual((census.get('reason'),census.get('references'),census.get('detail',{}).get('substep'),census.get('detail',{}).get('pid')),
                         (None,1,'reference-cwd',101),census)

    @unittest.skipUnless(sys.platform.startswith('linux'),'real Linux /proc ownership, ptrace and zombie semantics')
    @unittest.skipIf(os.geteuid()==0,'root reads non-dumpable processes')
    def test_linux_unfixed_red_and_fixed_green_on_the_real_procfs(self):
        if not descriptor_capacity():self.skipTest('descriptor hard limit below 8300: scenario (b) cannot run here')
        unfixed=self.before()
        old=unittest.TestResult();unfixed.CreatorPreVmClosure(ORIGINAL).run(old)
        new=unittest.TestResult();current.CreatorPreVmClosure(ORIGINAL).run(new)
        details='\n'.join(text for _,text in old.failures+old.errors+new.failures+new.errors)
        # Unfixed: scenario (b)'s live holder refuses the later scenarios' scans.
        self.assertEqual((1,0),(old.testsRun,len(old.errors)),details)
        self.assertTrue(old.failures,details)
        self.assertTrue(all('actor_descriptor_limit'in text for _,text in old.failures),details)
        # Fixed: each scenario ends its own holders and every scenario passes.
        self.assertEqual((1,0,0,0),(new.testsRun,len(new.failures),len(new.errors),len(new.skipped)),details)

    def test_retained_whole_before_and_ci_evidence_custody(self):
        provenance=json.loads(PROVENANCE.read_bytes())
        self.assertFalse(provenance['nativeFailureClaimed'])
        self.assertEqual(BEFORE_SHA256,hashlib.sha256(BEFORE.read_bytes()).hexdigest())
        event=provenance['originalFailureEvent']
        self.assertEqual(('finished','failure',provenance['originalFailureTestId']),(event['event'],event['outcome'],event['publicTestId']))
        self.assertEqual(provenance['originalFailureEventSha256'],hashlib.sha256(json.dumps(event,sort_keys=True,separators=(',',':')).encode()).hexdigest())


if __name__=='__main__':unittest.main()
