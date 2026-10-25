"""Whole-before RED/GREEN for macOS guest identities built from this host's durable births.

Fast Checks run 40187427911 (ubuntu-latest) failed or errored four precredential
cases and two original-observer receipt cases. Both modules derived a macOS
guest actor from this host: the precredential custody stand-in used
durable_remote_job._birth(os.getpid()) and the receipt cases an actual local
durable owner. On Linux those births are 'linux:<start ticks>'; MacTartBackend
admits only 'darwin:<seconds>:<microseconds>' and raised
MacBlocked('macos_actor_invalid') before any behaviour under test ran. Here only
those birth strings take the Linux encoding on every host; processes, pipes,
RFB peers and the durable owner stay actual. No VM, guest or input is involved.
"""
import hashlib,json,os,sys,types,unittest,uuid
from pathlib import Path
from unittest import mock

from agent_tools import durable_remote_job as jobs
from agent_tools.tests import test_tart_macos_precredential as precredential
from agent_tools.tests import test_tart_macos_unlock_observer as receipts

FIXTURES=Path(__file__).parent/'fixtures/tart_macos_host_birth_encoding'
PROVENANCE=FIXTURES/'provenance.json'
BEFORE={'precredential':(FIXTURES/'test_tart_macos_precredential.py.before.source','f27a4b0d8830d4ed69a5e3cabf28373e91c58ee6815ab35fd53382515e9eb176'),
        'receipts':(FIXTURES/'test_tart_macos_unlock_observer.py.before.source','42538e9fcf15168cec05e4eae30632105a172427a40cef5935baa8399988daa8')}
PRECREDENTIAL={'test_authentic_incident_fault_old_masks_and_leaks_new_retains_and_closes':'failure',
               'test_old_recipient_guard_masked_new_has_exact_owned_code':'error'}
RECEIPTS=('test_original_durable_owner_after_client_death_has_one_execution_complete_streams',
          'test_forged_terminal_hash_or_other_original_cannot_reuse_real_owner_receipt')


def linux(birth):
    """The same process start in Linux durable_remote_job form: linux:<clock ticks>."""
    if type(birth)is not str or not birth.startswith('darwin:'):return birth
    _,seconds,micros=birth.split(':')
    return 'linux:%d'%(int(seconds)*100+int(micros)//10000)


def linux_births():
    """durable_remote_job._birth as on a Linux host, for every in-process caller."""
    actual=jobs._birth
    return mock.patch.object(jobs,'_birth',lambda pid:linux(actual(pid)))


def linux_owner_records():
    """Owner identities read back from the actual owner's records, as a Linux owner writes them."""
    actual=jobs.observe
    def observe(*args,**kwargs):
        value=actual(*args,**kwargs)
        for row in (value.get('owner'),(value.get('terminal')or{}).get('owner')):
            if type(row)is dict:row['birth']=linux(row.get('birth'))
        return value
    return mock.patch.object(jobs,'observe',observe)


def terminal_calls(calls):
    """observer._terminal, recording each reply's owner birth and the outcome."""
    actual=receipts.observer._terminal
    def terminal(reply,parameters,program):
        birth=((reply.get('status')or{}).get('owner')or{}).get('birth')
        try:value=actual(reply,parameters,program)
        except Exception as error:calls.append((birth,type(error).__name__,str(error)));raise
        calls.append((birth,'admitted',None));return value
    return mock.patch.object(receipts.observer,'_terminal',terminal)


@unittest.skipUnless(os.name=='posix','real POSIX protected FDs and process generations required')
class HostBirthEncodingRegression(unittest.TestCase):
    def before(self,key,current):
        provenance=json.loads(PROVENANCE.read_bytes());path,digest=BEFORE[key];raw=path.read_bytes()
        self.assertEqual((digest,len(raw),False),(provenance['files'][path.name]['sha256'],provenance['files'][path.name]['bytes'],provenance['nativeFailureClaimed']))
        self.assertEqual(digest,hashlib.sha256(raw).hexdigest())
        module=types.ModuleType('_tart_birth_before_'+uuid.uuid4().hex);module.__file__=current.__file__
        exec(compile(raw,str(path),'exec',dont_inherit=True),module.__dict__)
        return module

    @staticmethod
    def run_cases(cls,names):
        result=unittest.TestResult();unittest.TestSuite([cls(name)for name in names]).run(result);return result

    @staticmethod
    def outcomes(result,names):
        rows={name:'success'for name in names}
        for kind,rows_of in (('failure',result.failures),('error',result.errors)):
            for case,_ in rows_of:rows[getattr(case,'test_case',case)._testMethodName]=kind
        for case,_ in result.skipped:rows[getattr(case,'test_case',case)._testMethodName]='skipped'
        return rows

    def test_precredential_custody_actor_red_and_fixed_green_under_linux_births(self):
        names=sorted(PRECREDENTIAL);old_module=self.before('precredential',precredential);start=len(precredential.RESULTS)
        with linux_births():
            old=self.run_cases(old_module.Checks,names);new=self.run_cases(precredential.Checks,names)
        details=lambda:'\n'.join(text for _,text in old.failures+old.errors+new.failures+new.errors)+'\nrecords=%r/%r'%(old_module.RESULTS,precredential.RESULTS[start:])
        # Unfixed: the host birth reaches MacTartBackend's actor check first, with the
        # run 40187427911 outcome of each case.
        self.assertEqual(PRECREDENTIAL,self.outcomes(old,names),details())
        self.assertTrue(any('False is not true'in text for _,text in old.failures),details())
        self.assertTrue(all("'NoneType' object is not subscriptable"in text for _,text in old.errors),details())
        # Fixed: the controlled guest operator keeps the macOS encoding on every host.
        self.assertEqual({name:'success'for name in names},self.outcomes(new,names),details())

    def test_original_owner_receipts_red_and_fixed_green_under_linux_owner_records(self):
        names=list(RECEIPTS);old_module=self.before('receipts',receipts);old_calls=[];new_calls=[]
        with linux_owner_records():
            with terminal_calls(old_calls):old=self.run_cases(old_module.OriginalObserverReceiptTests,names)
            with terminal_calls(new_calls):new=self.run_cases(receipts.OriginalObserverReceiptTests,names)
        details=lambda:'\n'.join(text for _,text in old.failures+old.errors+new.failures+new.errors)+'\nskipped=%r\ncalls=%r/%r'%(old.skipped+new.skipped,old_calls,new_calls)
        # Unfixed: the actual owner's Linux birth raises MacBlocked out of _terminal.
        self.assertEqual({name:'error'for name in names},self.outcomes(old,names),details())
        for name in names:
            self.assertTrue(any('macos_actor_invalid'in text for case,text in old.errors
                                if getattr(case,'test_case',case)._testMethodName==name),details())
        refused=('linux','MacBlocked','macos_actor_invalid');blocked=lambda scheme:(scheme,'QualificationBlocked',None)
        shape=lambda calls:[(str(birth).split(':')[0],kind,reason if kind=='MacBlocked' else None)for birth,kind,reason in calls]
        # Only the forged originalOperationId is refused before the actor check; the forged
        # counter then meets the Linux birth and the case ends.
        self.assertEqual([refused,blocked('linux'),refused],shape(old_calls),details())
        # Fixed: each case first has the actual owner's Linux birth refused, then the same
        # receipt with the macOS guest birth is admitted and every forged field refused.
        self.assertEqual({name:'success'for name in names},self.outcomes(new,names),details())
        self.assertEqual([refused,('darwin','admitted',None),refused]+[blocked('darwin')]*3,shape(new_calls),details())
        self.assertEqual({receipts.GUEST_OWNER_BIRTH},{birth for birth,_,_ in new_calls if str(birth).startswith('darwin:')},details())

    @unittest.skipUnless(sys.platform=='darwin','an actual darwin durable owner exists only on macOS hosts')
    def test_fixed_receipts_admit_the_actual_darwin_owner_natively(self):
        names=list(RECEIPTS);calls=[]
        with terminal_calls(calls):new=self.run_cases(receipts.OriginalObserverReceiptTests,names)
        details='\n'.join(text for _,text in new.failures+new.errors)+'\ncalls=%r'%(calls,)
        self.assertEqual({name:'success'for name in names},self.outcomes(new,names),details)
        # Natively the actual owner's own darwin birth is admitted; no guest birth is substituted.
        self.assertEqual(['admitted']+['QualificationBlocked']*3,[kind for _,kind,_ in calls],details)
        guest=getattr(receipts,'GUEST_OWNER_BIRTH',None)
        self.assertTrue(all(str(birth).startswith('darwin:')and birth!=guest for birth,_,_ in calls),details)

    def test_retained_whole_befores_and_ci_evidence_custody(self):
        provenance=json.loads(PROVENANCE.read_bytes())
        self.assertFalse(provenance['nativeFailureClaimed'])
        for path,digest in BEFORE.values():self.assertEqual(digest,hashlib.sha256(path.read_bytes()).hexdigest(),path.name)
        for event in provenance['originalFailureEvents']:
            self.assertEqual(('finished',True),(event['event'],event['outcome']in('failure','error')))
        self.assertEqual(provenance['originalFailureEventsSha256'],hashlib.sha256(json.dumps(provenance['originalFailureEvents'],sort_keys=True,separators=(',',':')).encode()).hexdigest())


if __name__=='__main__':unittest.main()
