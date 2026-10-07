"""Stable package comparison causal coverage, no ignored/native dependencies.

Read-body snapshots exercise the real parser/observe/run. The operational
constructor, physical reader, transport and source-admission remain separate
native gates; supplied inert facts cannot establish an acceptance proof.
"""
import copy
import unittest
from agent_tools.tests.fixtures import android_process_package_comparison as fixture

PACKAGE='Packages:\n  Package [com.kardinal.vpncontrol] (123abc):\n    appId=10209\n    versionName=2.2.2\n    versionCode=16840 minSdk=24 targetSdk=35\n    User 0: installed=true hidden=false\n    object=PackageState@1234\n'
FACTS={'sdk':'35','guestBootId':'10000000-0000-4000-8000-000000000001','packagePath':'/data/app/fixed/base.apk','packageSha256':'a'*64}


def observe(packages,repaired=True,facts=None):
    guard=fixture.reader(repaired).__new__(fixture.reader(repaired));queue=iter(packages)
    guard._physical=lambda:copy.deepcopy(FACTS if facts is None else facts)
    def text(words):
        if words==['shell','-T','dumpsys','package','com.kardinal.vpncontrol']:return next(queue)
        if words==['shell','-T','ps','-A','-o','PID,UID,NAME']:return 'PID UID NAME\n1 0 init\n'
        raise AssertionError('unreviewed read')
    guard._text=text;guard.diagnostics=lambda:{};guard._evidence=lambda *args:None
    return guard


class PackageComparisonTests(unittest.TestCase):
    def test_actual_old_hash_only_failure_then_stable_verified_facts_pass(self):
        other=PACKAGE.replace('@1234','@9876')
        old=observe([PACKAGE,other,other],False).run();self.assertEqual('process_census_changed',old['failure'])
        new=observe([PACKAGE,other]).run();self.assertEqual('api35-current-process-observed',new['state']);self.assertTrue(new['closingGuardsVerified'])
        self.assertNotEqual(new['first']['packageDumpSha256'],new['last']['packageDumpSha256'])
        self.assertEqual(new['first']['packageFacts'],new['last']['packageFacts'])
        for field in ('certificateGranted','guestMutationPerformed','acceptanceComplete','replayAllowed'):self.assertIs(new[field],False)
        for field in ('currentOwner','persistentOff','runtimeStopped'):self.assertEqual('unknown',new[field])
    def test_authoritative_package_fields_never_normalized(self):
        for changed in (PACKAGE.replace('appId=10209','appId=10210'),PACKAGE.replace('versionName=2.2.2','versionName=2.2.3'),PACKAGE.replace('versionCode=16840','versionCode=16841'),PACKAGE.replace('installed=true','installed=false'),PACKAGE+'    flags=DEBUGGABLE\n'):
            with self.subTest(changed=changed):
                result=observe([PACKAGE,changed,changed]).run();self.assertEqual('unknown',result['state']);self.assertFalse(result['closingGuardsVerified'])
    def test_full_boot_apk_path_and_process_birth_drift_refused(self):
        for key,value in (('guestBootId','20000000-0000-4000-8000-000000000001'),('packagePath','/data/app/other/base.apk'),('packageSha256','b'*64)):
            guard=observe([PACKAGE,PACKAGE,PACKAGE]);facts=iter([copy.deepcopy(FACTS),{**FACTS,key:value},{**FACTS,key:value}]);guard._physical=lambda:next(facts)
            with self.subTest(key=key):self.assertEqual('unknown',guard.run()['state'])
        guard=observe([PACKAGE,PACKAGE]);first=guard.observe();last=copy.deepcopy(first);last['processes']=[{'pid':17,'startTicks':124}]
        self.assertFalse(guard.equivalent(first,last))
    def test_schema_drift_not_hidden_by_comparator(self):
        guard=observe([PACKAGE]);first=guard.observe();last={**first,'unreviewedField':True}
        self.assertFalse(guard.equivalent(first,last))

if __name__=='__main__':unittest.main()
