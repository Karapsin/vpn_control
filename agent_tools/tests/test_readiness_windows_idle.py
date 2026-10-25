"""Incomplete Windows work visibility can never authorize a guest reboot."""
import copy
import unittest
from agent_tools import readiness_windows_idle as idle
from agent_tools.tests.test_readiness_windows_guest import facts,MACHINE,SID

BOOT='2026-10-20T09:37:35.5000000Z'
ROOT='12345678:0000000000000042:0000000000000001'


def observation():
    return {'schemaVersion':1,'sessionFacts':facts(),
            'leaseFacts':{'schemaVersion':1,'machine':MACHINE,'boot':BOOT,'rootGeneration':ROOT,
                          'visibilityComplete':True,'blockers':[],'terminalCount':1},
            'jobFacts':{'schemaVersion':1,'machine':MACHINE,'boot':BOOT,'rootGeneration':None,
                        'admissionGeneration':None,'visibilityComplete':True,'blockers':[],'terminalCount':0},
            'processes':[{'pid':4,'name':'System','session':0,'knownSystem':True,'self':False}],
            'lifecycle':{'setupComplete':True,'fixtureTaskDisabled':True,'installerAbsent':True},
            'blockers':[],'visibilityComplete':True}


class WindowsIdleTests(unittest.TestCase):
    def check(self,value):return idle.validate(value,MACHINE,BOOT,'recovery',SID,ROOT)

    def test_only_complete_current_native_inventory_has_no_blockers(self):
        value=self.check(observation())
        self.assertTrue(value['visibilityComplete']);self.assertEqual(frozenset(),value['blockers'])

    def test_active_unknown_lease_or_missing_visibility_blocks(self):
        for missing in ['guest','leases','unknownlease','jobs','unknownjob','operator','unknownprocess','installer']:
            value=observation()
            if missing=='guest':value['visibilityComplete']=False
            elif missing=='leases':value['leaseFacts']['visibilityComplete']=False;value['leaseFacts']['blockers']=[{'operationId':None,'reason':'lease_inventory_unavailable'}]
            elif missing=='unknownlease':value['leaseFacts']['blockers']=[{'operationId':MACHINE,'reason':'lease_original_work_not_terminal'}]
            elif missing=='jobs':value['jobFacts']['visibilityComplete']=False;value['jobFacts']['blockers']=[{'operationId':None,'reason':'job_inventory_unavailable'}]
            elif missing=='unknownjob':value['jobFacts']['blockers']=[{'operationId':MACHINE,'reason':'job_original_work_not_terminal'}]
            elif missing=='operator':value['sessionFacts']['sessions'].append({'Id':3,'Name':'RDP-Tcp#0','State':0})
            elif missing=='unknownprocess':value['processes'][0]['knownSystem']=False
            else:value['lifecycle']['installerAbsent']=False
            with self.subTest(case=missing):self.assertTrue(self.check(value)['blockers'])

    def test_foreign_epoch_and_malformed_census_are_refused(self):
        value=observation();value['sessionFacts']['boot']='2026-10-20T10:37:35.5000000Z'
        with self.assertRaisesRegex(ValueError,'windows_idle_epoch'):self.check(value)
        for field,bad in [('pid',True),('session',True),('self',1),('name','private\ninput')]:
            value=observation();value['processes'][0][field]=bad
            with self.subTest(field=field),self.assertRaises(ValueError):self.check(value)

    def test_generator_has_readonly_boundaries_and_no_input_channel(self):
        source=idle.powershell_source(MACHINE,BOOT,'recovery',SID,ROOT)
        self.assertEqual(1,source.count('[Console]::WriteLine'))
        self.assertIn('Win32_Process',source);self.assertIn('VpnControlFixtureInitialize',source)
        for command in ['guest-shutdown','Restart-Computer','Set-ItemProperty','SendKeys','SendInput']:
            self.assertNotIn(command,source)
        for bad in [None,'operator\ncommand']:
            with self.assertRaises(ValueError):idle.powershell_source(MACHINE,BOOT,bad,SID,ROOT)


if __name__=='__main__':unittest.main()
