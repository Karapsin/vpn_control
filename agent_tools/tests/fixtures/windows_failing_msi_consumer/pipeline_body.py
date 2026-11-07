"""Whole exact caller pipeline, finite source declarations supplied by routine owner."""
from pathlib import Path
import unittest
from unittest.mock import patch
B=_canonical_root/'agent_tools/windows_system_collector'
BEFORE_ROOT=_fixture_root/'before/caller-protocol'
BODY=_load_source(_fixture_root/'caller_body.py')
OLD_P=_load_source(BEFORE_ROOT/'hold_protocol.py')
OLD_H=_load_source(BEFORE_ROOT/'caller_hold.py')
NEW_CONTRACT='802303fab31a395853807ac3558144e2c163aa18bf949403844860575a57e6b4'
NEW_WORKER='72d52731192589c1c4aa0c94f4bfbaf5335bc408b178077c4e53f1e48e1e0bc0'
ACTUAL_COLLECTOR='7c23f177a701b7e553cccc1fc4ec9de1fadde8991e451050e64e94539da36a8b'
BEFORE=False
CAUSAL_RESULTS={}
def guard():_guard()

class PipelineTests(unittest.TestCase):
    def setUp(self):guard()
    def tearDown(self):guard()
    def test_same_actual_failing_collector_arms_binds_ready_and_ack_once(self):
        pmod,hmod=(OLD_P,OLD_H) if BEFORE else (BODY.P,BODY.H)
        base=BEFORE_ROOT if BEFORE else B
        caller='caller_hold.py' if BEFORE else 'failing_msi_caller_hold.py'
        protocol='hold_protocol.py' if BEFORE else 'failing_msi_hold_protocol.py'
        with patch.multiple(BODY,P=pmod,H=hmod,B=base,SELF='C:\\AdmittedSources\\'+caller,PROTOCOL='C:\\AdmittedSources\\'+protocol):
            patches=[patch.object(hmod,'__file__',BODY.SELF),patch.object(hmod.sys,'executable',BODY.PYTHON),
                patch.object(hmod,'owner_source_path',lambda owner:BODY.OWNER_SOURCE),patch.object(hmod.os,'getpid',lambda:77),
                patch.dict(hmod.os.environ,{'ProgramData':'C:\\ProgramData'}),patch.object(hmod.time,'sleep',lambda _:None)]
            for p in patches:p.start();self.addCleanup(p.stop)
            peer=BODY.Peer();peer.inputs.update(collectorSourceSha256=ACTUAL_COLLECTOR,
                systemContractSourceSha256=NEW_CONTRACT,systemWorkerSourceSha256=NEW_WORKER)
            # The caller fixture supplies declared native storage; request values are actual current source hashes.
            # Pin caller/protocol from the selected complete authentic source, not a synthetic hash claim.
            original_binding=peer.binding
            def binding():
                original_binding();peer.system_request['modules']['contract']['sha256']=NEW_CONTRACT
                peer.system_request['modules']['worker']['sha256']=NEW_WORKER
                peer.system_request['modules']['collector']['sha256']=ACTUAL_COLLECTOR
                peer.system_request['collectorRequest']['collectorSourceSha256']=ACTUAL_COLLECTOR
                peer.publish_binding()
            peer.binding=binding;completed=False;unknown=None
            try:
                hold=peer.arm();peer.write_counts=[1,3,17]
                def closed_collector():
                    self.assertTrue(peer.alive)
                    self.assertEqual(hold.state,'waiting-release')
                    return peer.release()
                peer.release_factory=closed_collector
                hold.driver_completed(0);release=hold.wait_for_release()
                completed=hold.state=='released' and release['collectorOperationId']==BODY.COLLECTOR
                self.assertEqual(peer.inputs['collectorSourceSha256'],ACTUAL_COLLECTOR)
                self.assertEqual(bytes(peer.files[hold.ready_path]['raw']),pmod.encoded(hold.ready))
                self.assertEqual(len(peer.created),1);self.assertIs(peer.caller_collection_hold,hold)
                self.assertIsNotNone(hold.ready_lease);self.assertIsNotNone(hold.release_lease)
                self.assertEqual(hold.collector_request['modules']['collector']['sha256'],ACTUAL_COLLECTOR)
                self.assertEqual(hold.collector_request['modules']['contract']['sha256'],NEW_CONTRACT)
                self.assertEqual(hold.collector_request['modules']['worker']['sha256'],NEW_WORKER)
                self.assertGreater(len([v for v in peer.calls if v[0]=='write']),1)
            except BODY.Parked as exc:unknown=str(exc)
            self.assertTrue(completed,'actual failing collector must finish original caller arm→binding→READY→ACK; '+str(unknown))

    def test_authentic_before_and_current_full_pipeline_pair(self):
        global BEFORE
        for phase,before in [('before',True),('current',False)]:
            BEFORE=before;r=unittest.TestResult();PipelineTests('test_same_actual_failing_collector_arms_binds_ready_and_ack_once').run(r)
            CAUSAL_RESULTS[phase]={'testsRun':r.testsRun,'failures':[v for _,v in r.failures],'errors':[v for _,v in r.errors]}
        BEFORE=False
        self.assertEqual({k:(v['testsRun'],len(v['failures']),len(v['errors'])) for k,v in CAUSAL_RESULTS.items()},
            {'before':(1,1,0),'current':(1,0,0)})
