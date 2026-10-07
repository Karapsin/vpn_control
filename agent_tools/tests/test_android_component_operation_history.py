"""Current bounded history is independent of a retained historical receipt."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
import uuid

from agent_tools import android_component_operation_history as history

ROOT=Path(__file__).resolve().parents[2]
OWNER='6373d143-1372-4835-a89b-baafb0959b9f'
HISTORICAL={'controllerId':OWNER,'id':'cf7ca786-f4ce-4c21-9885-856d6eaffffe',
    'requestId':'889dc73b-b874-588c-adea-f513b0f7f21f','operation':'diagnostics.export',
    'phase':'succeeded','final':True,'cancellable':False,'completedUnits':None,
    'totalUnits':None,'code':'OK','configurationRevision':0,'restartRequired':False}


class HistoryTests(unittest.TestCase):
    def validate(self,rows):
        return history.validate(rows,owner=OWNER,revision=0,historical_operation=copy.deepcopy(HISTORICAL))

    def test_empty_current_retains_separate_historical_receipt(self):
        value=self.validate([[],[]])
        self.assertEqual(0,value['currentLedgerCount']);self.assertEqual(2,value['currentLedgerSnapshots'])
        self.assertEqual(hashlib.sha256(b'[]').hexdigest(),value['currentLedgerSha256'])
        self.assertEqual(HISTORICAL['id'],value['historicalOperationId'])
        self.assertFalse(value['historicalOperationPresent']);self.assertFalse(value['replayAllowed'])

    def test_present_exact_historical_and_absent_historical_have_same_proof_hash(self):
        row=copy.deepcopy(HISTORICAL);value=self.validate([[row],[copy.deepcopy(row)]])
        self.assertTrue(value['historicalOperationPresent']);self.assertEqual(1,value['currentLedgerCount'])
        self.assertEqual(value['historicalOperationSha256'],self.validate([[],[]])['historicalOperationSha256'])
        self.assertEqual(HISTORICAL,row)

    def test_changed_historical_row_is_refused_even_if_terminal(self):
        for changes in ({'requestId':str(uuid.uuid4())},{'operation':'routing.export'},
                        {'phase':'failed','code':'PERSISTENCE_FAILED'},{'restartRequired':True}):
            with self.subTest(changes=changes):
                row={**HISTORICAL,**changes}
                with self.assertRaisesRegex(ValueError,'historical_changed'):self.validate([[row],[row]])

    def test_foreign_duplicate_and_nonfinal_current_entries_refused(self):
        for rows in ([{**HISTORICAL,'controllerId':str(uuid.uuid4())}],
                     [HISTORICAL,HISTORICAL],
                     [HISTORICAL,{**HISTORICAL,'id':str(uuid.uuid4())}],
                     [{**HISTORICAL,'final':False}], [{**HISTORICAL,'cancellable':True}]):
            with self.subTest(rows=rows):
                with self.assertRaises(ValueError):self.validate([rows,rows])

    def test_schema_id_phase_code_and_progress_refused(self):
        cases=[{'id':'not-an-operation-id'},{'requestId':False},{'operation':'private.unknown'},
            {'phase':'running'},{'phase':'succeeded','code':'ACCEPTED'},
            {'phase':'failed','code':'OUTCOME_UNKNOWN'},{'phase':'failed','code':'TIMEOUT'},
            {'code':'CANCELLED'},{'configurationRevision':True},{'configurationRevision':1},
            {'restartRequired':None},{'completedUnits':True},{'totalUnits':-1},
            {'completedUnits':history._LONG_MAX+1},{'completedUnits':2,'totalUnits':1}]
        for changes in cases:
            row={**HISTORICAL,**changes}
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):self.validate([[row],[row]])
        for row in ({k:v for k,v in HISTORICAL.items() if k!='code'}, {**HISTORICAL,'privateInput':'untrusted'}):
            with self.assertRaisesRegex(ValueError,'row_unknown'):self.validate([[row],[row]])

    def test_current_terminal_failure_and_cancellation_are_accounted(self):
        for phase,code in (('failed','PERSISTENCE_FAILED'),('cancelled','CANCELLED')):
            row={**HISTORICAL,'id':str(uuid.uuid4()),'requestId':str(uuid.uuid4()),'phase':phase,'code':code}
            self.assertEqual(1,self.validate([[row],[row]])['currentLedgerCount'])

    def test_current_lists_must_repeat_without_expiry_or_order_drift(self):
        other={**HISTORICAL,'id':str(uuid.uuid4()),'requestId':str(uuid.uuid4())}
        for lists in ([[],[HISTORICAL]],[[HISTORICAL],[]],[[HISTORICAL,other],[other,HISTORICAL]]):
            with self.assertRaisesRegex(ValueError,'current_changed'):self.validate(lists)

    def test_finite_list_snapshot_and_revision_boundaries(self):
        for lists in ([],[[]],tuple([[],[]]),[[]]*(history.MAX_SNAPSHOTS+1),[{},{}]):
            with self.assertRaises(ValueError):self.validate(lists)
        rows=[{**HISTORICAL,'id':str(uuid.uuid4()),'requestId':str(uuid.uuid4())} for _ in range(257)]
        with self.assertRaisesRegex(ValueError,'bounded_list_required'):self.validate([rows,rows])
        for owner,revision in ((False,0),(OWNER,True),(OWNER,-1),(OWNER,history._LONG_MAX+1)):
            with self.assertRaises(ValueError):history.validate([[],[]],owner=owner,revision=revision,historical_operation=HISTORICAL)


class NativeProofTests(unittest.TestCase):
    """Actual archived whole consumer with explicit synthetic protocol histories.

    Original 413 remains UNKNOWN; this never opens or promotes its private raw.
    """
    def consume(self,proof):
        import tempfile
        from agent_tools.tests.fixtures.android_api29_epoch import history as fixture
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        capture=fixture.Capture(Path(temporary.name));caller=fixture.consumer()
        raw=(json.dumps(proof,sort_keys=True)+'\n').encode()
        # Raw original transport bytes are durable before semantic consumption.
        original=caller.archive(capture,'original-raw',raw)
        state={'capture':capture,'request':proof['request'],'historicalOperation':copy.deepcopy(HISTORICAL),'leaf':'synthetic-protocol-history'}
        return caller,raw,state,capture,original

    def test_whole_immutable_native_proof_reproduces_expiry_without_adopting_old_unknown(self):
        from agent_tools.tests.fixtures.android_api29_epoch import history as fixture
        proof=fixture.proof(OWNER,[])
        caller,raw,state,capture,original=self.consume(proof)
        self.assertNotEqual('95209229ab66de46b5f5535bfc7af92f5144b649386fe765a26faa07637bf3bc',hashlib.sha256(raw).hexdigest())
        value=caller.validate_proof(raw,state)
        self.assertEqual(158,value['recordCount']);self.assertEqual(0,value['operationHistory']['currentLedgerCount'])
        self.assertEqual(2,value['operationHistory']['currentLedgerSnapshots'])
        self.assertFalse(value['operationHistory']['historicalOperationPresent'])
        self.assertEqual(HISTORICAL['id'],value['historicalTerminalOperation'])
        self.assertFalse(value['acceptanceComplete']);self.assertFalse(value['replayAllowed'])
        self.assertEqual(hashlib.sha256(raw).hexdigest(),original['sha256']);capture.verify()
        chunk=original['chunks'][0];self.assertEqual(raw,(capture.path/chunk['name']).read_bytes())

    def test_actual_whole_consumer_present_exact_history_and_repeated_expiry(self):
        from agent_tools.tests.fixtures.android_api29_epoch import history as fixture
        proof=fixture.proof(OWNER,[copy.deepcopy(HISTORICAL)])
        caller,raw,state,capture,_=self.consume(proof);value=caller.validate_proof(raw,state)
        self.assertTrue(value['operationHistory']['historicalOperationPresent']);capture.verify()
        proof=fixture.proof(OWNER,[])
        row=proof['records'][3];import base64
        record=json.loads(base64.b64decode(row['rawBase64']));reply=json.loads(record['record']['stdoutRaw']);reply['data']['operations']=[HISTORICAL];record['record']['stdoutRaw']=json.dumps(reply)
        content=json.dumps(record).encode();row.update(bytes=len(content),sha256=hashlib.sha256(content).hexdigest(),pin={'sha256':hashlib.sha256(content).hexdigest()},rawBase64=base64.b64encode(content).decode())
        caller,raw,state,capture,_=self.consume(proof)
        with self.assertRaisesRegex(ValueError,'current_changed'):caller.validate_proof(raw,state)
        capture.verify()

    def test_closing_row_tamper_retains_raw_before_refusal_and_capture_drift(self):
        from agent_tools.tests.fixtures.android_api29_epoch import history as fixture
        proof=fixture.proof(OWNER,[]);proof['records'][-1]['sha256']='f'*64
        caller,raw,state,capture,original=self.consume(proof)
        with self.assertRaisesRegex(ValueError,'baseline_evidence_bytes_changed'):caller.validate_proof(raw,state)
        self.assertIn('guard-record-156-manifest.json',capture.pins);capture.verify()
        (capture.path/original['chunks'][0]['name']).write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'fixture_capture_changed'):capture.verify()


if __name__=='__main__':unittest.main()
