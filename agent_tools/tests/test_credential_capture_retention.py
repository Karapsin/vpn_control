"""The actual private-prepare producer's metadata survives retention safely."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import types
import unittest

from agent_tools import check_output_retention as retention

FIXTURE=Path(__file__).parent/'fixtures/credential_capture_retention'


@unittest.skipUnless(os.name=='posix','private descriptor-relative retention')
class CredentialCaptureRetentionTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve()

    def capture(self):
        return {'stdout':b'','stderr':b'','counts':{'stdout':127,'stderr':0},
                'eof':{'stdout':True,'stderr':True},'returnCode':0,'complete':True,
                'overflow':False,'timeout':False,'readError':False,'pid':123,
                'credentialStreamsSuppressed':True}

    def retain(self,module,capture):
        return module.retain_observation_capture(self.root,label='private-prepare',capture=capture,source_fingerprint='a'*64)

    def test_whole_before_rejects_actual_producer_shape_red_current_green(self):
        path=FIXTURE/'before.source';raw=path.read_bytes();pin=json.loads((FIXTURE/'provenance.json').read_bytes())
        self.assertEqual(pin['sha256'],hashlib.sha256(raw).hexdigest());self.assertEqual(pin['bytes'],len(raw))
        old=types.ModuleType('_retention_before');exec(compile(raw,str(path),'exec'),old.__dict__)
        with self.assertRaisesRegex(old.RetentionError,'input'):self.retain(old,self.capture())
        result=self.retain(retention,self.capture())
        self.assertIsInstance(result,dict)
        receipts=list((self.root/'.rag_index/observation-runs').rglob('receipt.json'))
        self.assertEqual(1,len(receipts));record=json.loads(receipts[0].read_bytes())
        self.assertIs(True,record['credentialStreamsSuppressed'])
        self.assertEqual(self.capture()['counts'],record['counts'])
        self.assertEqual(b'',receipts[0].with_name('stdout.private').read_bytes())
        self.assertEqual(b'',receipts[0].with_name('stderr.private').read_bytes())

    def test_suppression_cannot_admit_bytes_false_flag_or_invalid_completion(self):
        for field,value in (('stdout',b'partial-private'),('stderr',b'private'),
                            ('credentialStreamsSuppressed',False),('credentialStreamsSuppressed',1),
                            ('complete',False),('counts',{'stdout':-1,'stderr':0})):
            capture=self.capture();capture[field]=value
            with self.subTest(field=field,value=value),self.assertRaises(retention.RetentionError):self.retain(retention,capture)
        self.assertFalse((self.root/'.rag_index').exists())

    def test_ordinary_capture_still_requires_retained_prefix_or_overflow(self):
        capture=self.capture();capture.pop('credentialStreamsSuppressed')
        with self.assertRaises(retention.RetentionError):self.retain(retention,capture)


if __name__=='__main__':unittest.main()
