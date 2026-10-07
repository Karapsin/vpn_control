"""Public whole-caller fixture; only prepared device facts are synthetic.

Real AuthorityCapture, original collector/parser, own subprocess/pipe/once and
source FD checks run. This is not Android/native effect acceptance.
"""
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
import uuid
from agent_tools import android_installer_asset_collection as collection
from agent_tools import android_installer_asset_staging as assets
from agent_tools import android_installer_direct_transport as direct
from agent_tools.windows_diagnostic_authority_capture import AuthorityCapture

HERE = Path(__file__).resolve().parent
from agent_tools import android_capture_result_publication as publication


def fixture_namespace(name, expected):
    path = HERE/'fixtures/android_copy_evidence_publication'/name
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected
    ns = {'__file__': str(path), '__name__': 'public_fixture'}
    exec(compile(raw, str(path), 'exec', dont_inherit=True), ns)
    return ns, raw.decode()


class PinTypes(unittest.TestCase):
    def test_creation_pin_is_exact_and_type_preserving(self):
        pin = {'sha256': 'a'*64, 'generation': [1]*9}
        self.assertTrue(publication.matches(pin, pin))
        for value in (True, 1.0):
            bad = {'sha256': pin['sha256'], 'generation': [value]+[1]*8}
            self.assertFalse(publication.matches(pin, bad))
        self.assertFalse(publication.matches(pin, dict(pin, path='untrusted')))


@unittest.skipUnless(hasattr(os, 'O_NOFOLLOW') and hasattr(os, 'getuid'), 'POSIX private FD custody')
class WholeCaller(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.root.chmod(0o700)
        directory = self.root/'.runtime/parity-evidence/evidence'
        directory.mkdir(parents=True, mode=0o700)
        self.capture = AuthorityCapture(self.root, 'evidence')
        self.source = self.root/'synthetic-prepared-source.py'
        direct.bundle._write(self.source, b'PUBLIC_PROTOCOL_FIXTURE=1\n')
        raw, pin = direct.snapshot(self.source, private=True)
        self.state = {'root': self.root, 'source': raw, 'correlationId': str(uuid.uuid4()), 'request': {'protocolSeam': True}}
        self.source_held = [direct._dispatch_hold(self.source, pin, raw)]
        @contextlib.contextmanager
        def population(state):
            direct._dispatch_guard(self.source_held)
            yield self.source_held
            direct._dispatch_guard(self.source_held)
        self.reader = types.SimpleNamespace(assets=assets, collector=lambda root:(collection.collector(), {}), _readonly_population=population, source_closing=lambda state:direct._dispatch_guard(self.source_held))
        self.ns, self.text = fixture_namespace('contained-copy.source', 'ff179a63057d829830a5d3129ccdd9fba2d5eb3db375a3658e90c4109a8657e7')
        diagnostic, _ = fixture_namespace('exception-diagnostic.source', '41a4f4df1eccdafed1fde20736614fc6698897b18daa77dbcd072a8d6830bc8c')
        self.ns['exception_diagnostic'] = types.SimpleNamespace(**diagnostic)
        self.ns['publication'] = publication
        old = """  def publish(name,body):
   original=capture.create(name,body)"""
        new = """  def publish(name,body):
   if name=='copy-result.raw':
    publication.publish_result(capture,body,held=held,source_held=[*extra_held,*original_population],source_custody=lambda:(source_closing(),readonly.source_closing(state)))
    return
   original=capture.create(name,body)"""
        self.assertEqual(self.text.count(old), 1)
        self.fixed = dict(self.ns)
        exec(compile(self.text.replace(old, new), '<actual-contained-copy-with-publication>', 'exec', dont_inherit=True), self.fixed)
        self.corr, self.boot = str(uuid.uuid4()), str(uuid.uuid4())
        self.original = {'path': self.ns['ROOT']+'/original.json', 'sha256':'a'*64, 'size':17}
        self.stage = {'schema':1,'kind':'android-baseline-opening-input','correlationId':self.corr,'path':self.ns['ROOT']+'/android-baseline-opening-'+self.corr+'/opening-routing.json','sha256':'a'*64,'size':17,'generation':[1,2,0o100600,1000,1000,1,17,3,4],'directory':[1,3,0o40700,1000,1000],'originalPath':self.original['path'],'originalSha256':'a'*64,'replayAllowed':False}
        self.doc = {'schema':1,'kind':'android-baseline-opening-stage','correlationId':self.state['correlationId'],'request':self.state['request'],'original':self.original,'staged':self.stage,'hostBootId':self.boot,**{k:False for k in ('installerLeaseGranted','guestMutationPerformed','acceptanceComplete','replayAllowed')}}

    def tearDown(self):
        for _,_,chain,fd in self.source_held:
            os.close(fd)
            direct.bundle._close(chain)
        self.capture.close()
        self.tmp.cleanup()

    def call(self, old=False, large=True):
        compact=json.dumps(self.doc).encode()
        self.body=(b' '*(2*1048576) if large else b'')+compact
        header={'schema':1,'kind':'api29-component-baseline-terminal','returncode':0,'failure':None,'hostIdentity':{'uid':1000,'euid':1000,'gid':1000,'egid':1000,'groups':[1000]},'sourceBytes':len(self.state['source']),'sourceSha256':assets.sha(self.state['source']),'stdoutBytes':len(self.body),'stdoutSha256':assets.sha(self.body),'stderrBytes':0,'stderrSha256':assets.sha(b'')}
        code="import sys,json,base64;sys.stdin.buffer.read();raw=b' '*"+str(2*1048576 if large else 0)+'+'+repr(compact)+";sys.stdout.write(json.dumps("+repr(header)+")+'\\n');[sys.stdout.write('out:'+base64.b64encode(raw[i:i+524288]).decode()+'\\n')for i in range(0,len(raw),524288)];sys.stdout.flush()"
        ns=self.ns if old else self.fixed
        return ns['collect'](self.reader,self.state,self.capture,[sys.executable,'-I','-B','-c',code],b'PUBLIC_FIXTURE\n',self.original,self.corr,self.boot,lambda:direct._dispatch_guard(self.source_held))

    def test_actual_old_limit_red(self):
        result=self.call(old=True)
        self.assertEqual(result['state'],'unknown')
        self.assertEqual(result['originalProcess'].returncode,0)
        diagnostic=json.loads((self.capture.path/'builder-copy-collect-exception.private').read_bytes())
        self.assertEqual(diagnostic['chain'][0]['message'],'diagnostic-bytes')

    def test_large_archive_green_and_sticky_once(self):
        result=self.call()
        self.assertEqual(result['state'],'complete')
        manifest=json.loads((self.capture.path/'copy-result.raw-manifest.json').read_bytes())
        raw=b''.join((self.capture.path/r['name']).read_bytes() for r in manifest['chunks'])
        self.assertEqual(raw,self.body)
        self.assertEqual(manifest['sha256'],assets.sha(raw))
        self.assertTrue(all((self.capture.path/r['name']).stat().st_size<=524288 for r in manifest['chunks']))
        self.assertEqual(result['originalProcess'].returncode,0)
        with self.assertRaises(FileExistsError):self.call()

    def test_small_publication_unchanged(self):
        self.assertEqual(self.call(large=False)['state'],'complete')
        self.assertEqual((self.capture.path/'copy-result.raw').read_bytes(),self.body)
        self.assertFalse((self.capture.path/'copy-result.raw-manifest.json').exists())

    def mutation(self, manifest=False):
        original=self.capture.create
        def create(name,body):
            pin=original(name,body)
            if name=='copy-source-closing.json':
                victim='copy-result.raw-manifest.json' if manifest else 'copy-result.raw-0.private'
                (self.capture.path/victim).write_bytes(b'CHANGED')
            return pin
        self.capture.create=create
        result=self.call()
        self.assertEqual(result['state'],'unknown')
        self.assertEqual(result['originalProcess'].returncode,0)
        self.assertFalse(result['replayAllowed'])
        with self.assertRaises(FileExistsError):self.call()

    def test_late_chunk_drift_unknown(self):self.mutation()
    def test_late_manifest_drift_unknown(self):self.mutation(True)

    def test_midstorage_failure_same_pid_unknown(self):
        original=self.capture.create
        def create(name,body):
            if name=='copy-result.raw-1.private':raise OSError('PUBLIC_STORAGE_FAILURE')
            return original(name,body)
        self.capture.create=create
        result=self.call()
        self.assertEqual(result['state'],'unknown')
        self.assertEqual(result['originalProcess'].returncode,0)
        handle=json.loads((self.capture.path/'handle.json').read_bytes())
        self.assertEqual(handle['pid'],result['originalProcess'].pid)
        self.assertTrue(result['diagnostic']['originalExceptionRetained'])
        self.assertFalse((self.capture.path/'copy-result.raw-manifest.json').exists())
        with self.assertRaises(FileExistsError):self.call()

    def test_source_callback_before_final_all_original_leaves(self):
        held=[]
        try:
            publication.publish_result(self.capture,b' '*1100000,held=held,source_held=self.source_held,source_custody=lambda:None)
            def mutate():self.source.write_bytes(b'CHANGED')
            with self.assertRaises(ValueError):publication.closing(held,source_held=self.source_held,source_custody=mutate)
        finally:
            for _,_,chain,fd in held:os.close(fd);direct.bundle._close(chain)

    def test_late_result_parent_read_cannot_hide_source_mutation(self):
        from unittest.mock import patch
        held=[]
        try:
            publication.publish_result(self.capture,b' '*1100000,held=held,source_held=self.source_held,source_custody=lambda:None)
            parent=held[-1][2][-1][0]
            original=os.stat
            changed=[]
            def stat(path,*args,**kwargs):
                result=original(path,*args,**kwargs)
                if path==parent and not changed:
                    changed.append(True)
                    self.source.write_bytes(b'LATE_SOURCE_MUTATION')
                return result
            with patch.object(os,'stat',side_effect=stat),self.assertRaisesRegex(ValueError,'direct_dispatch_changed'):
                publication.closing(held,source_held=self.source_held,source_custody=lambda:None)
            self.assertTrue(changed)
        finally:
            for _,_,chain,fd in held:os.close(fd);direct.bundle._close(chain)

if __name__=='__main__':unittest.main()
