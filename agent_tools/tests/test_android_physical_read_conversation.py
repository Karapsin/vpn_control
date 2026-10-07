"""Real local pipe/child regressions; no device or acceptance authority."""
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from agent_tools import android_component_command_transport as old
from agent_tools import android_physical_read_conversation as read

CORRELATION='d475b822-e8b5-4a8d-a27e-ecf3a07a2d88'
PACKAGE='/data/app/fixture/base.apk'

@unittest.skipUnless(os.name=='posix','POSIX FD/pipe boundary')
class ConversationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name).resolve()
        self.bin=self.root/'bin';self.bin.mkdir()
        self.log=self.root/'log'
        self.adb=self.bin/'adb'
        self.adb.write_text('#!'+sys.executable+'\n'+'''import os,sys,shlex
from pathlib import Path
args=sys.argv[1:]
assert args[:4]==['-s','emulator-5682','shell','-T'] and len(args)==5
remote=shlex.split(args[4]);assert remote[:2]==['sh','-c'] and len(remote)==3
script=remote[2];mode=os.environ.get('FIXTURE_MODE','')
Path(os.environ['FIXTURE_LOG']).write_text(script)
if mode=='foreign':script=script.replace('VCREAD-1','FOREIGN',1)
if mode=='missing':script=script.replace('_emit 4 ', 'exit 0\\n_emit 4 ',1)
if mode=='trailing':script+='\\nprintf extra\\n'
if mode=='terminal':script+='\\nexit 7\\n'
if mode=='response-loss':script=script.replace('_emit 10 ', 'exit 0\\n_emit 10 ',1)
if mode=='duplicate':script=script.replace('_emit 4 ', '_emit 3 ',1)
if mode=='corrupt':script=script.replace('VCREAD-1','VCREAD-X')
if mode=='premature':script=script.replace("IFS=' ' read -r hash_nonce package_path || exit 90",'hash_nonce=00000000000000000000000000000000; package_path=/data/app/fixture/base.apk; sleep 0.1').replace('if IFS= read -r extra; then exit 91; fi','true')
if mode=='input-loss':script=script.replace("IFS=' ' read -r hash_nonce package_path || exit 90","sleep 2; IFS=' ' read -r hash_nonce package_path || exit 90")
if mode=='partial':script=script.replace(' END %s', ' BROKEN %s',1)
if mode=='stdout-only-eof':script+='\\nexec 1>&-\\nsleep 2\\n'
if mode=='same-inode-change':Path(sys.argv[0]).write_text(Path(sys.argv[0]).read_text()+'\\n#changed\\n')
if mode=='capture-name-change':
 p=Path(os.environ['FIXTURE_LOG']).parent/'raw-1.json';q=p.with_suffix('.other');q.write_text('foreign');os.replace(q,p)
os.execv('/bin/sh',['/bin/sh','-c',script])
''');self.adb.chmod(0o700)
        commands={
          'getprop':"import os,sys,time\np=sys.argv[1]\nif os.environ.get('FIXTURE_MODE')=='overflow':print('x'*16385);raise SystemExit\nif os.environ.get('FIXTURE_MODE')=='boundary':print('x'*16383);raise SystemExit\nif os.environ.get('FIXTURE_MODE')=='stderr':print('fault',file=sys.stderr)\nif os.environ.get('FIXTURE_MODE')=='utf8':sys.stdout.buffer.write(b'\\xff');raise SystemExit\nif os.environ.get('FIXTURE_MODE')=='marker':sys.stdout.buffer.write(b'\\x1e');raise SystemExit\nif os.environ.get('FIXTURE_MODE')=='hang':time.sleep(2)\nprint({'ro.build.version.sdk':'35','ro.product.cpu.abi':'x86_64','ro.kernel.qemu.avd_name':'fixture','ro.boot.qemu.avd_name':'','sys.boot_completed':'1'}[p])\n",
          'id':"print('2000')\n",
          'cat':"print('28b8f9af-efbb-44da-9836-0237cb714df9')\n",
          'pidof':"raise SystemExit(1)\n",
          'pm':"import os\nprint('package:'+('/data/app/../base.apk' if os.environ.get('FIXTURE_MODE')=='changedpath' else '/data/app/'+'x'*16000+'/base.apk' if os.environ.get('FIXTURE_MODE')=='input-loss' else '/data/app/fixture/base.apk'))\n",
          'sha256sum':"import os,sys\nfrom pathlib import Path\nPath(os.environ['FIXTURE_LOG']+'.hash').write_text(sys.argv[1])\nprint('a'*64+'  '+('/data/app/foreign/base.apk' if os.environ.get('FIXTURE_MODE')=='wronghashpath' else sys.argv[1]))\n"}
        for name,body in commands.items():
            p=self.bin/name;p.write_text('#!'+sys.executable+'\n'+body);p.chmod(0o700)
        self.env={**os.environ,'PATH':str(self.bin)+':/usr/bin:/bin','FIXTURE_LOG':str(self.log)}
        self.pin=read.binary_pin(self.adb)
        self.sequence=0
    def tearDown(self):self.tmp.cleanup()
    def run_read(self,mode='',deadline=None):
        self.sequence+=1;self.env['FIXTURE_MODE']=mode
        return read.observe(self.adb,self.pin,serial='emulator-5682',api=35,
            correlation_id=CORRELATION,source_sha256='b'*64,environment=self.env,
            capture_path=self.root/('raw-'+str(self.sequence)+'.json'),deadline=deadline)
    def test_current_transport_cannot_complete_real_stdin_handoff(self):
        tree=ast.parse(old.REMOTE)
        binary=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='command_binary')
        self.assertNotIn('stdin',[a.arg for a in binary.args.args])
        p=subprocess.run([sys.executable,'-I','-c','import sys;print("nine");print("hash" if sys.stdin.readline() else "no-path")'],stdin=subprocess.DEVNULL,capture_output=True,timeout=3)
        self.assertEqual(b'nine\nno-path\n',p.stdout)
        # The new fixed conversation supplies the sole path only after frame9.
        self.assertEqual(PACKAGE,self.run_read()['packagePath'])
    def test_actual_fixed_script_complete_raw_and_private_capture(self):
        result=self.run_read()
        self.assertEqual(10,len(result['frames']));self.assertEqual(PACKAGE,result['packagePath'])
        self.assertEqual(b'\n',result['frames'][3]['stdout'])
        self.assertEqual('a'*64,result['frames'][9]['stdout'].decode().split()[0])
        self.assertEqual(PACKAGE,Path(str(self.log)+'.hash').read_text())
        raw=json.loads((self.root/'raw-1.json').read_bytes())
        self.assertTrue(raw['stdoutEOF'] and raw['stderrEOF']);self.assertEqual(0,raw['returncode'])
        self.assertFalse(raw['replayAllowed']);self.assertFalse(raw['admissionGranted'])
        self.assertEqual(0o600,(self.root/'raw-1.json').stat().st_mode&0o777)
    def test_malformed_missing_duplicate_foreign_corrupt_trailing_terminal_loss(self):
        for mode in ('foreign','missing','duplicate','corrupt','trailing','terminal','response-loss','stderr','overflow','premature','partial','utf8','marker','wronghashpath'):
            with self.subTest(mode=mode),self.assertRaises(read.ConversationUnknown):self.run_read(mode,time.monotonic()+1)
            raw=json.loads((self.root/('raw-'+str(self.sequence)+'.json')).read_bytes())
            self.assertFalse(raw['admissionGranted']);self.assertTrue(raw['failure'])
    def test_path_refusal_precedes_actual_hash(self):
        with self.assertRaisesRegex(read.ConversationUnknown,'package_path'):self.run_read('changedpath')
        self.assertFalse(Path(str(self.log)+'.hash').exists())
    def test_real_timeout_preserves_unknown_and_reaps_child(self):
        import time
        with self.assertRaisesRegex(read.ConversationUnknown,'deadline'):self.run_read('hang',time.monotonic()+0.2)
        raw=json.loads((self.root/'raw-1.json').read_bytes())
        self.assertIsNotNone(raw['returncode']);self.assertFalse(raw['complete'])
    def test_binary_name_change_refuses_before_launch(self):
        self.adb.write_text(self.adb.read_text()+'\n#changed\n')
        with self.assertRaisesRegex(read.ConversationUnknown,'binary'):self.run_read()
        self.assertFalse(self.log.exists())
    def test_real_path_handoff_without_reader_is_deadline_bounded(self):
        with self.assertRaisesRegex(read.ConversationUnknown,'deadline'):
            self.run_read('input-loss',time.monotonic()+0.4)
        raw=json.loads((self.root/'raw-1.json').read_bytes())
        self.assertFalse(raw['complete']);self.assertIsNotNone(raw['returncode'])
    def test_exact_field_cap_and_script_catalogue(self):
        result=self.run_read('boundary')
        self.assertEqual(16384,len(result['frames'][0]['stdout']))
        script=self.log.read_text()
        self.assertNotIn('su ',script);self.assertNotIn('mktemp',script)
        self.assertNotIn('base64',script);self.assertEqual(10,script.count('\n_emit '))
        self.assertEqual(1,script.count('sha256sum'))
    def test_actual_name_and_same_inode_changes_refuse(self):
        for mode in ('same-inode-change','capture-name-change'):
            with self.subTest(mode=mode),self.assertRaises(read.ConversationUnknown):self.run_read(mode)
            if mode=='same-inode-change':self.pin=read.binary_pin(self.adb)
            self.sequence=0
            (self.root/'raw-1.json').unlink()
    def test_both_eofs_required_and_environment_unchanged(self):
        import time
        before=dict(self.env);self.env['FIXTURE_MODE']='stdout-only-eof'
        with self.assertRaises(read.ConversationUnknown):self.run_read('stdout-only-eof',time.monotonic()+0.4)
        raw=json.loads((self.root/'raw-1.json').read_bytes())
        self.assertTrue(raw['stdoutEOF']);self.assertFalse(raw['stderrEOF'])
        self.assertEqual('stdout-only-eof',self.env.pop('FIXTURE_MODE'))
        before.pop('FIXTURE_MODE',None);self.assertEqual(before,self.env)
    def test_real_same_inode_capture_overwrite_refuses_and_retains_unknown(self):
        real_fsync=os.fsync;mutations=[];path=self.root/'raw-1.json'
        def overwrite_at_fsync(fd):
            if not mutations and path.exists() and os.fstat(fd).st_ino==path.stat().st_ino:
                before=path.read_bytes();generation=read._fp(os.fstat(fd))
                os.pwrite(fd,b'!',0)
                mutations.append({'before':before,'after':path.read_bytes(),'generation':generation})
            return real_fsync(fd)
        try:
            with mock.patch.object(read.os,'fsync',side_effect=overwrite_at_fsync):
                with self.assertRaisesRegex(read.ConversationUnknown,'capture') as caught:self.run_read()
            self.assertEqual(1,len(mutations));self.assertEqual(b'!',path.read_bytes()[:1])
            self.assertFalse(caught.exception.record['complete'])
            self.assertFalse(caught.exception.record['admissionGranted'])
            self.assertTrue(caught.exception.record['stdoutBase64'])
        finally:
            evidence=os.environ.get('PARITY_CAPTURE_CAUSAL_EVIDENCE')
            if evidence and mutations:
                out=Path(evidence);out.mkdir(parents=True,exist_ok=True)
                for name,raw in [('original-capture.json',mutations[0]['before']),('corrupted-capture.private',path.read_bytes())]:
                    (out/name).write_bytes(raw)
                (out/'mutation.json').write_text(json.dumps({'mutationCount':len(mutations),'openingGeneration':mutations[0]['generation'],'closingGeneration':read._fp(path.stat()),'nativeInvoked':False},indent=2)+'\n')
    def test_actual_overwrite_during_readback_refuses_closing_generation(self):
        real_pread=os.pread;path=self.root/'raw-1.json';mutated=[]
        def overwrite_after_read(fd,size,offset):
            raw=real_pread(fd,size,offset)
            if not mutated and path.exists() and os.fstat(fd).st_ino==path.stat().st_ino and raw:
                os.pwrite(fd,b'!',0);mutated.append(True)
            return raw
        with mock.patch.object(read.os,'pread',side_effect=overwrite_after_read):
            with self.assertRaisesRegex(read.ConversationUnknown,'capture') as caught:self.run_read()
        self.assertEqual([True],mutated);self.assertEqual(b'!',path.read_bytes()[:1])
        self.assertFalse(caught.exception.record['complete'])
        retained=json.loads(__import__('base64').b64decode(caught.exception.serializedRecordBase64))
        self.assertFalse(retained['complete']);self.assertTrue(retained['stdoutBase64'])
    def test_typed_host_clock_and_finite_deadline(self):
        with mock.patch.object(read.time,'monotonic',return_value=True):
            with self.assertRaisesRegex(ValueError,'host_clock'):self.run_read()
        for invalid in (True,float('inf'),float('nan'),-1):
            with self.subTest(deadline=repr(invalid)),self.assertRaises(ValueError):self.run_read(deadline=invalid)
    def test_typed_inputs_and_create_only_capture(self):
        for kwargs in ({'api':True},{'serial':'emulator-9999'},{'source_sha256':True},{'correlation_id':'bad'}):
            values=dict(serial='emulator-5682',api=35,correlation_id=CORRELATION,source_sha256='b'*64,environment=self.env,capture_path=self.root/'bad.json');values.update(kwargs)
            with self.assertRaises(ValueError):read.observe(self.adb,self.pin,**values)
        self.run_read();self.sequence=0
        with self.assertRaises(FileExistsError):self.run_read()

if __name__=='__main__':unittest.main()
