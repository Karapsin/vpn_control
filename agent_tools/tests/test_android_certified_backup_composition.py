"""Routine reproduction of actual certified-backup namespace/source-load failures."""
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock
from agent_tools import android_installer_component_bundle as bundle
from agent_tools.tests.fixtures import android_certified_backup_wrapper as wrapper
from agent_tools.tests import test_android_installer_component_bundle as fixture

DECLARED_NAMESPACE = "import hashlib,re\nfrom pathlib import Path\nBASELINE_BASE64=__import__('base64')\n"
POSIX = os.name == 'posix' and hasattr(os, 'O_NOFOLLOW') and hasattr(os, 'O_DIRECTORY')

def raw(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()

class SourceShapeTests(unittest.TestCase):
    def test_fixture_is_fixed_public_wrapper_without_private_proof(self):
        for source in (wrapper.GUARD_SOURCE, wrapper.APP_SOURCE, wrapper.PARSER_LOAD_SOURCE):
            compile(source, '<fixed-certified-backup-fragment>', 'exec', dont_inherit=True)
            self.assertNotIn('.runtime/', source)
            self.assertNotIn('ssh.karapsin.com', source)
        tree = ast.parse(wrapper.PARSER_LOAD_SOURCE)
        self.assertEqual([ast.If, ast.Assign, ast.Expr, ast.If], [type(n) for n in tree.body])
        self.assertIn("compile(local[root / CERTIFICATE_CALLER][0]", wrapper.PARSER_LOAD_SOURCE)
        self.assertIn("'__name__': '__reviewed_certificate_parser__'", wrapper.PARSER_LOAD_SOURCE)
        self.assertEqual('2e0d48223acd00e6dcf91edb69c38355fb754a4a4d303261f0975247c4587685', hashlib.sha256(wrapper.GUARD_SOURCE.encode()).hexdigest())
        self.assertEqual('10d944a3df4907db27f4619daa8347fbeef8ff8f06d20b38aa18b27771288326', hashlib.sha256(wrapper.PARSER_LOAD_SOURCE.encode()).hexdigest())

@unittest.skipUnless(POSIX, 'real descriptor source guards and inert POSIX SDK child')
class WrapperCompositionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture.BundleTests(); self.fixture.setUp(); self.addCleanup(self.fixture.tearDown)
        self.root = self.fixture.root
        self.apk = self.root / 'fixture.apk'; self.apk.write_bytes(b'public inert package bytes')
        self.stage = self.root / 'stage.json'; self.stage.write_bytes(b'public inert staged CLI bytes'); self.stage.chmod(0o600)
        self.processes = '\n'.join(name+'\t'+str(pid)+'\t'+str(pid)+' ('+name+') '+' '.join(['S']+['0']*18+['123']) for name,pid in [('adbd',11),('zygote64',22)])
        self.boot = '32a7f8de-3d48-4c88-aa80-18f2b0ebaa24'
        self.facts = {'sdk':'35','abi':'x86_64','kernelAvd':'','bootAvd':'fixture-api35','bootCompleted':'1','shellUid':'2000','guestBootId':self.boot,'processes':bundle._process_facts(self.processes),'packagePath':'/data/app/fixture/base.apk','packageSha256':hashlib.sha256(self.apk.read_bytes()).hexdigest()}
        self.app = {'pid':31,'uid':10123,'name':'com.kardinal.vpncontrol','comm':'vpncontrol','startTicks':991,'guestBootId':self.boot}
        # Explicit portability seam: this is the Linux coordinator identity bound
        # by the real carrier, not authority inferred from this test host's UID.
        self.host = {'uid':0,'euid':0,'gid':0,'egid':0,'groups':[0]}
        self.generation = {'child':{'pid':17,'generation':'fixture'},'guest':{'pid':18,'generation':'fixture'},'device':{'guestBootId':self.boot}}
        self.generation_path = self.root / 'generation.json'; self.generation_path.write_bytes(raw(self.generation)); self.generation_path.chmod(0o600)
        state = self.root / 'state.json'; state.write_bytes(raw({'facts':self.facts,'processes':self.processes,'app':self.app,'apk':str(self.apk)}))
        self.log = self.root / 'calls.jsonl'
        self.child = self.root / 'inert-adb'
        body = '''import json,sys,hashlib
from pathlib import Path
state=json.loads(Path(STATE).read_text());args=sys.argv[1:]
with Path(LOG).open('a') as out:out.write(json.dumps(args)+'\\n')
words=[v for v in args[2:] if v!='-T']
if words[:2]==['shell','getprop']:
 keys={'ro.build.version.sdk':'sdk','ro.product.cpu.abi':'abi','ro.kernel.qemu.avd_name':'kernelAvd','ro.boot.qemu.avd_name':'bootAvd','sys.boot_completed':'bootCompleted'};print(state['facts'][keys[words[2]]])
elif words==['shell','id','-u']:print(state['facts']['shellUid'])
elif words==['shell','cat','/proc/sys/kernel/random/boot_id']:print(state['facts']['guestBootId'])
elif len(words)==2 and words[0]=='shell' and words[1].startswith('sh -c '):print(state['processes'])
elif words==['shell','pm','path','com.kardinal.vpncontrol']:print('package:'+state['facts']['packagePath'])
elif words[:2]==['shell','sha256sum']:print(hashlib.sha256(Path(state['apk']).read_bytes()).hexdigest()+'  '+state['facts']['packagePath'])
elif words==['shell','pidof','com.kardinal.vpncontrol']:print(state['app']['pid'])
elif words==['shell','ps','-A','-o','PID,UID,NAME']:print('PID UID NAME\\n31 10123 com.kardinal.vpncontrol')
elif words==['shell','cat','/proc/31/stat']:print('31 (vpncontrol) '+' '.join(['S']+['0']*18+['991']))
else:sys.exit(23)
'''
        self.child.write_text('#!'+sys.executable+'\nSTATE='+repr(str(state))+'\nLOG='+repr(str(self.log))+'\n'+body); self.child.chmod(0o700)
        self.child_pin = bundle._read(self.child)[1]; self.stage_pin = bundle._read(self.stage,True)[1]; self.generation_pin = bundle._read(self.generation_path,True)[1]
        self.external = {'kind':'fixed-inert-jdk-fixture','sourceSha256':self.child_pin['sha256']}
        certificate = {'host':self.host,'stage':self.stage_pin,'backendBinding':self.external,'facts':self.facts,'appProcess':self.app}
        self.certificate_path = self.root / 'certificate.json'; self.certificate_path.write_bytes(raw(certificate)); self.certificate_path.chmod(0o600)
        certificate_raw,certificate_pin = bundle._read(self.certificate_path,True)
        self.scope = {'ROOT':self.root,'COMPONENT_BUNDLE':bundle,'COMPONENT_RECEIPT':self.fixture.receipt,'CERTIFICATE_PATH':str(self.certificate_path),'CERTIFICATE_RAW':certificate_raw,'CERTIFICATE_PIN':certificate_pin,'CERTIFICATE':certificate,'EXTERNAL':self.external,'GETTER_RECORDS':{},'LAUNCH':{'adbPath':str(self.child),'adbFacts':{'generation':self.child_pin},'environment':{'PATH':os.defpath},'correlationId':'fixture'}}
        self.scope.update(command_host_identity=lambda:dict(self.host),command_host_guard=self.host_guard,external_jdk_guard=self.child_guard,getter_stage=lambda:bundle._read(self.stage,True)[1],getter_generation=self.generation_read,command_binary=self.run_child)
    def host_guard(self):
        self.assertEqual({'uid':0,'euid':0,'gid':0,'egid':0,'groups':[0]},self.host)
    def child_guard(self):
        self.assertEqual(self.child_pin,bundle._read(self.child)[1])
    def generation_read(self,path):
        value,pin=bundle._read(self.generation_path,True);self.assertEqual(self.generation_pin,pin);return json.loads(value)
    def run_child(self,path,generation,args,environment,*,limit,timeout):
        self.assertEqual(self.child,path);self.assertEqual(self.child_pin,generation)
        result=subprocess.run([str(path),*args],env=environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
        self.assertLessEqual(len(result.stdout)+len(result.stderr),limit)
        record={'returncode':result.returncode,'stdoutRaw':result.stdout.decode(),'stderrRaw':result.stderr.decode()}
        self.scope['GETTER_RECORDS'].setdefault('captures',[]).append({'returncode':result.returncode,'stdoutBase64':base64.b64encode(result.stdout).decode(),'stderrBase64':base64.b64encode(result.stderr).decode(),'failure':None})
        return record
    def compile_wrapper(self,quote=True):
        source=DECLARED_NAMESPACE+(wrapper.QUOTE_BINDING if quote else '')+wrapper.APP_SOURCE+wrapper.GUARD_SOURCE
        exec(compile(source,'<actual-certified-backup-wrapper>','exec',dont_inherit=True),self.scope)
    def test_missing_declared_quote_binding_reproduces_nine_record_boundary(self):
        self.compile_wrapper(quote=False)
        with self.assertRaises(NameError) as caught:self.scope['certificate_guard']()
        self.assertEqual('SHLEX_HELPER',caught.exception.name)
        self.assertEqual(9,len(self.scope['CERTIFICATE_OBSERVATIONS']))
        calls=[json.loads(line)for line in self.log.read_text().splitlines()];self.assertEqual(7,len(calls));self.assertFalse(any('sh -c ' in word for call in calls for word in call))
    def test_exact_declared_binding_completes_fifteen_records_and_closing(self):
        self.compile_wrapper();self.scope['certificate_guard']()
        observations=self.scope['CERTIFICATE_OBSERVATIONS'];self.assertEqual(15,len(observations));self.assertEqual(13,len(self.log.read_text().splitlines()))
        calls=[json.loads(line)for line in self.log.read_text().splitlines()]
        self.assertEqual(['-s','emulator-5682','shell','-T','sh -c '+self.scope['SHLEX_HELPER'].quote(bundle._PROCESS_READ)],calls[7])
        self.assertEqual(self.certificate_path.read_bytes(),base64.b64decode(observations[0]['rawBase64']))
        self.assertEqual(self.stage_pin,bundle._read(self.stage,True)[1]);self.assertEqual(self.child_pin,bundle._read(self.child)[1])

@unittest.skipUnless(POSIX, 'descriptor/named-generation source exchange requires POSIX')
class SnapshotParserCompositionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
        self.path=self.root/'parser.py';self.marker=self.root/'executed.txt'
        self.approved="from pathlib import Path\nPath(__file__).with_name('executed.txt').write_text('approved')\nassert __name__!='__main__'\nPARSED='approved'\n"
        self.foreign=self.approved.replace('approved','foreign')
        self.path.write_text(self.approved);self.path.chmod(0o600);self.original=bundle._read(self.path)
        self.scope={'root':self.root,'CERTIFICATE_CALLER':'parser.py','local':{self.path:self.original},'bundle':bundle}
    def replace(self,text):
        target=self.root/'replacement.py';target.write_text(text);target.chmod(0o600);os.replace(target,self.path)
    def load_fixed(self):
        exec(compile(wrapper.PARSER_LOAD_SOURCE,'<actual-authenticated-parser-load>','exec',dont_inherit=True),self.scope)
    def test_old_name_reopen_executes_unreviewed_replacement_red(self):
        self.replace(self.foreign);runpy.run_path(str(self.path));self.assertEqual('foreign',self.marker.read_text());self.assertNotEqual(self.original,bundle._read(self.path))
    def test_fixed_original_bytes_execute_in_declared_nonmain_namespace_green(self):
        self.load_fixed();self.assertEqual('approved',self.marker.read_text());parser=self.scope['certificate_parser'];self.assertEqual(str(self.path),parser['__file__']);self.assertEqual('__reviewed_certificate_parser__',parser['__name__']);self.assertIsNone(parser['__package__'])
    def test_prior_replacement_refuses_before_execution(self):
        self.replace(self.foreign)
        with self.assertRaisesRegex(ValueError,'baseline_local_source_or_authority_changed'):self.load_fixed()
        self.assertFalse(self.marker.exists())
    def test_after_opened_snapshot_name_swap_executes_only_reviewed_bytes_then_refuses(self):
        actual=bundle._read;calls=[]
        def read(path,*args,**kwargs):
            value=actual(path,*args,**kwargs);calls.append(path)
            if len(calls)==1:self.replace(self.foreign)
            return value
        with mock.patch.object(bundle,'_read',side_effect=read):
            with self.assertRaisesRegex(ValueError,'baseline_local_source_or_authority_changed'):self.load_fixed()
        self.assertEqual('approved',self.marker.read_text());self.assertEqual(2,len(calls))
    def test_same_bytes_new_generation_refuses_before_execution(self):
        self.replace(self.approved);self.assertEqual(self.original[0],bundle._read(self.path)[0]);self.assertNotEqual(self.original[1],bundle._read(self.path)[1])
        with self.assertRaisesRegex(ValueError,'baseline_local_source_or_authority_changed'):self.load_fixed()
        self.assertFalse(self.marker.exists())

if __name__=='__main__':unittest.main()
