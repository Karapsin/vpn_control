#!/usr/bin/env python3
"""Routine INERT protocol regression: actual Linux harness, no native admission.

Runs only own TempFS and Python HTTP/CLI children. The CLI below is a simulator,
not VPN Control. Explicit OS/package boundary seams are reported, never native
proof. Actual harness run/order/error/raw/recovery checks remain unchanged.
"""
import contextlib
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import threading
import time
import uuid
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
_IMPORT_PATH = list(sys.path)
try:
 sys.path.insert(0, str(ROOT / 'scripts'))
 import test_linux_public_install as harness
 import prepare_desktop_update_fixture as fixture
finally:
 sys.path[:] = _IMPORT_PATH
 del _IMPORT_PATH

CLI = r'''#!PYTHON
import hashlib,json,os,shutil,sys,time,uuid,urllib.request
from pathlib import Path
c=json.loads(Path(os.environ['INERT_PROTOCOL_CONFIG']).read_text())
root=Path(c['root']); args=sys.argv[1:]; workspace=None
if '--version' in args:
 print((root/'installed-version').read_text().strip());raise SystemExit(0)
if '--state-dir' in args:
 i=args.index('--state-dir');workspace=Path(args[i+1]);del args[i:i+2]
if '--json' in args:args.remove('--json')
if '--timeout-seconds' in args:
 i=args.index('--timeout-seconds');del args[i:i+2]
def save(path,value):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as f:json.dump(value,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
def emit(code='OK',data=None,final=True,owner='inert-owner',exit=0):
 v={'schemaVersion':1,'ok':exit==0,'code':code,'final':final,'controllerId':owner,
    'requestId':c['requestId'],'operationId':c['operationId'],'data':data or {}}
 print(json.dumps(v),flush=True);raise SystemExit(exit)
save(root/('command-'+str(uuid.uuid4())+'.json'),{'argv':args,'pid':os.getpid(),'simulation':True})
if args==['serve']:
 workspace.mkdir(mode=0o700);(workspace/'activation.port').write_text('INERT-NO-PRODUCT-PORT')
 deadline=time.monotonic()+8
 while time.monotonic()<deadline and not (root/'owner-stop').exists():time.sleep(.01)
 raise SystemExit(0)
if args==['quit']:
 (root/'owner-stop').touch();emit()
if args==['status']:emit(data={'runtimeRunning':False})
if args==['updates','check']:emit()
if args==['updates','status']:
 phase=json.loads((root/'download-terminal.json').read_text())['phase'] if (root/'download-terminal.json').exists() else 'idle'
 emit(data={'available':True,'compatible':True,'availableVersion':'2.2.2','phase':phase})
if args==['updates','download']:
 data=urllib.request.urlopen(c['origin']+'/asset',timeout=3).read(1048577)
 actual=hashlib.sha256(data).hexdigest();valid=len(data)==c['size'] and actual==c['sha256']
 save(root/'download-terminal.json',{'phase':'ready' if valid else 'failed','code':'OK' if valid else 'RUNTIME_FAILED',
      'operationId':c['operationId'],'requestId':c['requestId'],'bytes':len(data),'sha256':actual,'simulation':True})
 if not valid:emit('RUNTIME_FAILED',data={'phase':'failed'},exit=1)
 emit()
if args==['updates','install']:
 assert json.loads((root/'download-terminal.json').read_text())['phase']=='ready'
 shutil.copyfile(c['targetJar'],c['baseJar']);(root/'installed-version').write_text('2.2.2\n')
 save(root/'protected-terminal.json',{'version':1,'jobId':c['jobId'],'phase':'SUCCEEDED','code':'OK','simulation':True})
 (root/'owner-stop').touch()
 emit('ACCEPTED',data={'handoffReady':True,'jobId':c['jobId']},final=False)
if args==['operations','status',c['operationId']]:
 emit(data={'jobId':c['jobId'],'originControllerId':'inert-owner','originRequestId':c['requestId']},owner='inert-next-owner')
emit('NOT_FOUND',exit=1)
'''

def exclusive_json(path,value):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as stream:
  json.dump(value,stream,indent=2,sort_keys=True);stream.write('\n');stream.flush();os.fsync(stream.fileno())

def inert_image(root,version):
 # Version metadata is parsed by the real identity helper; code bytes are
 # intentionally not executable JVM bytecode and no real package is used.
 app=root/'lib/app';app.mkdir(parents=True)
 jar=app/'inert.jar'
 with zipfile.ZipFile(jar,'w') as z:
  z.writestr(fixture.MAIN_CLASS,b'NOT-JVM-BYTECODE-INERT-PROTOCOL-ONLY')
  z.writestr(fixture.VERSION_RESOURCE,'displayVersion='+version+'\nbuildNumber='+str(fixture.version_build(version))+'\n')
 (app/'inert.cfg').write_text('[Application]\napp.mainclass=com.kardinal.vpncontrol.desktop.MainKt\napp.classpath=$APPDIR/inert.jar\n')
 return jar,fixture.image_identity(root,version)

def negative_terminal(config,owner,evidence):
 """Prototype case assertions, not a production update implementation."""
 root=Path(config['root']);receipt=json.loads((root/'download-terminal.json').read_text())
 if (receipt['phase']!='failed' or receipt['code']!='RUNTIME_FAILED' or
     receipt['operationId']!=config['operationId'] or receipt['requestId']!=config['requestId']):
  raise AssertionError('original-negative-terminal-mismatch')
 calls=[json.loads(p.read_text()) for p in root.glob('command-*.json')]
 if any(v['argv']==['updates','install'] for v in calls) or (root/'protected-terminal.json').exists():
  raise AssertionError('installation-after-failed-download')
 if not (evidence/'workspace').is_dir() or not owner.poll() is None:
  raise AssertionError('negative-original-evidence-or-owner-lost')
 return receipt

def run_protocol_case(base, *, corrupt):
 advertised=b'INERT-ASSET-NOT-A-PACKAGE\n'*4096
 label='corrupt' if corrupt else 'honest'
 root=base/label;root.mkdir(mode=0o700)
 image=root/'image';jar,identity=inert_image(image,'2.1.19')
 targetJar,_=inert_image(root/'target-image','2.2.2')
 launcher=image/'bin/inert-protocol';launcher.parent.mkdir()
 launcher.write_text(CLI.replace('PYTHON',sys.executable,1));launcher.chmod(0o700)
 marker={'testOnly':True,'productionTrustChanged':False,'sameSourceBuild':True,
         'version':'2.1.19','sourceFingerprint':'b'*64,**identity}
 exclusive_json(image/'TEST-ONLY-INSTALL-FIXTURE.json',marker)
 (root/'installed-version').write_text('2.1.19\n')
 requests=[];asset_path=root/'immutable-asset'
 asset_path.write_bytes(advertised);asset_path.chmod(0o400)
 asset_manifest={'assets':[{'fileName':'asset','sizeBytes':len(advertised),
                            'sha256':hashlib.sha256(advertised).hexdigest()}]}
 class Handler(BaseHTTPRequestHandler):
  def do_GET(self):
   requests.append(self.path)
   handler=self
   class Wire:
    header=True;flipped=False
    def sendall(self,chunk):
     if self.header:self.header=False
     elif corrupt and not self.flipped:
      # Only the inert transport projection changes. Frozen asset bytes stay honest.
      chunk=bytes([chunk[0]^1])+chunk[1:];self.flipped=True
     handler.wfile.write(chunk);handler.wfile.flush()
   fixture.write_resource_response(Wire(),'asset',asset_manifest,{'asset':asset_path},b'')
  def log_message(self,*args):pass
 server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
 thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
 config={'root':str(root),'origin':'http://127.0.0.1:'+str(server.server_address[1]),
         'sha256':hashlib.sha256(advertised).hexdigest(),'size':len(advertised),
         'jobId':str(uuid.uuid4()),'operationId':str(uuid.uuid4()),'requestId':str(uuid.uuid4()),
         'targetJar':str(targetJar),'baseJar':str(jar)}
 exclusive_json(root/'config.json',config)
 owners=[];boundaries=[];public=io.StringIO();error=None
 real_require=harness.require;real_owner=harness.launch_fixture_owner
 real_mkdtemp=tempfile.mkdtemp
 seam_messages={'Explicit owned-disposable-VM confirmation and non-root Linux user required',
                'Requires the native packaged launcher','Installed image ancestry must be root-owned/non-writable'}
 def inert_require(value,message):
  if message in seam_messages:
   if message not in boundaries:boundaries.append(message)
   return
  return real_require(value,message)
 def owner(*args,**kwargs):
  child=real_owner(*args,**kwargs);owners.append(child);return child
 def private_receipt(job):
  value=json.loads((root/'protected-terminal.json').read_text());assert value['jobId']==job;return value
 try:
  with patch.dict(os.environ,{**{k:v for k,v in os.environ.items() if k!='DYLD_INSERT_LIBRARIES'},
                              'INERT_PROTOCOL_CONFIG':str(root/'config.json')},clear=True),\
       patch.object(harness,'require',inert_require),\
       patch.object(harness,'require_human_terminal',lambda _:boundaries.append('No human TTY in inert local fixture')),\
       patch.object(harness,'require_package_managed_launcher',lambda _:boundaries.append('No package ownership in inert local fixture')),\
       patch.object(harness,'protected_receipt',private_receipt),\
       patch.object(harness,'launch_fixture_owner',owner),\
       patch.object(harness.tempfile,'mkdtemp',lambda **kwargs:real_mkdtemp(dir=root,**kwargs)),\
       contextlib.redirect_stdout(public):
   try:harness.run(launcher,'2.2.2',True,same_source_recovery=True)
   except RuntimeError as e:error=str(e)
  evidence=Path(json.loads(public.getvalue().splitlines()[0])['evidence'])
  assert requests==['/asset'];assert len(owners)==1
  assert asset_path.read_bytes()==advertised
  assert asset_path.stat().st_mode&0o777==0o400
  if label=='corrupt':
   assert error and 'Public command failed' in error
   terminal=negative_terminal(config,owners[0],evidence)
   raw=json.loads((evidence/'cli-4.json').read_text());assert raw['code']=='RUNTIME_FAILED'
   assert raw['requestId']==terminal['requestId'] and raw['operationId']==terminal['operationId']
   assert fixture.image_identity(image,'2.1.19')==identity
   env=dict(os.environ,INERT_PROTOCOL_CONFIG=str(root/'config.json'))
   quitrun=subprocess.run([str(launcher),'--state-dir',str(evidence/'workspace'),'--json','quit'],env=env,capture_output=True,timeout=3)
   assert quitrun.returncode==0;owners[0].wait(timeout=3)
   (evidence/'workspace/activation.port').unlink();(evidence/'workspace').rmdir()
   closed={'expectedNegativeComplete':True,'noInstall':True,'ownerNaturalExit':owners[0].returncode,
           'workspaceRemoved':not (evidence/'workspace').exists(),'receipt':terminal}
  else:
   assert error is None,error
   result=json.loads((evidence/'install-result.json').read_text())
   assert result['sameSourceRecoveryProven'] is True and result['protectedReceipt']['phase']=='SUCCEEDED'
   assert result['replacementRecoveryObservation']['controllerId']=='inert-next-owner'
   owners[0].wait(timeout=3)
   (evidence/'workspace/activation.port').unlink();(evidence/'workspace').rmdir()
   closed={'successHarnessComplete':True,'sameSourceRecoveryAssertions':True,'ownerNaturalExit':owners[0].returncode,
           'workspaceRemoved':not (evidence/'workspace').exists()}
  shutil.copytree(evidence,root/'retained-harness-evidence')
  shutil.rmtree(evidence)
  exclusive_json(root/'case-result.json',closed)
  return {'case':label,'nativeAcceptance':False,'productExecuted':False,
          'portabilityAdmissionSeams':boundaries,'calls':len(list(root.glob('command-*.json'))),
          'evidence':str(root/'retained-harness-evidence'),**closed}
 finally:
  (root/'owner-stop').touch()
  for child in owners:child.wait(timeout=9) # own protocol children exit naturally; never kill
  server.shutdown();server.server_close();thread.join(timeout=3)


class LinuxNegativeImportIsolationTests(unittest.TestCase):
    def test_fresh_process_import_restores_exact_original_search_path(self):
        # A fresh process prevents cached harness imports from hiding the leak.
        code = """import importlib.util,json,sys
from pathlib import Path
before=list(sys.path)
source=Path(sys.argv[1]).resolve()
spec=importlib.util.spec_from_file_location('owned_negative_import_check',source)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert sys.path==before, ('import-search-path-leaked',before,sys.path)
assert Path(module.harness.run.__code__.co_filename).resolve()==source.with_name('test_linux_public_install.py')
assert Path(module.fixture.__file__).resolve()==source.with_name('prepare_desktop_update_fixture.py')
print(json.dumps({'searchPathRestored':True,'actualHarnessImported':True}))
"""
        environment=dict(os.environ)
        environment.pop('DYLD_INSERT_LIBRARIES',None)
        with tempfile.TemporaryDirectory(prefix='vpn-negative-import-') as directory:
            result=subprocess.run([sys.executable,'-c',code,str(Path(__file__).resolve())],
                                  cwd=directory,env=environment,capture_output=True,timeout=10)
        self.assertEqual(0,result.returncode,result.stderr.decode(errors='replace'))
        self.assertEqual({'searchPathRestored':True,'actualHarnessImported':True},
                         json.loads(result.stdout))


@unittest.skipUnless(os.name == 'posix', 'POSIX shebang/owned-process fixture; Linux native acceptance remains separate')
class LinuxPublicInstallNegativeTests(unittest.TestCase):
    """Real harness/HTTP/processes, simulated CLI and package boundaries only."""

    def test_corrupt_wire_refuses_before_install_and_preserves_terminal_cleanup(self):
        with tempfile.TemporaryDirectory(prefix='vpn-negative-protocol-') as directory:
            result = run_protocol_case(Path(directory), corrupt=True)
            self.assertTrue(result['expectedNegativeComplete'])
            self.assertTrue(result['noInstall'])
            self.assertEqual(0, result['ownerNaturalExit'])
            self.assertTrue(result['workspaceRemoved'])
            self.assertIs(False, result['nativeAcceptance'])
            self.assertIs(False, result['productExecuted'])
            evidence = Path(result['evidence'])
            raw = json.loads((evidence / 'cli-4.json').read_text())
            self.assertEqual('RUNTIME_FAILED', raw['code'])
            self.assertIs(True, raw['final'])
            self.assertIs(False, raw['ok'])
            self.assertEqual(result['receipt']['requestId'], raw['requestId'])
            self.assertEqual(result['receipt']['operationId'], raw['operationId'])
            self.assertEqual('1', (evidence / 'cli-4.exit').read_text().strip())
            self.assertEqual(b'', (evidence / 'cli-4.stderr').read_bytes())
            self.assertFalse((evidence / 'install-result.json').exists())
            case_root = Path(directory) / 'corrupt'
            self.assertEqual('2.1.19', (case_root / 'installed-version').read_text().strip())
            self.assertEqual(result['receipt'], json.loads((case_root / 'download-terminal.json').read_text()))
            self.assertNotEqual(hashlib.sha256((case_root / 'immutable-asset').read_bytes()).hexdigest(),
                                result['receipt']['sha256'])

    def test_honest_wire_completes_original_handoff_recovery_and_cleanup(self):
        with tempfile.TemporaryDirectory(prefix='vpn-honest-protocol-') as directory:
            result = run_protocol_case(Path(directory), corrupt=False)
            self.assertTrue(result['successHarnessComplete'])
            self.assertTrue(result['sameSourceRecoveryAssertions'])
            self.assertEqual(0, result['ownerNaturalExit'])
            self.assertTrue(result['workspaceRemoved'])
            self.assertIs(False, result['nativeAcceptance'])
            self.assertIs(False, result['productExecuted'])


if __name__ == '__main__':
    unittest.main()
