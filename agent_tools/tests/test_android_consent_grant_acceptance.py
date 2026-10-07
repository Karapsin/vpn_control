"""Executed grant-only consent regressions; no emulator or native actions."""
import unittest
from agent_tools import android_consent_grant_acceptance as s

WARNING='VPN Control wants to set up a VPN connection that allows it to monitor network traffic. Only accept if you trust the source.'
def dialog(warning=WARNING, button='OK'):
 return '<hierarchy><node package="com.android.vpndialogs" resource-id="android:id/alertTitle" text="Connection request"/><node package="com.android.vpndialogs" resource-id="com.android.vpndialogs:id/warning" text="'+warning+'"/><node package="com.android.vpndialogs" resource-id="android:id/button1" text="'+button+'" enabled="true" bounds="[10,20][110,80]"/></hierarchy>'
class GrantUiTest(unittest.TestCase):
 def test_api29_unknown_warning_cannot_use_api35_geometry(self):
  self.assertIsNone(s._positive_button(dialog(),api=29))
 def test_exact_owned_positive(self): self.assertEqual(s._positive_button(dialog()),(60,50))
 def test_warning_and_button_must_be_owned(self):
  self.assertIsNone(s._positive_button(dialog('VPN Control wants to set up a VPN connection for a foreign operation')))
  self.assertIsNone(s._positive_button(dialog(button='Delete')))
  self.assertIsNone(s._positive_button(dialog(WARNING+' Foreign approval required.')))

import hashlib,io,json,os,stat,subprocess,sys,tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
C='b68a93e0-445d-4cf5-8fee-2f5d90065bd3'
OWNER='e8d73f61-f7bf-4e24-b13a-aff40b1c8e1b'
OP='ff817f82-7160-46f3-b3c0-1689142942de'
RULES={'ignore_rules':False,'block_quic_udp_443':True,'proxy_packages':[],'direct_domain_suffixes':['example.org']}

class Fixture:
 def __init__(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.root.chmod(0o700)
  self.job=self.root/('android-consent-grant-'+C);self.job.mkdir(mode=0o700)
  self.adb=str(self.root/'adb');self.cli=str(self.root/('android-cli-stage-'+C+'/tree/opt/vpn-control/bin/vpn-control'))
  Path(self.cli).parent.mkdir(parents=True)
  for p in (Path(self.adb),Path(self.cli)):p.write_text('#!/bin/sh\n');p.chmod(0o700)
  readback=self.root/('android-readback-'+C);readback.mkdir(mode=0o700)
  self.backup=readback/'routing.json';self.write(self.backup,{'type':'vpn_control_routing_rules','version':7,'exported_at':'old','rules':RULES})
  self.intent={'schema':2,'host':'archlinux','device':'api35','api':35,'correlationId':C,'artifactId':'artifact','packageSha256':'d'*64,'cliStageCorrelationId':C,'cliPath':self.cli,'cliManifestSha256':'a'*64,'cliRpmSha256':'b'*64,'cliLauncherSha256':'c'*64,'cliDesktopJarSha256':'d'*64,'openingReadbackCorrelationId':C,'backupSha256':hashlib.sha256(self.backup.read_bytes()).hexdigest(),'expectedOwner':OWNER,'expectedRevision':2,'expectedAvd':'owned-api35','fixtureRoot':str(self.root),'sourceSha':'a'*40}
  self.expected=json.dumps(self.intent,sort_keys=True,separators=(',',':'));self.write(self.job/'intent.json',self.intent)
  self.write(self.job/'identity.json',{'pid':99999999,'startTicks':1})
  self.rules=dict(RULES);self.accepted=False;self.tapped=False;self.on=0;self.taps=0;self.reads=0;self.calls=[];self.break_at=None;self.xml=dialog();self.code='INVALID_ARGUMENT';self.drift=None;self.stage=0;self.permission_override=None;self.closing_drift=None;self.closure_drift=None;self.wait_count=0;self.diagnostic_ledger=[]
 def close(self):self.temp.cleanup()
 @staticmethod
 def write(path,v):path.write_text(json.dumps(v));path.chmod(0o600)
 def done(self,v,code=0):return SimpleNamespace(returncode=code,stdout=(v if isinstance(v,str) else json.dumps(v)).encode())
 def run(self,argv,**kwargs):
  self.calls.append(argv)
  if argv[0]=='python3':
   self.stage+=1
   jar='e'*64 if self.drift=='stage' and self.stage>=3 else 'd'*64
   return self.done({'state':'published','correlationId':C,'receipt':{'cliPath':self.cli,'manifestSha256':'a'*64,'rpmSha256':'b'*64,'launcherSha256':'c'*64,'desktopJarSha256':jar}})
  if argv[0]==self.adb:
   words=argv[5:]
   facts={('id','-u'):'2000',('getprop','ro.build.version.sdk'):str(self.intent['api']),('getprop','ro.product.cpu.abi'):'x86_64',('getprop','ro.kernel.qemu.avd_name'):self.intent['expectedAvd'],('getprop','ro.boot.qemu.avd_name'):'',('pm','path','com.kardinal.vpncontrol'):'package:/data/app/owned/base.apk',('sha256sum','/data/app/owned/base.apk'):('e'*64 if self.drift=='package' and self.accepted else 'd'*64)+'  /data/app/owned/base.apk'}
   if tuple(words) in facts:return self.done(facts[tuple(words)])
   if words[:2]==['uiautomator','dump']:return self.done('UI hierarchy dumped')
   if words[0]=='cat':return self.done(self.xml if self.accepted or getattr(self,'preexisting',False) else '<hierarchy><node package="com.kardinal.vpncontrol" text="Home"/></hierarchy>')
   if words[0]=='rm':return self.done('')
   if words[:2]==['input','tap']:
    self.taps+=1
    record=json.loads((self.job/'operation.json').read_text())
    assert record['operationId']==OP and stat.S_IMODE((self.job/'operation.json').stat().st_mode)==0o600
    assert json.loads((self.job/'tap-intent.json').read_text())['point']==[60,50]
    self.tapped=True
    if self.break_at=='tap':raise subprocess.TimeoutExpired(argv,30)
    return self.done('')
   raise AssertionError(words)
  assert argv[0]==self.cli,argv
  if 'diagnostics' in argv:
   if '--json' in argv:
    if '--output' not in argv or argv[argv.index('--output')+1]=='-':return self.done({'ok':False,'final':True,'code':'INVALID_ARGUMENT'},1)
    import uuid
    op=str(uuid.uuid4());request=str(uuid.uuid4());self.diagnostic_ledger.append({'controllerId':OWNER,'id':op,'requestId':request,'operation':'diagnostics.export','phase':'succeeded','final':True,'cancellable':False,'completedUnits':None,'totalUnits':None,'code':'OK','configurationRevision':2,'restartRequired':False})
    target=Path(argv[argv.index('--output')+1]);assert not target.exists();target.write_text('[runtime]\nmode=VPN\nvpn_permission_granted='+(self.permission_override if self.permission_override is not None else ('true' if self.tapped else 'false'))+'\nis_vpn_running=false\n');target.chmod(0o600)
    return self.done({'ok':True,'final':True,'code':'OK','controllerId':OWNER,'configurationRevision':2,'operationId':op,'requestId':request,'restartRequired':False,'data':{'format':'text','bytes':target.stat().st_size}})
   return self.done('[runtime]\nmode=VPN\nvpn_permission_granted='+(self.permission_override if self.permission_override is not None else ('true' if self.tapped else 'false'))+'\nis_vpn_running=false\n')
  words=argv[7:]
  if words[:2]==['routing','export']:
   target=Path(words[words.index('--output')+1]);assert not target.exists() and not target.is_symlink()
   self.reads+=1;r=dict(self.rules)
   if self.drift=='routing' and self.accepted:r['direct_domain_suffixes']=['foreign.org']
   self.write(target,{'type':'vpn_control_routing_rules','version':7,'exported_at':str(self.reads),'rules':r})
   return self.done({'ok':True,'final':True,'code':'OK','controllerId':OWNER,'configurationRevision':3 if self.drift in ('revision','routing') and self.accepted else 2,'data':{'format':'json','bytes':target.stat().st_size}})
  envelope={'ok':True,'final':True,'code':'OK','controllerId':OWNER,'configurationRevision':3 if self.drift in ('revision','routing') and self.accepted else 2}
  if '--async' in words:
   assert words==['--controller-id',OWNER,'--if-revision','2','--interactive','--async','on'],words
   assert (self.job/'on-intent.json').is_file()
   self.on+=1;self.accepted=True
   if self.break_at=='on':raise subprocess.TimeoutExpired(argv,30)
   return self.done({**envelope,'code':'ACCEPTED','final':False,'operationId':OP})
  if 'wait' in words:
   self.wait_count+=1
   if self.wait_count>1 and self.closure_drift:
    lease=self.root/'android-native-device-api35.lease'
    if self.closure_drift=='write':lease.write_bytes(lease.read_bytes())
    else:lease.chmod(0o644);lease.chmod(0o600)
   assert words==['--controller-id',OWNER,'operations','wait',OP],words
   if self.break_at=='wait':raise subprocess.TimeoutExpired(argv,30)
   return self.done({**envelope,'ok':self.code=='OK','code':self.code,'operationId':OP},1 if self.code=='INVALID_ARGUMENT' else 0)
  if words==['status']:data={'runtimeRunning':False,'runtimeObservation':'stopped','configuredMode':'vpn','selectedLocationId':None,'activeLocationId':None}
  elif words==['source','show']:data={'mode':'subscription','subscriptionId':''} if self.drift=='empty-subscription' else {'mode':'current-locations','subscriptionId':None}
  elif words==['settings','show']:data={'validation.test-url':'https://example.org','language':'en'}
  elif words==['locations','list']:data={'locations':[] if self.drift!='locations' else [{'id':1}]}
  elif words==['operations','list']:
   ops=[] if not self.accepted else [{'controllerId':OWNER,'id':OP,'operation':'on','phase':'failed' if self.tapped else 'awaiting-user','final':self.tapped}]
   if self.drift=='op' and self.accepted:ops[0]['id']=OWNER
   data={'operations':ops+list(self.diagnostic_ledger)}
  elif words==['routing','show']:
   self.reads+=1;r=dict(self.rules)
   if self.drift=='routing' and self.accepted:r['direct_domain_suffixes']=['foreign.org']
   data={'routing':{'type':'vpn_control_routing_rules','version':7,'exported_at':str(self.reads),'rules':r}}
  else:raise AssertionError(words)
  if self.tapped and self.closing_drift=='settings' and words==['settings','show']:data['validation.test-url']='https://foreign.org'
  if self.tapped and self.closing_drift=='source' and words==['source','show']:data['extra']='foreign'
  if self.tapped and self.closing_drift=='runtime' and words==['status']:data['runtimeRunning']=True
  if self.tapped and self.closing_drift=='selected' and words==['status']:data['selectedLocationId']=1
  return self.done({**envelope,'data':data})
 def execute(self,mode='run',after_marker=None,replacement=None,continuation=None):
  output=io.StringIO()
  argv=['worker',mode,self.adb,self.cli,'emulator-5556',str(self.root),C,self.expected]+([json.dumps(replacement,sort_keys=True,separators=(',',':'))] if replacement is not None else [])+([json.dumps(continuation,sort_keys=True,separators=(',',':'))] if continuation is not None else [])
  original_fsync=os.fsync
  def fsync(fd):
   original_fsync(fd)
   for name in ('collected.json','no-effect-closed.json','replacement-no-effect-closed.json')+tuple(p.name for p in self.job.glob('continuation-*-closed.json')):
    marker=self.job/name
    if after_marker is not None and marker.exists() and os.fstat(fd).st_ino==marker.stat().st_ino:after_marker()
  with mock.patch.object(sys,'argv',argv),mock.patch.object(subprocess,'run',side_effect=self.run),mock.patch('sys.stdout',output),mock.patch.object(os,'fsync',side_effect=fsync):
   try:exec(s._REMOTE,{'__name__':'__main__'})
   except SystemExit:pass
  result=json.loads(output.getvalue())
  if mode=='run':self.write(self.job/'result.json',{'state':'complete' if result['state']=='complete' else 'unknown','result':result if result['state']=='complete' else None,'reason':None if result['state']=='complete' else result.get('reason')})
  return result

class ExecutedWorkerTest(unittest.TestCase):
 def fixture(self):
  f=Fixture();self.addCleanup(f.close);return f
 def test_api29_unreviewed_dialog_is_retained_and_never_tapped(self):
  f=self.fixture();f.intent.update(device='api29',api=29,expectedAvd='owned-api29')
  f.expected=json.dumps(f.intent,sort_keys=True,separators=(',',':'));f.write(f.job/'intent.json',f.intent)
  result=f.execute()
  self.assertEqual(result['reason'],'prompt_not_owned')
  self.assertEqual((f.on,f.taps),(1,0))
  self.assertFalse((f.job/'tap-intent.json').exists())
  self.assertFalse((f.job/'terminal.json').exists())
  self.assertTrue((f.root/'android-native-device-api29.lease').exists())
  self.assertFalse((f.root/'android-native-device-api35.lease').exists())
  prompts=list(f.root.glob('android-grant-prompt-'+C+'-*/ui.xml'))
  self.assertEqual(len(prompts),1);self.assertEqual(prompts[0].read_text(),f.xml)
  self.assertEqual(stat.S_IMODE(prompts[0].stat().st_mode),0o600)
 def test_crossed_api29_device_rejected_before_on_or_tap(self):
  f=self.fixture();f.intent.update(device='api29',api=35)
  f.expected=json.dumps(f.intent,sort_keys=True,separators=(',',':'));f.write(f.job/'intent.json',f.intent)
  self.assertEqual(f.execute()['reason'],'device_changed')
  self.assertEqual((f.on,f.taps),(0,0))
 def test_actual_invalid_argument_grants_only_and_metadata_varies(self):
  f=self.fixture();result=f.execute()
  self.assertEqual(result['state'],'complete');self.assertEqual(result['operationCode'],'INVALID_ARGUMENT')
  self.assertTrue(result['noLocation']);self.assertTrue(result['permissionGranted']);self.assertFalse(result['runtimeStarted'])
  self.assertEqual((f.on,f.taps),(1,1));self.assertGreaterEqual(f.reads,4)
  self.assertEqual(f.execute('status')['state'],'complete')
  self.assertEqual(f.execute('collect')['freshProof'],True)
  self.assertFalse((f.root/'android-native-device-api35.lease').exists())
  self.assertEqual(f.execute('collect')['freshProof'],True) # response loss recovery never taps
  self.assertEqual((f.on,f.taps),(1,1))
 def test_full_large_backup_semantics_preserved(self):
  f=self.fixture();f.rules={**RULES,'direct_domain_suffixes':['%06d.'%i+'x'*205+'.example.org' for i in range(56000)]}
  f.write(f.backup,{'type':'vpn_control_routing_rules','version':7,'exported_at':'opening','rules':f.rules})
  self.assertGreater(f.backup.stat().st_size,11800000)
  f.intent['backupSha256']=hashlib.sha256(f.backup.read_bytes()).hexdigest();f.expected=json.dumps(f.intent,sort_keys=True,separators=(',',':'));f.write(f.job/'intent.json',f.intent)
  self.assertEqual(f.execute()['state'],'complete');self.assertEqual(f.execute('collect')['state'],'complete')
 def test_ui_hostile_warning_blocks_after_durable_op(self):
  f=self.fixture();f.xml=dialog('Foreign VPN wants traffic')
  self.assertEqual(f.execute()['reason'],'prompt_not_owned');self.assertEqual(f.taps,0)
  self.assertTrue((f.job/'operation.json').exists());self.assertTrue((f.root/'android-native-device-api35.lease').exists())
 def test_empty_subscription_source_preserved_through_future_grant(self):
  f=self.fixture();f.drift='empty-subscription'
  self.assertEqual(f.execute()['state'],'complete');self.assertEqual(f.execute('collect')['state'],'complete')
  self.assertEqual(json.loads((f.job/'opening.json').read_text())['source'],{'mode':'subscription','subscriptionId':''})
 def test_never_accepts_ok_as_no_location(self):
  f=self.fixture();f.code='OK';self.assertEqual(f.execute()['reason'],'operation_not_no_location')
  self.assertEqual(f.execute('status')['state'],'unknown')
 def test_drift_before_tap_and_empty_baseline(self):
  for drift in ('package','stage','revision','routing','op','locations'):
   with self.subTest(drift=drift):
    f=self.fixture();f.drift=drift;result=f.execute();self.assertEqual(result['state'],'unknown');self.assertEqual(f.taps,0)
 def test_loss_never_infers_terminal_or_replays(self):
  for where in ('on','tap','wait'):
   with self.subTest(where=where):
    f=self.fixture();f.break_at=where;self.assertEqual(f.execute()['state'],'unknown')
    self.assertEqual(f.execute('status')['state'],'unknown');self.assertEqual(f.on,1)
    self.assertTrue((f.root/'android-native-device-api35.lease').exists())
    self.assertEqual(f.execute()['state'],'unknown');self.assertEqual(f.on,1)
 def test_retained_backup_symlink_and_hardlink_block_before_on(self):
  for kind in ('symlink','hardlink','world','hash','shape','oversize'):
   with self.subTest(kind=kind):
    f=self.fixture()
    if kind in ('symlink','hardlink'):
     original=f.root/'original';f.backup.rename(original)
     if kind=='symlink':f.backup.symlink_to(original)
     else:os.link(original,f.backup)
    elif kind=='world':f.backup.chmod(0o644)
    elif kind=='hash':f.backup.write_text('{}')
    elif kind=='oversize':
     with f.backup.open('wb') as out:out.truncate(67108865)
    else:
     f.write(f.backup,{'type':'vpn_control_routing_rules','version':7,'rules':{'ignore_rules':False}})
     f.intent['backupSha256']=hashlib.sha256(f.backup.read_bytes()).hexdigest();f.expected=json.dumps(f.intent,sort_keys=True,separators=(',',':'));f.write(f.job/'intent.json',f.intent)
    self.assertEqual(f.execute()['state'],'unknown');self.assertEqual(f.on,0)
 def test_collector_fresh_drift_retains_claim(self):
  for drift in ('routing','revision','package','stage','locations'):
   with self.subTest(drift=drift):
    f=self.fixture();self.assertEqual(f.execute()['state'],'complete');f.drift=drift
    self.assertEqual(f.execute('collect')['state'],'unknown');self.assertTrue((f.root/'android-native-device-api35.lease').exists())
 def test_independent_permission_and_full_state_required(self):
  for changed in ('settings','source','runtime','selected','permission'):
   with self.subTest(changed=changed):
    f=self.fixture();f.closing_drift=changed
    if changed=='permission':
     original=f.run
     def fail_permission(argv,**kwargs):
      if f.tapped:f.permission_override='false'
      return original(argv,**kwargs)
     f.run=fail_permission
    self.assertEqual(f.execute()['state'],'unknown');self.assertEqual((f.on,f.taps),(1,1))
    self.assertFalse((f.job/'terminal.json').exists());self.assertTrue((f.root/'android-native-device-api35.lease').exists())
 def test_remote_same_inode_lease_changes_are_retained(self):
  for change in ('write','chmod'):
   with self.subTest(change=change):
    f=self.fixture();self.assertEqual(f.execute()['state'],'complete');f.closure_drift=change
    self.assertEqual(f.execute('collect')['state'],'unknown');self.assertTrue((f.root/'android-native-device-api35.lease').exists())
 def test_remote_drift_after_close_marker_preserves_claim(self):
  f=self.fixture();self.assertEqual(f.execute()['state'],'complete');lease=f.root/'android-native-device-api35.lease'
  def change():lease.write_bytes(lease.read_bytes())
  self.assertEqual(f.execute('collect',after_marker=change)['state'],'unknown');self.assertTrue(lease.exists())
  # The immutable marker pins the original inode metadata, so a retry cannot re-admit the changed claim.
  self.assertEqual(f.execute('collect')['state'],'unknown');self.assertTrue(lease.exists())
 def test_terminal_substitution_and_unsafe_op_stay_unknown(self):
  for kind in ('terminal','operation','mode'):
   with self.subTest(kind=kind):
    f=self.fixture();self.assertEqual(f.execute()['state'],'complete')
    path=f.job/('operation.json' if kind=='operation' else 'terminal.json')
    if kind=='mode':path.chmod(0o644)
    else:
     value=json.loads(path.read_text());value['operationId']=OWNER;f.write(path,value)
    self.assertEqual(f.execute('status')['state'],'unknown')
 def test_actual_wrapper_unknown_without_terminal_preserves_reason(self):
  f=self.fixture();release=f.job/'release';release.touch(mode=0o600)
  wrapper=s.android_document_acceptance._worker('pass',[])
  with mock.patch.object(sys,'argv',['wrapper',str(f.job)]),mock.patch.object(subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=json.dumps({'state':'unknown','reason':'device_changed'}).encode())):
   exec(wrapper,{'__name__':'__main__'})
  record=f.job/'result.json';before=record.read_bytes();self.assertEqual(json.loads(before),{'state':'unknown','result':None,'reason':'device_changed'})
  calls=len(f.calls);got=f.execute('status')
  self.assertEqual(got['state'],'unknown');self.assertEqual(got['reason'],'device_changed');self.assertEqual(got['checkpoint'],'worker-returned-unknown')
  self.assertEqual(record.read_bytes(),before);self.assertEqual(len(f.calls),calls);self.assertFalse((f.job/'terminal.json').exists())
 def test_unknown_worker_reason_schema_never_projects_private_or_forged_text(self):
  for record in ({'state':'unknown','result':None,'reason':'private /secret'}, {'state':'unknown','result':{},'reason':'device_changed'}, {'state':'unknown','result':None,'reason':{'private':'content'}}, {'state':'unknown','reason':'device_changed'}, {'state':'unknown','result':None,'reason':'device_changed','extra':'foreign'}):
   with self.subTest(record=record):
    f=self.fixture();f.write(f.job/'result.json',record);got=f.execute('status')
    self.assertEqual(got['state'],'unknown');self.assertEqual(got['reason'],'worker_receipt_invalid');self.assertNotIn('checkpoint',got)
 def test_original_failed_attempt_diagnostic_is_finite_and_read_only(self):
  f=self.fixture();f.drift='empty-subscription'
  # Original worker receipt predates the new empty-source admission.
  f.write(f.job/'result.json',{'state':'unknown','result':None,'reason':'baseline_not_empty_off'})
  lease=f.root/'android-native-device-api35.lease';f.write(lease,s._claim(C));lock=f.root/'android-native-device-api35.lock';lock.touch(mode=0o600)
  before={p:p.read_bytes() for p in (f.job/'intent.json',f.job/'result.json',lease)};got=f.execute('diagnostic')
  self.assertEqual(got['state'],'diagnosed');self.assertEqual(got['historicalReason'],'baseline_not_empty_off')
  self.assertEqual(got['observationClass'],'fresh-current-baseline');self.assertFalse(got['checks']['sourceCurrentLocations']);self.assertFalse(got['checks']['subscriptionNull'])
  self.assertEqual(got['facts']['subscriptionBinding'],'empty');self.assertEqual(got['facts']['locationCount'],0)
  self.assertEqual((f.on,f.taps),(0,0));self.assertEqual(before,{p:p.read_bytes() for p in before});self.assertNotIn('settings',got);self.assertNotIn('source',got)
 def test_diagnostic_reports_exact_predicate_without_raw_values(self):
  cases=[('status','runtimeRunning',True,'runtimeOff'),('status','runtimeObservation','running','runtimeStopped'),('status','configuredMode','private-unknown-mode','vpnMode'),('status','selectedLocationId','private-selected-id','selectionNull'),('status','activeLocationId','private-active-id','activeNull'),('locations','locations',[{'name':'private-location'}],'locationsEmpty'),('source','mode','subscription','sourceCurrentLocations'),('source','subscriptionId','private-subscription','subscriptionNull')]
  for command,key,value,failed in cases:
   with self.subTest(failed=failed):
    f=self.fixture();f.write(f.job/'result.json',{'state':'unknown','result':None,'reason':'baseline_not_empty_off'})
    f.write(f.root/'android-native-device-api35.lease',s._claim(C));(f.root/'android-native-device-api35.lock').touch(mode=0o600)
    original=f.run
    def read(argv,**kwargs):
     result=original(argv,**kwargs)
     if argv[0]==f.cli and '--json' in argv and command in argv[7:]:
      response=json.loads(result.stdout);response['data'][key]=value;return f.done(response)
     return result
    f.run=read;got=f.execute('diagnostic')
    self.assertEqual(got['state'],'diagnosed');self.assertFalse(got['checks'][failed]);self.assertEqual((f.on,f.taps),(0,0))
    self.assertNotIn('private-',json.dumps(got));self.assertNotIn('settings',got)
 def test_diagnostic_unrelated_or_forged_attempt_never_reads_product(self):
  f=self.fixture();f.write(f.job/'result.json',{'state':'unknown','result':None,'reason':'other-private-reason'})
  got=f.execute('diagnostic');self.assertEqual(got['state'],'unknown');self.assertEqual(got['reason'],'diagnostic_attempt_not_admitted');self.assertEqual(f.calls,[])
 def test_original_baseline_failure_no_effect_reconcile(self):
  f=self.fixture();f.drift='empty-subscription';f.write(f.job/'result.json',{'state':'unknown','result':None,'reason':'baseline_not_empty_off'})
  f.write(f.job/'worker.py',{'fixed':'original-inert-test-worker'});f.write(f.root/'android-native-device-api35.lease',s._claim(C));(f.root/'android-native-device-api35.lock').touch(mode=0o600)
  preserved={p:p.read_bytes() for p in (f.job/'intent.json',f.job/'result.json',f.job/'worker.py',f.backup)}
  got=f.execute('reconcile');self.assertEqual(got['state'],'closed');self.assertFalse(got['proof']['historicalSourceSettingsAvailable']);self.assertTrue(got['proof']['configurationGenerationUnchanged'])
  self.assertEqual((f.on,f.taps),(0,0));self.assertFalse((f.root/'android-native-device-api35.lease').exists());self.assertEqual(preserved,{p:p.read_bytes() for p in preserved})
  self.assertEqual(f.execute('reconcile')['state'],'closed');self.assertEqual(f.execute('status')['reason'],'baseline_not_empty_off')
 def test_reconcile_rejects_grant_records_live_worker_and_changed_state(self):
  for kind in ('on-intent.json','operation.json','tap-intent.json','terminal.json','live','foreign','rules','package','revision','permission','baseline'):
   with self.subTest(kind=kind):
    f=self.fixture();f.drift='empty-subscription';f.write(f.job/'result.json',{'state':'unknown','result':None,'reason':'baseline_not_empty_off'});f.write(f.job/'worker.py',{'fixed':'original'})
    lease=f.root/'android-native-device-api35.lease';f.write(lease,s._claim(C));(f.root/'android-native-device-api35.lock').touch(mode=0o600)
    if kind.endswith('.json'):f.write(f.job/kind,{'foreign':True})
    elif kind=='foreign':f.write(lease,{'owner':'foreign'})
    elif kind=='rules':f.rules={**RULES,'ignore_rules':True}
    elif kind=='package':f.drift='package';f.accepted=True
    elif kind=='revision':f.drift='revision';f.accepted=True
    elif kind=='permission':f.permission_override='true'
    elif kind=='baseline':f.write(f.job/'baseline-source-settings.json',{'foreign':True})
    original=Path.read_text
    def read(path,*args,**kwargs):
     if kind=='live' and str(path)=='/proc/99999999/stat':return '99999999 (worker) '+' '.join(['S']+['0']*18+['1'])
     return original(path,*args,**kwargs)
    with mock.patch.object(Path,'read_text',read):got=f.execute('reconcile')
    self.assertEqual(got['state'],'unknown');self.assertTrue(lease.exists());self.assertEqual((f.on,f.taps),(0,0))
 def test_future_baseline_is_private_before_rejection_and_exact_on_reconcile(self):
  f=self.fixture();f.drift='locations';self.assertEqual(f.execute()['reason'],'baseline_not_empty_off')
  baseline=f.job/'baseline-source-settings.json';self.assertTrue(baseline.exists());self.assertEqual(stat.S_IMODE(baseline.stat().st_mode),0o600)
  self.assertFalse((f.job/'on-intent.json').exists());f.write(f.job/'worker.py',{'fixed':'original'});f.drift=None
  got=f.execute('reconcile');self.assertEqual(got['state'],'closed');self.assertTrue(got['proof']['historicalSourceSettingsAvailable'])
  self.assertEqual(json.loads(baseline.read_text())['source'],{'mode':'current-locations','subscriptionId':None})
 def test_future_nonempty_subscription_and_missing_null_fields_denied(self):
  for kind in ('selected-subscription','missing-subscription','missing-selected','missing-active'):
   with self.subTest(kind=kind):
    f=self.fixture();original=f.run
    def read(argv,**kwargs):
     response=original(argv,**kwargs)
     if argv[0]==f.cli and '--json' in argv:
      v=json.loads(response.stdout);words=argv[7:]
      if words==['source','show'] and kind=='selected-subscription':v['data']={'mode':'subscription','subscriptionId':'private-selected'}
      if words==['source','show'] and kind=='missing-subscription':v['data']={'mode':'current-locations'}
      if words==['status'] and kind in ('missing-selected','missing-active'):v['data'].pop('selectedLocationId' if kind=='missing-selected' else 'activeLocationId')
      response=f.done(v)
     return response
    f.run=read;self.assertEqual(f.execute()['reason'],'baseline_not_empty_off');self.assertEqual((f.on,f.taps),(0,0))
 def test_no_effect_reconcile_preserves_changed_claim_and_unstable_current_data(self):
  for kind in ('claim','settings','operations'):
   with self.subTest(kind=kind):
    f=self.fixture();f.drift='empty-subscription';f.write(f.job/'result.json',{'state':'unknown','result':None,'reason':'baseline_not_empty_off'});f.write(f.job/'worker.py',{'fixed':'original'})
    lease=f.root/'android-native-device-api35.lease';f.write(lease,s._claim(C));(f.root/'android-native-device-api35.lock').touch(mode=0o600)
    original=f.run;counts={'settings':0,'operations':0}
    def read(argv,**kwargs):
     response=original(argv,**kwargs)
     if argv[0]==f.cli and '--json' in argv and kind in argv[7:]:
      counts[kind]+=1;v=json.loads(response.stdout)
      if kind=='settings' and counts[kind]>1:v['data']['language']='private-changed'
      if kind=='operations':v['data']['operations']=[{'controllerId':OWNER,'id':OP,'requestId':str(counts[kind]),'operation':'off','phase':'succeeded','final':True}]
      response=f.done(v)
     return response
    f.run=read
    got=f.execute('reconcile',after_marker=(lambda:lease.write_bytes(lease.read_bytes())) if kind=='claim' else None)
    self.assertEqual(got['state'],'unknown');self.assertTrue(lease.exists());self.assertEqual((f.on,f.taps),(0,0))
 def replacement_fixture(self):
  f=self.fixture();f.drift='empty-subscription'
  f.write(f.job/'result.json',{'state':'unknown','result':None,'reason':'baseline_not_empty_off'});f.write(f.job/'worker.py',{'fixed':'original'})
  f.write(f.root/'android-native-device-api35.lease',s._claim(C));(f.root/'android-native-device-api35.lock').touch(mode=0o600)
  rc='57e28a00-8009-421d-8897-5e8f48645729';new_owner='430178de-c966-435a-9ffd-3900e959b665'
  readback=f.root/('android-readback-'+rc);readback.mkdir(mode=0o700);backup=readback/'routing.json'
  f.write(backup,{'type':'vpn_control_routing_rules','version':7,'exported_at':'new-timestamp','rules':f.rules})
  ri={'host':'archlinux','device':'api35','correlationId':rc,'expectedBaseSha256':f.intent['packageSha256'],'serial':'emulator-5556','expectedAvd':'owned-api35','api':35,'fixtureRoot':str(f.root)}
  sha=hashlib.sha256(backup.read_bytes()).hexdigest()
  result={'admitted':True,'device':{'uid':'2000','api':35,'avd':'owned-api35','abi':'x86_64'},'package':{'baseSha256':f.intent['packageSha256']},'guard':{'controllerId':new_owner,'configurationRevision':0,'backupSha256':sha,'backupSize':backup.stat().st_size},'backup':{'sha256':sha,'size':backup.stat().st_size,'path':str(backup),'type':'vpn_control_routing_rules','version':7,'rulesValid':True}}
  identity={'pid':99999998,'startTicks':2};rjob=f.root/('android-readback-job-'+rc);rjob.mkdir(mode=0o700)
  for name,value in [('intent.json',ri),('result.json',{'state':'complete','result':result,'reason':None}),('identity.json',identity)]:f.write(rjob/name,value)
  binding={'schema':1,'originalIntentSha256':hashlib.sha256(f.expected.encode()).hexdigest(),'readbackCorrelationId':rc,'backupSha256':sha,'owner':new_owner,'revision':0,'readbackIntent':ri,'readbackResultSha256':hashlib.sha256(json.dumps(result,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'readbackIdentity':identity}
  original=f.run
  def run(argv,**kwargs):
   response=original(argv,**kwargs)
   if argv[0]==f.cli and '--json' in argv:
    value=json.loads(response.stdout);value['controllerId']=new_owner;value['configurationRevision']=0
    for op in value.get('data',{}).get('operations',[]):
     op['controllerId']=new_owner
     if op.get('operation')=='diagnostics.export':op['configurationRevision']=0
    response=f.done(value)
   return response
  f.run=run
  return f,binding,result
 def test_replacement_owner_closure_compares_full_rules_preserves_unknown(self):
  f,binding,_=self.replacement_fixture();before={name:(f.job/name).read_bytes() for name in ('intent.json','worker.py','result.json','identity.json')}
  self.assertEqual(f.execute('reconcile')['reason'],'owner_or_revision_changed')
  got=f.execute('reconcile-replacement',replacement=binding)
  self.assertEqual(got['state'],'closed');self.assertTrue(got['proof']['replacementOwnerAdmitted']);self.assertTrue(got['proof']['originalOwnerChanged']);self.assertFalse(got['proof']['historicalSourceSettingsAvailable'])
  self.assertFalse((f.root/'android-native-device-api35.lease').exists());self.assertFalse((f.job/'no-effect-closed.json').exists());self.assertEqual((f.on,f.taps),(0,0))
  self.assertEqual({name:(f.job/name).read_bytes() for name in before},before)
  self.assertEqual(f.execute('status')['state'],'unknown')
  self.assertEqual(f.execute('reconcile-replacement',replacement=binding)['state'],'closed')
 def test_replacement_closure_rejects_receipt_effect_and_current_drift(self):
  for kind in ('readback-result','readback-intent','readback-identity','backup','rules','original-backup','on-intent.json','operation.json','tap-intent.json','terminal.json','opening.json','permission','owner','package','stage','foreign-claim','live-worker','baseline'):
   with self.subTest(kind=kind):
    f,binding,rv=self.replacement_fixture();lease=f.root/'android-native-device-api35.lease';rc=binding['readbackCorrelationId'];rjob=f.root/('android-readback-job-'+rc)
    if kind.startswith('readback-'):f.write(rjob/(kind[9:]+'.json'),{'forged':'private'})
    elif kind=='backup':f.write(f.root/('android-readback-'+rc)/'routing.json',{'foreign':True})
    elif kind=='rules':f.rules={**RULES,'ignore_rules':True}
    elif kind=='original-backup':f.write(f.backup,{'foreign':True})
    elif kind.endswith('.json'):f.write(f.job/kind,{'foreign':True})
    elif kind=='permission':f.permission_override='true'
    elif kind=='owner':binding['owner']=OWNER
    elif kind=='package':f.drift='package';f.accepted=True
    elif kind=='stage':f.drift='stage';f.stage=3
    elif kind=='foreign-claim':f.write(lease,{'owner':'foreign'})
    elif kind=='baseline':f.write(f.job/'baseline-source-settings.json',{'foreign':True})
    original=Path.read_text
    def read(path,*args,**kwargs):
     if kind=='live-worker' and str(path)=='/proc/99999999/stat':return '99999999 (worker) '+' '.join(['S']+['0']*18+['1'])
     return original(path,*args,**kwargs)
    with mock.patch.object(Path,'read_text',read):got=f.execute('reconcile-replacement',replacement=binding)
    self.assertEqual(got['state'],'unknown');self.assertTrue(lease.exists());self.assertEqual((f.on,f.taps),(0,0))
    self.assertFalse((f.job/'replacement-no-effect-closed.json').exists())
 def test_replacement_uses_proven_export_not_timed_out_inline_show(self):
  f,binding,_=self.replacement_fixture();original=f.run;exports=[]
  def run(argv,**kwargs):
   if argv[0]==f.cli and 'routing' in argv:
    if 'show' in argv:return f.done({'ok':False,'final':False,'code':'TIMEOUT','message':'PRIVATE_SENTINEL'},2)
    self.assertIn('export',argv);self.assertEqual(argv[6],'300');self.assertEqual(kwargs['timeout'],315);self.assertLessEqual(kwargs.get('limit',16384),16384)
    target=Path(argv[argv.index('--output')+1]);self.assertFalse(target.exists());self.assertEqual(stat.S_IMODE(target.parent.stat().st_mode),0o700);exports.append(target)
    f.write(target,{'type':'vpn_control_routing_rules','version':7,'exported_at':str(len(exports)),'rules':f.rules})
    return f.done({'ok':True,'final':True,'code':'OK','controllerId':binding['owner'],'configurationRevision':0,'data':{'format':'json','bytes':target.stat().st_size}})
   return original(argv,**kwargs)
  f.run=run;got=f.execute('reconcile-replacement',replacement=binding)
  self.assertEqual(got['state'],'closed');self.assertEqual(len(exports),3);self.assertTrue(all(not p.parent.exists() for p in exports));self.assertEqual((f.on,f.taps),(0,0))
 def test_reconciliation_cli_nonzero_code_is_finite_and_not_raw(self):
  for code,expected in [('TIMEOUT','TIMEOUT'),('UNAVAILABLE','OTHER'),('PRIVATE_SENTINEL','UNCLASSIFIED')]:
   with self.subTest(code=code):
    f,binding,_=self.replacement_fixture();original=f.run
    def run(argv,**kwargs):
     if argv[0]==f.cli and 'routing' in argv:return f.done({'ok':False,'final':False,'code':code,'message':'PRIVATE_SENTINEL'},2)
     return original(argv,**kwargs)
    f.run=run;got=f.execute('reconcile-replacement',replacement=binding)
    self.assertEqual(got['state'],'unknown');self.assertEqual(got['commandCode'],expected);self.assertEqual(got['checkpoint'],'routing');self.assertNotIn('PRIVATE_SENTINEL',json.dumps(got));self.assertTrue((f.root/'android-native-device-api35.lease').exists())
 def test_export_private_file_and_cleanup_identity_guards(self):
  for kind in ('symlink','hardlink','public-mode','bytes','format','extra-file','same-inode','directory-chmod'):
   with self.subTest(kind=kind):
    f,binding,_=self.replacement_fixture();original=f.run;outputs=[]
    def run(argv,**kwargs):
     response=original(argv,**kwargs)
     if argv[0]==f.cli and 'export' in argv and 'routing' in argv:
      target=Path(argv[argv.index('--output')+1]);outputs.append(target)
      if kind=='symlink':target.unlink();target.symlink_to(f.backup)
      elif kind=='hardlink':os.link(target,target.parent/'foreign-link')
      elif kind=='public-mode':target.chmod(0o644)
      elif kind=='extra-file':f.write(target.parent/'foreign',{'private':True})
      elif kind in ('bytes','format'):
       value=json.loads(response.stdout);value['data']['bytes' if kind=='bytes' else 'format']=1 if kind=='bytes' else 'PRIVATE_SENTINEL';response=f.done(value)
     elif argv[0]=='python3' and outputs and kind in ('same-inode','directory-chmod'):
      if kind=='same-inode':outputs[-1].write_bytes(outputs[-1].read_bytes())
      else:outputs[-1].parent.chmod(0o700)
     return response
    f.run=run;got=f.execute('reconcile-replacement',replacement=binding)
    self.assertEqual(got['state'],'unknown');self.assertTrue((f.root/'android-native-device-api35.lease').exists());self.assertFalse((f.job/'replacement-no-effect-closed.json').exists());self.assertTrue(outputs[0].parent.exists());
    if kind in ('extra-file','same-inode','directory-chmod'):self.assertEqual(got['reason'],'routing_export_cleanup_unknown')
    self.assertNotIn('PRIVATE_SENTINEL',json.dumps(got));self.assertEqual((f.on,f.taps),(0,0))
 def continuation_fixture(self):
  f,binding,rv=ExecutedWorkerTest.replacement_fixture(self)
  observed=f.execute('reconcile-replacement-status',replacement=binding)
  continuation={'schema':1,'continuationId':'02c644a8-d477-4767-8e50-ab51f41b696d','originalIntentSha256':binding['originalIntentSha256'],'replacementBindingSha256':hashlib.sha256(json.dumps(binding,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'openingDisposition':{'state':'unknown','reason':'replacement_closure_incomplete','provenance':'fresh-read-only',**{k:observed[k] for k in ('currentSnapshotSha256','retainedBindingsSha256')}}}
  return f,binding,continuation
 def test_distinct_continuation_closes_no_effect_claim_preserves_original(self):
  f,binding,continuation=self.continuation_fixture();before={name:(f.job/name).read_bytes() for name in ('intent.json','worker.py','identity.json','result.json')}
  self.assertEqual(f.execute('reconcile-replacement-status',replacement=binding)['reason'],'replacement_closure_incomplete')
  got=f.execute('reconcile-continuation',replacement=binding,continuation=continuation)
  self.assertEqual(got['state'],'closed');self.assertEqual(got['proof']['continuationId'],continuation['continuationId']);self.assertTrue(got['proof']['replacementOwnerAdmitted']);self.assertFalse(got['proof']['historicalSourceSettingsAvailable'])
  self.assertFalse((f.job/'replacement-binding.json').exists());self.assertFalse((f.job/'replacement-no-effect-closed.json').exists())
  self.assertFalse((f.root/'android-native-device-api35.lease').exists());self.assertEqual({name:(f.job/name).read_bytes() for name in before},before);self.assertEqual((f.on,f.taps),(0,0))
  self.assertEqual(f.execute('reconcile-continuation',replacement=binding,continuation=continuation)['reason'],'continuation_consumed')
  before={p:p.read_bytes() for p in f.job.iterdir() if p.is_file()}
  self.assertEqual(f.execute('reconcile-continuation-status',replacement=binding,continuation=continuation)['state'],'closed')
  self.assertEqual({p:p.read_bytes() for p in before},before)
 def test_continuation_unknown_is_consumed_and_partial_marker_never_infers_release(self):
  for kind in ('timeout','unlink','claim'):
   with self.subTest(kind=kind):
    f,binding,continuation=self.continuation_fixture();original=f.run;lease=f.root/'android-native-device-api35.lease';unlink=Path.unlink
    def run(argv,**kwargs):
     if kind=='timeout' and argv[0]==f.cli and 'routing' in argv:raise subprocess.TimeoutExpired(argv,315)
     return original(argv,**kwargs)
    def fail(path,*args,**kwargs):
     if kind=='unlink' and path==lease:raise OSError('lost unlink')
     return unlink(path,*args,**kwargs)
    f.run=run
    with mock.patch.object(Path,'unlink',fail):got=f.execute('reconcile-continuation',replacement=binding,continuation=continuation,after_marker=(lambda:lease.write_bytes(lease.read_bytes())) if kind=='claim' else None)
    self.assertEqual(got['state'],'unknown');self.assertTrue(lease.exists());self.assertEqual((f.on,f.taps),(0,0))
    self.assertTrue((f.job/('continuation-'+continuation['continuationId']+'.json')).exists())
    self.assertEqual(f.execute('reconcile-continuation',replacement=binding,continuation=continuation)['reason'],'continuation_consumed')
    f.run=original;self.assertEqual(f.execute('reconcile-continuation-status',replacement=binding,continuation=continuation)['state'],'unknown');self.assertTrue(lease.exists())
 def test_continuation_denies_hostile_intent_and_prior_grant_effect(self):
  for kind in ('foreign-hash','foreign-id','historical-invention','grant-effect','receipt-drift'):
   with self.subTest(kind=kind):
    f,binding,continuation=self.continuation_fixture()
    if kind=='foreign-hash':continuation['replacementBindingSha256']='e'*64
    elif kind=='foreign-id':continuation['continuationId']=C
    elif kind=='historical-invention':continuation['openingDisposition']['provenance']='historical-proof'
    elif kind=='grant-effect':f.write(f.job/'on-intent.json',{'foreign':True})
    else:f.write(f.root/('android-readback-job-'+binding['readbackCorrelationId'])/'result.json',{'foreign':True})
    self.assertEqual(f.execute('reconcile-continuation',replacement=binding,continuation=continuation)['state'],'unknown');self.assertTrue((f.root/'android-native-device-api35.lease').exists());self.assertEqual((f.on,f.taps),(0,0))
 def test_continuation_pins_the_fresh_opening_source_settings_runtime_and_history(self):
  for kind in ('source','settings','runtime','operations','binding-hash'):
   with self.subTest(kind=kind):
    f,binding,continuation=self.continuation_fixture();original=f.run
    if kind=='binding-hash':continuation['openingDisposition']['retainedBindingsSha256']='e'*64
    def run(argv,**kwargs):
     response=original(argv,**kwargs)
     if argv[0]==f.cli and '--json' in argv:
      words=argv[7:];v=json.loads(response.stdout)
      if kind=='source' and words==['source','show']:v['data']={'mode':'current-locations','subscriptionId':None}
      elif kind=='settings' and words==['settings','show']:v['data']['language']='de'
      elif kind=='runtime' and words==['status']:v['data']['privateExtra']='changed'
      elif kind=='operations' and words==['operations','list']:v['data']['operations'].append({'controllerId':binding['owner'],'id':OP,'operation':'off','phase':'succeeded','final':True})
      response=f.done(v)
     return response
    f.run=run;result=f.execute('reconcile-continuation',replacement=binding,continuation=continuation)
    self.assertEqual(result['reason'],'reconcile_current_snapshots_changed');self.assertTrue((f.root/'android-native-device-api35.lease').exists());self.assertEqual((f.on,f.taps),(0,0))
 def test_continuation_child_marker_substitution_cannot_be_collected(self):
  f,binding,continuation=self.continuation_fixture();self.assertEqual(f.execute('reconcile-continuation',replacement=binding,continuation=continuation)['state'],'closed')
  marker=f.job/('continuation-'+continuation['continuationId']+'-closed.json');value=json.loads(marker.read_bytes());value['continuationIntentSha256']='e'*64;f.write(marker,value)
  self.assertEqual(f.execute('reconcile-continuation-status',replacement=binding,continuation=continuation)['state'],'unknown')
 def test_actual_diagnostics_export_ledger_growth_is_owned_not_foreign_drift(self):
  f,binding,_=self.replacement_fixture();original=f.run;ledger=[]
  def run(argv,**kwargs):
   if argv[0]==f.cli and 'diagnostics' in argv:
    op=str(__import__('uuid').uuid4());request=str(__import__('uuid').uuid4());ledger.append({'controllerId':binding['owner'],'id':op,'requestId':request,'operation':'diagnostics.export','phase':'succeeded','final':True,'cancellable':False,'completedUnits':None,'totalUnits':None,'code':'OK','configurationRevision':0,'restartRequired':False})
    if '--json' not in argv:return original(argv,**kwargs)
    target=Path(argv[argv.index('--output')+1]);self.assertFalse(target.exists());target.write_text('[runtime]\nmode=VPN\nvpn_permission_granted=false\nis_vpn_running=false\n');target.chmod(0o600)
    return f.done({'ok':True,'final':True,'code':'OK','controllerId':binding['owner'],'configurationRevision':0,'operationId':op,'requestId':request,'restartRequired':False,'data':{'format':'text','bytes':target.stat().st_size}})
   if argv[0]==f.cli and argv[7:]==['operations','list']:return f.done({'ok':True,'final':True,'code':'OK','controllerId':binding['owner'],'configurationRevision':0,'data':{'scope':'android-provider-operations','operations':list(ledger)}})
   return original(argv,**kwargs)
  f.run=run;got=f.execute('reconcile-replacement',replacement=binding);self.assertEqual(got['state'],'closed');self.assertEqual(len(ledger),3);self.assertEqual((f.on,f.taps),(0,0))
 def test_persistent_owned_diagnostics_allow_cross_observation_but_not_foreign_tasks(self):
  for kind in ('unchanged','foreign-diagnostic','changed-owned','expired-owned','foreign-active'):
   with self.subTest(kind=kind):
    f,binding,_=self.replacement_fixture();self.assertEqual(f.execute('reconcile-replacement',replacement=binding)['state'],'closed')
    self.assertEqual(f.execute('reconcile-replacement-status',replacement=binding)['state'],'closed')
    if kind.startswith('foreign'):
     summary={**f.diagnostic_ledger[-1],'id':OP,'requestId':OWNER}
     if kind=='foreign-active':summary.update(final=False,phase='running')
     f.diagnostic_ledger.append(summary)
    elif kind=='changed-owned':f.diagnostic_ledger[0]['code']='UNAVAILABLE'
    elif kind=='expired-owned':f.diagnostic_ledger.pop(0)
    result=f.execute('reconcile-replacement-status',replacement=binding)
    self.assertEqual(result['state'],'closed' if kind in ('unchanged','expired-owned') else 'unknown')
    if kind=='changed-owned':self.assertEqual(result['reason'],'observation_history_changed')
    if kind=='expired-owned':self.assertEqual(result['diagnosticHistory']['absentRetained'],1);self.assertEqual(result['diagnosticHistory']['absenceCause'],'unproven')
    self.assertEqual((f.on,f.taps),(0,0))
 def test_read_only_status_reports_bounded_foreign_operation_difference(self):
  f,binding,_=self.replacement_fixture();original=f.run;added=False
  def run(argv,**kwargs):
   nonlocal added
   response=original(argv,**kwargs)
   if argv[0]==f.cli and 'diagnostics' in argv and not added:
    f.diagnostic_ledger.append({**f.diagnostic_ledger[-1],'id':OP,'requestId':OWNER});added=True
   return response
  f.run=run;result=f.execute('reconcile-replacement-status',replacement=binding)
  self.assertEqual(result['reason'],'reconcile_operations_changed');self.assertEqual(result['operationsDiff'],{'added':1,'removed':0,'changed':0,'addedDiagnostics':1,'addedOther':0});self.assertNotIn(OP,json.dumps(result));self.assertNotIn(OWNER,json.dumps(result))
 def test_diagnostic_provenance_receipt_tamper_is_unknown(self):
  for kind in ('mode','hardlink','binding','summary'):
   with self.subTest(kind=kind):
    f,binding,_=self.replacement_fixture();self.assertEqual(f.execute('reconcile-replacement-status',replacement=binding)['reason'],'replacement_closure_incomplete')
    path=next(f.root.glob('android-grant-observations-*/*.json'))
    if kind=='mode':path.chmod(0o644)
    elif kind=='hardlink':os.link(path,f.root/'foreign-link')
    else:
     value=json.loads(path.read_bytes())
     if kind=='binding':value['bindingSha256']='e'*64
     else:value['summary']['final']=False
     f.write(path,value)
    self.assertEqual(f.execute('reconcile-replacement-status',replacement=binding)['state'],'unknown');self.assertTrue((f.root/'android-native-device-api35.lease').exists());self.assertEqual((f.on,f.taps),(0,0))
 def test_reused_foreign_diagnostic_id_cannot_acquire_owned_provenance(self):
  f,binding,_=self.replacement_fixture();foreign={'controllerId':binding['owner'],'id':OP,'requestId':OWNER,'operation':'diagnostics.export','phase':'succeeded','final':True,'cancellable':False,'completedUnits':None,'totalUnits':None,'code':'OK','configurationRevision':0,'restartRequired':False};f.diagnostic_ledger.append(foreign);original=f.run
  def run(argv,**kwargs):
   if argv[0]==f.cli and 'diagnostics' in argv:
    target=Path(argv[argv.index('--output')+1]);target.write_text('[runtime]\nmode=VPN\nvpn_permission_granted=false\nis_vpn_running=false\n');target.chmod(0o600)
    return f.done({'ok':True,'final':True,'code':'OK','controllerId':binding['owner'],'configurationRevision':0,'operationId':OP,'requestId':OWNER,'restartRequired':False,'data':{'format':'text','bytes':target.stat().st_size}})
   return original(argv,**kwargs)
  f.run=run;result=f.execute('reconcile-replacement-status',replacement=binding)
  self.assertEqual(result['reason'],'diagnostics_ambiguous');self.assertEqual(list(f.root.glob('android-grant-observations-*/'+OP+'.json')),[]);self.assertTrue((f.root/'android-native-device-api35.lease').exists())
 def test_actual_parser_requires_diagnostic_output_and_json_metadata(self):
  f,binding,_=self.replacement_fixture();original=f.run;seen=[]
  def run(argv,**kwargs):
   if argv[0]==f.cli and 'diagnostics' in argv:
    if '--output' not in argv:return f.done({'ok':False,'final':True,'code':'INVALID_ARGUMENT','message':'An output destination is required.'},1)
    self.assertIn('--json',argv);self.assertNotEqual(argv[argv.index('--output')+1],'-');self.assertNotIn('--format',argv);self.assertEqual(argv[6],'90');self.assertEqual(kwargs['timeout'],105);seen.append(argv)
   return original(argv,**kwargs)
  f.run=run;result=f.execute('reconcile-replacement-status',replacement=binding)
  self.assertEqual(result['reason'],'replacement_closure_incomplete');self.assertEqual(len(seen),2);self.assertEqual((f.on,f.taps),(0,0))
 def test_diagnostic_private_export_schema_and_cleanup_guards(self):
  for kind in ('format','bytes','symlink','hardlink','mode','same-inode','extra-file'):
   with self.subTest(kind=kind):
    f,binding,_=self.replacement_fixture();original=f.run;targets=[]
    def run(argv,**kwargs):
     response=original(argv,**kwargs)
     if argv[0]==f.cli and 'diagnostics' in argv:
      target=Path(argv[argv.index('--output')+1]);targets.append(target)
      if kind in ('format','bytes'):
       value=json.loads(response.stdout);value['data']['format' if kind=='format' else 'bytes']='json' if kind=='format' else 1;response=f.done(value)
      elif kind=='symlink':target.unlink();target.symlink_to(f.backup)
      elif kind=='hardlink':os.link(target,target.parent/'foreign-link')
      elif kind=='mode':target.chmod(0o644)
      elif kind=='extra-file':f.write(target.parent/'foreign',{'private':True})
     elif argv[0]==f.cli and argv[7:]==['operations','list'] and targets and kind=='same-inode':targets[-1].write_bytes(targets[-1].read_bytes())
     return response
    f.run=run;result=f.execute('reconcile-replacement-status',replacement=binding)
    self.assertEqual(result['state'],'unknown');self.assertTrue((f.root/'android-native-device-api35.lease').exists());self.assertTrue(targets[0].parent.exists());self.assertEqual((f.on,f.taps),(0,0))
    if kind in ('format','bytes'):self.assertEqual(result['reason'],'diagnostic_export_invalid')
    if kind in ('same-inode','extra-file'):self.assertEqual(result['reason'],'diagnostic_export_cleanup_unknown')
 def test_actual_thirty_minute_terminal_pruning_does_not_permanently_block_owned_reads(self):
  f,binding,continuation=self.continuation_fixture();retention_millis=30*60*1000;completed_at={x['id']:0 for x in f.diagnostic_ledger};now=retention_millis;original=f.run
  def run(argv,**kwargs):
   if argv[0]==f.cli and argv[7:]==['operations','list']:
    f.diagnostic_ledger[:]=[x for x in f.diagnostic_ledger if not (x['final'] is True and now-completed_at.get(x['id'],now)>=retention_millis)]
   response=original(argv,**kwargs)
   if argv[0]==f.cli and 'diagnostics' in argv:
    for x in f.diagnostic_ledger:completed_at.setdefault(x['id'],now)
   return response
  f.run=run;result=f.execute('reconcile-continuation',replacement=binding,continuation=continuation)
  self.assertEqual(result['state'],'closed');self.assertGreater(result['diagnosticHistory']['absentRetained'],0);self.assertEqual(result['diagnosticHistory']['absenceCause'],'unproven');self.assertEqual((f.on,f.taps),(0,0))
  self.assertEqual(f.execute('reconcile-continuation-status',replacement=binding,continuation=continuation)['state'],'closed')
 def test_foreign_terminal_pruning_changes_pinned_history(self):
  f,binding,_=self.replacement_fixture();f.diagnostic_ledger.append({'controllerId':binding['owner'],'id':OP,'requestId':OWNER,'operation':'diagnostics.export','phase':'succeeded','final':True,'cancellable':False,'completedUnits':None,'totalUnits':None,'code':'OK','configurationRevision':0,'restartRequired':False})
  observed=f.execute('reconcile-replacement-status',replacement=binding)
  continuation={'schema':1,'continuationId':'02c644a8-d477-4767-8e50-ab51f41b696d','originalIntentSha256':binding['originalIntentSha256'],'replacementBindingSha256':hashlib.sha256(json.dumps(binding,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'openingDisposition':{'state':'unknown','reason':'replacement_closure_incomplete','provenance':'fresh-read-only',**{k:observed[k] for k in ('currentSnapshotSha256','retainedBindingsSha256')}}}
  f.diagnostic_ledger[:]=[x for x in f.diagnostic_ledger if x['id']!=OP]
  result=f.execute('reconcile-continuation',replacement=binding,continuation=continuation)
  self.assertEqual(result['state'],'unknown');self.assertEqual(result['reason'],'reconcile_current_snapshots_changed');self.assertTrue((f.root/'android-native-device-api35.lease').exists())
 def test_terminal_pruning_never_archives_foreign_nonfinal_or_changed_owned(self):
  for kind in ('foreign-active','changed-present','nonfinal-receipt'):
   with self.subTest(kind=kind):
    f,binding,continuation=self.continuation_fixture();archived=f.diagnostic_ledger.pop(0)
    if kind=='foreign-active':f.diagnostic_ledger.append({**archived,'id':OP,'requestId':OWNER,'final':False,'phase':'running'})
    elif kind=='changed-present':f.diagnostic_ledger[-1]['code']='UNAVAILABLE'
    else:
     path=next(f.root.glob('android-grant-observations-*/'+archived['id']+'.json'));receipt=json.loads(path.read_bytes());receipt['summary']['final']=False;f.write(path,receipt)
    result=f.execute('reconcile-continuation',replacement=binding,continuation=continuation)
    self.assertEqual(result['state'],'unknown');self.assertTrue((f.root/'android-native-device-api35.lease').exists());self.assertEqual((f.on,f.taps),(0,0))
    if kind=='foreign-active':self.assertEqual(result['reason'],'operations_active')
    if kind=='changed-present':self.assertEqual(result['reason'],'observation_history_changed')
 def test_retained_absence_metadata_is_bounded_and_does_not_assert_expiry(self):
  flags={'nativeActionAllowed':False,'productAction':False}
  for history in ({'presentOwned':1,'absentRetained':2,'absenceCause':'expired'}, {'presentOwned':True,'absentRetained':2,'absenceCause':'unproven'}, {'presentOwned':128,'absentRetained':1,'absenceCause':'unproven'}, {'presentOwned':1,'absentRetained':[],'absenceCause':'unproven'}, {'presentOwned':1,'absentRetained':2,'absenceCause':'unproven','raw':'PRIVATE_SENTINEL'}):
   result=s._reconcile_unknown(C,{'reason':'replacement_closure_incomplete','diagnosticHistory':history},flags)
   self.assertEqual(result['reason'],'reconcile_observation_invalid');self.assertNotIn('PRIVATE_SENTINEL',json.dumps(result))
  history={'presentOwned':3,'absentRetained':4,'absenceCause':'unproven'}
  result=s._reconcile_unknown(C,{'reason':'replacement_closure_incomplete','diagnosticHistory':history},flags)
  self.assertEqual(result['diagnosticHistory'],history);self.assertFalse(result['replayAllowed']);self.assertFalse(result['productAction'])
 def test_replacement_lock_busy_and_immutable_binding_substitution(self):
  import fcntl
  f,binding,_=self.replacement_fixture();lease=f.root/'android-native-device-api35.lease'
  with (f.root/'android-native-device-api35.lock').open('rb') as lock:
   fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
   self.assertEqual(f.execute('reconcile-replacement',replacement=binding)['reason'],'device_lock_busy')
  self.assertTrue(lease.exists());self.assertEqual(f.on,0)
  f.write(f.job/'replacement-binding.json',{**binding,'revision':1})
  self.assertEqual(f.execute('reconcile-replacement',replacement=binding)['reason'],'replacement_receipt_invalid');self.assertTrue(lease.exists())
 def test_replacement_same_size_semantic_backup_substitution_denied(self):
  f,binding,rv=self.replacement_fixture();path=f.root/('android-readback-'+binding['readbackCorrelationId'])/'routing.json'
  doc=json.loads(path.read_bytes());doc['rules']['direct_domain_suffixes']=['foreign.org'];f.write(path,doc)
  binding['backupSha256']=hashlib.sha256(path.read_bytes()).hexdigest();rv['backup'].update(sha256=binding['backupSha256'],size=path.stat().st_size);rv['guard'].update(backupSha256=binding['backupSha256'],backupSize=path.stat().st_size);binding['readbackResultSha256']=hashlib.sha256(json.dumps(rv,sort_keys=True,separators=(',',':')).encode()).hexdigest()
  f.write(f.root/('android-readback-job-'+binding['readbackCorrelationId'])/'result.json',{'state':'complete','result':rv,'reason':None})
  self.assertEqual(f.execute('reconcile-replacement',replacement=binding)['reason'],'routing_changed');self.assertTrue((f.root/'android-native-device-api35.lease').exists())
 def test_replacement_status_never_closes_incomplete_or_releases_claims(self):
  f,binding,_=self.replacement_fixture();lease=f.root/'android-native-device-api35.lease'
  got=f.execute('reconcile-replacement-status',replacement=binding);self.assertEqual(got['reason'],'replacement_closure_incomplete');self.assertTrue(lease.exists())
  f.write(f.job/'replacement-binding.json',binding)
  before={p.relative_to(f.root):p.read_bytes() for p in f.root.rglob('*') if p.is_file()}
  got=f.execute('reconcile-replacement-status',replacement=binding);self.assertEqual(got['reason'],'replacement_closure_incomplete')
  after={p.relative_to(f.root):p.read_bytes() for p in f.root.rglob('*') if p.is_file()}
  self.assertTrue(before.items()<=after.items());self.assertTrue(all(p.parts[0].startswith('android-grant-observations-') for p in set(after)-set(before)))
 def test_replacement_partial_remote_marker_is_not_claim_release_proof(self):
  f,binding,_=self.replacement_fixture();lease=f.root/'android-native-device-api35.lease'
  original=Path.unlink
  def fail(path,*args,**kwargs):
   if path==lease:raise OSError('simulated unlink failure')
   return original(path,*args,**kwargs)
  with mock.patch.object(Path,'unlink',fail):self.assertEqual(f.execute('reconcile-replacement',replacement=binding)['state'],'unknown')
  self.assertTrue((f.job/'replacement-no-effect-closed.json').exists());self.assertTrue(lease.exists())
  before={p.relative_to(f.root):p.read_bytes() for p in f.root.rglob('*') if p.is_file()}
  self.assertEqual(f.execute('reconcile-replacement-status',replacement=binding)['reason'],'replacement_closure_incomplete')
  after={p.relative_to(f.root):p.read_bytes() for p in f.root.rglob('*') if p.is_file()}
  self.assertTrue(before.items()<=after.items());self.assertTrue(all(p.parts[0].startswith('android-grant-observations-') for p in set(after)-set(before)))
 def test_replacement_full_large_rules_ignore_only_export_metadata(self):
  f,binding,rv=self.replacement_fixture();f.rules={**RULES,'direct_domain_suffixes':['%06d.'%i+'x'*205+'.example.org' for i in range(56000)]}
  f.write(f.backup,{'type':'vpn_control_routing_rules','version':7,'exported_at':'original','rules':f.rules});f.intent['backupSha256']=hashlib.sha256(f.backup.read_bytes()).hexdigest();f.expected=json.dumps(f.intent,sort_keys=True,separators=(',',':'));f.write(f.job/'intent.json',f.intent)
  fresh=f.root/('android-readback-'+binding['readbackCorrelationId'])/'routing.json';f.write(fresh,{'type':'vpn_control_routing_rules','version':7,'exported_at':'replacement','rules':f.rules});self.assertGreater(fresh.stat().st_size,11800000)
  binding['originalIntentSha256']=hashlib.sha256(f.expected.encode()).hexdigest();binding['backupSha256']=hashlib.sha256(fresh.read_bytes()).hexdigest()
  rv['backup'].update(sha256=binding['backupSha256'],size=fresh.stat().st_size);rv['guard'].update(backupSha256=binding['backupSha256'],backupSize=fresh.stat().st_size)
  binding['readbackResultSha256']=hashlib.sha256(json.dumps(rv,sort_keys=True,separators=(',',':')).encode()).hexdigest();f.write(f.root/('android-readback-job-'+binding['readbackCorrelationId'])/'result.json',{'state':'complete','result':rv,'reason':None})
  self.assertNotEqual(binding['backupSha256'],f.intent['backupSha256']);self.assertEqual(f.execute('reconcile-replacement',replacement=binding)['state'],'closed')
 def test_replacement_postmarker_receipt_and_same_inode_claim_change_retained(self):
  for kind in ('receipt','original-intent','claim','chmod'):
   with self.subTest(kind=kind):
    f,binding,_=self.replacement_fixture();lease=f.root/'android-native-device-api35.lease'
    def change():
     if kind=='receipt':f.write(f.root/('android-readback-job-'+binding['readbackCorrelationId'])/'result.json',{'forged':True})
     elif kind=='original-intent':f.write(f.job/'intent.json',{**f.intent,'expectedRevision':99})
     elif kind=='claim':lease.write_bytes(lease.read_bytes())
     else:lease.chmod(0o644);lease.chmod(0o600)
    self.assertEqual(f.execute('reconcile-replacement',replacement=binding,after_marker=change)['state'],'unknown');self.assertTrue(lease.exists());self.assertEqual((f.on,f.taps),(0,0))
    self.assertEqual(f.execute('reconcile-replacement-status',replacement=binding)['state'],'unknown');self.assertTrue(lease.exists())
 def test_reconcile_status_reads_private_closure_state_without_product_calls(self):
  f=self.fixture();f.write(f.job/'result.json',{'state':'unknown','result':None,'reason':'baseline_not_empty_off'});f.write(f.job/'worker.py',{'fixed':'original'})
  lease=f.root/'android-native-device-api35.lease';f.write(lease,s._claim(C));(f.root/'android-native-device-api35.lock').touch(mode=0o600)
  before={p:p.read_bytes() for p in (f.job/'intent.json',f.job/'result.json',lease)}
  got=f.execute('reconcile-status');self.assertEqual(got['state'],'observed');self.assertEqual(got['records']['remoteMarker'],'absent');self.assertEqual(got['records']['remoteClaim'],'owned');self.assertEqual(got['records']['workerState'],'terminal')
  self.assertEqual(f.calls,[]);self.assertEqual(before,{p:p.read_bytes() for p in before});self.assertFalse((f.job/'no-effect-closed.json').exists())
 def test_reconcile_diagnostic_finite_timeout_nonzero_private_and_baseline_causes(self):
  for kind,reason,phase in [('timeout','reconcile_command_timeout','routing'),('nonzero','reconcile_command_nonzero','routing'),('private','private_file_unsafe','original-worker'),('baseline','baseline_not_empty_off','baseline')]:
   with self.subTest(kind=kind):
    f=self.fixture();f.write(f.job/'result.json',{'state':'unknown','result':None,'reason':'baseline_not_empty_off'});f.write(f.job/'worker.py',{'fixed':'original'})
    lease=f.root/'android-native-device-api35.lease';f.write(lease,s._claim(C));(f.root/'android-native-device-api35.lock').touch(mode=0o600)
    if kind=='private':(f.job/'worker.py').chmod(0o644)
    if kind=='baseline':f.drift='locations'
    original=f.run
    def read(argv,**kwargs):
     if 'routing' in argv and kind=='timeout':raise subprocess.TimeoutExpired(argv,120)
     if 'routing' in argv and kind=='nonzero':return f.done('{}',1)
     return original(argv,**kwargs)
    f.run=read;got=f.execute('reconcile-diagnostic');self.assertEqual(got['state'],'unknown');self.assertEqual(got['reason'],reason);self.assertEqual(got['checkpoint'],phase)
    self.assertTrue(lease.exists());self.assertFalse((f.job/'no-effect-closed.json').exists());self.assertEqual((f.on,f.taps),(0,0))
 def test_reconcile_status_reports_remote_closed_and_busy_lock_without_inference(self):
  import fcntl
  f=self.fixture();f.drift='empty-subscription';f.write(f.job/'result.json',{'state':'unknown','result':None,'reason':'baseline_not_empty_off'});f.write(f.job/'worker.py',{'fixed':'original'})
  f.write(f.root/'android-native-device-api35.lease',s._claim(C));(f.root/'android-native-device-api35.lock').touch(mode=0o600)
  original=fcntl.flock
  def busy(fd,flags):
   if flags&fcntl.LOCK_NB:raise BlockingIOError('busy')
   return original(fd,flags)
  with mock.patch.object(fcntl,'flock',side_effect=busy):got=f.execute('reconcile-status')
  self.assertEqual(got['records']['lockState'],'busy');self.assertEqual(got['currentProof'],'not-probed');self.assertEqual(f.calls,[])
  self.assertEqual(f.execute('reconcile')['state'],'closed');f.calls.clear();got=f.execute('reconcile-status')
  self.assertEqual(got['state'],'observed');self.assertEqual(got['records']['remoteMarker'],'valid');self.assertEqual(got['records']['remoteClaim'],'absent');self.assertEqual(f.calls,[])
 def test_remote_foreign_claim_blocks_without_changes(self):
  f=self.fixture();lease=f.root/'android-native-device-api35.lease';f.write(lease,{'owner':'foreign'})
  before=lease.read_bytes();self.assertEqual(f.execute()['reason'],'device_lease_active');self.assertEqual(f.on,0);self.assertEqual(lease.read_bytes(),before)

class HostContractTest(unittest.TestCase):
 def test_input_negative_revision_rejected_before_admission(self):
  with mock.patch.object(s.ssh_transport,'load_config') as dispatch:
   with self.assertRaises(ValueError):s.start('/tmp','archlinux','api35',C,'artifact',C,C,'d'*64,OWNER,-1)
   dispatch.assert_not_called()
 def test_existing_intent_never_dispatches_even_malformed(self):
  with tempfile.TemporaryDirectory() as root:
   path=s._journal(root,C);path.parent.mkdir(parents=True);path.write_text('malformed')
   with mock.patch.object(s.ssh_transport,'load_config') as dispatch:
    self.assertEqual(s.start(root,'archlinux','api35',C,'artifact',C,C,'d'*64,OWNER,2)['reason'],'existing_intent_no_replay');dispatch.assert_not_called()
 def test_active_endpoint_blocks_before_local_intent(self):
  with tempfile.TemporaryDirectory() as root:
   with s.android_endpoint_admission._shared_device_lease(Path(root),'archlinux','api35') as lease:lease.write_text('foreign');lease.chmod(0o600)
   with mock.patch.object(s.ssh_transport,'load_config') as dispatch:
    self.assertEqual(s.start(root,'archlinux','api35',C,'artifact',C,C,'d'*64,OWNER,2)['reason'],'device_lease_active');dispatch.assert_not_called()
   self.assertFalse(s._journal(root,C).exists())


from contextlib import ExitStack
import base64
# Captured native readback_status response; only the private machine path is redacted.
NATIVE_LIVE_RESPONSE=json.loads('{"admissionReady":false,"correlationId":"f19953c7-7422-4741-97ba-83b9101ad450","deviceAlias":"api35","host":"archlinux","nextAction":{"kind":"inspect-evidence","reason":"workflow response has no recognised safe continuation","replayAllowed":false,"requiresFreshEvidence":true},"ok":true,"outcome":"observed","replayAllowed":false,"result":{"backup":{"domainCount":56000,"formatValid":true,"path":"<retained-private-backup>","sha256":"d6a01e2c74b53d57c6bf388321d4e4e3df2a3824a17dea3c61a5393267724674","size":11872243},"configurationRevision":0,"controllerId":"ee3c98df-6d61-4ba2-be88-6259cd7fed7f","deviceIdentity":true,"stage":"backup_present"},"state":"observed","tool":"vm_workflow"}')

class HostAdmissionTest(unittest.TestCase):
 def fixture(self):
  f=Fixture();self.addCleanup(f.close);return f
 def admissions(self,f,probe):
  stack=ExitStack();self.addCleanup(stack.close);self.admission_stack=stack
  host=SimpleNamespace(android_devices={f.intent['device']:object()},fixture_transfer_root=str(f.root))
  config=SimpleNamespace(root=f.root,hosts={'archlinux':host})
  stage={'state':'published','ok':True,'sourceSha':f.intent['sourceSha'],'receipt':{'cliPath':f.cli,'manifestSha256':'a'*64,'rpmSha256':'b'*64,'launcherSha256':'c'*64,'desktopJarSha256':'d'*64}}
  result={'package':{'baseSha256':'d'*64},'backup':{'sha256':f.intent['backupSha256'],'rulesValid':True},'guard':{'controllerId':f.intent['expectedOwner'],'configurationRevision':f.intent['expectedRevision']},'device':{'api':f.intent['api'],'uid':'2000','avd':f.intent['expectedAvd'],'abi':'x86_64'}}
  live={'ok':True,'result':{'deviceIdentity':True,'stage':'backup_present','controllerId':f.intent['expectedOwner'],'configurationRevision':f.intent['expectedRevision'],'backup':{'sha256':f.intent['backupSha256'],'formatValid':True}}}
  patches=[mock.patch.object(s.ssh_transport,'load_config',return_value=config),mock.patch.object(s.ssh_transport,'connection_host',return_value=SimpleNamespace(password=None)),mock.patch.object(s.android_observation,'_profile',return_value={'api':f.intent['api'],'expectedAvd':f.intent['expectedAvd'],'adb':f.adb,'serial':'emulator-5556'}),mock.patch.object(s.subprocess,'run',return_value=SimpleNamespace(stdout='a'*40)),mock.patch.object(s.native_artifact_registry,'verify_artifact',return_value={'verification':'verified','artifact':{'platform':'android','artifactKind':'native-fixture-apk','sourceSha':'a'*40,'sha256':'d'*64},'location':{'localPath':'/local.apk'}}),mock.patch.object(s.android_package_install,'_inspect_apk'),mock.patch.object(s.android_cli_stage,'status',return_value=stage),mock.patch.object(s.android_admission_readback,'async_collect',return_value={'ok':True,'state':'complete','result':result}),mock.patch.object(s.android_admission_readback,'readback_status',return_value=live),mock.patch.object(s.android_consent_acceptance,'preflight',return_value={'state':'ready'}),mock.patch.object(s.ssh_transport,'build_ssh_argv',side_effect=lambda config,host,timeout,command:list(command)),mock.patch.object(s.android_observation,'_run_probe',side_effect=probe),mock.patch.object(s,'_ui_preflight',return_value={'state':'ready'})]
  return [stack.enter_context(p) for p in patches]
 def start(self,f):return s.start(f.root,'archlinux',f.intent['device'],C,'artifact',C,C,f.intent['backupSha256'],f.intent['expectedOwner'],f.intent['expectedRevision'])
 def test_api29_route_is_typed_and_admitted_without_adopting_api35_warning(self):
  f=self.fixture();f.intent.update(device='api29',api=29,expectedAvd='owned-api29')
  self.admissions(f,lambda *a:(0,json.dumps({'state':'submitted','correlationId':C,'identity':{'pid':42,'startTicks':99}}).encode()))
  self.assertEqual(self.start(f)['state'],'submitted')
  self.assertEqual(s._load(f.root,C)['device'],'api29')
  self.assertEqual(s._load(f.root,C)['api'],29)
  self.assertTrue(s._exact(f.root/'.rag_index/android-native-device-leases/lease-archlinux-api29.json',s._claim(C,'api29')))
  self.assertFalse((f.root/'.rag_index/android-native-device-leases/lease-archlinux-api35.json').exists())
 def test_api29_profile_crossed_to_api35_rejected_before_intent(self):
  f=self.fixture();f.intent.update(device='api29',api=35,expectedAvd='owned-api35')
  self.admissions(f,lambda *a:self.fail('crossed profile dispatch'))
  with self.assertRaises(ValueError):self.start(f)
  self.assertFalse(s._journal(f.root,C).exists())
 def test_start_durable_claims_full_stage_and_no_redispatch(self):
  f=self.fixture();seen=[]
  def probe(argv,timeout):
   seen.append(argv);self.assertEqual(s._load(f.root,C),f.intent)
   lease=f.root/'.rag_index/android-native-device-leases/lease-archlinux-api35.json';self.assertTrue(s._exact(lease,s._claim(C)))
   doc=s.android_document_acceptance._lease(f.root,'archlinux','api35',C);self.assertTrue(doc.exists())
   worker=base64.urlsafe_b64decode(argv[-1]).decode();self.assertIn('owned-api35',worker)
   return 0,json.dumps({'state':'submitted','correlationId':C,'identity':{'pid':42,'startTicks':99}}).encode()
  self.admissions(f,probe)
  self.assertEqual(self.start(f)['state'],'submitted');before=s._journal(f.root,C).read_bytes()
  self.assertEqual(self.start(f)['reason'],'existing_intent_no_replay');self.assertEqual(len(seen),1);self.assertEqual(s._journal(f.root,C).read_bytes(),before)
 def test_admission_failures_have_no_dispatch_or_intent(self):
  for kind in ('readback','stage','permission','apk'):
   with self.subTest(kind=kind):
    f=self.fixture();mocks=self.admissions(f,lambda *a:self.fail('dispatch before admission'))
    if kind=='readback':mocks[8].return_value={'ok':False,'result':mocks[8].return_value['result']}
    elif kind=='stage':mocks[6].return_value['receipt']['desktopJarSha256']='bad'
    elif kind=='permission':mocks[9].return_value={'state':'blocked'}
    else:mocks[4].return_value['artifact']['artifactKind']='rpm'
    with self.assertRaises(ValueError):self.start(f)
    self.assertFalse(s._journal(f.root,C).exists())
    self.admission_stack.close()
 def test_saved_native_live_response_admits_without_rules_valid(self):
  f=self.fixture();native=json.loads(json.dumps(NATIVE_LIVE_RESPONSE));proof=native['result']
  self.assertNotIn('rulesValid',proof['backup']);self.assertIs(proof['backup']['formatValid'],True)
  f.intent['expectedOwner']=proof['controllerId'];f.intent['expectedRevision']=proof['configurationRevision'];f.intent['backupSha256']=proof['backup']['sha256']
  mocks=self.admissions(f,lambda *a:(0,json.dumps({'state':'submitted','correlationId':C,'identity':{'pid':42,'startTicks':99}}).encode()))
  mocks[8].return_value=native
  self.assertEqual(self.start(f)['state'],'submitted');self.assertTrue(s._journal(f.root,C).exists())
 def test_live_format_valid_cannot_replace_async_rules_valid(self):
  f=self.fixture();mocks=self.admissions(f,lambda *a:self.fail('invalid proof dispatched'))
  mocks[7].return_value['result']['backup']={'sha256':f.intent['backupSha256'],'formatValid':True}
  with self.assertRaisesRegex(ValueError,'grant readback not admitted'):self.start(f)
  self.assertFalse(s._journal(f.root,C).exists())
 def test_live_rules_valid_is_not_live_format_proof(self):
  f=self.fixture();mocks=self.admissions(f,lambda *a:self.fail('invalid proof dispatched'))
  mocks[8].return_value['result']['backup']={'sha256':f.intent['backupSha256'],'rulesValid':True}
  with self.assertRaisesRegex(ValueError,'grant readback changed'):self.start(f)
  self.assertFalse(s._journal(f.root,C).exists())
 def test_submit_prefix_and_create_only_job_executed(self):
  f=self.fixture();(f.job/'intent.json').unlink();(f.job/'identity.json').unlink();f.job.rmdir()
  out=io.StringIO();fake=SimpleNamespace(pid=4242,kill=lambda:None,wait=lambda timeout:None)
  original=Path.read_text
  def read(path,*args,**kwargs):
   if str(path)=='/proc/4242/stat':return '4242 (worker) '+' '.join(['S']+['0']*19+['77'])
   return original(path,*args,**kwargs)
  with mock.patch.object(sys,'argv',['submit',str(f.root),C,f.expected,base64.urlsafe_b64encode(b'pass').decode()]),mock.patch('sys.stdout',out),mock.patch.object(subprocess,'Popen',return_value=fake) as spawn,mock.patch.object(Path,'read_text',read):
   exec(s._SUBMIT,{'__name__':'__main__'})
   self.assertEqual(json.loads(out.getvalue())['state'],'submitted')
   self.assertTrue((f.job/'release').exists());self.assertEqual(json.loads((f.job/'intent.json').read_text()),f.intent)
   with self.assertRaises(FileExistsError):exec(s._SUBMIT,{'__name__':'__main__'})
   self.assertEqual(spawn.call_count,1)
 def test_fresh_collector_uses_real_bounded_ssh_builder(self):
  f=self.fixture()
  host=s.ssh_transport.SshHost(alias='archlinux',host='fixture',port=22,user='owner',identity_file=Path('/key'),known_hosts_file=Path('/known'))
  config=SimpleNamespace(root=f.root,hosts={'archlinux':host})
  profile={'adb':f.adb,'serial':'emulator-5556'}
  with mock.patch.object(s,'_route',return_value=(config,profile)),mock.patch.object(s.android_observation,'_run_probe',return_value=(0,json.dumps({'state':'complete','correlationId':C,'freshProof':True}).encode())) as probe:
   self.assertTrue(s._observe(f.root,f.intent,'collect')['freshProof'])
   self.assertIn('ConnectTimeout=60',probe.call_args.args[0]);self.assertEqual(probe.call_args.args[1],s._COLLECT_OBSERVER_SECONDS)
 def test_host_collect_needs_fresh_proof_and_exact_claims(self):
  for changed in (False,True):
   with self.subTest(changed=changed):
    f=self.fixture();s._save(f.root,f.intent)
    with s.android_endpoint_admission._shared_device_lease(f.root,'archlinux','api35') as lease:f.write(lease,s._claim(C))
    with s.android_document_acceptance._device_guard(f.root,'archlinux','api35') as doc:f.write(doc,{'host':'archlinux','device':'api35','correlationId':C})
    result={'operationCode':'INVALID_ARGUMENT','runtimeStarted':False}
    with mock.patch.object(s,'_observe',side_effect=[{'state':'complete','result':result},{'state':'unknown' if changed else 'complete','freshProof':not changed}]),mock.patch.object(s.android_cli_stage,'status',return_value={'ok':True,'state':'published','sourceSha':'a'*40,'receipt':{'cliPath':f.cli,'manifestSha256':'a'*64,'rpmSha256':'b'*64,'launcherSha256':'c'*64,'desktopJarSha256':'d'*64}}):
     collected=s.collect(f.root,C)
    self.assertEqual(collected['state'],'unknown' if changed else 'complete');self.assertEqual(lease.exists(),changed);self.assertEqual(doc.exists(),changed)

 def test_host_same_inode_claim_change_retained_and_closed_recollection(self):
  for change in ('write','chmod',None):
   with self.subTest(change=change):
    f=self.fixture();s._save(f.root,f.intent)
    with s.android_endpoint_admission._shared_device_lease(f.root,'archlinux','api35') as lease:f.write(lease,s._claim(C))
    with s.android_document_acceptance._device_guard(f.root,'archlinux','api35') as doc:f.write(doc,{'host':'archlinux','device':'api35','correlationId':C})
    def observe(root,intent,mode):
     if mode=='status':return {'state':'complete','result':{'operationCode':'INVALID_ARGUMENT','runtimeStarted':False}}
     if change=='write':lease.write_bytes(lease.read_bytes())
     elif change=='chmod':doc.chmod(0o644);doc.chmod(0o600)
     return {'state':'complete','freshProof':True}
    stage={'ok':True,'state':'published','sourceSha':'a'*40,'receipt':{'cliPath':f.cli,'manifestSha256':'a'*64,'rpmSha256':'b'*64,'launcherSha256':'c'*64,'desktopJarSha256':'d'*64}}
    with mock.patch.object(s,'_observe',side_effect=observe),mock.patch.object(s.android_cli_stage,'status',return_value=stage):
     got=s.collect(f.root,C)
     self.assertEqual(got['state'],'unknown' if change else 'complete')
     self.assertEqual(lease.exists(),bool(change));self.assertEqual(doc.exists(),bool(change))
     if change is None:
      self.assertEqual(s.collect(f.root,C)['state'],'complete')

 def test_host_diagnose_validates_finite_projection(self):
  f=self.fixture();s._save(f.root,f.intent);f.write(f.job/'result.json',{'state':'unknown','result':None,'reason':'baseline_not_empty_off'})
  f.write(f.root/'android-native-device-api35.lease',s._claim(C));(f.root/'android-native-device-api35.lock').touch(mode=0o600)
  projection=f.execute('diagnostic')
  with mock.patch.object(s,'_observe',return_value=projection) as observe:
   got=s.diagnose(f.root,C);self.assertTrue(got['ok']);self.assertEqual(got['state'],'diagnosed');self.assertFalse(got['productAction']);self.assertFalse(got['nativeActionAllowed']);self.assertFalse(got['replayAllowed']);observe.assert_called_once_with(f.root,f.intent,'diagnostic')
  for field,value in [('facts',{'sourceMode':'private'}),('checks',{'runtimeOff':'true'}),('observationClass','historical-proof')]:
   with mock.patch.object(s,'_observe',return_value={**projection,field:value}):
    got=s.diagnose(f.root,C);self.assertFalse(got['ok']);self.assertEqual(got['reason'],'diagnostic_proof_unknown');self.assertNotIn('facts',got)
 def test_host_no_effect_reconcile_closes_exact_claims_idempotently(self):
  f=self.fixture();s._save(f.root,f.intent);before=s._journal(f.root,C).read_bytes()
  with s.android_endpoint_admission._shared_device_lease(f.root,'archlinux','api35') as lease:f.write(lease,s._claim(C))
  with s.android_document_acceptance._device_guard(f.root,'archlinux','api35') as doc:f.write(doc,{'host':'archlinux','device':'api35','correlationId':C})
  proof={k:True for k in s._NO_EFFECT_PROOF};proof.update(historicalSourceSettingsAvailable=False,retainedBindingsSha256='a'*64,currentSnapshotSha256='b'*64)
  with mock.patch.object(s,'_observe',return_value={'state':'closed','proof':proof,'markerSha256':'c'*64}) as observe:
   got=s.reconcile(f.root,C);self.assertEqual(got['state'],'closed');self.assertTrue(got['ok']);self.assertTrue(got['claimsReleased']);self.assertFalse(got['grantObserved']);self.assertEqual(got['originalOutcome'],'unknown');self.assertFalse(got['productAction'])
   self.assertFalse(lease.exists());self.assertFalse(doc.exists());again=s.reconcile(f.root,C);self.assertEqual(again['state'],'closed');self.assertTrue(again['ok']);self.assertEqual(again['originalOutcome'],'unknown');self.assertFalse(again['grantObserved']);self.assertEqual(observe.call_count,2)
  self.assertEqual(s._journal(f.root,C).read_bytes(),before)
 def test_reconcile_unknown_retains_finite_remote_cause(self):
  f=self.fixture();s._save(f.root,f.intent)
  with s.android_endpoint_admission._shared_device_lease(f.root,'archlinux','api35') as lease:f.write(lease,s._claim(C))
  with s.android_document_acceptance._device_guard(f.root,'archlinux','api35') as doc:f.write(doc,{'host':'archlinux','device':'api35','correlationId':C})
  with mock.patch.object(s,'_observe',return_value={'state':'unknown','reason':'reconcile_command_timeout','checkpoint':'routing'}):
   got=s.reconcile(f.root,C);self.assertEqual(got['reason'],'reconcile_command_timeout');self.assertEqual(got['checkpoint'],'routing');self.assertTrue(lease.exists());self.assertTrue(doc.exists())
 def test_reconciliation_observer_projects_local_records_and_transport_without_writes(self):
  f=self.fixture();s._save(f.root,f.intent);before=s._journal(f.root,C).read_bytes()
  with s.android_endpoint_admission._shared_device_lease(f.root,'archlinux','api35') as lease:f.write(lease,s._claim(C))
  with s.android_document_acceptance._device_guard(f.root,'archlinux','api35') as doc:f.write(doc,{'owner':'foreign'})
  records={'workerState':'terminal','grantRecords':'absent','baselineRecord':'absent','remoteMarker':'absent','remoteClaim':'owned','lockState':'free'}
  with mock.patch.object(s,'_observe',return_value={'state':'observed','records':records,'currentProof':'not-probed'}):
   got=s.reconcile_status(f.root,C);self.assertTrue(got['ok']);self.assertEqual(got['localMarker'],'absent');self.assertEqual(got['localClaims'],{'shared':'owned','document':'foreign'});self.assertFalse(got['productAction'])
  for failure,reason in [(TimeoutError(),'reconcile_transport_timeout'),(RuntimeError('private raw error'),'reconcile_transport_unknown')]:
   with mock.patch.object(s,'_observe',side_effect=failure):
    got=s.reconcile_diagnose(f.root,C);self.assertEqual(got['reason'],reason);self.assertEqual(got['checkpoint'],'transport');self.assertNotIn('private raw',json.dumps(got))
  self.assertEqual(s._journal(f.root,C).read_bytes(),before);self.assertTrue(lease.exists());self.assertTrue(doc.exists());self.assertFalse(s._journal(f.root,C).with_suffix('.no-effect.closed.json').exists())
 def test_reconciliation_observer_hostile_projection_is_finite_and_read_only(self):
  f=self.fixture();s._save(f.root,f.intent)
  with s.android_endpoint_admission._shared_device_lease(f.root,'archlinux','api35') as lease:f.write(lease,s._claim(C))
  with s.android_document_acceptance._device_guard(f.root,'archlinux','api35') as doc:f.write(doc,{'host':'archlinux','device':'api35','correlationId':C})
  before={p.relative_to(f.root):p.read_bytes() for p in f.root.rglob('*') if p.is_file()}
  records={'workerState':'terminal','grantRecords':'absent','baselineRecord':'absent','remoteMarker':'absent','remoteClaim':'owned','lockState':'free'}
  valid={'state':'observed','records':records,'currentProof':'not-probed'}
  hostile=[None,[],{'state':'observed','records':None,'currentProof':'not-probed'},
   {**valid,'records':{**records,'raw':'PRIVATE_SENTINEL'}},
   {**valid,'records':{k:v for k,v in records.items() if k!='workerState'}}]
  hostile += [{'state':'unknown','reason':'PRIVATE_SENTINEL'}, {'state':'unknown','reason':'reconcile_command_timeout','checkpoint':'PRIVATE_SENTINEL'}, {'state':'unknown','reason':['PRIVATE_SENTINEL']}, {'state':'unknown','reason':'reconcile_command_timeout','checkpoint':['PRIVATE_SENTINEL']}]
  hostile += [{**valid,'records':{**records,k:'PRIVATE_SENTINEL'}} for k in records]
  hostile += [{**valid,'currentProof':v} for v in ('PRIVATE_SENTINEL',None,[],{})]
  hostile += [{**valid,'historicalSourceSettings':v} for v in ('PRIVATE_SENTINEL',None,[],{})]
  for value in hostile:
   with self.subTest(value=value),mock.patch.object(s,'_observe',return_value=value):
    got=s.reconcile_diagnose(f.root,C)
    self.assertFalse(got['ok']);self.assertEqual(got['state'],'unknown');self.assertEqual(got['reason'],'reconcile_observation_invalid')
    self.assertFalse(got['replayAllowed']);self.assertFalse(got['nativeActionAllowed']);self.assertFalse(got['productAction'])
    self.assertNotIn('records',got);self.assertNotIn('PRIVATE_SENTINEL',json.dumps(got))
  self.assertEqual({p.relative_to(f.root):p.read_bytes() for p in f.root.rglob('*') if p.is_file()},before)
 def test_reconcile_unknown_hostile_reason_and_checkpoint_are_redacted(self):
  flags={'nativeActionAllowed':False,'productAction':False}
  values=[None,[],{'reason':'PRIVATE_SENTINEL'}, {'reason':['PRIVATE_SENTINEL']},
   {'reason':'reconcile_command_timeout','checkpoint':'PRIVATE_SENTINEL'},
   {'reason':'reconcile_command_timeout','checkpoint':['PRIVATE_SENTINEL']}]
  for value in values:
   with self.subTest(value=value):
    got=s._reconcile_unknown(C,value,flags)
    self.assertFalse(got['ok']);self.assertEqual(got['reason'],'reconcile_observation_invalid');self.assertNotIn('checkpoint',got);self.assertNotIn('PRIVATE_SENTINEL',json.dumps(got))
  got=s._reconcile_unknown(C,{'reason':'reconcile_command_timeout','checkpoint':'routing','raw':'PRIVATE_SENTINEL'},flags)
  self.assertEqual(got['reason'],'reconcile_command_timeout');self.assertEqual(got['checkpoint'],'routing');self.assertNotIn('PRIVATE_SENTINEL',json.dumps(got))
 def test_host_replacement_one_shot_loss_status_and_fresh_collect(self):
  f,binding,rv=ExecutedWorkerTest.replacement_fixture(self);s._save(f.root,f.intent)
  with s.android_endpoint_admission._shared_device_lease(f.root,'archlinux','api35') as lease:f.write(lease,s._claim(C))
  with s.android_document_acceptance._device_guard(f.root,'archlinux','api35') as doc:f.write(doc,{'host':'archlinux','device':'api35','correlationId':C})
  stage={'ok':True,'state':'published','sourceSha':'a'*40,'receipt':{'cliPath':f.cli,'manifestSha256':'a'*64,'rpmSha256':'b'*64,'launcherSha256':'c'*64,'desktopJarSha256':'d'*64}}
  live={'ok':True,'result':{'deviceIdentity':True,'stage':'backup_present','controllerId':binding['owner'],'configurationRevision':0,'backup':{'sha256':binding['backupSha256'],'formatValid':True}}}
  calls=[]
  def observe(root,intent,mode,replacement):
   calls.append(mode);self.assertEqual(s._closed_marker(s._journal(root,C).with_suffix('.replacement.json')),replacement)
   result=f.execute(mode,replacement=replacement)
   if mode=='reconcile-replacement':raise TimeoutError('simulated lost response after remote closure')
   return result
  args=(f.root,C,binding['readbackCorrelationId'],binding['backupSha256'],binding['owner'],0)
  before=s._journal(f.root,C).read_bytes()
  with mock.patch.object(s,'_route',return_value=(None,{'serial':'emulator-5556'})),mock.patch.object(s.android_admission_readback,'_load_async_intent',return_value=binding['readbackIntent']),mock.patch.object(s.android_admission_readback,'async_collect',return_value={'ok':True,'state':'complete','result':rv,'identity':binding['readbackIdentity']}),mock.patch.object(s.android_admission_readback,'readback_status',return_value=live),mock.patch.object(s.android_cli_stage,'status',return_value=stage),mock.patch.object(s,'_observe',side_effect=observe):
   first=s.reconcile_replacement(*args);self.assertEqual(first['reason'],'reconcile_transport_timeout');self.assertTrue(lease.exists());self.assertTrue(doc.exists())
   again=s.reconcile_replacement(*args);self.assertEqual(again['state'],'observed');self.assertTrue(again['ok']);self.assertEqual(calls.count('reconcile-replacement'),1);self.assertTrue(lease.exists());self.assertTrue(doc.exists())
   changed=s.reconcile_replacement(*args[:-1],1);self.assertEqual(changed['reason'],'replacement_receipt_invalid');self.assertEqual(calls.count('reconcile-replacement'),1)
   collected=s.reconcile_replacement_collect(f.root,C);self.assertTrue(collected['ok']);self.assertEqual(collected['state'],'closed');self.assertFalse(collected['grantObserved']);self.assertEqual(collected['originalOutcome'],'unknown');self.assertFalse(lease.exists());self.assertFalse(doc.exists())
   self.assertTrue(s.reconcile_replacement_collect(f.root,C)['ok']);self.assertEqual(calls.count('reconcile-replacement'),1)
  self.assertEqual(s._journal(f.root,C).read_bytes(),before)
 def test_host_replacement_admission_checks_actual_readback_schemas_before_intent(self):
  for invalid in ('live-rulesValid','collected-formatValid','package','owner','identity','source-intent','stage'):
   with self.subTest(invalid=invalid):
    f,binding,rv=ExecutedWorkerTest.replacement_fixture(self);s._save(f.root,f.intent)
    stage={'ok':True,'state':'published','sourceSha':'a'*40,'receipt':{'cliPath':f.cli,'manifestSha256':'a'*64,'rpmSha256':'b'*64,'launcherSha256':'c'*64,'desktopJarSha256':'d'*64}}
    ri=dict(binding['readbackIntent']);identity=binding['readbackIdentity'];live={'ok':True,'result':{'deviceIdentity':True,'stage':'backup_present','controllerId':binding['owner'],'configurationRevision':0,'backup':{'sha256':binding['backupSha256'],'formatValid':True}}}
    if invalid=='live-rulesValid':live['result']['backup']={'sha256':binding['backupSha256'],'rulesValid':True}
    elif invalid=='collected-formatValid':rv['backup'].pop('rulesValid');rv['backup']['formatValid']=True
    elif invalid=='package':rv['package']['baseSha256']='e'*64
    elif invalid=='owner':rv['guard']['controllerId']=OWNER
    elif invalid=='identity':identity={'pid':True,'startTicks':1}
    elif invalid=='source-intent':ri['device']='api29'
    elif invalid=='stage':stage['receipt']['desktopJarSha256']='e'*64
    with mock.patch.object(s,'_route',return_value=(None,{'serial':'emulator-5556'})),mock.patch.object(s.android_admission_readback,'_load_async_intent',return_value=ri),mock.patch.object(s.android_admission_readback,'async_collect',return_value={'ok':True,'state':'complete','result':rv,'identity':identity}),mock.patch.object(s.android_admission_readback,'readback_status',return_value=live),mock.patch.object(s.android_cli_stage,'status',return_value=stage),mock.patch.object(s,'_observe') as observe:
     got=s.reconcile_replacement(f.root,C,binding['readbackCorrelationId'],binding['backupSha256'],binding['owner'],0)
    self.assertFalse(got['ok']);observe.assert_not_called();self.assertFalse(s._journal(f.root,C).with_suffix('.replacement.json').exists())
 def test_host_replacement_failed_admission_never_redispatches(self):
  f,binding,_=ExecutedWorkerTest.replacement_fixture(self);s._save(f.root,f.intent)
  with s.android_endpoint_admission._shared_device_lease(f.root,'archlinux','api35') as lease:f.write(lease,s._claim(C))
  with s.android_document_acceptance._device_guard(f.root,'archlinux','api35') as doc:f.write(doc,{'host':'archlinux','device':'api35','correlationId':C})
  with mock.patch.object(s,'_observe',side_effect=TimeoutError()):got=s._reconcile(f.root,C,binding)
  self.assertEqual(got['reason'],'reconcile_transport_timeout');self.assertTrue(lease.exists());self.assertTrue(doc.exists())
  with mock.patch.object(s,'_observe',return_value={'state':'unknown','reason':'replacement_binding_missing','checkpoint':'private-record'}) as observe:
   again=s.reconcile_replacement(f.root,C,binding['readbackCorrelationId'],binding['backupSha256'],binding['owner'],0)
   self.assertEqual(again['state'],'unknown');self.assertEqual(observe.call_args.args[2],'reconcile-replacement-status')
   self.assertEqual(s.reconcile_replacement_collect(f.root,C)['state'],'unknown');self.assertTrue(lease.exists());self.assertTrue(doc.exists())
 def test_observer_budget_covers_all_guarded_full_exports(self):
  self.assertEqual(s._FULL_SNAPSHOT_SECONDS,2640);self.assertEqual(s._RECONCILE_OBSERVER_SECONDS,3*2640+3*135+120)
  f=self.fixture();host=s.ssh_transport.SshHost(alias='archlinux',host='fixture',port=22,user='owner',identity_file=Path('/key'),known_hosts_file=Path('/known'));config=SimpleNamespace(root=f.root,hosts={'archlinux':host})
  with mock.patch.object(s,'_route',return_value=(config,{'adb':f.adb,'serial':'emulator-5556'})),mock.patch.object(s.android_observation,'_run_probe',return_value=(0,json.dumps({'state':'unknown','correlationId':C,'reason':'replacement_closure_incomplete'}).encode())) as probe:
   s._observe(f.root,f.intent,'reconcile-replacement-status',{'finite':'binding'})
   self.assertEqual(probe.call_args.args[1],8445);self.assertIn('ConnectTimeout=60',probe.call_args.args[0])
 def test_cli_error_classifier_projection_rejects_hostile_code(self):
  flags={'nativeActionAllowed':False,'productAction':False}
  for code in ('PRIVATE_SENTINEL',None,[],{}):
   got=s._reconcile_unknown(C,{'state':'unknown','reason':'reconcile_command_nonzero','checkpoint':'routing','commandCode':code},flags)
   self.assertEqual(got['reason'],'reconcile_observation_invalid');self.assertNotIn('PRIVATE_SENTINEL',json.dumps(got))
  for code in ('TIMEOUT','OTHER','UNCLASSIFIED'):
   got=s._reconcile_unknown(C,{'state':'unknown','reason':'reconcile_command_nonzero','checkpoint':'routing','commandCode':code,'raw':'PRIVATE_SENTINEL'},flags)
   self.assertEqual(got['commandCode'],code);self.assertNotIn('PRIVATE_SENTINEL',json.dumps(got))
 def test_host_continuation_loss_is_status_only_then_fresh_child_collect(self):
  f,binding,continuation=ExecutedWorkerTest.continuation_fixture(self);s._save(f.root,f.intent);s._write_closed_marker(s._journal(f.root,C).with_suffix('.replacement.json'),binding)
  with s.android_endpoint_admission._shared_device_lease(f.root,'archlinux','api35') as lease:f.write(lease,s._claim(C))
  with s.android_document_acceptance._device_guard(f.root,'archlinux','api35') as doc:f.write(doc,{'host':'archlinux','device':'api35','correlationId':C})
  original=s._journal(f.root,C).read_bytes();binding_before=s._journal(f.root,C).with_suffix('.replacement.json').read_bytes();calls=[]
  def observe(root,intent,mode,replacement,child=None):
   calls.append(mode)
   if child is not None:self.assertEqual(s._closed_marker(s._continuation_path(root,C,child['continuationId'])),child)
   result=f.execute(mode,replacement=replacement,continuation=child)
   if mode=='reconcile-continuation':raise TimeoutError('lost remote completion')
   return result
  with mock.patch.object(s,'_observe',side_effect=observe):
   got=s.replacement_continue_no_effect(f.root,C,continuation['continuationId']);self.assertEqual(got['reason'],'reconcile_transport_timeout');self.assertTrue(lease.exists());self.assertTrue(doc.exists())
   again=s.replacement_continue_no_effect(f.root,C,continuation['continuationId']);self.assertEqual(again['state'],'observed');self.assertEqual(calls.count('reconcile-continuation'),1);self.assertTrue(lease.exists());self.assertTrue(doc.exists())
   result=s.replacement_continue_no_effect_collect(f.root,C,continuation['continuationId']);self.assertTrue(result['ok']);self.assertEqual(result['state'],'closed');self.assertEqual(result['continuationId'],continuation['continuationId']);self.assertEqual(result['originalOutcome'],'unknown');self.assertFalse(result['grantObserved']);self.assertFalse(lease.exists());self.assertFalse(doc.exists())
   self.assertTrue(s.replacement_continue_no_effect_collect(f.root,C,continuation['continuationId'])['ok'])
  self.assertEqual(s._journal(f.root,C).read_bytes(),original);self.assertEqual(s._journal(f.root,C).with_suffix('.replacement.json').read_bytes(),binding_before)
 def test_host_continuation_requires_fresh_incomplete_not_timeout_or_closed(self):
  for reason,state in [('reconcile_command_timeout','unknown'),('replacement_closure_incomplete','observed'),('owner_or_revision_changed','unknown')]:
   with self.subTest(reason=reason):
    f,binding,continuation=ExecutedWorkerTest.continuation_fixture(self);s._save(f.root,f.intent);s._write_closed_marker(s._journal(f.root,C).with_suffix('.replacement.json'),binding)
    with mock.patch.object(s,'reconcile_replacement_status',return_value={'state':state,'reason':reason}),mock.patch.object(s,'_observe') as observe:
     result=s.replacement_continue_no_effect(f.root,C,continuation['continuationId'])
    self.assertEqual(result['state'],'unknown');observe.assert_not_called();self.assertFalse(s._continuation_path(f.root,C,continuation['continuationId']).exists())
 def test_continuation_collector_requires_exact_child_proof(self):
  f,binding,continuation=ExecutedWorkerTest.continuation_fixture(self)
  for proof in ([],None,{'continuationId':'foreign'},{}):
   with self.subTest(proof=proof):self.assertFalse(s._no_effect_valid({'state':'closed','proof':proof,'markerSha256':'a'*64},binding,continuation))
 def test_incomplete_disposition_hashes_are_finite_and_paired(self):
  flags={'nativeActionAllowed':False,'productAction':False}
  for value in ({'currentSnapshotSha256':'PRIVATE_SENTINEL'},{'currentSnapshotSha256':'a'*64},{'retainedBindingsSha256':[]},{'currentSnapshotSha256':'a'*64,'retainedBindingsSha256':'b'*64}):
   result=s._reconcile_unknown(C,{'reason':'replacement_closure_incomplete',**value},flags)
   if len(value)==2:self.assertEqual(result['currentSnapshotSha256'],'a'*64)
   else:self.assertEqual(result['reason'],'reconcile_observation_invalid')
   self.assertNotIn('PRIVATE_SENTINEL',json.dumps(result))
 def test_host_partial_close_recovery_and_marker_substitution(self):
  f=self.fixture();s._save(f.root,f.intent)
  with s.android_endpoint_admission._shared_device_lease(f.root,'archlinux','api35') as lease:f.write(lease,s._claim(C))
  with s.android_document_acceptance._device_guard(f.root,'archlinux','api35') as doc:f.write(doc,{'host':'archlinux','device':'api35','correlationId':C})
  calls=[]
  def observe(root,intent,mode):
   calls.append(mode)
   return {'state':'complete','result':{'operationCode':'INVALID_ARGUMENT','runtimeStarted':False}} if mode=='status' else {'state':'complete','freshProof':True}
  stage={'ok':True,'state':'published','sourceSha':'a'*40,'receipt':{'cliPath':f.cli,'manifestSha256':'a'*64,'rpmSha256':'b'*64,'launcherSha256':'c'*64,'desktopJarSha256':'d'*64}}
  original=Path.unlink
  def interrupted(path,*args,**kwargs):
   if path.resolve()==lease.resolve():raise OSError('simulated close loss')
   return original(path,*args,**kwargs)
  with mock.patch.object(s,'_observe',side_effect=observe),mock.patch.object(s.android_cli_stage,'status',return_value=stage):
   with mock.patch.object(Path,'unlink',interrupted):self.assertEqual(s.collect(f.root,C)['state'],'unknown')
   self.assertFalse(doc.exists());self.assertTrue(lease.exists())
   marker=s._journal(f.root,C).with_suffix('.closed.json');before=marker.read_bytes()
   self.assertEqual(s.collect(f.root,C)['state'],'complete');self.assertFalse(lease.exists())
   self.assertEqual(s.collect(f.root,C)['state'],'complete');self.assertEqual(marker.read_bytes(),before)
   self.assertEqual(calls.count('collect'),3)
   value=json.loads(before);value['intentSha256']='e'*64;f.write(marker,value)
   self.assertEqual(s.collect(f.root,C)['state'],'unknown');self.assertEqual(calls.count('collect'),3)
 def test_host_drift_after_marker_before_unlink_retains_both(self):
  f=self.fixture();s._save(f.root,f.intent)
  with s.android_endpoint_admission._shared_device_lease(f.root,'archlinux','api35') as lease:f.write(lease,s._claim(C))
  with s.android_document_acceptance._device_guard(f.root,'archlinux','api35') as doc:f.write(doc,{'host':'archlinux','device':'api35','correlationId':C})
  original=s._write_closed_marker
  def write(path,value):
   original(path,value);doc.chmod(0o644);doc.chmod(0o600)
  stage={'ok':True,'state':'published','sourceSha':'a'*40,'receipt':{'cliPath':f.cli,'manifestSha256':'a'*64,'rpmSha256':'b'*64,'launcherSha256':'c'*64,'desktopJarSha256':'d'*64}}
  with mock.patch.object(s,'_observe',side_effect=lambda root,intent,mode:{'state':'complete','result':{'operationCode':'INVALID_ARGUMENT','runtimeStarted':False}} if mode=='status' else {'state':'complete','freshProof':True}),mock.patch.object(s.android_cli_stage,'status',return_value=stage),mock.patch.object(s,'_write_closed_marker',side_effect=write):
   self.assertEqual(s.collect(f.root,C)['state'],'unknown');self.assertTrue(doc.exists());self.assertTrue(lease.exists())
   self.assertEqual(s.collect(f.root,C)['state'],'unknown');self.assertTrue(doc.exists());self.assertTrue(lease.exists())

if __name__=='__main__':unittest.main()

class PromptEvidenceTest(unittest.TestCase):
 def fixture(self):
  f=Fixture();self.addCleanup(f.close);return f
 def test_rejected_prompt_retained_before_unknown(self):
  f=self.fixture();f.xml=dialog(WARNING+' foreign suffix')
  result=f.execute();self.assertEqual(result['reason'],'prompt_not_owned')
  dirs=list(f.root.glob('android-grant-prompt-*'));self.assertEqual(len(dirs),1)
  self.assertEqual((dirs[0]/'ui.xml').read_text(),f.xml)
  meta=json.loads((dirs[0]/'binding.json').read_text());self.assertEqual(meta['operation']['operationId'],OP)
  self.assertEqual(meta['xml']['sha256'],hashlib.sha256(f.xml.encode()).hexdigest())
  self.assertEqual(stat.S_IMODE((dirs[0]/'ui.xml').stat().st_mode),0o600)
  self.assertFalse((f.job/'tap-intent.json').exists());self.assertEqual(f.taps,0)
 def setup_attempt(self,f):
  f.xml=dialog(WARNING+' foreign suffix');self.assertEqual(f.execute()['reason'],'prompt_not_owned');f.write(f.job/'worker.py',{'retained':'worker'})
 def diagnostic_run(self,f,mode='pending',drift=None):
  original=f.run;seen=0
  def run(argv,**kw):
   nonlocal seen
   if argv[0]==f.adb and 'exec-out' in argv:
    if drift=='tap':f.write(f.job/'tap-intent.json',{})
    return SimpleNamespace(returncode=0,stdout=b'\x89PNG\r\n\x1a\nprivate pixels')
   if argv[0]==f.cli and 'operations' in argv and 'status' in argv:
    seen+=1
    if seen==2 and drift in ('xml','png','binding'):
     directory=max(f.root.glob('android-grant-prompt-*'),key=lambda x:x.stat().st_mtime_ns)
     path=directory/{'xml':'ui.xml','png':'ui.png','binding':'binding.json'}[drift]
     path.write_bytes(path.read_bytes()+b' ')
    return f.done({'controllerId':OWNER,'configurationRevision':2,'operationId':OP,'final':mode=='terminal','ok':mode!='terminal','code':'INVALID_ARGUMENT' if mode=='terminal' else 'ACCEPTED'},1 if mode=='terminal' else 0)
   if drift=='owner' and argv[0]==f.cli and argv[7:]==['status']:return f.done({'controllerId':OP,'configurationRevision':2})
   return original(argv,**kw)
  with mock.patch.object(f,'run',side_effect=run):return f.execute('prompt-diagnostic')
 def test_fresh_prompt_diagnosis_no_effects_and_terminal_is_finite(self):
  for mode in ('pending','terminal'):
   with self.subTest(mode=mode):
    f=self.fixture();self.setup_attempt(f);before=f.on;leases=(f.root/'android-native-device-api35.lease').read_bytes()
    result=self.diagnostic_run(f,mode)
    self.assertEqual(result['state'],'diagnosed');self.assertEqual(result['observationClass'],'fresh-current-prompt')
    self.assertFalse(result['checks']['positiveOwned']);self.assertEqual(result['checks']['operationFinal'],mode=='terminal')
    self.assertNotIn('foreign suffix',json.dumps(result));self.assertEqual(f.on,before);self.assertEqual(f.taps,0)
    self.assertEqual((f.root/'android-native-device-api35.lease').read_bytes(),leases)
    self.assertFalse((f.job/'tap-intent.json').exists())
    dirs=list(f.root.glob('android-grant-prompt-*'));self.assertEqual(len(dirs),2)
    self.assertEqual(sum((d/'ui.png').exists() for d in dirs),1)
 def test_diagnose_rejects_changed_owner_or_tap_intent(self):
  f=self.fixture();self.setup_attempt(f)
  self.assertEqual(self.diagnostic_run(f,drift='owner')['reason'],'owner_or_revision_changed')
  f.write(f.job/'tap-intent.json',{})
  self.assertEqual(self.diagnostic_run(f)['reason'],'prompt_attempt_not_admitted')
  self.assertEqual(f.taps,0)

 def test_diagnose_final_forbidden_and_same_inode_evidence_drift(self):
  for drift in ('tap','xml','png','binding'):
   with self.subTest(drift=drift):
    f=self.fixture();self.setup_attempt(f)
    result=self.diagnostic_run(f,drift=drift)
    self.assertEqual(result['state'],'unknown')
    self.assertEqual(result['reason'],'prompt_observation_changed' if drift=='tap' else 'prompt_evidence_invalid')
    self.assertEqual(f.taps,0)
    self.assertTrue((f.root/'android-native-device-api35.lease').exists())

class PromptChunkCollectorTest(unittest.TestCase):
 fixture=PromptEvidenceTest.fixture
 setup_attempt=PromptEvidenceTest.setup_attempt
 diagnostic_run=PromptEvidenceTest.diagnostic_run
 def prepare(self):
  f=self.fixture();self.setup_attempt(f)
  result=self.diagnostic_run(f);obs=result['observationId'];directory=f.root/('android-grant-prompt-'+C+'-'+obs)
  png=b'\x89PNG\r\n\x1a\n'+b'x'*(65839-8);(directory/'ui.png').write_bytes(png)
  metadata=json.loads((directory/'binding.json').read_text());metadata['png']={'sha256':hashlib.sha256(png).hexdigest(),'bytes':len(png)};f.write(directory/'binding.json',metadata)
  parent=s._journal(f.root,C).parent;parent.mkdir(parents=True,mode=0o700)
  f.write(s._journal(f.root,C),f.intent)
  return f,obs,directory
 def collect(self,f,obs,drift=None):
  calls=[]
  def probe(argv,timeout):
   request=json.loads(argv[-1]);calls.append(request)
   out=io.StringIO()
   with mock.patch.object(sys,'argv',['fetch',*argv[-5:]]),mock.patch('sys.stdout',out):exec(s._PROMPT_FETCH,{'__name__':'__main__'})
   value=json.loads(out.getvalue())
   if request['mode']=='metadata' and len(calls)==1 and drift in ('original-write','original-replace'):
    path=f.job/'worker.py';raw=path.read_bytes()
    if drift=='original-replace':path.unlink()
    path.write_bytes(raw);path.chmod(0o600)
   if request['mode']=='chunk':
    if drift=='chunk':value['offset']+=1
    if drift=='hash':value['sha256']='f'*64
    if drift=='remote':
     directory=f.root/('android-grant-prompt-'+C+'-'+obs);p=directory/'ui.png';p.write_bytes(p.read_bytes()+b'x')
    if drift=='partial':return 1,''
   encoded=json.dumps(value);self.assertLessEqual(len(encoded),16384)
   return 0,encoded
  with mock.patch.object(s,'_route',return_value=({},{})),mock.patch.object(s.ssh_transport,'build_ssh_argv',side_effect=lambda *a,**kw:list(kw['command'])),mock.patch.object(s.android_observation,'_run_probe',side_effect=probe):result=s.prompt_collect(f.root,C,obs)
  return result,calls
 def test_real_png_size_exceeds_single_reply_but_chunk_collects(self):
  f,obs,d=self.prepare()
  self.assertGreater(len(__import__('base64').b64encode((d/'ui.png').read_bytes())),16384)
  result,calls=self.collect(f,obs);self.assertEqual(result['state'],'complete')
  self.assertEqual(Path(result['localPaths']['ui.png']).read_bytes(),(d/'ui.png').read_bytes())
  self.assertGreater(len([x for x in calls if x.get('name')=='ui.png']),1)
  self.assertFalse(result['claimsReleased']);self.assertEqual(f.taps,0)
  second,_=self.collect(f,obs);self.assertEqual(second['state'],'unknown')
 def test_malformed_hash_drift_partial_unknown_never_overwrite(self):
  for drift in ('chunk','hash','remote','partial'):
   with self.subTest(drift=drift):
    f,obs,d=self.prepare();result,_=self.collect(f,obs,drift)
    self.assertEqual(result['state'],'unknown');self.assertFalse(result['claimsReleased'])
    local=s._journal(f.root,C).parent/('prompt-'+C+'-'+obs)
    before={p.name:p.read_bytes() for p in local.iterdir()};self.assertTrue(before)
    again,_=self.collect(f,obs);self.assertEqual(again['state'],'unknown')
    self.assertEqual(before,{p.name:p.read_bytes() for p in local.iterdir()})

 def test_actual_bounded_observer_rejects_whole_65839_byte_png(self):
  import base64
  png=b'\x89PNG\r\n\x1a\n'+b'x'*(65839-8)
  encoded=base64.b64encode(png).decode()
  with self.assertRaisesRegex(RuntimeError,'oversized_output'):
   s.android_observation._run_probe([sys.executable,'-I','-c','print('+repr(encoded)+')'],5)
 def test_invalid_uuid_or_unrecognized_paths_never_dispatch(self):
  with mock.patch.object(s.android_observation,'_run_probe') as probe:
   for original,obs in (('../foreign',C),(C,'../foreign'),(None,C),(C,None)):
    self.assertEqual(s.prompt_collect('/tmp',original,obs)['state'],'unknown')
   probe.assert_not_called()

 def test_original_same_bytes_record_generation_drift_is_unknown(self):
  for drift in ('original-write','original-replace'):
   with self.subTest(drift=drift):
    f,obs,d=self.prepare();result,_=self.collect(f,obs,drift)
    self.assertEqual(result['state'],'unknown');self.assertFalse(result['claimsReleased'])


# Exact API35 system XML retained from the failed owned grant prompt.
API35_OWNED_PROMPT_XML='<?xml version=\'1.0\' encoding=\'UTF-8\' standalone=\'yes\' ?><hierarchy rotation="0"><node index="0" text="" resource-id="" class="android.widget.FrameLayout" package="com.android.vpndialogs" content-desc="" checkable="false" checked="false" clickable="false" enabled="true" focusable="false" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[0,136][320,456]"><node index="0" text="" resource-id="" class="android.widget.FrameLayout" package="com.android.vpndialogs" content-desc="" checkable="false" checked="false" clickable="false" enabled="true" focusable="false" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[16,152][304,440]"><node index="0" text="" resource-id="android:id/content" class="android.widget.FrameLayout" package="com.android.vpndialogs" content-desc="" checkable="false" checked="false" clickable="false" enabled="true" focusable="false" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[16,152][304,440]"><node index="0" text="" resource-id="android:id/parentPanel" class="android.widget.LinearLayout" package="com.android.vpndialogs" content-desc="" checkable="false" checked="false" clickable="false" enabled="true" focusable="false" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[16,152][304,440]"><node index="0" text="" resource-id="android:id/topPanel" class="android.widget.LinearLayout" package="com.android.vpndialogs" content-desc="" checkable="false" checked="false" clickable="false" enabled="true" focusable="false" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[16,152][304,198]"><node index="0" text="" resource-id="android:id/title_template" class="android.widget.LinearLayout" package="com.android.vpndialogs" content-desc="" checkable="false" checked="false" clickable="false" enabled="true" focusable="false" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[16,152][304,198]"><node index="0" text="Connection request" resource-id="android:id/alertTitle" class="android.widget.TextView" package="com.android.vpndialogs" content-desc="" checkable="false" checked="false" clickable="false" enabled="true" focusable="false" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[40,170][280,198]" /></node></node><node index="1" text="" resource-id="android:id/customPanel" class="android.widget.FrameLayout" package="com.android.vpndialogs" content-desc="" checkable="false" checked="false" clickable="false" enabled="true" focusable="false" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[16,198][304,384]"><node index="0" text="" resource-id="android:id/custom" class="android.widget.FrameLayout" package="com.android.vpndialogs" content-desc="" checkable="false" checked="false" clickable="false" enabled="true" focusable="false" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[16,198][304,384]"><node index="0" text="" resource-id="" class="android.widget.ScrollView" package="com.android.vpndialogs" content-desc="" checkable="false" checked="false" clickable="false" enabled="true" focusable="true" focused="false" scrollable="true" long-clickable="false" password="false" selected="false" bounds="[16,198][304,384]"><node index="0" text="VPN Control wants to set up a VPN connection that allows it to monitor network traffic. Only accept if you trust the source. &#10;&#10;￼ appears at the top of your screen when VPN is active." resource-id="com.android.vpndialogs:id/warning" class="android.widget.TextView" package="com.android.vpndialogs" content-desc="" checkable="false" checked="false" clickable="false" enabled="true" focusable="false" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[16,198][304,384]" /></node></node></node><node index="2" text="" resource-id="android:id/buttonPanel" class="android.widget.ScrollView" package="com.android.vpndialogs" content-desc="" checkable="false" checked="false" clickable="false" enabled="true" focusable="true" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[16,384][304,440]"><node index="0" text="" resource-id="" class="android.widget.LinearLayout" package="com.android.vpndialogs" content-desc="" checkable="false" checked="false" clickable="false" enabled="true" focusable="false" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[16,384][304,440]"><node index="0" text="Cancel" resource-id="android:id/button2" class="android.widget.Button" package="com.android.vpndialogs" content-desc="" checkable="false" checked="false" clickable="true" enabled="true" focusable="true" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[162,388][228,436]" /><node index="1" text="OK" resource-id="android:id/button1" class="android.widget.Button" package="com.android.vpndialogs" content-desc="" checkable="false" checked="false" clickable="true" enabled="true" focusable="true" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[228,388][292,436]" /></node></node></node></node></node></node></hierarchy>'

class ActualApi35PromptTest(unittest.TestCase):
 def test_retained_api35_prompt_exact_warning_variant(self):
  self.assertIsNotNone(s._positive_button(API35_OWNED_PROMPT_XML))
 def test_api35_variant_suffix_or_ownership_drift_rejected(self):
  self.assertIsNone(s._positive_button(API35_OWNED_PROMPT_XML.replace('VPN is active.','VPN is active. Foreign approval.')))
  self.assertIsNone(s._positive_button(API35_OWNED_PROMPT_XML.replace('com.android.vpndialogs','foreign.package')))
  self.assertIsNone(s._positive_button(API35_OWNED_PROMPT_XML.replace('text="OK"','text="Delete"')))
  self.assertEqual(s._positive_button(dialog()),(60,50))
 def test_retained_actual_xml_does_not_authorize_obsolete_terminal_operation(self):
  f=Fixture();self.addCleanup(f.close);f.xml=API35_OWNED_PROMPT_XML;original=f.run
  def run(argv,**kw):
   if argv[0]==f.cli and argv[7:]==['operations','list'] and f.accepted:
    return f.done({'ok':True,'final':True,'code':'OK','controllerId':OWNER,'configurationRevision':2,'data':{'operations':[{'controllerId':OWNER,'id':OP,'operation':'on','phase':'failed','final':True,'code':'INTERACTION_REQUIRED'}]+list(f.diagnostic_ledger)}})
   return original(argv,**kw)
  with mock.patch.object(f,'run',side_effect=run):result=f.execute()
  self.assertEqual(result['reason'],'pending_operation_changed');self.assertEqual(f.taps,0)
  self.assertFalse((f.job/'tap-intent.json').exists());self.assertEqual(f.on,1)

class LiveConsentWindowTest(unittest.TestCase):
 def test_no_full_routing_export_between_on_and_tap(self):
  f=Fixture();self.addCleanup(f.close);original=f.run;between=[]
  def run(argv,**kw):
   if argv[0]==f.cli and 'routing' in argv and f.accepted and not f.tapped:between.append(argv)
   return original(argv,**kw)
  with mock.patch.object(f,'run',side_effect=run):result=f.execute()
  self.assertEqual(result['state'],'complete');self.assertEqual(between,[])
  self.assertGreater(f.reads,0)
 def test_deadline_expiry_after_on_never_taps(self):
  f=Fixture();self.addCleanup(f.close);original=f.run;clock=[100.0]
  def run(argv,**kw):
   result=original(argv,**kw)
   if argv[0]==f.cli and '--async' in argv:clock[0]+=121
   return result
  with mock.patch.object(f,'run',side_effect=run),mock.patch('time.monotonic',side_effect=lambda:clock[0]):result=f.execute()
  self.assertEqual(result['state'],'unknown');self.assertEqual(result['reason'],'prompt_deadline_expired')
  self.assertEqual(f.taps,0);self.assertTrue((f.job/'operation.json').exists())

 def test_full_rules_are_checked_after_disposition_even_without_revision_signal(self):
  f=Fixture();self.addCleanup(f.close);original=f.run
  def run(argv,**kw):
   if argv[0]==f.cli and 'routing' in argv and f.tapped:f.rules['direct_domain_suffixes']=['silent-corruption.example']
   return original(argv,**kw)
  with mock.patch.object(f,'run',side_effect=run):result=f.execute()
  self.assertEqual(result['state'],'unknown');self.assertEqual(result['reason'],'routing_changed')
  self.assertEqual(f.taps,1);self.assertFalse((f.job/'terminal.json').exists())
 def test_pinned_admitted_rules_changed_after_on_never_taps(self):
  f=Fixture();self.addCleanup(f.close);original=f.run
  def run(argv,**kw):
   result=original(argv,**kw)
   if argv[0]==f.cli and '--async' in argv:f.write(f.backup,{'type':'vpn_control_routing_rules','version':7,'rules':{**RULES,'direct_domain_suffixes':['foreign.example']}})
   return result
  with mock.patch.object(f,'run',side_effect=run):result=f.execute()
  self.assertEqual(result['state'],'unknown');self.assertEqual(result['reason'],'admitted_backup_changed');self.assertEqual(f.taps,0)

class PromptNoEffectClosureTest(unittest.TestCase):
 fixture=PromptEvidenceTest.fixture
 setup_attempt=PromptEvidenceTest.setup_attempt
 diagnostic_run=PromptEvidenceTest.diagnostic_run
 def prepare(self):
  f=self.fixture();self.setup_attempt(f);observed=self.diagnostic_run(f,mode='terminal');obs=observed['observationId']
  directory=f.root/('android-grant-prompt-'+C+'-'+obs);context=json.loads((directory/'operation-observation.json').read_text())
  for key in ('statusBefore','statusAfter'):context[key]['code']='INTERACTION_REQUIRED'
  terminal={'controllerId':OWNER,'id':OP,'requestId':C,'operation':'on','phase':'failed','final':True,'cancellable':False,'completedUnits':None,'totalUnits':None,'code':'INTERACTION_REQUIRED','configurationRevision':2,'restartRequired':False}
  context['listBefore']=context['listAfter']=[terminal]
  f.write(directory/'operation-observation.json',context)
  payload={'schema':1,'kind':'prompt-no-effect','correlationId':C,'closureId':OP,'observationId':obs,'intentSha256':hashlib.sha256(f.expected.encode()).hexdigest()}
  return f,payload
 def execute(self,f,payload,mode='prompt-close',drift=None):
  original=f.run
  def run(argv,**kw):
   if argv[0]=='python3' and argv[4]=='exec('+repr(s._PROMPT_FETCH)+')':
    out=io.StringIO()
    with mock.patch.object(sys,'argv',['fetch',*argv[-5:]]),mock.patch('sys.stdout',out):exec(s._PROMPT_FETCH,{'__name__':'__main__'})
    return SimpleNamespace(returncode=0,stdout=out.getvalue().encode())
   if argv[0]==f.cli and argv[7:]==['operations','list']:
    entry={'controllerId':OWNER,'id':__import__('agent_tools.tests.test_android_consent_grant_acceptance',fromlist=['OP']).OP,'requestId':C,'operation':'on','phase':'failed','final':True,'cancellable':False,'completedUnits':None,'totalUnits':None,'code':'INTERACTION_REQUIRED','configurationRevision':2,'restartRequired':False}
    if drift=='pending':entry['final']=False;entry['phase']='awaiting-user'
    if drift=='code':entry['code']='INVALID_ARGUMENT'
    entries=[] if drift=='absent' else [entry]
    return f.done({'ok':True,'final':True,'code':'OK','controllerId':OWNER,'configurationRevision':2,'data':{'operations':entries+list(f.diagnostic_ledger)}})
   if argv[0]==f.cli and 'operations' in argv and 'status' in argv:return f.done({'ok':False,'final':True,'code':'INTERACTION_REQUIRED','controllerId':OWNER,'configurationRevision':2,'operationId':__import__('agent_tools.tests.test_android_consent_grant_acceptance',fromlist=['OP']).OP},1)
   if drift=='permission':f.permission_override='true'
   if drift=='source':f.drift='empty-subscription'
   return original(argv,**kw)
  output=io.StringIO();argv=['remote',mode,f.adb,f.cli,'emulator-5556',str(f.root),C,f.expected,json.dumps(payload,sort_keys=True,separators=(',',':'))]
  with mock.patch.object(sys,'argv',argv),mock.patch.object(subprocess,'run',side_effect=run),mock.patch('sys.stdout',output):
   try:exec(s._PROMPT_CLOSE_SOURCE,{'__name__':'__main__'})
   except SystemExit:pass
  return json.loads(output.getvalue())
 def test_actual_remote_closes_without_ui_or_original_replay(self):
  for disposition in (None,'absent'):
   with self.subTest(disposition=disposition):
    f,payload=self.prepare();before={p.name:p.read_bytes() for p in f.job.iterdir()}
    result=self.execute(f,payload,drift=disposition);self.assertEqual(result['state'],'closed');self.assertFalse(result['proof']['grantObserved'])
    self.assertFalse((f.root/'android-native-device-api35.lease').exists());self.assertEqual(f.on,1);self.assertEqual(f.taps,0)
    for name,raw in before.items():self.assertEqual((f.job/name).read_bytes(),raw)
    self.assertEqual(self.execute(f,payload,mode='prompt-close-status',drift=disposition)['state'],'observed')
    self.assertEqual(self.execute(f,payload)['reason'],'prompt_closure_consumed')
 def test_rejects_pending_foreign_terminal_permission_source_and_tap(self):
  for drift in ('pending','code','permission','source','tap'):
   with self.subTest(drift=drift):
    f,payload=self.prepare()
    if drift=='tap':f.write(f.job/'tap-intent.json',{})
    result=self.execute(f,payload,drift=drift);self.assertEqual(result['state'],'unknown')
    self.assertTrue((f.root/'android-native-device-api35.lease').exists());self.assertEqual(f.taps,0)
 def test_host_once_start_status_collect_preserves_original_unknown(self):
  f,payload=self.prepare();s._save(f.root,f.intent);original=s._journal(f.root,C).read_bytes()
  with s.android_endpoint_admission._shared_device_lease(f.root,'archlinux','api35') as lease:f.write(lease,s._claim(C))
  with s.android_document_acceptance._device_guard(f.root,'archlinux','api35') as doc:f.write(doc,{'host':'archlinux','device':'api35','correlationId':C})
  modes=[]
  def observe(root,intent,value,mode):modes.append(mode);return self.execute(f,value,mode)
  with mock.patch.object(s,'_prompt_close_observe',side_effect=observe):
   first=s.prompt_close_no_effect(f.root,C,OP,payload['observationId']);self.assertEqual(first['state'],'closed');self.assertFalse(first['claimsReleased'])
   again=s.prompt_close_no_effect(f.root,C,OP,payload['observationId']);self.assertEqual(again['state'],'observed');self.assertEqual(modes.count('prompt-close'),1)
   collected=s.prompt_close_no_effect_collect(f.root,C,OP);self.assertTrue(collected['claimsReleased']);self.assertTrue(collected['ok']);self.assertFalse(lease.exists());self.assertFalse(doc.exists())
   twice=s.prompt_close_no_effect_collect(f.root,C,OP);self.assertTrue(twice['claimsReleased'])
  self.assertEqual(s._journal(f.root,C).read_bytes(),original);self.assertEqual(f.on,1);self.assertEqual(f.taps,0)
 def test_host_unknown_consumed_no_dispatch_and_local_claim_drift(self):
  f,payload=self.prepare();s._save(f.root,f.intent)
  with s.android_endpoint_admission._shared_device_lease(f.root,'archlinux','api35') as lease:f.write(lease,s._claim(C))
  with s.android_document_acceptance._device_guard(f.root,'archlinux','api35') as doc:f.write(doc,{'host':'archlinux','device':'api35','correlationId':C})
  calls=[]
  def observe(root,intent,value,mode):calls.append(mode);return self.execute(f,value,mode,drift='permission')
  with mock.patch.object(s,'_prompt_close_observe',side_effect=observe):
   self.assertEqual(s.prompt_close_no_effect(f.root,C,OP,payload['observationId'])['state'],'unknown')
   self.assertEqual(s.prompt_close_no_effect(f.root,C,OP,payload['observationId'])['state'],'unknown')
  self.assertEqual(calls,['prompt-close','prompt-close-status']);self.assertTrue(lease.exists());self.assertTrue(doc.exists())

 def test_host_collect_same_inode_owned_claim_rewrite_retains_claims(self):
  f,payload=self.prepare();s._save(f.root,f.intent)
  with s.android_endpoint_admission._shared_device_lease(f.root,'archlinux','api35') as lease:f.write(lease,s._claim(C))
  with s.android_document_acceptance._device_guard(f.root,'archlinux','api35') as doc:f.write(doc,{'host':'archlinux','device':'api35','correlationId':C})
  def observe(root,intent,value,mode):return self.execute(f,value,mode)
  with mock.patch.object(s,'_prompt_close_observe',side_effect=observe):self.assertEqual(s.prompt_close_no_effect(f.root,C,OP,payload['observationId'])['state'],'closed')
  def changed(root,intent,value,mode):
   result=self.execute(f,value,mode);lease.write_bytes(lease.read_bytes());return result
  with mock.patch.object(s,'_prompt_close_observe',side_effect=changed):result=s.prompt_close_no_effect_collect(f.root,C,OP)
  self.assertEqual(result['state'],'unknown');self.assertTrue(lease.exists());self.assertTrue(doc.exists());self.assertFalse(result['claimsReleased'])
 def test_host_collect_post_marker_historical_generation_drift_retains_claims(self):
  for changed in ('original','child','marker'):
   with self.subTest(changed=changed):
    f,payload=self.prepare();s._save(f.root,f.intent)
    with s.android_endpoint_admission._shared_device_lease(f.root,'archlinux','api35') as lease:f.write(lease,s._claim(C))
    with s.android_document_acceptance._device_guard(f.root,'archlinux','api35') as doc:f.write(doc,{'host':'archlinux','device':'api35','correlationId':C})
    def observe(root,intent,value,mode):return self.execute(f,value,mode)
    with mock.patch.object(s,'_prompt_close_observe',side_effect=observe):self.assertEqual(s.prompt_close_no_effect(f.root,C,OP,payload['observationId'])['state'],'closed')
    write=s._write_closed_marker
    def mutate(path,value):
     created=write(path,value)
     if path.name.endswith('.closed.json'):
      target=s._journal(f.root,C) if changed=='original' else s._prompt_close_intent(f.root,C,OP) if changed=='child' else path
      target.write_bytes(target.read_bytes())
     return created
    with mock.patch.object(s,'_prompt_close_observe',side_effect=observe),mock.patch.object(s,'_write_closed_marker',side_effect=mutate):result=s.prompt_close_no_effect_collect(f.root,C,OP)
    self.assertEqual(result['state'],'unknown');self.assertFalse(result['claimsReleased']);self.assertTrue(lease.exists());self.assertTrue(doc.exists())

 def test_closure_budget_covers_all_serial_full_and_extra_reads(self):
  self.assertEqual(s._PROMPT_CLOSE_SECONDS,2*s._FULL_SNAPSHOT_SECONDS+4*120+4*135+120)
  self.assertGreater(s._PROMPT_CLOSE_SECONDS,s._COLLECT_OBSERVER_SECONDS)

class PreexistingDialogAdmissionTest(unittest.TestCase):
 fixture=HostAdmissionTest.fixture
 admissions=HostAdmissionTest.admissions
 start=HostAdmissionTest.start
 def test_present_owned_dialog_blocks_before_local_intent_or_submit(self):
  f=self.fixture();submitted=[]
  def probe(*args):submitted.append(args);return 0,json.dumps({'state':'submitted','correlationId':C,'identity':{'pid':42,'startTicks':99}}).encode()
  self.admissions(f,probe)
  with mock.patch.object(s,'_ui_preflight',create=True,return_value={'state':'blocked','reason':'preexisting_consent_prompt'}):got=self.start(f)
  self.assertEqual(got['state'],'blocked');self.assertEqual(got['reason'],'preexisting_consent_prompt')
  self.assertFalse(s._journal(f.root,C).exists());self.assertEqual(submitted,[])
  self.assertEqual(f.on,0);self.assertEqual(f.taps,0)

class PreexistingDialogRemoteTest(unittest.TestCase):
 def fixture(self):
  f=Fixture();self.addCleanup(f.close)
  lock=f.root/'android-native-device-api35.lock';lock.write_text('');lock.chmod(0o600)
  return f
 def execute(self,f,run=None):
  output=io.StringIO()
  with mock.patch.object(sys,'argv',['worker','ui-preflight',f.adb,f.cli,'emulator-5556',str(f.root),C,f.expected]),mock.patch.object(subprocess,'run',side_effect=run or f.run),mock.patch('sys.stdout',output):
   try:exec(s._UI_PREFLIGHT,{'__name__':'__main__'})
   except SystemExit:pass
  return json.loads(output.getvalue())
 def test_exact_old_owned_api35_prompt_blocks_without_grant_records_or_actions(self):
  f=self.fixture();f.preexisting=True;f.xml=API35_OWNED_PROMPT_XML
  historical={p.name:p.read_bytes() for p in f.job.iterdir()}
  got=self.execute(f)
  self.assertEqual((got['state'],got['reason']),('blocked','preexisting_consent_prompt'))
  self.assertTrue(got['vpnDialogPresent']);self.assertNotEqual(got['observationId'],C)
  dirs=list(f.root.glob('android-grant-preflight-ui-*'));self.assertEqual(len(dirs),1)
  self.assertEqual((dirs[0]/'ui.xml').read_text(),API35_OWNED_PROMPT_XML)
  self.assertEqual(got['xmlSha256'],hashlib.sha256(API35_OWNED_PROMPT_XML.encode()).hexdigest())
  self.assertEqual({p.name:p.read_bytes() for p in f.job.iterdir()},historical)
  self.assertEqual((f.on,f.taps),(0,0));self.assertFalse(any('on' in argv or 'input' in argv or 'set' in argv for argv in f.calls))
 def test_absent_dialog_ready_and_worker_second_check_never_adopts_old_prompt(self):
  f=self.fixture();got=self.execute(f)
  self.assertEqual(got['state'],'ready');self.assertFalse(got['vpnDialogPresent']);self.assertEqual((f.on,f.taps),(0,0))
  f.preexisting=True;f.xml=API35_OWNED_PROMPT_XML
  got=f.execute()
  self.assertEqual(got['reason'],'preexisting_consent_prompt');self.assertEqual((f.on,f.taps),(0,0))
  self.assertFalse((f.job/'on-intent.json').exists());self.assertFalse((f.job/'tap-intent.json').exists())
 def test_owner_history_configuration_package_stage_and_claim_generation_drift_deny(self):
  for drift in ('owner','revision','history','settings','source','locations','runtime','package','stage','claim','lock','xml'):
   with self.subTest(drift=drift):
    f=self.fixture();original=f.run;captured=[False]
    def run(argv,**kw):
     if argv[0]==f.adb and argv[5:6]==['cat']:captured[0]=True
     result=original(argv,**kw)
     if captured[0]:
      if drift=='owner' and argv[0]==f.cli:
       value=json.loads(result.stdout);value['controllerId']=C;return f.done(value)
      if drift=='revision' and argv[0]==f.cli:
       value=json.loads(result.stdout);value['configurationRevision']=3;return f.done(value)
      if drift in ('history','settings','source','locations','runtime') and argv[0]==f.cli:
       value=json.loads(result.stdout)
       words=argv[7:]
       expected={'history':['operations','list'],'settings':['settings','show'],'source':['source','show'],'locations':['locations','list'],'runtime':['status']}[drift]
       if words==expected:
        if drift=='history':value['data']['operations']=[{'controllerId':OWNER,'id':OP,'final':True,'phase':'failed'}]
        else:value['data']['foreign']='changed'
        return f.done(value)
      if drift=='package' and argv[0]==f.adb and argv[5:6]==['sha256sum']:return f.done('e'*64+'  /data/app/owned/base.apk')
      if drift=='stage' and argv[0]=='python3':
       value=json.loads(result.stdout);value['receipt']['desktopJarSha256']='e'*64;return f.done(value)
      if drift=='claim':f.write(f.root/'android-native-device-api35.lease',{'foreign':True})
      if drift=='lock':(f.root/'android-native-device-api35.lock').write_bytes(b'changed')
      if drift=='xml':
       paths=list(f.root.glob('android-grant-preflight-ui-*/ui.xml'))
       if paths:paths[0].write_bytes(paths[0].read_bytes())
     return result
    got=self.execute(f,run);self.assertEqual(got['state'],'unknown');self.assertEqual((f.on,f.taps),(0,0))
 def test_malformed_empty_or_foreign_vpn_dialog_fail_closed(self):
  for xml,state in (('<invalid','unknown'),('<hierarchy/>','unknown'),(dialog('Foreign VPN warning'),'blocked')):
   f=self.fixture();f.preexisting=True;f.xml=xml
   got=self.execute(f);self.assertEqual(got['state'],state);self.assertEqual((f.on,f.taps),(0,0))
 def test_preflight_budget_and_host_schema_are_bounded(self):
  self.assertEqual(s._UI_PREFLIGHT_SECONDS,2*(7*45+120)+10*135+3*45+120)
  f=self.fixture();config=SimpleNamespace()
  for value in ({'state':'ready','correlationId':C,'reason':None}, {'state':'unknown','correlationId':C,'reason':'raw private data'}, {'state':'unknown','correlationId':C,'reason':[]}, {'state':'unknown','correlationId':C,'reason':{'private':'text'}}, {'state':'ready','correlationId':C,'reason':None,'observationId':OP,'xmlSha256':'a'*64,'xmlBytes':True,'vpnDialogPresent':False}):
   with mock.patch.object(s,'_route',return_value=(config,{'adb':f.adb,'serial':'emulator-5556'})),mock.patch.object(s.ssh_transport,'build_ssh_argv',return_value=['fixed']),mock.patch.object(s.android_observation,'_run_probe',return_value=(0,json.dumps(value).encode())):
    self.assertEqual(s._ui_preflight(f.root,f.intent),{'state':'unknown','reason':'ui_observation_invalid'})

class GrantWorkerBudgetTest(unittest.TestCase):
 def run_wrapper(self,worker_factory):
  f=Fixture();self.addCleanup(f.close);(f.job/'release').write_text('released')
  source=worker_factory(s._REMOTE,['run',f.adb,f.cli,'emulator-5556',str(f.root),C,f.expected])
  measured={'outer':None,'serial':0,'live':0};original=f.run
  def outer(argv,**kw):
   measured['outer']=kw['timeout'];output=io.StringIO()
   def inner(command,**options):
    live='--async' in command or (f.accepted and not f.tapped)
    if live:measured['live']+=options['timeout']
    else:measured['serial']+=options['timeout']
    if measured['serial']>measured['outer']:raise subprocess.TimeoutExpired(argv,measured['outer'])
    return original(command,**options)
   with mock.patch.object(subprocess,'run',side_effect=inner),mock.patch.object(sys,'argv',['remote',*argv[5:]]),mock.patch('sys.stdout',output):
    try:exec(s._REMOTE,{'__name__':'__main__'})
    except SystemExit:pass
   if measured['serial']+110>measured['outer']:raise subprocess.TimeoutExpired(argv,measured['outer'])
   return SimpleNamespace(returncode=0,stdout=output.getvalue().encode())
  with mock.patch.object(subprocess,'run',side_effect=outer),mock.patch.object(sys,'argv',['worker',str(f.job)]):exec(source,{'__name__':'__main__'})
  return json.loads((f.job/'result.json').read_text()),measured,f
 def test_actual_emitted_worker_budget_covers_complete_serial_graph(self):
  value,measured,f=self.run_wrapper(s._grant_worker)
  self.assertEqual(value['state'],'complete');self.assertEqual(value['result']['operationCode'],'INVALID_ARGUMENT')
  self.assertEqual(measured['outer'],s._GRANT_WORKER_SECONDS)
  self.assertEqual(measured['serial']+110,4*s._FULL_SNAPSHOT_SECONDS+(s._UI_PREFLIGHT_SECONDS-120)+110+315)
  self.assertLessEqual(measured['serial']+110+120,s._GRANT_WORKER_SECONDS)
  self.assertEqual((f.on,f.taps),(1,1))
 def test_inherited_1800_expires_before_on_without_replaying(self):
  value,measured,f=self.run_wrapper(s.android_document_acceptance._worker)
  self.assertEqual(value['state'],'unknown');self.assertEqual(value['reason'],'worker_unknown')
  self.assertEqual(measured['outer'],1800);self.assertGreater(measured['serial'],1800)
  self.assertEqual((f.on,f.taps),(0,0))
 def test_ast_replacement_unique_and_consent_window_unchanged(self):
  import ast
  self.assertEqual(s._GRANT_WORKER_SECONDS,4*s._FULL_SNAPSHOT_SECONDS+s._UI_PREFLIGHT_SECONDS+110+315+120)
  source=s._grant_worker(s._REMOTE,['run','fixed'])
  calls=[n for n in ast.walk(ast.parse(source)) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=='subprocess' and n.func.attr=='run']
  self.assertEqual(len(calls),1);timeouts=[k.value.value for k in calls[0].keywords if k.arg=='timeout'];self.assertEqual(timeouts,[13580])
  self.assertIn('interaction_deadline=time.monotonic()+110',s._REMOTE)
  with mock.patch.object(s.android_document_acceptance,'_worker',return_value=source):
   with self.assertRaises(ValueError):s._grant_worker(s._REMOTE,[])
  with mock.patch.object(s.android_document_acceptance,'_worker',return_value='import subprocess\nsubprocess.run([],timeout=1800)\nsubprocess.run([],timeout=1800)\n'):
   with self.assertRaises(ValueError):s._grant_worker(s._REMOTE,[])

class PositiveCollectGenerationTest(unittest.TestCase):
 def fixture(self,existing=False):
  f=Fixture();self.addCleanup(f.close);s._save(f.root,f.intent)
  with s.android_endpoint_admission._shared_device_lease(f.root,'archlinux','api35') as lease:f.write(lease,s._claim(C))
  with s.android_document_acceptance._device_guard(f.root,'archlinux','api35') as doc:f.write(doc,{'host':'archlinux','device':'api35','correlationId':C})
  result={'operationCode':'INVALID_ARGUMENT','runtimeStarted':False};marker=s._journal(f.root,C).with_suffix('.closed.json')
  digest=lambda value:hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
  if existing:s._write_closed_marker(marker,{'schema':1,'intentSha256':digest(f.intent),'terminalSha256':digest(result),'claims':{'shared':s._fingerprint(lease.stat()),'document':s._fingerprint(doc.stat())}})
  stage={'ok':True,'state':'published','sourceSha':'a'*40,'receipt':{'cliPath':f.cli,'manifestSha256':'a'*64,'rpmSha256':'b'*64,'launcherSha256':'c'*64,'desktopJarSha256':'d'*64}}
  return f,lease,doc,marker,result,stage
 def observe(self,result):return lambda root,intent,mode:{'state':'complete','result':result} if mode=='status' else {'state':'complete','freshProof':True}
 def test_same_byte_existing_marker_rewrite_after_read_retains_both_claims(self):
  f,lease,doc,marker,result,stage=self.fixture(True);read=s._closed_marker
  def changed(path):
   value=read(path)
   if path==marker:path.write_bytes(path.read_bytes())
   return value
  with mock.patch.object(s,'_observe',side_effect=self.observe(result)),mock.patch.object(s.android_cli_stage,'status',return_value=stage),mock.patch.object(s,'_closed_marker',side_effect=changed):got=s.collect(f.root,C)
  self.assertEqual(got['state'],'unknown');self.assertTrue(lease.exists());self.assertTrue(doc.exists())
 def test_existing_marker_generation_held_across_native_status_and_fresh_proof(self):
  for during in ('status','collect'):
   f,lease,doc,marker,result,stage=self.fixture(True)
   def observer(root,intent,mode):
    if mode==during:marker.write_bytes(marker.read_bytes())
    return self.observe(result)(root,intent,mode)
   with mock.patch.object(s,'_observe',side_effect=observer),mock.patch.object(s.android_cli_stage,'status',return_value=stage):got=s.collect(f.root,C)
   self.assertEqual(got['state'],'unknown');self.assertTrue(lease.exists());self.assertTrue(doc.exists())
 def test_new_marker_and_original_generation_changes_fail_before_unlink(self):
  for changed in ('marker-write','marker-chmod','marker-replace','intent-write','intent-chmod','status-intent','fresh-intent'):
   with self.subTest(changed=changed):
    f,lease,doc,marker,result,stage=self.fixture();write=s._write_closed_marker;original=s._journal(f.root,C)
    def mutate(path):
     if changed.endswith('chmod'):path.chmod(0o644);path.chmod(0o600)
     elif changed.endswith('replace'):
      other=path.with_suffix('.replacement');other.write_bytes(path.read_bytes());other.chmod(0o600);os.replace(other,path)
     else:path.write_bytes(path.read_bytes())
    def writer(path,value):
     fp=write(path,value)
     if changed.startswith('marker'):mutate(path)
     elif changed.startswith('intent'):mutate(original)
     return fp
    def observer(root,intent,mode):
     if (changed=='status-intent' and mode=='status') or (changed=='fresh-intent' and mode=='collect'):mutate(original)
     return self.observe(result)(root,intent,mode)
    with mock.patch.object(s,'_observe',side_effect=observer),mock.patch.object(s.android_cli_stage,'status',return_value=stage),mock.patch.object(s,'_write_closed_marker',side_effect=writer):got=s.collect(f.root,C)
    self.assertEqual(got['state'],'unknown');self.assertTrue(lease.exists());self.assertTrue(doc.exists())
 def test_marker_generation_checked_before_second_unlink_and_final(self):
  for after in ('document','shared'):
   with self.subTest(after=after):
    f,lease,doc,marker,result,stage=self.fixture();unlink=Path.unlink
    def mutation(path,*args,**kwargs):
     result=unlink(path,*args,**kwargs)
     if path.resolve()==({'document':doc,'shared':lease}[after]).resolve():marker.write_bytes(marker.read_bytes())
     return result
    with mock.patch.object(s,'_observe',side_effect=self.observe(result)),mock.patch.object(s.android_cli_stage,'status',return_value=stage),mock.patch.object(Path,'unlink',mutation):got=s.collect(f.root,C)
    self.assertEqual(got['state'],'unknown')
    if after=='document':self.assertTrue(lease.exists())
 def test_normal_and_idempotent_collection_preserve_original_and_marker_bytes(self):
  f,lease,doc,marker,result,stage=self.fixture();original=s._journal(f.root,C).read_bytes()
  with mock.patch.object(s,'_observe',side_effect=self.observe(result)),mock.patch.object(s.android_cli_stage,'status',return_value=stage):
   self.assertEqual(s.collect(f.root,C)['state'],'complete');marker_raw=marker.read_bytes();marker_fp=s._fingerprint(marker.stat())
   self.assertEqual(s.collect(f.root,C)['state'],'complete')
  self.assertFalse(lease.exists());self.assertFalse(doc.exists());self.assertEqual(s._journal(f.root,C).read_bytes(),original);self.assertEqual(marker.read_bytes(),marker_raw);self.assertEqual(s._fingerprint(marker.stat()),marker_fp)


class TerminalTypedProofTest(unittest.TestCase):
 def test_actual_worker_numeric_flags_never_complete_or_release_original_claim(self):
  for mode in ('status','collect'):
   for field,bad in (('permissionGranted',1),('permissionGranted',1.0),('runtimeStarted',0),('runtimeStarted',0.0),('noLocation',1),('revision',2.0)):
    with self.subTest(mode=mode,field=field,bad=bad):
     f=Fixture()
     try:
      self.assertEqual(f.execute()['state'],'complete')
      terminal=json.loads((f.job/'terminal.json').read_bytes())
      receipt=json.loads((f.job/'result.json').read_bytes())
      terminal[field]=bad;receipt['result'][field]=bad
      f.write(f.job/'terminal.json',terminal);f.write(f.job/'result.json',receipt)
      retained=(f.job/'result.json').read_bytes()
      got=f.execute(mode)
      self.assertEqual(got['state'],'unknown')
      self.assertEqual(got['reason'],'terminal_binding_invalid')
      self.assertTrue((f.root/'android-native-device-api35.lease').exists())
      self.assertFalse((f.job/'collected.json').exists())
      self.assertEqual((f.job/'result.json').read_bytes(),retained)
      self.assertEqual((f.on,f.taps),(1,1))
     finally:f.close()
 def test_actual_worker_exact_terminal_status_and_fresh_collect_still_close_once(self):
  f=Fixture()
  try:
   self.assertEqual(f.execute()['state'],'complete')
   original=(f.job/'result.json').read_bytes()
   self.assertEqual(f.execute('status')['state'],'complete')
   self.assertEqual(f.execute('collect')['freshProof'],True)
   self.assertEqual(f.execute('collect')['freshProof'],True)
   self.assertFalse((f.root/'android-native-device-api35.lease').exists())
   self.assertEqual((f.job/'result.json').read_bytes(),original)
   self.assertEqual((f.on,f.taps),(1,1))
  finally:f.close()
