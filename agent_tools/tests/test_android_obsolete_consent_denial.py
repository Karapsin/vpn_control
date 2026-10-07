"""Executed obsolete-dialog negative-only regressions; no native actions."""
import io,json,os,stat,subprocess,sys,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from agent_tools import android_obsolete_consent_denial as s
from agent_tools.tests import test_android_consent_grant_acceptance as support

DENIAL='3e50f72f-659d-4710-b8d2-393b21bf0e16'
class ObsoleteDenialTest(unittest.TestCase):
 def prepare(self):
  helper=support.PromptNoEffectClosureTest();f,closing=helper.prepare();self.addCleanup(helper.doCleanups)
  g=s.grant;g._save(f.root,f.intent)
  with g.android_endpoint_admission._shared_device_lease(f.root,'archlinux','api35') as lease:f.write(lease,g._claim(support.C))
  with g.android_document_acceptance._device_guard(f.root,'archlinux','api35') as doc:f.write(doc,{'host':'archlinux','device':'api35','correlationId':support.C})
  with mock.patch.object(g,'_prompt_close_observe',side_effect=lambda root,intent,payload,mode:helper.execute(f,payload,mode)):
   self.assertEqual(g.prompt_close_no_effect(f.root,support.C,support.OP,closing['observationId'])['state'],'closed')
   self.assertTrue(g.prompt_close_no_effect_collect(f.root,support.C,support.OP)['claimsReleased'])
  f.xml=support.API35_OWNED_PROMPT_XML
  original,payload,historical=s._admission(f.root,support.C,support.OP,DENIAL,closing['observationId'])
  return f,payload
 def remote(self,f,payload,mode='obsolete-deny',drift=None):
  original=f.run;denied=getattr(f,'denied',False);cancelled=0;seen=[]
  def run(argv,**kw):
   nonlocal denied,cancelled
   seen.append(argv)
   if argv[0]=='python3' and argv[4]=='exec('+repr(s.grant._PROMPT_FETCH)+')':
    output=io.StringIO()
    with mock.patch.object(sys,'argv',['fetch',*argv[-5:]]),mock.patch('sys.stdout',output):exec(s.grant._PROMPT_FETCH,{'__name__':'__main__'})
    return SimpleNamespace(returncode=0,stdout=output.getvalue().encode())
   if argv[0]==f.adb and 'exec-out' in argv:
    if drift=='ui-artifact':
     directory=max(f.root.glob('android-grant-prompt-*'),key=lambda p:p.stat().st_mtime_ns);path=directory/'ui.xml';path.write_bytes(path.read_bytes()+b' ')
    if drift=='old-worker':path=f.job/'worker.py';path.write_bytes(path.read_bytes())
    return SimpleNamespace(returncode=0,stdout=b'\x89PNG\r\n\x1a\nprivate')
   if argv[0]==f.adb:
    words=argv[5:]
    if words and words[0]=='cat':
     tap=f.job/('obsolete-denial-'+DENIAL+'-tap.json')
     if drift=='tap-record' and tap.exists():tap.write_bytes(tap.read_bytes())
     xml=f.xml if not denied or drift=='dialog-retained' else '<hierarchy><node package="com.kardinal.vpncontrol" text="Home"/></hierarchy>'
     if drift=='warning':xml=xml.replace('VPN is active.','VPN is active. Foreign approval.')
     if drift=='foreign':xml=xml.replace('com.android.vpndialogs','foreign.package')
     if drift=='positive-only':xml=xml.replace('android:id/button2','android:id/button9')
     return f.done(xml)
    if words[:2]==['input','tap']:
     self.assertEqual(tuple(map(int,words[2:])),s._cancel_button(f.xml));cancelled+=1;denied=True;f.denied=True
     tap=json.loads((f.job/('obsolete-denial-'+DENIAL+'-tap.json')).read_text())
     self.assertEqual(tap['action'],'Cancel');self.assertEqual(tap['button'],'android:id/button2')
     if drift=='tap-loss':raise subprocess.TimeoutExpired(argv,45)
     return f.done('')
   if argv[0]==f.cli and argv[7:]==['operations','list']:
    context=json.loads((f.root/('android-grant-prompt-'+support.C+'-'+payload['observationId'])/'operation-observation.json').read_text())
    entries=context['listAfter']+list(f.diagnostic_ledger)
    if drift=='active':entries=entries+[{'controllerId':support.OWNER,'id':DENIAL,'operation':'on','phase':'awaiting-user','final':False}]
    return f.done({'ok':True,'final':True,'code':'OK','controllerId':support.OWNER,'configurationRevision':2,'data':{'operations':entries}})
   if drift=='owner' and argv[0]==f.cli and argv[7:]==['status']:return f.done({'ok':True,'final':True,'code':'OK','controllerId':DENIAL,'configurationRevision':2,'data':{}})
   if drift=='permission':f.permission_override='true'
   if drift=='source':f.drift='empty-subscription'
   if drift=='package':f.drift='package'
   if drift=='stage':f.drift='stage'
   if drift=='rules':f.rules['direct_domain_suffixes']=['foreign.example']
   return original(argv,**kw)
  output=io.StringIO();argv=['remote',mode,f.adb,f.cli,'emulator-5556',str(f.root),support.C,f.expected,json.dumps(payload,sort_keys=True,separators=(',',':'))]
  with mock.patch.object(sys,'argv',argv),mock.patch.object(subprocess,'run',side_effect=run),mock.patch('sys.stdout',output):
   try:exec(s._SOURCE,{'__name__':'__main__'})
   except SystemExit:pass
  value=json.loads(output.getvalue());self.assertEqual(f.on,1);self.assertEqual(f.taps,0)
  self.assertFalse(any('cancel' in a or '--async' in a for a in seen))
  return value,cancelled
 def test_exact_api35_cancel_and_foreign_variants(self):
  xml=support.API35_OWNED_PROMPT_XML;self.assertIsNotNone(s._cancel_button(xml))
  for changed in (xml.replace('VPN is active.','VPN is active. Foreign.'),xml.replace('com.android.vpndialogs','foreign.package'),xml.replace('text="Cancel"','text="OK"'),xml.replace('android:id/button2','android:id/button9')):self.assertIsNone(s._cancel_button(changed))
 def test_remote_full_success_status_and_once_only(self):
  f,p=self.prepare();before={path.name:path.read_bytes() for path in f.job.iterdir()}
  result,taps=self.remote(f,p);self.assertEqual(result['state'],'complete');self.assertEqual(taps,1)
  self.assertTrue(result['proof']['uiAbsent']);self.assertFalse(result['proof']['permissionGranted'])
  self.assertFalse((f.root/'android-native-device-api35.lease').exists())
  for name,raw in before.items():self.assertEqual((f.job/name).read_bytes(),raw)
  status,taps=self.remote(f,p,'obsolete-deny-status');self.assertEqual(status['state'],'complete');self.assertEqual(taps,0)
  repeated,taps=self.remote(f,p);self.assertEqual(repeated['reason'],'denial_consumed');self.assertEqual(taps,0)
 def test_pre_effect_guards_unknown_preserve_claims_and_no_tap(self):
  for drift in ('warning','foreign','positive-only','owner','permission','source','package','stage','rules','active','ui-artifact','old-worker','tap-record'):
   with self.subTest(drift=drift):
    f,p=self.prepare();result,taps=self.remote(f,p,drift=drift)
    self.assertEqual(result['state'],'unknown');self.assertEqual(taps,0);self.assertTrue((f.root/'android-native-device-api35.lease').exists())
 def test_tap_loss_or_still_visible_never_replay(self):
  for drift in ('tap-loss','dialog-retained'):
   with self.subTest(drift=drift):
    f,p=self.prepare();result,taps=self.remote(f,p,drift=drift);self.assertEqual(result['state'],'unknown');self.assertEqual(taps,1)
    self.assertTrue((f.root/'android-native-device-api35.lease').exists())
    status,taps=self.remote(f,p,'obsolete-deny-status');self.assertEqual(status['state'],'unknown');self.assertEqual(taps,0)
 def test_host_actual_adapter_collect_idempotent_preserves_original(self):
  f,p=self.prepare();before=s.grant._journal(f.root,support.C).read_bytes();modes=[]
  def observe(root,original,payload,mode):modes.append(mode);return self.remote(f,payload,mode)[0]
  with mock.patch.object(s,'_observe',side_effect=observe):
   first=s.start(f.root,support.C,support.OP,DENIAL,p['observationId']);self.assertEqual(first['state'],'complete');self.assertFalse(first['claimsReleased'])
   again=s.start(f.root,support.C,support.OP,DENIAL,p['observationId']);self.assertEqual(again['state'],'complete');self.assertEqual(modes.count('obsolete-deny'),1)
   collected=s.collect(f.root,DENIAL);self.assertTrue(collected['claimsReleased']);self.assertTrue(collected['ok'])
   self.assertTrue(s.collect(f.root,DENIAL)['claimsReleased'])
  self.assertEqual(s.grant._journal(f.root,support.C).read_bytes(),before)
 def test_unknown_consumed_and_unclosed_admission_no_native_dispatch(self):
  f,p=self.prepare();calls=[]
  def observe(root,original,payload,mode):calls.append(mode);return self.remote(f,payload,mode,drift='warning')[0]
  with mock.patch.object(s,'_observe',side_effect=observe):
   self.assertEqual(s.start(f.root,support.C,support.OP,DENIAL,p['observationId'])['state'],'unknown')
   self.assertEqual(s.start(f.root,support.C,support.OP,DENIAL,p['observationId'])['state'],'unknown')
  self.assertEqual(calls,['obsolete-deny','obsolete-deny-status'])
  with mock.patch.object(s,'_observe') as observe:
   self.assertEqual(s.start(f.root,support.C,DENIAL,support.OWNER,p['observationId'])['state'],'unknown');observe.assert_not_called()

 def test_collector_post_marker_same_inode_intent_change_retains_claims(self):
  f,p=self.prepare()
  def observe(root,original,payload,mode):return self.remote(f,payload,mode)[0]
  with mock.patch.object(s,'_observe',side_effect=observe):self.assertEqual(s.start(f.root,support.C,support.OP,DENIAL,p['observationId'])['state'],'complete')
  original=s.grant._write_closed_marker
  def mutate(path,value):
   created=original(path,value)
   if path==s._journal(f.root,DENIAL).with_suffix('.closed.json'):
    intent=s._journal(f.root,DENIAL);intent.write_bytes(intent.read_bytes())
   return created
  with mock.patch.object(s,'_observe',side_effect=observe),mock.patch.object(s.grant,'_write_closed_marker',side_effect=mutate):result=s.collect(f.root,DENIAL)
  self.assertEqual(result['state'],'unknown');self.assertFalse(result['claimsReleased'])
  with s.grant.android_endpoint_admission._shared_device_lease(f.root,'archlinux','api35') as lease:self.assertTrue(lease.exists())
  with s.grant.android_document_acceptance._device_guard(f.root,'archlinux','api35') as doc:self.assertTrue(doc.exists())
 def test_changed_closed_marker_or_original_generation_blocks_before_tap(self):
  for changed in ('schema','opening','baseline'):
   with self.subTest(changed=changed):
    f,p=self.prepare()
    if changed=='schema':
     path=f.job/('prompt-close-'+support.OP+'-closed.json');value=json.loads(path.read_text());value['schema']=True;f.write(path,value)
    else:
     path=f.job/('opening.json' if changed=='opening' else 'baseline-source-settings.json');path.write_bytes(path.read_bytes())
    result,taps=self.remote(f,p);self.assertEqual(result['state'],'unknown');self.assertEqual(taps,0)
 def test_source_contains_only_the_recovery_entry_before_original_worker_modes(self):
  compile(s._SOURCE,'obsolete-denial-remote','exec')
  self.assertEqual(s._DENIAL_SECONDS,2*s.grant._FULL_SNAPSHOT_SECONDS+2*(7*45+120+4*135)+3*180+135+5*120+4*135+120)
  with mock.patch.object(s,'_observe') as observer:
   for invalid in ('../path','',None):self.assertEqual(s.start('/tmp',invalid,support.OP,DENIAL,support.C)['state'],'unknown')
   observer.assert_not_called()
