import subprocess,tempfile,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools import android_fixture_tls_routes as r
from agent_tools import android_native_fixture
SOURCE='d'*40;BASE='sha256-'+'3'*64;TARGET='sha256-'+'2'*64
PLAN={'sourceSha':SOURCE,'baseArtifactId':BASE,'baseVersion':'2.2.2','baseCode':16840,'baseSignerSha256':'a'*64,'targetArtifactId':TARGET,'targetVersion':'2.2.3','targetCode':16860,'targetSha256':'2'*64,'targetSize':2,'endpoint':android_native_fixture.endpoint_contract(),'deviceMutationAllowed':False}
class T(unittest.TestCase):
 def repository(self,root):
  def git(*args):
   return subprocess.run(['git',*args],cwd=root,check=True,capture_output=True,text=True,timeout=10).stdout.strip()
  git('init','-q');git('config','user.name','Fixture');git('config','user.email','fixture@example.invalid')
  (root/'gradle.properties').write_text('vpnControlVersion=2.2.2\n')
  git('add','gradle.properties');git('-c','commit.gpgsign=false','commit','-qm','fixture')
  return git('rev-parse','HEAD')
 def call(self,root,extra=None):
  x={'campaignId':str(uuid.uuid4()),'sourceSha':SOURCE,'baseArtifactId':BASE,'targetArtifactId':TARGET};x.update(extra or {})
  with mock.patch.object(r.fixture,'prepare_requirements',return_value={k:v for k,v in PLAN.items() if k not in {'targetArtifactId','targetSha256','targetSize'}}),mock.patch.object(r.fixture,'verify_target',return_value=PLAN):return r.run(root,x)

 def test_dirty_source_rejects_before_mint_or_leaf(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);source=self.repository(root);c=str(uuid.uuid4())
   (root/'gradle.properties').write_text('vpnControlVersion=2.2.3\n')
   with mock.patch.object(r.mint,'mint') as mint:
    with self.assertRaisesRegex(ValueError,'source SHA differs'):r.run(root,{'campaignId':c,'sourceSha':source,'baseArtifactId':BASE,'targetArtifactId':TARGET})
   mint.assert_not_called();self.assertFalse((root/'.runtime/parity-evidence'/('android-fixture-tls-route-'+c)).exists())
 def test_bogus_artifact_rejects_before_mint_or_leaf(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);source=self.repository(root);c=str(uuid.uuid4())
   with mock.patch.object(r.mint,'mint') as mint:
    with self.assertRaisesRegex(ValueError,'Artifact ID is not registered'):r.run(root,{'campaignId':c,'sourceSha':source,'baseArtifactId':'sha256-'+'0'*64,'targetArtifactId':TARGET})
   mint.assert_not_called();self.assertFalse((root/'.runtime/parity-evidence'/('android-fixture-tls-route-'+c)).exists())
 def test_actual_mint_and_nonsecret_route_receipt(self):
  with tempfile.TemporaryDirectory() as d:
   out=self.call(d);self.assertTrue(out['ok']);self.assertFalse(out['deviceMutationPerformed']);self.assertNotIn('PRIVATE KEY',str(out['receipt']));self.assertIsInstance(out['receipt']['nestedBinding'],dict);self.assertEqual({'ca-key.pem','ca.pem','leaf-key.pem','leaf.pem','receipt.json'},set(out['receipt']['nestedBinding']['materialPins']))





 def test_actual_run_postmint_nested_directory_substitution_is_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   c=str(uuid.uuid4());inputs={'campaignId':c,'sourceSha':SOURCE,'baseArtifactId':BASE,'targetArtifactId':TARGET};requirements={k:v for k,v in PLAN.items() if k not in {'targetArtifactId','targetSha256','targetSize'}};original=r.mint.mint
   def replace(*args,**kwargs):
    out=original(*args,**kwargs);p=Path(out['directory']);p.rename(p.parent/'moved');p.mkdir(mode=0o700);return out
   with mock.patch.object(r.fixture,'prepare_requirements',return_value=requirements),mock.patch.object(r.fixture,'verify_target',return_value=PLAN),mock.patch.object(r.mint,'mint',side_effect=replace):
    with self.assertRaises(r.RouteError):r.run(d,inputs)
 def test_actual_run_postmint_receipt_substitution_is_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   c=str(uuid.uuid4());inputs={'campaignId':c,'sourceSha':SOURCE,'baseArtifactId':BASE,'targetArtifactId':TARGET};requirements={k:v for k,v in PLAN.items() if k not in {'targetArtifactId','targetSha256','targetSize'}};original=r.mint.mint
   def replace(*args,**kwargs):
    out=original(*args,**kwargs);p=Path(out['directory'])/'receipt.json';p.unlink();p.write_bytes(b'foreign');p.chmod(0o600);return out
   with mock.patch.object(r.fixture,'prepare_requirements',return_value=requirements),mock.patch.object(r.fixture,'verify_target',return_value=PLAN),mock.patch.object(r.mint,'mint',side_effect=replace):
    with self.assertRaises(r.RouteError):r.run(d,inputs)
 def test_actual_run_postmint_leaf_substitution_is_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   c=str(uuid.uuid4());inputs={'campaignId':c,'sourceSha':SOURCE,'baseArtifactId':BASE,'targetArtifactId':TARGET};requirements={k:v for k,v in PLAN.items() if k not in {'targetArtifactId','targetSha256','targetSize'}};original=r.mint.mint
   def replace(*args,**kwargs):
    out=original(*args,**kwargs);leaf=Path(out['directory'])/'leaf.pem';leaf.unlink();leaf.write_bytes(b'foreign');leaf.chmod(0o600);return out
   with mock.patch.object(r.fixture,'prepare_requirements',return_value=requirements),mock.patch.object(r.fixture,'verify_target',return_value=PLAN),mock.patch.object(r.mint,'mint',side_effect=replace):
    with self.assertRaises(r.RouteError):r.run(d,inputs)
   self.assertFalse((Path(d)/'.runtime/parity-evidence'/('android-fixture-tls-route-'+c)/'route-receipt.json').exists())
 def test_actual_run_child_replacement_after_archives_is_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   c=str(uuid.uuid4());inputs={'campaignId':c,'sourceSha':SOURCE,'baseArtifactId':BASE,'targetArtifactId':TARGET};requirements={k:v for k,v in PLAN.items() if k not in {'targetArtifactId','targetSha256','targetSize'}}
   def replace(parent,*args,**kwargs):
    child=Path(parent);moved=child.parent/'old';child.rename(moved);child.mkdir(mode=0o700);return {'receipt':{'receipt':{}}}
   with mock.patch.object(r.fixture,'prepare_requirements',return_value=requirements),mock.patch.object(r.fixture,'verify_target',return_value=PLAN),mock.patch.object(r.mint,'mint',side_effect=replace):
    with self.assertRaises(r.RouteError):r.run(d,inputs)
   route=Path(d)/'.runtime/parity-evidence'/('android-fixture-tls-route-'+c);self.assertTrue(route.exists());self.assertFalse((route/'route-receipt.json').exists())
 def test_actual_source_entry_replacement_after_fd_open_is_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   parent=Path(d)/'p';parent.mkdir();path=parent/'source.py';path.write_bytes(b'old');foreign=parent/'foreign';foreign.write_bytes(b'new')
   real=r.os.read;changed=[False]
   def read(fd,n):
    out=real(fd,n)
    if not changed[0]:
     changed[0]=True;r.os.replace(foreign,path)
    return out
   with mock.patch.object(r.os,'read',side_effect=read):
    with self.assertRaises(r.RouteError):r._snapshot(path)
 def test_actual_source_parent_replacement_is_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   parent=Path(d)/'p';parent.mkdir();path=parent/'source.py';path.write_bytes(b'old');moved=Path(d)/'moved';real=r.os.read;changed=[False]
   def read(fd,n):
    out=real(fd,n)
    if not changed[0]:
     changed[0]=True;r.os.rename(parent,moved);parent.mkdir();(parent/'source.py').write_bytes(b'foreign')
    return out
   with mock.patch.object(r.os,'read',side_effect=read):
    with self.assertRaises((r.RouteError,OSError)):r._snapshot(path)
 def test_unregistered_plan_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   with mock.patch.object(r.fixture,'prepare_requirements',return_value={}),mock.patch.object(r.fixture,'verify_target',return_value={}):
    with self.assertRaises(r.RouteError):r.run(d,{'campaignId':str(uuid.uuid4()),'sourceSha':SOURCE,'baseArtifactId':BASE,'targetArtifactId':TARGET})
 def test_partial_mint_retains_authority_without_public_receipt(self):
  with tempfile.TemporaryDirectory() as d:
   c=str(uuid.uuid4())
   with mock.patch.object(r.fixture,'prepare_requirements',return_value={k:v for k,v in PLAN.items() if k not in {'targetArtifactId','targetSha256','targetSize'}}),mock.patch.object(r.fixture,'verify_target',return_value=PLAN),mock.patch.object(r.mint,'mint',side_effect=ValueError('partial')):
    with self.assertRaises(ValueError):r.run(d,{'campaignId':c,'sourceSha':SOURCE,'baseArtifactId':BASE,'targetArtifactId':TARGET})
   child=Path(d)/'.runtime/parity-evidence'/('android-fixture-tls-route-'+c);self.assertTrue((child/'provenance.json').is_file());self.assertFalse((child/'route-receipt.json').exists())
 def test_source_drift_after_mint_is_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   first={k:v for k,v in PLAN.items() if k not in {'targetArtifactId','targetSha256','targetSize'}}
   with mock.patch.object(r.fixture,'prepare_requirements',side_effect=[first,dict(first,baseCode=1)]),mock.patch.object(r.fixture,'verify_target',return_value=PLAN):
    with self.assertRaises(r.RouteError):r.run(d,{'campaignId':str(uuid.uuid4()),'sourceSha':SOURCE,'baseArtifactId':BASE,'targetArtifactId':TARGET})
if __name__=='__main__':unittest.main()
