"""Exact complete preparer bytes, real private temp filesystem; no child/network."""
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import hashlib,json,os,stat,tempfile,unittest
HERE=Path(__file__).resolve().parent
class PreparationDirectoryTests(unittest.TestCase):
 def prepare(self,source):
  temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
  repo=Path(temporary.name).resolve()/'repo';repo.mkdir(mode=0o700)
  capsule=repo/'.runtime/tool-recovery/campaign/epoch';capsule.mkdir(parents=True,mode=0o700)
  helper=b'# fixed harmless helper\n';digest=hashlib.sha256(helper).hexdigest()
  controller=('CRITICAL={}\nNEW_OPERATIONS='+repr({'direct':'public-direct','nested':'public-nested'})+'\nRETENTION_SHA='+repr(digest)+'\n').encode()
  (capsule/'controller.py').write_bytes(controller);(capsule/'ordinary_retention.py').write_bytes(helper)
  metadata={p:hashlib.sha256(b'{}\n').hexdigest()for p in('agent_tools/affected_agent_test_dependencies.json','agent_tools/readiness_vm_dispatch.json','agent_tools/tool_action_policy.json','.github/required-workflows.json')}
  for name in metadata:
   path=repo/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'{}\n')
  for name in('scripts/public.py','gradle.properties','agent_docs/tools/lifecycle-and-api.md','agent_tools/README.md'):
   path=repo/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'# fixed public fixture\n')
  (capsule/'source-checkpoint.json').write_text(json.dumps({'stage':'root-reviewed-source-and-metadata-closed','controllerSha256':hashlib.sha256(controller).hexdigest(),'retentionSha256':digest,'criticalSourcePins':{},'metadataPins':metadata}))
  mask=os.umask(0o022)
  try:
   with redirect_stdout(StringIO()):exec(compile(source,str(capsule/'prepare_sources.py'),'exec'),{'__file__':str(capsule/'prepare_sources.py'),'__name__':'_controlled_complete_preparer'})
  finally:os.umask(mask)
  return capsule
 def test_complete_c141_red_fixed_explicit_private_roots_green(self):
  before=(HERE/'prepare_sources.c141.before.source').read_bytes()
  self.assertEqual('c14194f118c7f7ecffbcc4e79f6d77a8edfedb03188e0736389152de65d654b9',hashlib.sha256(before).hexdigest())
  for source,mode in((before,0o755),((HERE/'prepare_sources.py').read_bytes(),0o700)):
   capsule=self.prepare(source)
   for name in('direct','nested'):
    self.assertEqual(mode,stat.S_IMODE(os.lstat(capsule/name).st_mode))
    self.assertFalse((capsule/name/'.rag_index').exists())
 def test_fixed_preparer_existing_campaign_not_adopted(self):
  # A second exact execution fails before modifying any previous source capsule.
  source=(HERE/'prepare_sources.py').read_bytes();capsule=self.prepare(source)
  before={str(p.relative_to(capsule)):p.read_bytes()for p in capsule.rglob('*')if p.is_file()and not p.is_symlink()}
  with redirect_stdout(StringIO()),self.assertRaises(FileExistsError):
   exec(compile(source,str(capsule/'prepare_sources.py'),'exec'),{'__file__':str(capsule/'prepare_sources.py'),'__name__':'_controlled_complete_preparer'})
  after={str(p.relative_to(capsule)):p.read_bytes()for p in capsule.rglob('*')if p.is_file()and not p.is_symlink()}
  self.assertEqual(before,after)
if __name__=='__main__':unittest.main()
