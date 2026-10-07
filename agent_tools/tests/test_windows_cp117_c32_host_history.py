from __future__ import annotations
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from agent_tools.tests.test_windows_cp117_c32_host_archive import INTENT, DESCRIPTOR
from agent_tools import windows_cp117_c32_host_archive as host_archive

from agent_tools import windows_cp117_c32_archive_admission as archive

CORR='c32cb108-4d48-407e-9153-40774559ba50'

class HostCensusTests(unittest.TestCase):
 def test_absence_after_archive_requires_fresh_exact_history_proof(self):
  for state in ('archived','unknown','not-started'):
   with self.subTest(state=state),tempfile.TemporaryDirectory() as d:
    root=Path(d);(root/'.rag_index/windows-cp117-c32-host-archive').mkdir(parents=True)
    with mock.patch.object(archive.base,'_private_intent',return_value=INTENT),mock.patch.object(archive.base,'_remote',return_value=b'{"state":"absent"}'),mock.patch.object(host_archive,'status',return_value={**archive._UNKNOWN,'state':state}) as status:
     value=archive.host_status(root,object(),type('Target',(),{'fixture_transfer_root':Path('/fixed')})(),DESCRIPTOR)
    self.assertEqual('absent' if state=='archived' else 'unknown',value['state'])
    status.assert_called_once_with(root,{})

 def _tree(self, root: Path, *, binding=None):
  parent=root/'windows-cp117';group=parent/'windows-msi-base';leaf=group/CORR
  for p in (root,parent,group,leaf):
   p.mkdir(exist_ok=True);p.chmod(0o700)
  expected={'socketPath':'/q','pid':2,'startTicks':3,'sourceSha':'a'*40,'sourceFingerprint':'b'*64,'receiptArtifactId':'sha256-'+'c'*64,'baseArtifactId':'sha256-'+'d'*64,'targetArtifactId':'sha256-'+'e'*64,'commandSha256':'f'*64,'expectedSid':'S-1-5-21-1-2-3-4'}
  (leaf/'binding.json').write_text(json.dumps(expected if binding is None else binding));(leaf/'binding.json').chmod(0o600)
  (leaf/'dispatch.json').write_text('{"pid":9}');(leaf/'dispatch.json').chmod(0o600)
  return expected,leaf
 def _run(self, root, expected):
  result=subprocess.run((sys.executable,'-c',archive._HOST_CENSUS,str(root),'windows-cp117',CORR,json.dumps(expected,separators=(',',':'),sort_keys=True)),capture_output=True,text=True,check=True)
  return json.loads(result.stdout)
 def test_secure_exact_tree_is_retained(self):
  with tempfile.TemporaryDirectory() as d:
   expected,_=self._tree(Path(d));self.assertEqual({'state':'retained'},self._run(Path(d),expected))
 def test_wrong_binding_symlink_foreign_entry_and_group_write_are_unknown(self):
  for kind in ('binding','symlink','foreign','group-mode'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory() as d:
    root=Path(d);expected,leaf=self._tree(root)
    if kind=='binding':(leaf/'binding.json').write_text('{}')
    elif kind=='symlink':(leaf/'binding.json').unlink();(leaf/'binding.json').symlink_to(leaf/'dispatch.json')
    elif kind=='foreign':(leaf/'extra').write_text('x')
    else:(root/'windows-cp117'/'windows-msi-base').chmod(0o770)
    self.assertEqual('unknown',self._run(root,expected)['state'])
 def test_readonly_legacy_metadata_0644_inside_private_parents_is_retained(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);expected,leaf=self._tree(root);(leaf/'binding.json').chmod(0o644)
   value=self._run(root,expected)
   self.assertEqual('retained',value['state'])

if __name__=='__main__':unittest.main()
