"""Portable pure-source owner epoch controls; role fixtures remain data only.

Only the exact reviewed fixed helper or preserved RED helper is executed in
an isolated namespace. No owner, bundle, command or derived owner source runs.
"""
import ast,hashlib,unittest
from pathlib import Path

FIXTURES=Path(__file__).resolve().parent/'fixtures'/'android_current_owner_epoch'
FIXTURE_LIMITS={'owner':32768,'bundle':262144,'command':32768,'current-owner-factory':8192}
REVIEWED_FACTORY_SHAS={
 '4d7bac00c489d548210d7e5e124dff04430f6ba9b80ebca568291bbaec07d30a',
 '8ed8e128df1da814507b1efcce9fb31594dbec57493ab65fa03e22d27642d4a2',
}

def fixture_bytes(name):
 limit=FIXTURE_LIMITS[name]
 with (FIXTURES/(name+'.source')).open('rb') as handle:raw=handle.read(limit+1)
 if len(raw)>limit:raise ValueError('current_owner_epoch_fixture_limit')
 return raw

SOURCE=fixture_bytes('current-owner-factory')
if hashlib.sha256(SOURCE).hexdigest() not in REVIEWED_FACTORY_SHAS:
 raise ValueError('current_owner_epoch_unreviewed_helper')
NS={'__name__':'causal_current_owner_factory'}
exec(compile(SOURCE,'<actual-current-owner-factory>','exec',dont_inherit=True),NS)
RAW=[fixture_bytes(name) for name in ('owner','bundle','command')]

class BindingControls(unittest.TestCase):
 def test_actual_current_bundle_accepts_with_exact_inverse(self):
  try:r=NS['derive'](*RAW)
  except ValueError:self.fail('genuine current public bundle refused by preserved source pin')
  self.assertTrue(r['inverseVerified']);self.assertTrue(r['nativeTemplateUnchanged'])
  self.assertEqual(r['currentDependencySha256'],hashlib.sha256(RAW[1]).hexdigest())
  before=ast.parse(RAW[0]);after=ast.parse(r['source'])
  rows=[n for n in after.body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='BUNDLE_SHA']
  self.assertEqual(len(rows),1);self.assertEqual(ast.literal_eval(rows[0].value),hashlib.sha256(RAW[1]).hexdigest())
  rows[0].value=ast.Constant(NS['OLD_BUNDLE'])
  self.assertEqual(ast.dump(after,include_attributes=False),ast.dump(before,include_attributes=False))
 def reject_role(self,index):
  args=list(RAW);args[index]+=b'\n'
  with self.assertRaisesRegex(ValueError,'^current_owner_factory_source_changed$'):NS['derive'](*args)
 def test_changed_owner_refuses(self):self.reject_role(0)
 def test_changed_bundle_refuses(self):self.reject_role(1)
 def test_changed_command_refuses(self):self.reject_role(2)
if __name__=='__main__':unittest.main(verbosity=2)
