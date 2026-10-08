"""Actual public launcher prefix and shared actor selector; no native launch."""
import ast,copy,hashlib,json,unittest
from pathlib import Path
from unittest import mock
from agent_tools import ssh_keeper_sdk_custody as custody
import agent_tools
F=next(Path(p)/'tests/fixtures/ssh_keeper_causal' for p in agent_tools.__path__ if (Path(p)/'tests/fixtures/ssh_keeper_causal/consumer-before.source').is_file())
PINS={'consumer-before.source': 'b154867da14bea53001c74308a15b25eb918891822d1d03c51c8f3397c544da5', 'consumer-after.source': 'cf3ebbca8a9cb032b59f4a1a5c1e2551ca94790f5a47586dd324adbb09076ca7'}
def prefix(name):
 raw=(F/name).read_bytes()
 if hashlib.sha256(raw).hexdigest()!=PINS[name]:raise ValueError('consumer_fixture_source')
 nodes=[]
 for node in ast.parse(raw).body:
  if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='R' for t in node.targets):break
  if isinstance(node,ast.ImportFrom) and node.module=='agent_tools.ssh_channel_keeper_entry':continue
  nodes.append(node)
 return nodes
def expectations():
 values={}
 for node in prefix('consumer-after.source'):
  if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id in ('SDK','KEEPER'):values[node.targets[0].id]=ast.literal_eval(node.value)
 return values['SDK'],values['KEEPER']
def actual_prefix(name,actors,shared=False):
 nodes=prefix(name)
 if shared:
  # Exact successor assertion becomes the real shared identity selector.
  selected=[n for n in nodes if isinstance(n,ast.Assert)]
  if len(selected)!=1:raise ValueError('consumer_assert_boundary')
  expected=ast.parse('assert actor(22968)==KEEPER and actor(22943)==SDK').body[0]
  if ast.dump(selected[0],include_attributes=False)!=ast.dump(expected,include_attributes=False):raise ValueError('consumer_assert_inverse')
  nodes=[ast.parse('consumer_actors(SDK,KEEPER)').body[0] if n is selected[0] else n for n in nodes]
 ns={'actor':lambda pid:copy.deepcopy(actors[pid]),'consumer_actors':custody.consumer_actors}
 with mock.patch.object(custody.entry,'actor',side_effect=lambda pid:copy.deepcopy(actors[pid])):exec(compile(ast.Module(body=nodes,type_ignores=[]),'actual-consumer-prefix-before-source-Popen','exec'),ns)
class ConsumerTests(unittest.TestCase):
 def test_actual_old_prefix_refuses_separate_birth_and_shared_successor_accepts(self):
  sdk,keeper=expectations();actors={sdk['pid']:sdk,keeper['pid']:keeper}
  self.assertNotEqual(sdk['birthSha256'],keeper['birthSha256']);self.assertNotEqual(sdk['sessionId'],keeper['sessionId'])
  with self.assertRaises(AssertionError):actual_prefix('consumer-before.source',actors)
  actual_prefix('consumer-after.source',actors);actual_prefix('consumer-after.source',actors,shared=True)
 def test_actual_shared_consumer_refuses_each_replaced_original(self):
  sdk,keeper=expectations()
  for original in (sdk,keeper):
   with self.subTest(pid=original['pid']):
    actors=copy.deepcopy({sdk['pid']:sdk,keeper['pid']:keeper});actors[original['pid']]['birthSha256']='f'*64
    with self.assertRaisesRegex(ValueError,'consumer_original_actor'):actual_prefix('consumer-after.source',actors,shared=True)
 def test_actor_schema_and_typed_identity_refuse_without_authority(self):
  sdk,keeper=expectations()
  for field,value in (('pid',True),('uid',503.0),('sessionId',None),('birthSha256','f'*63)):
   bad=copy.deepcopy(keeper);bad[field]=value
   with self.subTest(field=field),mock.patch.object(custody.entry,'actor',side_effect=AssertionError('no process observation before schema')):
    with self.assertRaisesRegex(ValueError,'consumer_actor_schema'):custody.consumer_actors(sdk,bad)
  for bad in ({},None,{**keeper,'extra':False}):
   with self.assertRaisesRegex(ValueError,'consumer_actor_schema'):custody.consumer_actors(sdk,bad)
  with mock.patch.object(custody.entry,'actor',side_effect=lambda pid:{**(sdk if pid==sdk['pid'] else keeper),'uid':503.0}):
   with self.assertRaisesRegex(ValueError,'consumer_original_actor'):custody.consumer_actors(sdk,keeper)
 def test_repeated_before_after_consumer_guard_catches_replacement(self):
  sdk,keeper=expectations();actors={sdk['pid']:sdk,keeper['pid']:keeper}
  with mock.patch.object(custody.entry,'actor',side_effect=lambda pid:copy.deepcopy(actors[pid])) as read:
   custody.consumer_actors(sdk,keeper);self.assertEqual(read.call_count,2)
   actors[keeper['pid']]={**keeper,'birthSha256':'f'*64}
   with self.assertRaisesRegex(ValueError,'consumer_original_actor'):custody.consumer_actors(sdk,keeper)
