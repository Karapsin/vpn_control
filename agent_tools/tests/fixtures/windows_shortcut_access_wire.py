"""Inert fixture-only wire and source-AST prerequisites; no native action."""
import ast,base64,copy,hashlib,json

def inert_server_annotation_context(tree):
 """Restore the server module's typing context only for inert AST executions.

 Sealed historical factories retained the annotated server definitions while
 carrying only Mapping into their emitted namespace. Their original bytes stay
 unchanged; this fixture seam supplies the missing Any import for Python 3.12.
 """
 names={'_canonical','_validate_live_ready'}
 functions=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in names]
 if not functions:return tree
 if len(functions)!=2 or {node.name for node in functions}!=names:
  raise ValueError('inert-server-annotation-context')
 imports=[node for node in tree.body if isinstance(node,ast.ImportFrom) and node.module=='typing' and node.level==0]
 if (len(imports)!=1 or len(imports[0].names)!=1 or
     imports[0].names[0].name!='Mapping' or imports[0].names[0].asname is not None):
  raise ValueError('inert-server-annotation-context')
 imports[0].names.append(ast.copy_location(ast.alias(name='Any'),imports[0]))
 return ast.fix_missing_locations(tree)

def _validate_shortcut_access_native_rows(rows):
 if type(rows)is not list or len(rows)!=4:raise ValueError('access-native-wire-rows')
 for row in rows:
  if type(row)is not dict or set(row)!={'descriptor','sid','checks'}:raise ValueError('access-native-wire-fields')
  if any(type(row[name])is not str for name in ('descriptor','sid','checks')):raise ValueError('access-native-wire-types')
 return rows

def _assert_shortcut_access_native_cases(case,rows):
 rows=_validate_shortcut_access_native_rows(rows)
 for row in rows:case.assertEqual(row['sid'],rows[0]['sid'])
 case.assertEqual(rows[0]['checks'].split(';')[0].split('|')[2],'1');case.assertEqual(rows[1]['checks'].split(';')[0].split('|')[2],'0');case.assertEqual(rows[2]['checks'].split(';')[0].split('|')[2],'0');case.assertEqual(rows[3]['checks'].split(';')[0].split('|')[2],'1')
 maximum=int(rows[2]['checks'].split(';')[-1].split('|')[1]);case.assertEqual(maximum&0x60000,0x60000)

_ACCESS_LEGACY_CONSUMER = "  self.assertEqual(len(rows),4)\n  for row in rows:self.assertEqual(row[1],rows[0][1])\n  self.assertEqual(rows[0][2].split(';')[0].split('|')[2],'1');self.assertEqual(rows[1][2].split(';')[0].split('|')[2],'0');self.assertEqual(rows[2][2].split(';')[0].split('|')[2],'0');self.assertEqual(rows[3][2].split(';')[0].split('|')[2],'1')\n  maximum=int(rows[2][2].split(';')[-1].split('|')[1]);self.assertEqual(maximum&0x60000,0x60000)\n"

_ACCESS_LEGACY_CONSUMER_SHA = '3a328443e3bcd1a50bb1a4f3ec03a3f27ef2f233434890baf2264864583f0646'

def _assert_shortcut_access_legacy_cases(case,rows):
 # Exact Python consumer statements retained from pushedB, no guessed JSON keys.
 if hashlib.sha256(_ACCESS_LEGACY_CONSUMER.encode()).hexdigest()!=_ACCESS_LEGACY_CONSUMER_SHA:raise ValueError('access-legacy-consumer-source')
 ns={};exec(compile('def consume(self,rows):\n'+_ACCESS_LEGACY_CONSUMER,'preserved-native-access-consumer','exec'),ns)
 return ns['consume'](case,rows)

def _report_shortcut_access_wire(label,done):
 def stream(raw,limit):
  return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'base64':base64.b64encode(raw[:limit]).decode(),'truncated':len(raw)>limit}
 print('CP117_ACCESS_NATIVE_WIRE '+json.dumps({'label':label,'returncode':done.returncode,'stdout':stream(done.stdout,32768),'stderr':stream(done.stderr,65536)},sort_keys=True),flush=True)

def _test_shortcut_access_native_wire_schema(self):
  sid='S-1-5-21-1-2-3-1000'
  rows=[{'descriptor':'PUBLIC_SDDL','sid':sid,'checks':'2|2|'+allowed+'|0|0|;33554432|393216|1|0|0|'}for allowed in ('1','0','0','1')]
  _assert_shortcut_access_native_cases(self,rows)
  for candidate in (None,{},tuple(rows),rows[:3],rows+[rows[0]]):
   with self.subTest(rows=type(candidate).__name__),self.assertRaises(ValueError):_validate_shortcut_access_native_rows(candidate)
  for name in ('descriptor','sid','checks'):
   for mode in ('missing','extra','bool','integer','list','null'):
    bad=copy.deepcopy(rows)
    if mode=='missing':bad[0].pop(name)
    elif mode=='extra':bad[0]['unknown']='x'
    else:bad[0][name]={'bool':True,'integer':1,'list':[],'null':None}[mode]
    with self.subTest(field=name,mode=mode),self.assertRaises(ValueError):_validate_shortcut_access_native_rows(bad)
  for kind in ('sid','allow','deny','null','owner-rights'):
   bad=copy.deepcopy(rows)
   if kind=='sid':bad[1]['sid']+='1'
   elif kind=='allow':bad[0]['checks']=bad[0]['checks'].replace('2|2|1','2|2|0',1)
   elif kind=='deny':bad[1]['checks']=bad[1]['checks'].replace('2|2|0','2|2|1',1)
   elif kind=='null':bad[3]['checks']=bad[3]['checks'].replace('2|2|1','2|2|0',1)
   else:bad[2]['checks']=bad[2]['checks'].replace('33554432|393216','33554432|0')
   with self.subTest(consumer=kind),self.assertRaises(AssertionError):_assert_shortcut_access_native_cases(self,bad)

def _qualify_shortcut_access_native_wire(self,script,_run_complete_windows_fixture):
  legacy=script
  self.assertEqual(legacy.count('$r=[Cp117ShortcutAccess]::CheckDescriptor($b,$false,$sid);$rows+=@{descriptor=[string]$r[0];sid=[string]$r[1];checks=[string]$r[2]}'),1);legacy=legacy.replace('$r=[Cp117ShortcutAccess]::CheckDescriptor($b,$false,$sid);$rows+=@{descriptor=[string]$r[0];sid=[string]$r[1];checks=[string]$r[2]}','$rows+=,[Cp117ShortcutAccess]::CheckDescriptor($b,$false,$sid)',1)
  self.assertEqual(legacy.count('$r=[Cp117ShortcutAccess]::CheckDescriptor($bytes,$true,$sid);$rows+=@{descriptor=[string]$r[0];sid=[string]$r[1];checks=[string]$r[2]}'),1);legacy=legacy.replace('$r=[Cp117ShortcutAccess]::CheckDescriptor($bytes,$true,$sid);$rows+=@{descriptor=[string]$r[0];sid=[string]$r[1];checks=[string]$r[2]}','$rows+=,[Cp117ShortcutAccess]::CheckDescriptor($bytes,$true,$sid)',1)
  old_done=_run_complete_windows_fixture(legacy.encode('utf-8'),timeout=25);_report_shortcut_access_wire('legacy-nested-array',old_done)
  self.assertEqual(old_done.returncode,0,old_done.stderr.decode('utf-8','replace'));old_rows=json.loads(old_done.stdout);self.assertEqual(len(old_rows),4)
  legacy_failure=None
  try:_assert_shortcut_access_legacy_cases(self,old_rows)
  except (KeyError,TypeError,IndexError) as exc:
   import traceback
   legacy_failure={'exceptionType':type(exc).__name__,'message':str(exc),'traceback':traceback.format_exc()}
  print('CP117_ACCESS_LEGACY_CONSUMER_OUTCOME '+json.dumps({'testsRun':1,'failures':0,'errors':int(legacy_failure is not None),'skipped':0,'consumerSourceSha256':_ACCESS_LEGACY_CONSUMER_SHA,'outcome':'error'if legacy_failure is not None else'success','failure':legacy_failure,'originalPushedBFailureRemainsPreserved':True},sort_keys=True),flush=True)
  done=_run_complete_windows_fixture(script.encode('utf-8'),timeout=25);_report_shortcut_access_wire('explicit-scalar-dto',done)
  self.assertEqual(done.returncode,0,done.stderr.decode('utf-8','replace'));rows=json.loads(done.stdout)
  _assert_shortcut_access_native_cases(self,rows)

