import copy,unittest,warnings
from agent_tools import android_persisted_start as helper
from agent_tools.tests import android_interval_fixture_support as support
REPORTS=[]
class PortableReportSchemaTests(unittest.TestCase):
 def facts(self):
  op='22222222-2222-4222-8222-222222222222';root='/var/tmp/vc-android-persisted-'+op
  context={'schema':1,'operationId':op,'root':root,'rootGeneration':[1,2],'hostBootId':'25515f23-b966-4c3a-ae63-d38452375578','machineSha256':'a'*64,'account':'0'}
  record='3'*32;reference={'schema':1,'kind':'android-current1e15-unknown-interval-reference','operationId':op,'recordId':record,'guardInvocationId':'4'*32,'attempt':0,'root':root,'rootGeneration':[1,2],'directoryIdentity':[1,3,16832,0,0],'path':root+'/current-intervals/interval-'+record+'.json','generation':[1,4,33152,0,0,1,10,2,3],'bytes':10,'sha256':'b'*64,'retryable':False,'unknownInterval':True}
  return context,reference
 def test_pure_reference_and_catalog(self):
  context,reference=self.facts();namespace=helper._interval_report_namespace();self.assertEqual(namespace['interval_reference'](reference,context),reference)
  catalog={'schema':1,'kind':'android-current1e15-report-catalog','state':'observed','operationId':context['operationId'],'context':context,'directoryIdentity':reference['directoryIdentity'],'references':[reference],'aggregateBytes':10,'complete':True,'readOnly':True,'replayAllowed':False}
  self.assertEqual(helper.validate_interval_report_catalog(catalog,context),catalog)
 def test_pure_foreign_root_or_generation_never_qualifies(self):
  context,reference=self.facts();namespace=helper._interval_report_namespace()
  for delta in ({'path':reference['path']+'/../other'},{'operationId':'55555555-5555-4555-8555-555555555555'},{'rootGeneration':[1,999]}):
   with self.assertRaises(ValueError):namespace['interval_reference'](dict(reference,**delta),context)
 def test_pure_duplicate_or_aggregate_reference_refused(self):
  context,reference=self.facts();namespace=helper._interval_report_namespace()
  with self.assertRaises(ValueError):namespace['interval_references']([reference,reference],context)
  rows=[]
  for number in range(4):
   row=copy.deepcopy(reference);row['recordId']=str(number)*32;row['path']=context['root']+'/current-intervals/interval-'+row['recordId']+'.json';row['bytes']=8*1024**2;row['generation'][6]=row['bytes'];rows.append(row)
  with self.assertRaises(ValueError):namespace['interval_references'](rows,context)
 def test_pure_actual_emitted_warning_beforeimage_red_fixed_green(self):
  before=support.before_helper('helper-57c8.before.source','57c8b55fd9c6dc78f1352af2f33411c6ed76ada9f27c445df099a7696e08f4d7')
  context,unused=self.facts();counts={}
  for name,selected in [('before',before),('fixed',helper)]:
   with warnings.catch_warnings(record=True)as recorded:
    warnings.simplefilter('always');selected.interval_report_program(context,{'action':'discover'})
   counts[name]=len([value for value in recorded if issubclass(value.category,(SyntaxWarning,DeprecationWarning))])
  self.assertGreater(counts['before'],0);self.assertEqual(counts['fixed'],0)
  REPORTS.append({'kind':'actual-emitted-reader-stderr-causal','syntaxOrDeprecationWarnings':counts,'nativeEffectsAttempted':False})
