"""Measured Android --brief producer/consumer regression with real child pipes."""
import subprocess,sys,unittest
from agent_tools.tests.fixtures import android_ordinary_activity_resolution as fixture

class ResolutionTests(unittest.TestCase):
 def run_method(self,source,output):
  scope={};exec(compile(source,'<exact-resolver-method>','exec'),scope)
  class Guard:
   def captured(self,args,timeout,cap):
    data='0\n' if args==['shell','-T','am','get-current-user'] else output
    result=subprocess.run([sys.executable,'-I','-c','import sys;sys.stdout.write(sys.argv[1])',data],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    if result.returncode!=0 or result.stderr or len(result.stdout)>cap:raise ValueError('child_unknown')
    return result.stdout.decode('utf-8')
  return scope['resolved'](Guard())
 def test_actual_measured_producer_old_red_new_green(self):
  with self.assertRaisesRegex(ValueError,'ordinary_activity_unknown'):self.run_method(fixture.OLD_RESOLVED,fixture.MEASURED_OUTPUT)
  self.assertEqual('com.kardinal.vpncontrol/com.kardinal.vpncontrol.MainActivity',self.run_method(fixture.RESOLVED,fixture.MEASURED_OUTPUT))
 def test_exact_single_component_compatible(self):
  for value in ('com.kardinal.vpncontrol/.MainActivity\n','com.kardinal.vpncontrol/com.kardinal.vpncontrol.MainActivity\n'):
   self.assertEqual('com.kardinal.vpncontrol/com.kardinal.vpncontrol.MainActivity',self.run_method(fixture.RESOLVED,value))
 def test_foreign_extra_malformed_refused(self):
  for value in (fixture.MEASURED_OUTPUT+'foreign\n',fixture.MEASURED_OUTPUT.replace('priority=0','priority=1'),fixture.MEASURED_OUTPUT.replace('.MainActivity','.ForeignActivity'),fixture.MEASURED_OUTPUT.splitlines()[0]+'\n','', 'foreign/package.MainActivity\n'):
   with self.subTest(value=value),self.assertRaisesRegex(ValueError,'ordinary_activity_unknown'):self.run_method(fixture.RESOLVED,value)

if __name__=='__main__':unittest.main()
