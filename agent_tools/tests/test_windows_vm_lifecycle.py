"""Real owned Linux processes exercise stop/absence and no replay boundaries."""
import ast
import hashlib
import inspect
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
import threading
import unittest
from pathlib import Path
from agent_tools import windows_vm_instance as instance
from agent_tools import windows_vm_lifecycle as lifecycle


@unittest.skipUnless(sys.platform=='linux' and hasattr(os,'pidfd_open') and hasattr(signal,'pidfd_send_signal'),'Linux process handles')
class LifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(dir=Path('/tmp').resolve());self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.root.chmod(0o700)
        self.namespace={'os':os,'json':json,'hashlib':hashlib,'stat':stat,'root':self.root}
        source=inspect.getsource(instance._vm_main);tree=ast.parse(source)
        for name in ('require','generation','private','save','read','birth','record','process'):
            node=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name==name)
            exec(compile(ast.get_source_segment(source,node),'actual instance receipt primitive','exec'),self.namespace)
        self.children=[];self.addCleanup(self.close_children)
        self.spec={'deploymentId':'owned-inert-fixture'};self.context={'hostBootId':'inert-owned-boot'}
        self.actors={}
        for name,body in (('qemu','import sys;sys.stdin.buffer.read(1)'),('swtpm','import time;time.sleep(30)')):
            argv=[sys.executable,'-I','-c',body]
            child=subprocess.Popen(argv,stdin=subprocess.PIPE);self.children.append(child)
            exe=os.open(sys.executable,os.O_RDONLY)
            try:
                for _ in range(100):
                    try:row=self.namespace['record'](child,argv,exe);break
                    except (FileNotFoundError,ValueError):time.sleep(.01)
                else:self.fail('owned child identity did not settle')
            finally:os.close(exe)
            self.namespace['save'](name+'-started.json',row);self.actors[name]=row
        self.quits=[]
    def close_children(self):
        for child in self.children:
            if child.poll()is None:child.terminate()
            child.wait(timeout=5)
            if child.stdin:child.stdin.close()
    def callbacks(self,lost=False):
        def observe():
            for row in self.actors.values():self.namespace['process'](row)
            return {'productReady':False}
        def qmp(command):
            self.assertEqual('quit',command);self.quits.append(command)
            self.children[0].stdin.write(b'q');self.children[0].stdin.flush();self.children[0].wait(timeout=5)
            if lost:raise OSError('inert lost reply after original child exit')
            return {}
        return observe,qmp
    def stop(self,lost=False):
        observe,qmp=self.callbacks(lost)
        return lifecycle._stop_instance(self.spec,self.context,observe,self.namespace['read'],self.namespace['process'],
                                        self.namespace['birth'],qmp,self.namespace['save'],lambda:None)
    def test_original_handle_stop_and_positive_absence_survive_lost_quit_reply_without_replay(self):
        result=self.stop(lost=True);self.assertTrue(result['positiveAbsence']);self.assertEqual(['quit'],self.quits)
        original=(self.root/'stop-intent.json').read_bytes()
        self.assertFalse(self.namespace['read']('stop-result.json')['quitResponseClosed'])
        with self.assertRaises((ValueError,FileNotFoundError)):self.stop()
        self.assertEqual(['quit'],self.quits);self.assertEqual(original,(self.root/'stop-intent.json').read_bytes())
        self.assertTrue(lifecycle._closed_instance(self.spec,self.context,self.namespace['read'],self.namespace['process'],self.namespace['birth'])['positiveAbsence'])
    def test_live_actor_and_changed_intent_never_report_stopped(self):
        observe,_=self.callbacks()
        self.namespace['save']('stop-intent.json',{'schemaVersion':1,'deploymentId':self.spec['deploymentId'],
                            'hostBootId':self.context['hostBootId'],**self.actors,'beforeObservation':observe()})
        with self.assertRaisesRegex(ValueError,'instance_stop_incomplete'):
            lifecycle._closed_instance(self.spec,self.context,self.namespace['read'],self.namespace['process'],self.namespace['birth'])
        with self.assertRaisesRegex(ValueError,'instance_stop_intent'):
            lifecycle._closed_instance(self.spec,{'hostBootId':'foreign-boot'},self.namespace['read'],self.namespace['process'],self.namespace['birth'])
        self.assertTrue(all(child.poll()is None for child in self.children));self.assertEqual([],self.quits)

    def test_preserved_exit_race_red_fixed_positive_absence_green(self):
        folder=Path(__file__).parent/'fixtures/vm_stop_exit_race';raw=(folder/'before.source').read_bytes()
        metadata=json.loads((folder/'provenance.json').read_bytes())
        self.assertEqual(metadata['sourceSha256'],hashlib.sha256(raw).hexdigest())
        row=self.actors['qemu'];actual=self.namespace['process'];child=self.children[0]
        def exiting(record):
            child.terminate();child.wait(timeout=5);actual(record)
        # Compile the preserved actual absent helper, rather than a rewritten
        # model. Exit occurs physically between its birth and identity reads.
        source=raw.decode()
        tree=ast.parse(source)
        node=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='absent')
        namespace={'birth':self.namespace['birth'],'process':exiting}
        exec(compile(ast.get_source_segment(source,node),'preserved exit observer','exec'),namespace)
        with self.assertRaises(FileNotFoundError):namespace['absent'](row)
        fixed_row=self.actors['swtpm'];fixed_child=self.children[1]
        def fixed_exiting(record):
            fixed_child.terminate();fixed_child.wait(timeout=5);actual(record)
        self.assertTrue(lifecycle._actor_absent(fixed_row,fixed_exiting,self.namespace['birth']))
        live={'pid':os.getpid(),'startTicks':self.namespace['birth'](os.getpid())}
        def mismatch(_):raise ValueError('instance_process_changed')
        with self.assertRaisesRegex(ValueError,'instance_process_changed'):
            lifecycle._actor_absent(live,mismatch,self.namespace['birth'])

    def test_pidfd_wait_closes_exiting_actor_but_does_not_accept_a_live_mismatch(self):
        row=self.actors['qemu'];child=self.children[0]
        def terminate():child.terminate();child.wait(timeout=5)
        timer=threading.Timer(.05,terminate);timer.start()
        def exiting(_):raise ValueError('instance_process_changed')
        try:
            self.assertTrue(lifecycle._actor_absent(row,exiting,self.namespace['birth']))
        finally:timer.join(timeout=5)
        self.assertFalse(timer.is_alive())
        live=self.actors['swtpm']
        with self.assertRaisesRegex(ValueError,'instance_process_changed'):
            lifecycle._actor_absent(live,exiting,self.namespace['birth'])
        self.assertIsNone(self.children[1].poll())


if __name__=='__main__':unittest.main()
