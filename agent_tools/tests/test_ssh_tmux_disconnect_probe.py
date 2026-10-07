"""Real inert tmux servers/workers and original operator-owned local clients."""
import ast
import json
import os
from pathlib import Path
import shlex
import subprocess
import time
from unittest import mock
from uuid import uuid4

from agent_tools import ssh_tmux_disconnect_probe as probe
from agent_tools import ssh_gateway_tmux_master as pins
from agent_tools.tests import test_ssh_gateway_tmux_master as fixtures


class DisconnectProbeTests(fixtures.GatewayOwnerTests):
    def setUp(self):
        super().setUp()
        self.tmux.write_text(self.tmux.read_text().replace('start<12','start<35'))
        self.owner_source=self.home/'reviewed-owner.py';self.owner_source.write_bytes(self.raw);self.owner_source.chmod(0o600)
        owner_patch=mock.patch.object(pins,'__file__',str(self.owner_source));owner_patch.start();self.addCleanup(owner_patch.stop)
        hash_patch=mock.patch.object(probe,'OWNER_SHA',pins.sha(self.raw));hash_patch.start();self.addCleanup(hash_patch.stop)
        worker=probe.WORKER.replace('range(600)','range(40)')
        if self._testMethodName!='test_real_twenty_seconds_complete_after_exact_owned_client_disconnect':worker=worker.replace('time.sleep(1)','time.sleep(.01)')
        patch=mock.patch.object(probe,'WORKER',worker);patch.start();self.addCleanup(patch.stop)
        outer={'host':'gateway.invalid','port':22,'user':'owned','identityFile':str(self.home/'.ssh/key'),'knownHostsFile':str(self.home/'.ssh/known')}
        target={**outer,'host':'arch.invalid','transport':'nested','gateway':'gateway','remoteHostAlias':'arch','remoteControlPath':'/inert/existing-master'}
        self.config=self.home/probe.transport.CONFIG_FILENAME;self.config.write_bytes(pins.canonical({'schemaVersion':1,'hosts':{'gateway':outer,'archlinux':target}}));self.config.chmod(0o600)
        self.real_popen=subprocess.Popen;self.calls=[]
        def launch(argv,**kwargs):
            if not (len(argv)>=6 and argv[2:5]==['-B','-c',probe.EXEC]):return self.real_popen(argv,**kwargs)
            ssh=json.loads(argv[-1]);self.calls.append(ssh)
            self.assertEqual('/usr/bin/ssh',ssh[0]);self.assertIn('ControlPath=none',ssh);self.assertIn('ControlMaster=no',ssh)
            self.assertNotIn('inert-secret',' '.join(ssh));self.assertEqual('gateway.invalid',ssh[-2])
            command=shlex.split(ssh[-1])
            if command[0]=='/usr/bin/ssh':
                self.assertIn('ProxyCommand=false',command);self.assertIn('/inert/existing-master',command)
                command=shlex.split(command[-1])
            self.assertEqual(['/usr/bin/python3','-I','-B','-c'],command[:4])
            # A real sshd does not inherit the local SSH client's file limit.
            # This same-process inert gateway must keep its source-file writes
            # unrestricted; a separate test exercises the real local cap.
            code=command[4]
            child=self.real_popen([os.sys.executable,'-I','-B','-c',code],**kwargs)
            child.args=argv  # Popen retains the submitted wrapper argv after exec.
            return child
        patch=mock.patch.object(probe.subprocess,'Popen',side_effect=launch);patch.start();self.addCleanup(patch.stop)
        self.instances=[];self.addCleanup(self.finish_probes)

    def make(self,hop='gateway'):
        value=probe.Probe(self.home,hop,str(uuid4()));self.instances.append(value);return value

    def finish_probes(self):
        for value in self.instances:
            if value.client is not None and value.client.poll() is None and value.birth is not None:value.disconnect()
            if value.client is not None and value.client.stdin is not None:
                try:value.client.stdin.close()
                except OSError:pass
                try:value.client.wait(timeout=3)
                except subprocess.TimeoutExpired:pass
            value.close()
        deadline=time.monotonic()+4
        while time.monotonic()<deadline and list((self.home/'.vtd').glob('*/t')):time.sleep(.02)

    def wait_complete(self,value,timeout=4):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            result=value.observe()
            if result['state']=='completed':return result
            time.sleep(.03)
        self.fail(str(result))

    def test_actual_generated_loader_allows_its_own_atime_change(self):
        tree=ast.parse(probe.REMOTE)
        loader=next(ast.literal_eval(node.value) for node in ast.walk(tree)
                    if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='loader' for t in node.targets))
        body=b"print('harmless-loader-completed')\n"
        worker=self.home/'harmless-worker.py';worker.write_bytes(body);worker.chmod(0o600)
        os.utime(worker,ns=(1,worker.stat().st_mtime_ns))
        before=worker.stat()  # No read occurs before the extracted loader.
        result=subprocess.run([os.sys.executable,'-I','-B','-c',loader,str(worker),pins.sha(body),str(self.home),'0'*64],capture_output=True,timeout=3)
        after=worker.stat()
        self.assertNotEqual(before.st_atime_ns,after.st_atime_ns)
        self.assertEqual(0,result.returncode,result.stderr.decode())
        self.assertEqual(b'harmless-loader-completed\n',result.stdout)
        self.assertEqual(pins.generation(before),pins.generation(after))

    def test_real_twenty_seconds_complete_after_exact_owned_client_disconnect(self):
        value=self.make();self.assertEqual('prepared',value.prepare()['state']);self.assertEqual('released',value.release()['state'])
        before=time.monotonic();self.assertEqual('disconnected',value.disconnect()['state'])
        result=self.wait_complete(value,24)
        self.assertEqual(20,result['sequence']);self.assertGreaterEqual(time.monotonic()-before,18)
        self.assertFalse(result['productAcceptance']);self.assertFalse(result['replayAllowed'])
        remote=self.home/'.vtd'/value.correlation.replace('-','')[:16]
        self.assertEqual(20,len(list(remote.glob('beat-*.json'))));self.assertTrue((remote/'terminal.json').exists())

    def test_two_fixed_hops_and_no_existing_master_control(self):
        value=self.make('archlinux');self.assertEqual('prepared',value.prepare()['state']);self.assertEqual('released',value.release()['state'])
        self.assertEqual('disconnected',value.disconnect()['state']);self.assertEqual('completed',self.wait_complete(value)['state'])
        self.assertTrue(self.calls)
        for argv in self.calls:self.assertNotIn('-O exit',' '.join(argv));self.assertNotIn('kill-server',' '.join(argv))

    def test_lost_prepare_reply_is_consumed_and_never_replayed(self):
        value=self.make();actual=value._query
        def lost(action,*args,**kwargs):actual(action,*args,**kwargs);raise ValueError('lost')
        with mock.patch.object(value,'_query',side_effect=lost):self.assertEqual('unknown',value.prepare()['state'])
        before=len(self.calls);self.assertEqual('unknown',value.prepare()['state']);self.assertEqual(before,len(self.calls))
        self.assertEqual('unknown',value.observe()['state'])

    def test_lost_release_reply_observes_completion_without_release_replay(self):
        value=self.make();self.assertEqual('prepared',value.prepare()['state']);actual=value._query
        def lost(action,*args,**kwargs):actual(action,*args,**kwargs);raise ValueError('lost')
        with mock.patch.object(value,'_query',side_effect=lost):self.assertEqual('unknown',value.release()['state'])
        before=len(self.calls);self.assertEqual('unknown',value.release()['state']);self.assertEqual(before,len(self.calls))
        self.assertEqual('disconnected',value.disconnect()['state']);self.assertEqual('completed',self.wait_complete(value)['state'])

    def test_client_birth_mismatch_never_signals_any_process(self):
        value=self.make();self.assertEqual('prepared',value.prepare()['state']);actual=probe._birth
        with mock.patch.object(probe,'_birth',return_value={**value.birth,'birthSha':'f'*64}),mock.patch.object(os,'kill',side_effect=AssertionError('no signal')):
            self.assertEqual('unknown',value.disconnect()['state'])
        # The durable disconnect fence remains consumed even with identity restored.
        with mock.patch.object(os,'kill',side_effect=AssertionError('no replay')):self.assertEqual('unknown',value.disconnect()['state'])
        self.assertEqual(actual(value.client),value.birth)

    def test_same_byte_config_drift_rejects_release_before_query(self):
        value=self.make();self.assertEqual('prepared',value.prepare()['state']);self.config.write_bytes(self.config.read_bytes());before=len(self.calls)
        self.assertEqual('unknown',value.release()['state']);self.assertEqual(before,len(self.calls))

    def test_raw_reply_is_durable_before_schema_rejection(self):
        value=self.make();actual=value._query
        def malformed(action,*args,**kwargs):
            result=actual(action,*args,**kwargs);result['anchor']['pane']['startTicks']=True;return result
        with mock.patch.object(value,'_query',side_effect=malformed):self.assertEqual('unknown',value.prepare()['state'])
        capsules=list(value.job.glob('query-*'));self.assertEqual(1,len(capsules))
        self.assertTrue((capsules[0]/'receipt.json').exists());self.assertGreater((capsules[0]/'stdout.private').stat().st_size,0)


    def test_real_output_limit_preserves_raw_and_consumes_prepare(self):
        value=self.make()
        code="import os,resource;resource.setrlimit(resource.RLIMIT_FSIZE,(4096,resource.getrlimit(resource.RLIMIT_FSIZE)[1]));os.write(1,b'x'*5000)"
        def overflow(argv,**kwargs):
            child=self.real_popen([os.sys.executable,'-I','-B','-c',code],**kwargs);child.args=argv;return child
        with mock.patch.object(probe.subprocess,'Popen',side_effect=overflow):self.assertEqual('unknown',value.prepare()['state'])
        capsule=next(value.job.glob('query-*'))
        self.assertEqual(4096,(capsule/'stdout.private').stat().st_size)
        self.assertEqual(0,(capsule/'stderr.private').stat().st_size)
        self.assertTrue((capsule/'receipt.json').exists())
        with mock.patch.object(probe.subprocess,'Popen',side_effect=AssertionError('no replay')):self.assertEqual('unknown',value.prepare()['state'])

    def test_partial_failed_reply_remains_durable_with_empty_stderr(self):
        value=self.make()
        def partial(argv,**kwargs):
            child=self.real_popen([os.sys.executable,'-I','-B','-c',"import os;os.write(1,b'{partial');raise SystemExit(7)"],**kwargs);child.args=argv;return child
        with mock.patch.object(probe.subprocess,'Popen',side_effect=partial):self.assertEqual('unknown',value.prepare()['state'])
        capsule=next(value.job.glob('query-*'))
        self.assertEqual(b'{partial',(capsule/'stdout.private').read_bytes());self.assertEqual(b'',(capsule/'stderr.private').read_bytes())
        self.assertTrue((capsule/'receipt.json').exists())


for _name in dir(DisconnectProbeTests):
    if _name.startswith('test_') and _name not in DisconnectProbeTests.__dict__:setattr(DisconnectProbeTests,_name,None)
del _name
