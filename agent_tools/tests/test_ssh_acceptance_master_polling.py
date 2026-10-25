"""Private causal controls; real owned local actors/sockets, no SSH dispatch."""
from pathlib import Path
from contextlib import ExitStack
import ast,hashlib,json,os,socket,subprocess,sys,tempfile,time,unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
if os.name=='posix':
    from agent_tools import readiness_ssh_master as master
    from agent_tools import private_inventory_lock as private
    from agent_tools import ssh_connection_session as session
    from agent_tools import ssh_channel_keeper_entry as keeper
    from agent_tools import ssh_transport as transport
HERE=Path(__file__).resolve().parent/'fixtures/ssh_acceptance_master_polling'
BEFORE='aabda457980c81a2578adba9c29711d9c8644c7ed29b7af1d9a40bf1678940bb'
FIXED='e563136bbad91872a1ed35981d1ef80347672ff92b33e25c100c5a0e0daa40ab'

def selected(name,callback,mode='direct',old='a'*64):
    path=HERE/('controller.before.source' if name=='before' else 'controller.fixed.source')
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!={'before':BEFORE,'fixed':FIXED}[name]:raise ValueError('fixture_source_changed')
    tree=ast.parse(raw)
    nodes=[next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef)and n.name==key)for key in ('until','renewed_original_connection')]
    env={'time':time,'master':master,'connection':callback,'mode':mode,'old_connection':{'recoveryId':old,'correlationId':old}}
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),env)
    return env['renewed_original_connection'],env['until']

@unittest.skipUnless(os.name=='posix','requires owned POSIX process and UNIX socket identities')
class ActualMasterPolling(unittest.TestCase):
    def setUp(self):
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.root=Path(self.stack.enter_context(tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())));self.root.chmod(0o700)
        key=self.root/'public-dummy-key';key.write_bytes(b'public-test-input-not-a-real-key\n');key.chmod(0o600)
        trust=self.root/'public-trust';trust.write_bytes(b'public-test-trust\n');trust.chmod(0o600)
        self.config=transport.SshConfig(self.root,{'controlled':transport.SshHost('controlled','127.0.0.1',1,'public-test',key,trust)})
        # Sockets live where production creates them: an independently trusted native root, never inherited TMPDIR.
        self.parent=Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix='pm-',dir=master._socket_temp_root())));self.parent.chmod(0o700)
        self.path=self.parent/'m';self.listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.listener.bind(str(self.path));self.path.chmod(0o600);self.listener.listen(32);self.addCleanup(self.listener.close)
        self.journal=master.initialize(self.root,'controlled')
        self.machine=master.identity(self.config,'controlled')
        self.processes=[];self.addCleanup(self.close_children)
    def close_children(self):
        for p in self.processes:
            if not p.stdin.closed:p.stdin.close()
            p.wait(timeout=5)
    def child(self,dead=False):
        p=subprocess.Popen([sys.executable,'-I','-B','-c','import sys;sys.stdin.buffer.read(1)'],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.processes.append(p);actor=keeper.actor(p.pid)
        if dead:p.stdin.close();self.assertEqual(p.wait(timeout=5),0)
        return p,actor
    def publish(self,rid,*,dead=False,machine=None,actor_change=False,socket_parent=None):
        p,actor=self.child(dead)
        child={'recoveryId':rid,'pid':p.pid,'actor':dict(actor)}
        if actor_change:child['actor']['birthSha256']='0'*64
        intent={'recoveryId':rid,'host':'controlled','machine':self.machine if machine is None else machine,'socketPath':str(self.path),'socketParent':session._directory(self.parent)if socket_parent is None else socket_parent}
        with private.Directory(self.journal)as d:
            master._save(d,rid+'.intent.json',intent);master._save(d,rid+'.child.json',child)
            if not dead:master._save(d,rid+'.ready.json',{'recoveryId':rid,'masterActor':child['actor'],'socketFingerprint':session._socket(self.path,intent['socketParent'])})
            master._publish(d,rid)
        return p
    def status(self):return master.status(self.root,'controlled',self.config)
    def test_actual_dead_submitter_live_socket_old_red_fixed_green(self):
        self.publish('b'*64,dead=True)
        with self.assertRaisesRegex(master.MasterUnknown,'^master_socket_owner_unresolved$'):self.status()
        before,_=selected('before',self.status)
        with self.assertRaisesRegex(master.MasterUnknown,'^master_socket_owner_unresolved$'):before()
        fixed,_=selected('fixed',self.status);self.assertIsNone(fixed())
        self.publish('c'*64)
        ready=fixed();self.assertEqual((ready['state'],ready['recoveryId']),('ready','c'*64))
    def test_bounded_full_original_until_allows_only_later_ready_generation(self):
        self.publish('b'*64,dead=True);calls=[]
        def actual():
            calls.append(time.monotonic())
            if len(calls)==2:self.publish('c'*64)
            return self.status()
        fixed,until=selected('fixed',actual)
        out=until(fixed,time.monotonic()+3,'controlled_deadline')
        self.assertEqual(len(calls),2);self.assertEqual(out['recoveryId'],'c'*64)
    def test_live_owner_generation_mismatch_still_raises(self):
        self.publish('b'*64,actor_change=True)
        fixed,_=selected('fixed',self.status)
        with self.assertRaisesRegex(master.MasterUnknown,'^master_actor_changed$'):fixed()
    def test_trust_route_mismatch_still_raises(self):
        self.publish('b'*64,dead=True,machine='0'*64)
        fixed,_=selected('fixed',self.status)
        with self.assertRaisesRegex(master.MasterUnknown,'^master_authority_changed$'):fixed()
    def test_socket_parent_mismatch_still_raises(self):
        parent=session._directory(self.parent);parent[1]+=1
        self.publish('b'*64,dead=True,socket_parent=parent)
        fixed,_=selected('fixed',self.status)
        with self.assertRaisesRegex(master.MasterUnknown,'^master_socket_parent_changed$'):fixed()
    def test_nested_same_typed_unknown_is_not_suppressed(self):
        self.publish('b'*64,dead=True)
        fixed,_=selected('fixed',self.status,mode='nested')
        with self.assertRaisesRegex(master.MasterUnknown,'^master_socket_owner_unresolved$'):fixed()
    def test_same_ready_generation_is_not_recovery(self):
        self.publish('a'*64)
        fixed,_=selected('fixed',self.status);self.assertIsNone(fixed())
    def test_spent_deadline_performs_zero_status_probes(self):
        calls=[]
        fixed,until=selected('fixed',lambda:calls.append('unexpected'))
        with self.assertRaisesRegex(ValueError,'^controlled_deadline$'):until(fixed,time.monotonic()-1,'controlled_deadline')
        self.assertEqual(calls,[])
    def test_unresolved_owner_expires_without_recovery_or_replay(self):
        self.publish('b'*64,dead=True);fixed,until=selected('fixed',self.status)
        with self.assertRaisesRegex(ValueError,'^controlled_deadline$'):until(fixed,time.monotonic()+.05,'controlled_deadline')

if __name__=='__main__':unittest.main(verbosity=2)
