"""Actual generated method+bounded collector against local OpenSSH, no TCP."""
from pathlib import Path
from types import SimpleNamespace
import ast,hashlib,json,os,re,selectors,subprocess,sys,tempfile,time,unittest
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
HERE=Path(__file__).resolve().parent/'fixtures/ssh_nested_control_crlf'
from agent_tools import readiness
BEFORE='1aac6f55e4b1a856166f10d5cd090ed7e5aa1f540d3e7995c408afa8cfd30c7f'
FIXED='c85e37230be1e171010f13f4c385e860f3ba04b34362b40a3d7f8c4a8297be53'
# Deadline of each actual local control check. The child normally exits in milliseconds, but on a directory-bound
# host its service lookup can wait out a 10 s directory reconnect timeout, past the old 5 s deadline.
OBSERVE_SECONDS=60

def load(version,anchor,controlled=None):
    path=HERE/('readiness_transport.'+version+'.source');raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!={'before':BEFORE,'fixed':FIXED}[version]:raise ValueError('actual_source_fixture_changed')
    tree=ast.parse(raw);klass=next(n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='TransportAdapter')
    method=next(n for n in klass.body if isinstance(n,ast.FunctionDef)and n.name=='_nested_state')
    nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in('_bounded','_failure')]+[method]
    calls=[]
    def exact_local_control(config,gateway,timeout,command):
        expected=('ssh','-F','/dev/null','-S',str(anchor.remote_control_path),'-O','check','public-local-no-network')
        assert command==expected and gateway=='public-gateway'and timeout==10
        calls.append(command)
        return ['/usr/bin/ssh',*command[1:]]
    env={'subprocess':subprocess,'selectors':selectors,'time':time,'os':os,'re':re,'readiness':readiness,'transport':SimpleNamespace(build_ssh_argv=exact_local_control)}
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),env)
    original=env['_bounded'];captures=[]
    def retain(argv,deadline):
        v=original(argv,deadline)if controlled is None else dict(controlled)
        captures.append(v);return v
    env['_bounded']=retain
    return lambda:env['_nested_state'](None,object(),anchor,time.monotonic()+OBSERVE_SECONDS),captures,calls

@unittest.skipUnless(os.name=='posix'and Path('/usr/bin/ssh').is_file(),'requires actual local OpenSSH control observer')
class ExactNestedControl(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve());self.addCleanup(self.temp.cleanup)
        self.anchor=SimpleNamespace(remote_config_file=Path('/dev/null'),remote_control_path=Path(self.temp.name)/'m',remote_host_alias='public-local-no-network',gateway='public-gateway')
        self.error=('Control socket connect('+str(self.anchor.remote_control_path)+'): ').encode()
    def sample(self,suffix=b'No such file or directory\r\n',**changes):
        return {'complete':True,'overflow':False,'returnCode':255,'stdout':b'','stderr':self.error+suffix,**changes}
    def test_actual_openssh_absent_socket_full_before_red_fixed_green(self):
        old,records,calls=load('before',self.anchor)
        with self.assertRaisesRegex(readiness.AdapterBlocked,'^connection_outcome_unknown$'):old()
        self.assertEqual(records[0],self.sample());self.assertEqual(len(calls),1)
        fixed,records,calls=load('fixed',self.anchor);self.assertEqual(fixed(),'dead');self.assertEqual(records[0],self.sample());self.assertEqual(len(calls),1)
    def test_exact_lf_absence_unchanged(self):
        fixed,_,_=load('fixed',self.anchor,self.sample(b'No such file or directory\n'));self.assertEqual(fixed(),'dead')
    def test_exact_lf_refusal_unchanged(self):
        fixed,_,_=load('fixed',self.anchor,self.sample(b'Connection refused\n'));self.assertEqual(fixed(),'dead')
    def test_exact_crlf_refusal_accepted(self):
        fixed,_,_=load('fixed',self.anchor,self.sample(b'Connection refused\r\n'));self.assertEqual(fixed(),'dead')
    def not_dead(self,v):
        fixed,_,_=load('fixed',self.anchor,v)
        try:self.assertNotEqual(fixed(),'dead')
        except readiness.AdapterBlocked:pass
    def test_foreign_path_not_dead(self):self.not_dead(self.sample(stderr=b'Control socket connect(/other/m): No such file or directory\r\n'))
    def test_foreign_prefix_not_dead(self):self.not_dead(self.sample(stderr=b'wrong '+self.error+b'No such file or directory\r\n'))
    def test_trailing_data_not_dead(self):self.not_dead(self.sample(stderr=self.error+b'No such file or directory\r\nextra'))
    def test_stdout_not_empty_not_dead(self):self.not_dead(self.sample(stdout=b'extra'))
    def test_wrong_returncode_not_dead(self):self.not_dead(self.sample(returnCode=0))
    def test_truncated_not_dead(self):self.not_dead(self.sample(complete=False))
    def test_overflow_not_dead(self):self.not_dead(self.sample(overflow=True))
    def test_missing_line_ending_not_dead(self):self.not_dead(self.sample(b'No such file or directory'))
    def test_extra_line_ending_not_dead(self):self.not_dead(self.sample(b'No such file or directory\r\n\r\n'))

if __name__=='__main__':unittest.main(verbosity=2)
