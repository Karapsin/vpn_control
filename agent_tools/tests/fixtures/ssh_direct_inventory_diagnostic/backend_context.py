"""Fixed public source fixtures; no test classes or native admission."""
from contextlib import contextmanager
from pathlib import Path
import ast,errno,hashlib,importlib.util,inspect,json,os,sys,types
from unittest import mock
from agent_tools import ssh_direct_nested_channel as current_direct
from agent_tools import ssh_fresh_nested_channel as channel
from agent_tools import android_installer_direct_transport as direct
HERE=Path(__file__).parent
FIXTURE_SHA={'retained_after.py': 'fc6fffbbcdfc6d96d58b64a463c5a0415065eb62b9d413a8ea2a52ef2a1e4431', 'retained_before.py': 'c23c6d4f3c049d8b33de15e4596ccd32caa097b09bad0027fa908c2a2a23532f', 'direct_before.py': '99c6ce89cda8431936220be31ea0b6c989b78668d1a155b71cbb98d85c23ce0f', 'direct_after.py': '5b82a0a63fbd2fbc44aa4203c76060ede36236a11cdc8399e186bf7c69cc2ff3'}
CORR='a'*32
RECEIPT='b'*64

def fixed_module(filename):
    path=HERE/filename;raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=FIXTURE_SHA[filename]:raise ValueError('public_fixture_changed')
    name='agent_tools._inventory_fixture_'+path.stem
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    exec(compile(raw,str(path),'exec',dont_inherit=True),vars(module))
    return module

def generation(info):
    return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]

def fd_count():
    count=0
    for fd in range(65536):
        try:os.fstat(fd);count+=1
        except OSError:pass
    return count

def configured(root,mode=0o600):
    path=root/channel.transport.CONFIG_FILENAME
    path.write_bytes(b'{"harmlessPublicFixture":true}\n');os.chmod(path,mode)

class Capture:
    def __init__(self,path):
        self.path=path;path.mkdir(mode=0o700);self.fail_inventory=False
    def create(self,name,body):
        if self.fail_inventory and name=='selected-inventory-finite.json':raise OSError(errno.ENOSPC,'harmless fixture publication denied')
        path=self.path/name
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            at=0
            while at<len(body):
                count=os.write(fd,body[at:])
                if count<=0:raise OSError('fixture_full_write_refusal')
                at+=count
            os.fsync(fd);pin=generation(os.fstat(fd))
        finally:os.close(fd)
        return {'generation':pin,'sha256':hashlib.sha256(body).hexdigest()}
    def json(self,name):return json.loads((self.path/name).read_bytes())
    def bodies(self):return {p.name:p.read_bytes()for p in self.path.iterdir()}

class Context:
    def __init__(self,root,before=False):
        self.root=Path(root).resolve(strict=True);self.held=[];self.capture=Capture(self.root/'capture')
        self.provider=fixed_module('direct_before.py') if before else current_direct
        self.retained=fixed_module('retained_before.py' if before else 'retained_after.py')
        if not before:
            expected=fixed_module('direct_after.py')
            if ast.dump(ast.parse(inspect.getsource(self.provider.status)))!=ast.dump(ast.parse(inspect.getsource(expected.status))):
                raise ValueError('canonical_direct_status_not_reviewed_candidate')
            self.retained.direct_channel=self.provider
        self.originals=(channel.status,self.provider.status,channel.session.reuse_only_options)
        self.source_checks=0
    def source_custody(self):self.source_checks+=1
    def build(self,builder):
        return self.retained.build(builder,None,self.capture,source_custody=self.source_custody,
            held=self.held,root=self.root,correlation_id=CORR,diagnostic=None,runtime=None)
    def refused_route(self):
        try:self.build(lambda _:self.provider.route_options(self.root,channel.HOST,CORR,RECEIPT))
        except channel.ChannelUnknown as error:return error.result
        raise AssertionError('inventory refusal unexpectedly admitted route')
    def close(self):
        direct._dispatch_guard(self.held)
        seen=set();failures=[]
        for path,pin,chain,fd in reversed(self.held):
            for value in (fd,*(f for _,f in reversed(chain))):
                if value in seen:continue
                seen.add(value)
                try:os.close(value)
                except OSError as error:
                    if error.errno!=errno.EBADF:failures.append(type(error).__name__)
        self.held.clear()
        if failures:raise AssertionError('owned fixture descriptor cleanup failed')
        if (channel.status,self.provider.status,channel.session.reuse_only_options)!=self.originals:
            raise AssertionError('temporary provider functions were not restored')

@contextmanager
def context(root,before=False):
    value=Context(root,before)
    # Every real inventory-refusal control must stop before actual transport.
    with mock.patch.object(channel,'_collect',side_effect=AssertionError('forbidden fixture transport')):
        try:yield value
        finally:value.close()

def replacement_status(provider,source):
    original=provider.status
    exec(compile(source,'<public inert status seam>','exec'),vars(provider))
    return original

RAW={'stdout':b'public fixture output','stderr':b'','counts':{'stdout':21,'stderr':0},
     'eof':{'stdout':True,'stderr':True},'returnCode':0,'complete':True,
     'overflow':False,'timeout':False,'readError':False}
