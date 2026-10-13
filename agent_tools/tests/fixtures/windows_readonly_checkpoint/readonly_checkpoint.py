"""Two fixed read-only scopes; no command/effect API and no source adoption."""
import hashlib, json, os, stat, subprocess
from pathlib import Path

EXPECTED_HEAD='74cccc42ad09a5dd4abeb100db6edf8363488e33'
READONLY_SCOPES=frozenset(('connection_uid_boot','windows_admission_census'))
PRODUCT_PATHS=('app/','desktopApp/','shared/','buildSrc/','gradle/','scripts/','.github/',
    'gradle.properties','build.gradle','build.gradle.kts','settings.gradle','settings.gradle.kts',
    'gradlew','gradlew.bat','gradle.lockfile','.gitattributes','.gitignore','.gitmodules')

def _git(root,args):
    env=dict(os.environ)
    for name in tuple(env):
        if name.startswith('GIT_')or name=='DYLD_INSERT_LIBRARIES':env.pop(name,None)
    env.update(GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_NO_LAZY_FETCH='1',GIT_TERMINAL_PROMPT='0',GIT_OPTIONAL_LOCKS='0')
    result=subprocess.run(['git','-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null',*args],
        cwd=root,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        timeout=10,env=env)
    if result.returncode or result.stderr or len(result.stdout)>8388608:raise ValueError('readonly_checkpoint_git_query')
    return result.stdout

def _head(root):
    values=[_git(root,args).decode('ascii','strict').strip()for args in
        (('rev-parse','HEAD'),('rev-parse','origin/dev'),('symbolic-ref','--short','HEAD'))]
    if values!=[EXPECTED_HEAD,EXPECTED_HEAD,'dev']:raise ValueError('readonly_checkpoint_head')

def _path(raw):
    value=os.fsdecode(raw)
    if not value or value.startswith('/') or any(piece in ('','..','.')for piece in value.split('/')):raise ValueError('readonly_checkpoint_path')
    return value

def _tree_and_index(root):
    expected={}
    for row in _git(root,('ls-tree','-r','-z',EXPECTED_HEAD,'--',*PRODUCT_PATHS)).split(b'\0'):
        if not row:continue
        fields,path=row.split(b'\t',1);mode,kind,oid=fields.split()
        name=_path(path)
        if kind!=b'blob' or mode not in (b'100644',b'100755',b'120000') or len(oid)!=40 or name in expected:raise ValueError('readonly_checkpoint_product_tree')
        expected[name]=(mode.decode(),oid.decode())
    if not expected:raise ValueError('readonly_checkpoint_product_tree_empty')
    actual={}
    for row in _git(root,('ls-files','--stage','-z','--',*PRODUCT_PATHS)).split(b'\0'):
        if not row:continue
        fields,path=row.split(b'\t',1);mode,oid,stage=fields.split();name=_path(path)
        if stage!=b'0' or name in actual:raise ValueError('readonly_checkpoint_product_index')
        actual[name]=(mode.decode(),oid.decode())
    if actual!=expected:raise ValueError('readonly_checkpoint_product_index')
    if _git(root,('ls-files','--others','--exclude-standard','-z','--',*PRODUCT_PATHS)):
        raise ValueError('readonly_checkpoint_product_addition')
    return expected

def _generation(meta):
    return (meta.st_dev,meta.st_ino,meta.st_mode,meta.st_uid,meta.st_gid,
            meta.st_nlink,meta.st_size,meta.st_mtime_ns,meta.st_ctime_ns)
def _identity(meta):return _generation(meta)[:5]

def _close_all(fds,primary=None):
    secondary=[]
    for fd in reversed(fds):
        try:os.close(fd)
        except BaseException:secondary.append('OSError')
    if secondary:
        if primary is not None:BaseException.add_note(primary,'readonly_checkpoint_cleanup_secondary:OSError')
        else:raise RuntimeError('readonly_checkpoint_cleanup_secondary')

def _working_file(root,name,expected):
    """One bounded no-follow ancestor chain at a time; no target of a symlink is read."""
    path=root/name;fds=[];parents={};primary=None
    try:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(fd)
        parents['/']=_identity(os.fstat(fd));walk=Path('/')
        for piece in path.parent.parts[1:]:
            fd=os.open(piece,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);fds.append(fd)
            walk=walk/piece;parents[str(walk)]=_identity(os.fstat(fd))
        before=os.stat(path.name,dir_fd=fd,follow_symlinks=False);generation=_generation(before)
        if before.st_uid!=os.getuid() or before.st_nlink!=1:raise ValueError('readonly_checkpoint_product_owner')
        mode,oid=expected
        if mode=='120000':
            if not stat.S_ISLNK(before.st_mode):raise ValueError('readonly_checkpoint_product_mode')
            raw=os.fsencode(os.readlink(path.name,dir_fd=fd));digest=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        else:
            actual_mode='100755'if before.st_mode&0o111 else'100644'
            if not stat.S_ISREG(before.st_mode) or actual_mode!=mode:raise ValueError('readonly_checkpoint_product_mode')
            leaf=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd);fds.append(leaf)
            if _generation(os.fstat(leaf))!=generation:raise ValueError('readonly_checkpoint_product_generation')
            digest=hashlib.sha1();digest.update(b'blob '+str(before.st_size).encode()+b'\0');size=0
            while True:
                raw=os.read(leaf,65536)
                if not raw:break
                size+=len(raw);digest.update(raw)
                if size>before.st_size:raise ValueError('readonly_checkpoint_product_generation')
            if size!=before.st_size or _generation(os.fstat(leaf))!=generation:raise ValueError('readonly_checkpoint_product_generation')
            digest=digest.hexdigest()
        if digest!=oid:raise ValueError('readonly_checkpoint_product_bytes')
        if _generation(os.stat(path.name,dir_fd=fd,follow_symlinks=False))!=generation:raise ValueError('readonly_checkpoint_product_generation')
        for parent,identity in parents.items():
            if _identity(os.lstat(parent))!=identity:raise ValueError('readonly_checkpoint_product_ancestor')
        return generation,parents
    except BaseException as error:primary=error;raise
    finally:_close_all(fds,primary)

def _scan(root,expected):
    rows={};parents={}
    for name,pin in sorted(expected.items()):
        generation,ancestry=_working_file(root,name,pin);rows[name]=generation
        for parent,identity in ancestry.items():
            if parent in parents and parents[parent]!=identity:raise ValueError('readonly_checkpoint_product_ancestor')
            parents[parent]=identity
    return rows,parents

def _guards(source_guard,config_key_guard,primary=None):
    for callback,label in ((source_guard,'source'),(config_key_guard,'config_key')):
        try:
            if not callable(callback):raise ValueError('readonly_checkpoint_'+label+'_callback_required')
            result=callback()
            if result is not None and result is not True:raise ValueError('readonly_checkpoint_'+label+'_callback_refused')
        except BaseException as error:
            if primary is None:primary=error
            else:BaseException.add_note(primary,'readonly_checkpoint_'+label+'_secondary:'+type(error).__name__)
    return primary

def validate_readonly_checkpoint(root,scope,*,source_guard,config_key_guard):
    """Caller must provide its actual held current source and config/key guards.

    They run before and after even when Git/product validation refuses. This
    function never admits a transport, chooses a command, or adopts new source.
    """
    if type(scope)is not str or scope not in READONLY_SCOPES:raise ValueError('readonly_checkpoint_scope')
    root=Path(root).resolve(strict=True);primary=_guards(source_guard,config_key_guard)
    try:
        if primary is not None:raise primary
        _head(root);expected=_tree_and_index(root);first=_scan(root,expected);second=_scan(root,expected)
        if first!=second:raise ValueError('readonly_checkpoint_product_generation')
        _head(root)
        if _tree_and_index(root)!=expected:raise ValueError('readonly_checkpoint_product_index')
    except BaseException as error:primary=error
    finally:primary=_guards(source_guard,config_key_guard,primary)
    if primary is not None:raise primary
    # Refuse a callback-time product/name mutation without re-reading any private guard data.
    rows,parents=second
    for parent,identity in sorted(parents.items(),key=lambda row:len(Path(row[0]).parts)):
        if _identity(os.lstat(parent))!=identity:raise ValueError('readonly_checkpoint_product_ancestor')
    for name,generation in rows.items():
        if _generation(os.lstat(root/name))!=generation:raise ValueError('readonly_checkpoint_product_generation')
    digest=hashlib.sha256(json.dumps(expected,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return {'schema':1,'scope':scope,'head':EXPECTED_HEAD,'productFileCount':len(expected),
            'productTreeSha256':digest,'sourceAndConfigGuardsInvoked':True,
            'nativeActionAllowed':False,'replayAllowed':False}
