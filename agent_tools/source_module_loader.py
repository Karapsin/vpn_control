"""Fresh source-backed native adapter imports with transitive custody.

Compiled captured bytes bypass timestamp-valid .pyc files and process-global
module caches. A private package isolates each request; all consumed local
sources stay held through calls and are checked before and after effects.
"""
from __future__ import annotations
import contextvars
from contextlib import contextmanager, _GeneratorContextManager
import ast,builtins,functools,hashlib,importlib,importlib.abc,importlib.util,inspect,os,re,stat,sys,types,uuid
from pathlib import Path

_LOADED_BYTES=Path(__file__).read_bytes()
_LOADED_CODE=sys._getframe().f_code
if _LOADED_CODE!=compile(_LOADED_BYTES,__file__,'exec',dont_inherit=True,optimize=sys.flags.optimize):
    raise ValueError('Loaded adapter loader differs from its source')
_LOADED_SHA=hashlib.sha256(_LOADED_BYTES).hexdigest()
_BOOTSTRAP_MAX_BYTES=4*1024**2


@contextmanager
def _bootstrap_source(path, expected_sha=None):
    """Authenticate the custody primitive before any of its code can execute."""
    if os.name=='nt':
        from . import windows_source_custody as windows
        held=windows.WindowsHeld()
        try:
            held.read(str(Path(windows.__file__).absolute()),windows.LOADED_SHA)
            # This preliminary byte read supplies a digest, never executable
            # authority. Native held names/handles authenticate it before yield.
            with path.open('rb') as stream:raw=stream.read(_BOOTSTRAP_MAX_BYTES+1)
            if not 0<len(raw)<=_BOOTSTRAP_MAX_BYTES:raise ValueError('bootstrap_source_bound')
            raw=held.read(str(path),expected_sha or hashlib.sha256(raw).hexdigest(),max_bytes=_BOOTSTRAP_MAX_BYTES)
            held.finish();held.final_identity_pass()
            yield raw,held.finish
            held.finish();held.final_identity_pass()
        finally:held.close()
        return
    if os.name!='posix':raise ValueError('unsupported_source_bootstrap_platform')
    if not path.is_absolute() or '..' in path.parts or '\\' in str(path) or '\0' in str(path):
        raise ValueError('bootstrap_source_path')
    descriptors=[];parents=[]
    structural=lambda info:(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)
    generation=lambda info:(*structural(info),info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    def bounded_read(fd):
        os.lseek(fd,0,os.SEEK_SET);parts=[];size=0
        while size<=_BOOTSTRAP_MAX_BYTES:
            part=os.read(fd,min(65536,_BOOTSTRAP_MAX_BYTES+1-size))
            if not part:break
            parts.append(part);size+=len(part)
        if not 0<size<=_BOOTSTRAP_MAX_BYTES:raise ValueError('bootstrap_source_bound')
        return b''.join(parts)
    try:
        parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);descriptors.append(parent)
        parents.append((parent,None,None,structural(os.fstat(parent))))
        for name in path.parts[1:-1]:
            fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);descriptors.append(fd)
            info=os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode):raise ValueError('bootstrap_source_ancestor')
            parents.append((fd,parent,name,structural(info)));parent=fd
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent);descriptors.append(fd)
        info=os.fstat(fd);pin=generation(info)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1:
            raise ValueError('bootstrap_source_requires_regular_current_uid_single_link')
        if not 0<info.st_size<=_BOOTSTRAP_MAX_BYTES:raise ValueError('bootstrap_source_bound')
        raw=bounded_read(fd)
        if expected_sha is not None and hashlib.sha256(raw).hexdigest()!=expected_sha:
            raise ValueError('expected_source_bytes_changed')
        def guard():
            if bounded_read(fd)!=raw:raise ValueError('bootstrap_source_bytes_changed')
            for held,ancestor,name,identity in parents:
                named=os.lstat('/') if ancestor is None else os.stat(name,dir_fd=ancestor,follow_symlinks=False)
                if structural(os.fstat(held))!=identity or structural(named)!=identity:
                    raise ValueError('bootstrap_source_ancestor_changed')
            if len(raw)!=pin[6] or generation(os.fstat(fd))!=pin or generation(os.stat(path.name,dir_fd=parent,follow_symlinks=False))!=pin:
                raise ValueError('bootstrap_source_generation_changed')
        guard();yield raw,guard;guard()
    finally:
        for fd in reversed(descriptors):os.close(fd)


def _expected_sources(directory, value):
    if value is None:return None
    if os.name!='posix':raise ValueError('expected_source_manifest_platform')
    if type(value)is not dict or not 0<len(value)<=4096:raise ValueError('expected_source_manifest')
    roots=(directory,directory.parent/'scripts');result={}
    for name,digest in value.items():
        if (type(name)is not str or not name.startswith('/') or '\\'in name or '\0'in name
                or any(part in ('','.','..')for part in name.split('/')[1:])
                or not any(Path(name).is_relative_to(root)for root in roots)
                or type(digest)is not str or re.fullmatch('[0-9a-f]{64}',digest)is None):
            raise ValueError('expected_source_manifest_entry')
        result[name]=digest
    if str(directory/'native_review_source_closure.py')not in result:
        raise ValueError('expected_source_bootstrap_missing')
    return result


class _GuardedGeneratorContext:
    """A source-owned suspended generator retains its original session guard."""
    def __init__(self, session, context):
        self.session,self.context,self.entered,self.closed=session,context,False,False
    def __enter__(self):
        self.session.guard()
        if self.entered or self.closed:raise ValueError('adapter_context_already_consumed')
        result=self.context.__enter__();self.entered=True
        try:
            self.session.guard();result=self.session.hold_result(result);self.session.guard()
            return result
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise
    def __exit__(self,*error):
        if not self.entered or self.closed:raise ValueError('adapter_context_not_entered')
        try:return self.context.__exit__(*error)
        finally:
            self.closed=True
            self.session.guard()


class SourceSession:
    def __init__(self,directory,entry,*,expected_sources=None):
        if type(entry)is not str or not entry.isidentifier():raise ValueError('adapter_module_name')
        self.directory=Path(directory).absolute();self.expected_sources=_expected_sources(self.directory,expected_sources);self.prefix='_vpn_source_'+uuid.uuid4().hex
        self.cache={};self.closed=False;self.finder=None;self.held=None;self.instrumented=set();self.original_sys_path=tuple(sys.path)
        package=types.ModuleType(self.prefix);package.__path__=[];sys.modules[self.prefix]=package
        scripts=types.ModuleType(self.prefix+'._scripts');scripts.__path__=[];sys.modules[scripts.__name__]=scripts
        try:
            path=self.directory/'native_review_source_closure.py'
            expected=self.expected_sources[str(path)] if self.expected_sources is not None else None
            with _bootstrap_source(path,expected) as (raw,bootstrap_guard):
                custody=types.ModuleType(self.prefix+'.native_review_source_closure');custody.__file__=str(path);custody.__package__=self.prefix
                sys.modules[custody.__name__]=custody;code=compile(raw,str(path),'exec',dont_inherit=True)
                bootstrap_guard();exec(code,custody.__dict__);bootstrap_guard()
                if os.name=='nt':
                    from . import windows_source_custody as windows
                    self.held=windows.WindowsHeld()
                    self.held.read(str(Path(windows.__file__).absolute()),windows.LOADED_SHA)
                else:self.held=custody._Held()
                self.held.read(str(path),hashlib.sha256(raw).hexdigest(),max_bytes=_BOOTSTRAP_MAX_BYTES)
                self.held.finish();self.held.final_identity_pass()
            self.held.read(str(Path(__file__).absolute()),_LOADED_SHA)
            self.cache[custody.__name__]=(str(path),raw)
            inspect_view=types.ModuleType('inspect');inspect_view.__dict__.update(vars(inspect))
            def lines(target):
                module=getattr(target,'__module__',getattr(target,'__name__',''))
                if not module.startswith(self.prefix+'.'):return inspect.getsourcelines(target)
                name=module;path,body=self.cache[name]
                if inspect.ismodule(target):return body.decode().splitlines(True),1
                node=ast.parse(body)
                for part in target.__qualname__.split('.'):
                    matches=[n for n in node.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and n.name==part]
                    if len(matches)!=1:raise ValueError('adapter_source_target')
                    node=matches[0]
                first=min([node.lineno]+[d.lineno for d in node.decorator_list])
                return body.decode().splitlines(True)[first-1:node.end_lineno],first
            inspect_view.getsourcelines=lines;inspect_view.getsource=lambda target:''.join(lines(target)[0])
            import_view=types.ModuleType('importlib');import_view.__dict__.update(vars(importlib))
            def script_alias(name):
                if (type(name)is str and name.isidentifier() and name not in sys.stdlib_module_names
                        and (self.directory.parent/'scripts'/(name+'.py')).is_file()):
                    return self.prefix+'._scripts.'+name
                return None
            def import_module(name,package=None):
                if name=='agent_tools':name=self.prefix
                elif name.startswith('agent_tools.'):name=self.prefix+name[len('agent_tools'):]
                elif name=='scripts' or name.startswith('scripts.'):name=self.prefix+'._scripts'+name[len('scripts'):]
                if package=='agent_tools':package=self.prefix
                name=script_alias(name) or name
                return importlib.import_module(name,package)
            import_view.import_module=import_module
            sys_view=types.ModuleType('sys');sys_view.path=list(sys.path)
            sys_view.__getattr__=lambda name:getattr(sys,name)
            def importing(name,globals=None,locals=None,fromlist=(),level=0):
                if level==0:
                    if name=='inspect':return inspect_view
                    if name=='sys':return sys_view
                    if name=='importlib' or name.startswith('importlib.'):
                        actual=builtins.__import__(name,globals,locals,fromlist,0)
                        # Import the requested stdlib submodule before exposing
                        # our import_module wrapper. A startup snapshot alone
                        # misses modules first imported later in this request.
                        for key,value in vars(importlib).items():
                            if key!='import_module':setattr(import_view,key,value)
                        return actual if name!='importlib' and fromlist else import_view
                    if name=='agent_tools' or name.startswith('agent_tools.'):
                        name=self.prefix+name[len('agent_tools'):]
                    if name=='scripts' or name.startswith('scripts.'):
                        mapped=self.prefix+'._scripts'+name[len('scripts'):]
                        result=builtins.__import__(mapped,globals,locals,fromlist,0)
                        return result if fromlist else sys.modules[self.prefix+'._scripts']
                    script=script_alias(name)
                    if script:return builtins.__import__(script,globals,locals,fromlist or ('*',),0)
                return builtins.__import__(name,globals,locals,fromlist,level)
            owner=self
            class Loader(importlib.abc.Loader):
                def create_module(self,spec):return None
                def exec_module(self,module):
                    leaf=module.__name__.removeprefix(owner.prefix+'.');base=owner.directory
                    if leaf.startswith('_scripts.'):
                        leaf=leaf.removeprefix('_scripts.');base=owner.directory.parent/'scripts'
                    if not all(part.isidentifier() for part in leaf.split('.')):raise ImportError('undeclared_adapter_module')
                    path=base.joinpath(*leaf.split('.'))
                    path=path/'__init__.py' if path.is_dir() else path.with_suffix('.py')
                    raw=path.read_bytes();digest=hashlib.sha256(raw).hexdigest()
                    if owner.expected_sources is not None:
                        if owner.expected_sources.get(str(path))!=digest:raise ValueError('expected_source_bytes_changed')
                        digest=owner.expected_sources[str(path)]
                    raw=owner.held.read(str(path),digest);owner.cache[module.__name__]=(str(path),raw)
                    module.__file__=str(path);module.__builtins__={**vars(builtins),'__import__':importing}
                    owner.guard();exec(compile(raw,str(path),'exec',dont_inherit=True),module.__dict__);owner.guard()
            class Finder(importlib.abc.MetaPathFinder):
                def find_spec(self,name,path=None,target=None):
                    if name.startswith(owner.prefix+'.'):
                        leaf=name.removeprefix(owner.prefix+'.').removeprefix('_scripts.')
                        if not all(part.isidentifier() for part in leaf.split('.')):raise ImportError('undeclared_adapter_module')
                        base=owner.directory.parent/'scripts' if name.startswith(owner.prefix+'._scripts.') else owner.directory
                        path=base.joinpath(*leaf.split('.'));is_package=path.is_dir()
                        if is_package and not (path/'__init__.py').is_file():
                            spec=importlib.machinery.ModuleSpec(name,None,is_package=True);spec.submodule_search_locations=[];return spec
                        source=path/'__init__.py' if is_package else path.with_suffix('.py')
                        return importlib.util.spec_from_loader(name,Loader(),origin=str(source),is_package=is_package)
            self.finder=Finder();sys.meta_path.insert(0,self.finder)
            self.module=importlib.import_module(self.prefix+'.'+entry);self.guard()
        except BaseException:self.close();raise
    def load(self,entry):
        if type(entry)is not str or not entry.isidentifier():raise ValueError('adapter_module_name')
        self.guard();module=importlib.import_module(self.prefix+'.'+entry);self.guard();return module
    def hold_result(self,value,seen=None):
        if type(value)is _GeneratorContextManager:
            function=value.func;generator=value.gen
            name=getattr(function,'__module__','');module=sys.modules.get(name)
            source=self.cache.get(name)
            if (not name.startswith(self.prefix+'.') or source is None or module is None
                    or not inspect.isgeneratorfunction(function) or not inspect.isgenerator(generator)
                    or generator.gi_frame is None or generator.gi_frame.f_globals is not vars(module)
                    or function.__globals__ is not vars(module) or generator.gi_code is not function.__code__):
                raise ValueError('foreign_adapter_context')
            path,raw=source
            def codes(code):
                yield code
                for child in code.co_consts:
                    if isinstance(child,types.CodeType):yield from codes(child)
            if function.__code__ not in codes(compile(raw,path,'exec',dont_inherit=True)):
                raise ValueError('foreign_adapter_context')
            self.guard()
            return _GuardedGeneratorContext(self,value)
        # A list-compatible inline carrier also holds a saved-plan capability.
        # Ordinary container traversal cannot see that attribute. Keep both the
        # carrier methods and its retained plan under this request's custody.
        if (isinstance(value,list) and type(value).__name__=='BoundInlineArgv' and
                type(value).__module__==self.prefix+'.ssh_transport'):
            self.instrument(type(value))
            self.hold_result(value.saved_plan)
            self.hold_result(value.dispatch_admission)
        if isinstance(value,(dict,list,tuple,set,frozenset,types.MappingProxyType)):
            seen=set() if seen is None else seen
            if id(value) in seen:return value
            seen.add(id(value))
            children=value.values() if isinstance(value,(dict,types.MappingProxyType)) else value
            for item in children:
                checked=self.hold_result(item,seen)
                if checked is not item:raise ValueError('nested_adapter_capability_requires_guarded_owner')
            return value
        if inspect.isgenerator(value) or inspect.isasyncgen(value):raise ValueError('lazy_adapter_results_require_explicit_custody')
        if inspect.ismodule(value) and value.__name__.startswith(self.prefix+'.'):
            proxy=Adapter.__new__(Adapter);proxy._owned=False;proxy._session=self;proxy._module=value
            proxy.__name__='agent_tools.'+value.__name__.removeprefix(self.prefix+'.')
            return proxy
        cls=value if inspect.isclass(value) else type(value)
        if (getattr(cls,'__module__','').startswith(self.prefix+'.') and cls.__module__!=self.prefix+'.native_review_source_closure'
                and not issubclass(cls,BaseException)):
            self.instrument(cls)
        elif callable(value) and not inspect.isclass(value):return self.wrap(value)
        return value
    def wrap(self,function,*,cleanup=False,destructor=False):
        session=self
        if inspect.isgeneratorfunction(function) or inspect.isasyncgenfunction(function):
            def rejected(*args,**kwargs):raise ValueError('lazy_adapter_exports_require_explicit_custody')
            return rejected
        if inspect.iscoroutinefunction(function):
            @functools.wraps(function)
            async def awaited(*args,**kwargs):
                if not cleanup:session.guard()
                try:return session.hold_result(await function(*args,**kwargs))
                finally:session.guard()
            return awaited
        @functools.wraps(function)
        def call(*args,**kwargs):
            if not cleanup:session.guard()
            try:return session.hold_result(function(*args,**kwargs))
            finally:
                if destructor:
                    try:session.guard()
                    except Exception:pass
                else:session.guard()
        return call
    def instrument(self,cls):
        if cls in self.instrumented:return
        self.instrumented.add(cls)
        for base in cls.__bases__:
            if getattr(base,'__module__','').startswith(self.prefix+'.'):self.instrument(base)
        for name,value in tuple(vars(cls).items()):
            if inspect.isfunction(value):setattr(cls,name,self.wrap(value,cleanup=name in ('close','__exit__','__aexit__','__del__'),destructor=name=='__del__'))
            elif isinstance(value,(staticmethod,classmethod)):setattr(cls,name,type(value)(self.wrap(value.__func__)))
            elif isinstance(value,property):setattr(cls,name,property(*(self.wrap(f) if f else None for f in (value.fget,value.fset,value.fdel)),doc=value.__doc__))
    def guard(self):
        if self.closed:raise ValueError('closed_adapter_source')
        self.held.finish();self.held.final_identity_pass()
    def close(self):
        if not self.closed:
            self.closed=True
            if self.finder is not None and self.finder in sys.meta_path:sys.meta_path.remove(self.finder)
            if self.held is not None:self.held.close()
            for name in list(sys.modules):
                if name==self.prefix or name.startswith(self.prefix+'.'):sys.modules.pop(name,None)


class Adapter:
    def __init__(self,directory,entry,*,session=None,expected_sources=None):
        if session is not None and expected_sources is not None:raise ValueError('expected_source_session_already_bound')
        self._owned=session is None
        self._session=SourceSession(directory,entry,expected_sources=expected_sources) if self._owned else session
        self._module=self._session.module if self._owned else self._session.load(entry)
        self.__name__='agent_tools.'+entry
    def __getattr__(self,name):
        session=self._session;session.guard();value=getattr(self._module,name)
        if inspect.isclass(value):session.hold_result(value);return value
        if inspect.isgeneratorfunction(value) or inspect.isasyncgenfunction(value):raise ValueError('lazy_adapter_exports_require_explicit_custody')
        if inspect.iscoroutinefunction(value):
            @functools.wraps(value)
            async def async_call(*args,**kwargs):
                owner=self
                return await owner._session.wrap(value)(*args,**kwargs)
            return async_call
        if inspect.isfunction(value):
            @functools.wraps(value)
            def call(*args,**kwargs):
                owner=self
                return owner._session.wrap(value)(*args,**kwargs)
            return call
        return value
    def close(self):
        if self._owned:self._session.close()
    def __del__(self):
        if self.__dict__.get('_owned'):
            session=self.__dict__.get('_session')
            if session is not None:
                try:session.close()
                except Exception:pass

_ACTIVE=contextvars.ContextVar('vpn_control_native_source_request',default=None)


class RequestSources:
    def __init__(self,directory,expected_sources=None):
        self.directory=Path(directory).resolve();self.expected_sources=_expected_sources(self.directory,expected_sources);self.session=None
    def module(self,entry):
        if self.session is None:self.session=SourceSession(self.directory,entry,expected_sources=self.expected_sources)
        return Adapter(self.directory,entry,session=self.session)
    def guard(self):
        if self.session is not None:self.session.guard()
    def close(self):
        if self.session is not None:self.session.close()


@contextmanager
def request_scope(directory,*,expected_sources=None):
    directory=Path(directory).resolve();active=_ACTIVE.get()
    if active is not None:
        if active.directory!=directory:raise ValueError('adapter_request_root_changed')
        if expected_sources is not None and _expected_sources(directory,expected_sources)!=active.expected_sources:
            raise ValueError('expected_source_request_changed')
        active.guard();yield;active.guard();return
    session=RequestSources(directory,expected_sources);token=_ACTIVE.set(session)
    try:
        yield
    finally:
        try:session.guard()
        finally:_ACTIVE.reset(token);session.close()

def adapter(directory,entry,*,expected_sources=None):
    session=_ACTIVE.get()
    if session is not None:
        if session.directory!=Path(directory).resolve():raise ValueError('adapter_request_root_changed')
        if expected_sources is not None and _expected_sources(session.directory,expected_sources)!=session.expected_sources:
            raise ValueError('expected_source_request_changed')
        return session.module(entry)
    return Adapter(directory,entry,expected_sources=expected_sources)
