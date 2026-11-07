"""Execute complete routine suites with declared missing-capability peers."""
from __future__ import annotations
import builtins
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import types
import unittest
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]

def run(mode):
    assert mode in {'windows-like','without-powershell'}
    real_import=builtins.__import__;real_os=os;declared=[]
    class WindowsOs:
        name='nt'
        def rename(self,source,destination):
            if real_os.name=='nt':return real_os.rename(source,destination)
            assert real_os.name=='posix','declared-atomic-noreplace-peer-platform'
            # Owned local fixture file: atomic no-replace publication.
            real_os.link(source,destination,follow_symlinks=False)
            real_os.unlink(source)
        def __getattr__(self,key):
            if key in {'getuid','geteuid','O_DIRECTORY','O_NOFOLLOW','pread','fchmod'}:raise AttributeError(key)
            return getattr(real_os,key)
    surface=WindowsOs()
    def fixture_origin(globals):
        filename=(globals or {}).get('__file__','')
        return filename.startswith(str(HERE)) or filename.startswith(str(ROOT/'agent_tools/windows_'))
    def local_import(name,globals=None,locals=None,fromlist=(),level=0):
        if fixture_origin(globals):
            if mode=='windows-like' and name=='os':
                declared.append({'origin':globals['__file__'],'missing':['getuid','O_NOFOLLOW'],'osName':'nt'});return surface
            if mode=='without-powershell' and name=='shutil':
                normal=real_import(name,globals,locals,fromlist,level);view=types.SimpleNamespace(**vars(normal))
                view.which=lambda command,*args,**kwargs:None if command in {'powershell.exe','pwsh'} else normal.which(command,*args,**kwargs)
                return view
        return real_import(name,globals,locals,fromlist,level)
    previous_powershell_env=os.environ.get('VPN_CONTROL_TEST_POWERSHELL')
    if mode=='without-powershell':os.environ.pop('VPN_CONTROL_TEST_POWERSHELL',None)
    builtins.__import__=local_import
    try:
        from agent_tools.tests import test_windows_lifecycle_cases as lifecycle
        from agent_tools.tests import test_windows_runtime_branch_cases as branches
        from agent_tools.tests.fixtures.windows_lifecycle_runtime import boundary
        original_os=boundary.os;original_shutil=boundary.shutil
        if mode=='windows-like':boundary.os=surface
        else:
            view=types.SimpleNamespace(**vars(original_shutil))
            view.which=lambda command,*args,**kwargs:None if command in {'powershell.exe','pwsh'} else original_shutil.which(command,*args,**kwargs)
            boundary.shutil=view
        original_count=len(boundary.RUNS);before_methods={case:{name:value for name,value in vars(case).items() if name.startswith('test_')}
            for case in (lifecycle.LifecycleBodyTests,branches.RuntimeBranchBodyTests)}
        suite=unittest.TestSuite((unittest.defaultTestLoader.loadTestsFromModule(lifecycle),unittest.defaultTestLoader.loadTestsFromModule(branches)))
        stream=io.StringIO();stdout=io.StringIO()
        try:
            with redirect_stdout(stdout):result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
        finally:boundary.os=original_os;boundary.shutil=original_shutil
        assert all(vars(case)[name] is value for case,methods in before_methods.items() for name,value in methods.items()),'whole-routine-test-method-replaced'
        rows=boundary.RUNS[original_count:];pairs=[row for row in rows if 'phase' in row]
        assert result.testsRun==8 and result.wasSuccessful(),(stream.getvalue(),result.failures,result.errors)
        assert len(pairs)==42 and sum(row['exitCode']==1 for row in pairs)==21 and sum(row['exitCode']==0 for row in pairs)==21
        skipped=[test.id() for test,reason in result.skipped]
        if mode=='without-powershell':assert len(skipped)==1 and skipped[0].endswith('test_actual_powershell_parser_when_available')
        else:
            assert all(test.endswith('test_actual_powershell_parser_when_available') for test in skipped)
            assert declared,'actual-fixture-import-never-observed-windows-like-peer'
        return {'mode':mode,'testsRun':result.testsRun,'actualBodyControls':48,'causalPairs':21,
            'skipped':skipped,'wholeTestMethodsUnchanged':True,'declaredOsImports':declared,
            'nativeExecuted':False,'networkExecuted':False,'testOutput':stream.getvalue(),'bodyOutput':stdout.getvalue(),'pairRows':pairs}
    finally:
        builtins.__import__=real_import
        if previous_powershell_env is not None:os.environ['VPN_CONTROL_TEST_POWERSHELL']=previous_powershell_env
        else:os.environ.pop('VPN_CONTROL_TEST_POWERSHELL',None)

if __name__=='__main__':
    value=run(sys.argv[1]);value.pop('pairRows');print(json.dumps(value,sort_keys=True))
