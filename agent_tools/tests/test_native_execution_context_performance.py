"""Repository-shaped actual byte/FD control; no native or remote process runs."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import unittest
from agent_tools import native_execution_context as context
from agent_tools.tests import test_native_execution_context as fixtures

_CHILD = r'''
import errno,json,os,resource,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from agent_tools import native_execution_context as context
from agent_tools import native_artifact_registry as registry
root=Path(sys.argv[2]);source=Path(sys.argv[3]);request=json.loads(sys.argv[4])
resource.setrlimit(resource.RLIMIT_NOFILE,(1024,resource.getrlimit(resource.RLIMIT_NOFILE)[1]))
real_open=os.open;real_close=os.close;real_dup=os.dup;real_popen=subprocess.Popen
live=set();peak=0;git_calls=0
def opened(*a,**kw):
 global peak
 fd=real_open(*a,**kw);live.add(fd);peak=max(peak,len(live));return fd
def duplicated(*a,**kw):
 global peak
 fd=real_dup(*a,**kw);live.add(fd);peak=max(peak,len(live));return fd
def closed(fd):live.discard(fd);return real_close(fd)
def launched(*a,**kw):
 global git_calls
 argv=a[0] if a else kw.get('args',[])
 if isinstance(argv,(list,tuple)) and argv and argv[0]=='git':git_calls+=1
 return real_popen(*a,**kw)
os.open=opened;os.close=closed;os.dup=duplicated;subprocess.Popen=launched
metrics={'ok':False,'softFdLimit':1024}
try:
 package=root/'package.bin';package.write_bytes(b'original actual package');package.chmod(0o600)
 import hashlib
 artifact=registry.register_artifact(root,{'platform':'linux','artifactKind':'package','localPath':str(package),
  'sha256':hashlib.sha256(package.read_bytes()).hexdigest(),'size':package.stat().st_size,
  'evidenceClass':'local-verified','sourceSha':request['sourceSha']})
 begin=time.monotonic();qualified=context.EngineeringExecutionContext.qualify(root,source,request,(artifact['artifactId'],))
 metrics.update(qualificationSeconds=time.monotonic()-begin,qualificationGitProcesses=git_calls)
 begin=time.monotonic();before=git_calls;qualified.revalidate(source,request)
 metrics.update(ok=True,revalidateSeconds=time.monotonic()-begin,revalidateGitProcesses=git_calls-before,
                catalogueFiles=len(json.loads(qualified.authority)['catalogue']),finalAcceptance=False)
except Exception as error:
 metrics.update(errorType=type(error).__name__,errorErrno=getattr(error,'errno',None),gitProcessesBeforeFailure=git_calls)
finally:
 metrics['peakTrackedFDs']=peak
 print(json.dumps(metrics,sort_keys=True))
'''

@unittest.skipUnless(os.name=='posix' and shutil.which('git'),'POSIX local Git/FD control')
class NativeContextPerformanceTest(unittest.TestCase):
    setUp=fixtures.NativeExecutionContextTest.setUp
    git=fixtures.NativeExecutionContextTest.git
    def test_actual_1938_file_231mb_context_qualifies_and_revalidates_under_1024_fds(self):
        # Include the complete real scripts inventory, matching held native source
        # population as well as a large Kotlin/resource product population.
        shutil.copytree(fixtures.ROOT/'scripts',self.coordinator/'scripts',dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns('__pycache__'))
        self.git('add','scripts');self.git('commit','-m','complete fixed script inventory')
        tracked=[p for p in self.git('ls-tree','-r','--name-only','HEAD').splitlines() if not context._safe(p)]
        count=1938-len(tracked);self.assertGreater(count,0)
        current=sum((self.coordinator/p).stat().st_size for p in tracked)
        target=231_320_860;remaining=target-current;size,remainder=divmod(remaining,count)
        for i in range(count):
            path=self.coordinator/'desktopApp/src/main/resources/performance'/str(i%64)/(str(i)+'.bin')
            path.parent.mkdir(parents=True,exist_ok=True)
            length=size+(i<remainder);header=(str(i)+'\n').encode()
            path.write_bytes(header+b'R'*(length-len(header)))
        self.git('add','desktopApp');self.git('commit','-m','1938-file 231MB actual local source fixture')
        sha=self.git('rev-parse','HEAD');self.git('push','origin','dev')
        source=self.base/'shape-native';self.git('worktree','add','--detach',str(source),sha)
        request={**self.request,'sourceSha':sha}
        child=subprocess.run([sys.executable,'-I','-B','-c',_CHILD,str(fixtures.ROOT),str(self.coordinator),
                              str(source),json.dumps(request)],capture_output=True,text=True,timeout=180,check=True)
        metrics=json.loads(child.stdout);metrics.update(fixtureFiles=1938,fixtureBytes=target)
        if os.environ.get('VPN_CONTEXT_PERF_EVIDENCE'):
            Path(os.environ['VPN_CONTEXT_PERF_EVIDENCE']).write_text(json.dumps(metrics,indent=2,sort_keys=True))
        self.assertTrue(metrics['ok'],metrics)
        self.assertEqual(1938,metrics['catalogueFiles'])
        self.assertLessEqual(metrics['qualificationGitProcesses'],64)
        self.assertLessEqual(metrics['revalidateGitProcesses'],32)
        self.assertLess(metrics['peakTrackedFDs'],1024)
