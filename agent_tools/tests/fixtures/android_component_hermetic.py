"""Public inert component bodies and source-closed synthetic protocol contexts.

No checkout native histories/configuration are read. Actual backend and command
functions execute; only device/JVM effects and upstream receipt DTOs are seams.
"""
import ast,base64,copy,functools,hashlib,json,os,pathlib,re,select,stat,subprocess,time,types
from agent_tools import android_external_java_component_transport as transport
from agent_tools import android_component_command_transport as command
from agent_tools import android_api35_coldboot_product_observation as api35
from agent_tools.tests.fixtures.android_api29_epoch.adjacent import AdjacentContext
from agent_tools.tests.fixtures.android_api29_epoch.context import clone,guard
OWNER='6373d143-1372-4835-a89b-baafb0959b9f'

def jdk(alias='jdk17'):
 return {'state':'observed','alias':alias,'root':transport.proven.CANDIDATES[alias],'declaredJavaVersion':'17.0.20.1' if alias=='jdk17' else '21.0.8','files':{name:{'generation':[1,2,10,4,5,stat.S_IFREG|0o755,0,0,1],'bytesRead':10,'sha256':'a'*64,'hashScope':'full'}for name in transport.proven.JDK_FILES}}

class ComponentContext(AdjacentContext):
 def __init__(self,root):
  super().__init__(root)
  self.transport=clone(transport)
  self.transport.proven=self.external
  census=json.loads((self.root/self.external.CENSUS).read_bytes());census['baselineSha256']=self.external.BASELINE_SHA
  self.transport.CENSUS_SHA=self.write(self.external.CENSUS,census)
  proof=json.loads((self.root/self.component.PROOF).read_bytes())
  proof['records']={name:{'stderrRaw':''}for name in ('statusDiscovery','operationsBefore','statusPinned','operationsAfter','statusFinal')}
  proof['syntheticProtocol']=True
  self.transport.PROOF_SHA=self.write(self.component.PROOF,proof)
  original=self.transport.prepare_binding
  checkout=pathlib.Path(transport.__file__).resolve().parents[1]
  @functools.wraps(original)
  def relocated(root,prepared,device):
   root=pathlib.Path(root).resolve()
   if root==checkout:root=self.root
   elif root!=self.root:raise AssertionError('unexpected synthetic fixture root')
   return original(root,prepared,device)
  self.transport.prepare_binding=relocated
  self.command=clone(command);self.command.readonly=self.transport
 def prepared(self,device='android-api29'):
  value=self.owner_prepared()
  tree=ast.parse(value['program'])
  # The synthetic upstream provider inserts its same GETTER DTO twice while
  # combining actual templates. Keep one identical assignment; never alter a
  # getter body or accept differing identities.
  assignments=[n for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='GETTER'for t in n.targets)]
  if len(assignments)!=2 or ast.dump(assignments[0])!=ast.dump(assignments[1]):raise ValueError('synthetic_upstream_identity_changed')
  tree.body.remove(assignments[1]);value['program']=ast.unparse(tree)
  if device=='android-api35':
   tree=ast.parse(value['program']);node=next(n for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='GETTER'for t in n.targets))
   facts=ast.literal_eval(node.value);facts['generation']['device']['sdk']='35';node.value=ast.parse(repr(facts),mode='eval').body
   nodes=ast.parse(api35._GETTER.replace('__GETTER__','{}')).body
   for name in ('getter_cli','getter_bounded'):
    replacement=next(n for n in nodes if isinstance(n,ast.FunctionDef)and n.name==name)
    index=next(i for i,n in enumerate(tree.body)if isinstance(n,ast.FunctionDef)and n.name==name);tree.body[index]=replacement
   value['program']=ast.unparse(tree)
  elif device!='android-api29':raise ValueError('component_device_required')
  value['_historicalGuard']=guard
  # A real retained TempFS ledger snapshot for mutation coverage, not native evidence.
  path=self.root/self.external.BASELINE
  value['snapshots'][path]=transport.availability._snapshot(path)
  value['_modeledLaunchPath']=path
  return value
 def installed(self,device='android-api29'):
  p=self.prepared(device);b=self.transport.prepare_binding(self.root,p,device);self.transport.install(p,b);return p,b

def backend(device='android-api29'):
 # Public inert fixture runs the actual backend and frozen capture body without private files.
 getter={'cli':'/fixed/tree/opt/vpn-control/bin/vpn-control','stageId':'fixed-stage','packageSha256':'a'*64,'manifestSha256':'b'*64}
 b={'selectedJdk':jdk(),'classpath':['fixture%d.jar'%n for n in range(57)],'javaOptions':['-Djpackage.app-version=2.2.2','-Dcompose.application.resources.dir=$APPDIR/resources','-Dcompose.application.configure.swing.globals=true','-Dskiko.library.path=$APPDIR'],'serial':transport.DEVICES[device],'getterIdentity':getter,'backendSourceSha256':'c'*64}
 bounded=next(n for n in ast.parse(transport.bounded_source._OBSERVER).body if isinstance(n,ast.FunctionDef) and n.name=='getter_bounded')
 p={'program':'GETTER='+repr(getter)+'\nEXTERNAL='+repr(b)+'\n'+ast.unparse(bounded)+'\n'+transport._BACKEND+'\ndef getter_cli(words,owner=None):\n return component_cli(words,owner)\n'};tree=ast.parse(p['program']);nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('component_cli','getter_cli','getter_bounded') or isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='EXTERNAL' for t in n.targets)]
 env=dict(pathlib=pathlib,re=re,os=os,subprocess=subprocess,select=select,time=time,json=json,base64=base64,GETTER_RECORDS={},GETTER=transport._assignment(tree,'GETTER'),LAUNCH={'adbPath':'/fixed/adb','environment':{k:'fixed' for k in ('ANDROID_AVD_HOME','ANDROID_HOME','ANDROID_SDK_ROOT','HOME','LOGNAME','PATH','USER')}})
 exec(compile(ast.Module(body=nodes,type_ignores=[]),'<actual-installed-backend>','exec'),env)
 calls=[];env['getter_stage']=lambda:{'full155':'fixed'};env['external_jdk_guard']=lambda:None;env['public_cli_environment']=lambda *a:{}
 def invoke(path,pin,args,environment,limit):
  calls.append(args);raw=json.dumps({'ok':True,'code':'OK','controllerId':OWNER,'configurationRevision':0})
  env['GETTER_RECORDS'].setdefault('captures',[]).append({'returncode':0,'failure':None,'stdoutBase64':base64.b64encode(raw.encode()).decode(),'stderrBase64':'','stdoutBytes':len(raw.encode()),'stderrBytes':0})
  return {'returncode':0,'stdoutRaw':raw,'stderrRaw':''}
 env['getter_binary']=invoke
 return env,calls,p,b

def scope():
    env, calls, _, _ = backend()
    env['COMMAND_SOURCE_SHA']='d'*64
    exec(command.REMOTE, env)
    exec(command._bounded_source(),env)
    proxy=types.SimpleNamespace(**vars(os));proxy.getuid=proxy.geteuid=proxy.getgid=proxy.getegid=lambda:1000;proxy.getgroups=lambda:[1000,998]
    env['os']=proxy;env['COMMAND_HOST']=env['command_host_identity']()
    original=env['component_cli']
    def status(*args):
        value=original(*args);value['stdout'].update(final=True,data={'runtimeRunning':False});return value
    env['component_cli']=status
    def command_child(*args,**kwargs):
        kwargs.pop('timeout',None);value=env['getter_binary'](*args,**kwargs)
        value['stdoutRaw']=json.dumps({'ok':True,'final':True,'code':'OK','controllerId':OWNER,'configurationRevision':0,'data':{'runtimeRunning':False}})
        env['GETTER_RECORDS']['captures'][-1].update(stdoutBase64=base64.b64encode(value['stdoutRaw'].encode()).decode(),stdoutBytes=len(value['stdoutRaw'].encode()))
        return value
    env['command_binary']=command_child
    saved=[]; guards=[]
    def guard(): guards.append('guard')
    def capture(record): saved.append(record)
    return env, calls, saved, guards, guard, capture
