"""Local-only, source-bound route for disposable Android fixture TLS minting."""
from __future__ import annotations
import hashlib,json,os,stat,uuid
from pathlib import Path
from . import android_native_fixture as fixture
from . import android_fixture_tls_mint as mint
from .windows_diagnostic_authority_capture import AuthorityCapture
class RouteError(ValueError):pass
_FIELDS={'campaignId','sourceSha','baseArtifactId','targetArtifactId','sourceRoot'}
def _snapshot(path):
 parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
 try:
  before=os.fstat(fd);raw=b''
  while True:
   block=os.read(fd,65536)
   if not block:break
   raw+=block
  after=os.fstat(fd);named=os.stat(path.name,dir_fd=parent,follow_symlinks=False);parent_named=path.parent.lstat();parent_open=os.fstat(parent)
  if (parent_named.st_dev,parent_named.st_ino)!=(parent_open.st_dev,parent_open.st_ino):raise RouteError('source_parent_replaced')
  if before!=after or before!=named or not stat.S_ISREG(before.st_mode) or before.st_nlink!=1:raise RouteError('source_generation_changed')
  return raw,{'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'generation':[before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns,stat.S_IMODE(before.st_mode),before.st_uid,before.st_nlink]}
 finally:os.close(fd);os.close(parent)
def _write(parent_fd,name,data):
 fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent_fd)
 try:
  at=0
  while at<len(data):
   n=os.write(fd,data[at:])
   if n<=0:raise RouteError('archive_write_incomplete')
   at+=n
  os.fsync(fd)
 finally:os.close(fd)
 os.fsync(parent_fd)
def _dir_identity(info):return (info.st_dev,info.st_ino,info.st_uid,stat.S_IMODE(info.st_mode))
def _guard_named_directory(parent_fd,name,child_fd):
 named=os.stat(name,dir_fd=parent_fd,follow_symlinks=False);held=os.fstat(child_fd)
 if not stat.S_ISDIR(named.st_mode) or _dir_identity(named)!=_dir_identity(held):raise RouteError('route_named_child_replaced')
def _verify_mint_result(capture,result,held_fd=None):
 directory=Path(result.get('directory',''))
 if directory.parent!=capture.path or directory.is_symlink():raise RouteError('mint_directory_changed')
 fd=held_fd if held_fd is not None else os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  named=directory.lstat();held=os.fstat(fd)
  if _dir_identity(named)!=_dir_identity(held) or stat.S_IMODE(held.st_mode)!=0o700:raise RouteError('mint_directory_changed')
  receipt=result.get('receipt',{});files=receipt.get('files') if isinstance(receipt,dict) else None
  if not isinstance(files,dict) or set(files)!={'ca-key.pem','ca.pem','leaf-key.pem','leaf.pem'}:raise RouteError('mint_receipt_changed')
  for name,pin in files.items():mint._verify_named_file(fd,name,pin)
  receipt_pin=result['receipt'].get('receipt')
  if not isinstance(receipt_pin,dict):raise RouteError('mint_receipt_changed')
  mint._verify_named_file(fd,'receipt.json',receipt_pin)
  capture._check()
  return {'nestedName':directory.name,'nestedGeneration':[held.st_dev,held.st_ino,held.st_size,held.st_mtime_ns,held.st_ctime_ns,stat.S_IMODE(held.st_mode),held.st_uid,held.st_nlink],'materialPins':{**files,'receipt.json':receipt_pin}}
 finally:
  if held_fd is None:os.close(fd)
def run(root,inputs):
 if not isinstance(inputs,dict) or set(inputs)-_FIELDS or set(inputs)-{'sourceRoot'}!={'campaignId','sourceSha','baseArtifactId','targetArtifactId'}:raise RouteError('route_inputs_invalid')
 root=Path(root).resolve();campaign=inputs['campaignId']
 try:
  if str(uuid.UUID(campaign))!=campaign:raise ValueError()
 except Exception as e:raise RouteError('campaign_invalid') from e
 source_root=inputs.get('sourceRoot')
 if source_root is not None and not isinstance(source_root,str):raise RouteError('source_root_invalid')
 requirements=fixture.prepare_requirements(root,inputs['sourceSha'],inputs['baseArtifactId'],source_root=source_root)
 plan=fixture.verify_target(root,requirements,inputs['targetArtifactId'],source_root=source_root)
 needed={'sourceSha','baseArtifactId','baseVersion','baseCode','baseSignerSha256','targetArtifactId','targetVersion','targetCode','targetSha256','targetSize','endpoint','deviceMutationAllowed'}
 if set(plan)!=set(requirements)|{'targetArtifactId','targetSha256','targetSize'} or set(plan)&needed!=needed:raise RouteError('verified_plan_shape_changed')
 leaf='android-fixture-tls-route-'+campaign
 parent=root/'.runtime'/'parity-evidence';parent.mkdir(parents=True,exist_ok=True,mode=0o700)
 try:(parent/leaf).mkdir(mode=0o700)
 except FileExistsError as e:raise RouteError('campaign_consumed') from e
 capture=AuthorityCapture(root,leaf)
 nested=[None]
 try:
  sources=[Path(mint.__file__),Path(__file__),Path(fixture.__file__),Path(__file__).with_name('tests')/'test_android_fixture_tls_mint.py',Path(__file__).with_name('tests')/'test_android_fixture_tls_routes.py']
  captured={p:_snapshot(p) for p in sources};capture._check()
  provenance={'schema':1,'campaignId':campaign,'inputs':{k:v for k,v in inputs.items() if k!='sourceRoot'},'plan':plan,'sourcePins':{p.name:pin for p,(_,pin) in captured.items()},'deviceMutationAllowed':False}
  pins={'provenance.json':capture.create('provenance.json',(json.dumps(provenance,sort_keys=True,separators=(',',':'))+'\n').encode()),'verified-plan.json':capture.create('verified-plan.json',(json.dumps(plan,sort_keys=True,separators=(',',':'))+'\n').encode())}
  for p,(raw,_) in captured.items():pins[p.name+'.source']=capture.create(p.name+'.source',raw)
  for name,pin in pins.items():capture.verify(name,pin)
  def opened(path):
   nested[0]=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
   named=os.stat(path.name,dir_fd=capture.fd,follow_symlinks=False)
   if _dir_identity(named)!=_dir_identity(os.fstat(nested[0])):raise RouteError('mint_directory_changed')
   capture._check()
  capture._check();result=mint.mint(capture.path,campaign,{k:plan[k] for k in needed},after_directory_create=opened);nested_binding=_verify_mint_result(capture,result,nested[0]);capture._check()
  if fixture.prepare_requirements(root,inputs['sourceSha'],inputs['baseArtifactId'],source_root=source_root)!=requirements or fixture.verify_target(root,requirements,inputs['targetArtifactId'],source_root=source_root)!=plan or any(_snapshot(p)[1]!=pin for p,(_,pin) in captured.items()):raise RouteError('source_or_artifact_drift')
  for name,pin in pins.items():capture.verify(name,pin)
  receipt={'schema':1,'campaignId':campaign,'tlsReceipt':result['receipt']['receipt'],'nestedBinding':nested_binding,'verifiedPlanSha256':hashlib.sha256(json.dumps(plan,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'deviceMutationAllowed':False}
  _verify_mint_result(capture,result,nested[0]);finalpin=capture.create('route-receipt.json',(json.dumps(receipt,sort_keys=True,separators=(',',':'))+'\n').encode());capture.verify('route-receipt.json',finalpin);_verify_mint_result(capture,result,nested[0]);capture._check()
  return {'ok':True,'campaignId':campaign,'receipt':receipt,'deviceMutationPerformed':False,'evidenceDirectory':str(capture.path)}
 except ValueError as e:
  raise RouteError('authority_changed') from e
 finally:
  if nested[0] is not None:
   try:os.close(nested[0])
   except OSError:pass
  capture.close()
