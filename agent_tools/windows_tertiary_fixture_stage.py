"""Finite source-bound host staging for the owned tertiary Windows fixture.

Does not dispatch SSH or perform a guest/installer action. The actual generated
program is regression tested with explicit local filesystem/UID/input seams.
"""
import uuid

ROOT = "/home/kardinal/vpn-control-windows-parallel-vm-tertiary-20261005"
TARGET_SHA256 = "f8a8741bcfd22c04be50836aa22da77009105ab1b63df4d9b7648397779a8dfc"
TARGET_SIZE = 131101044
SOURCE_SHA = "d32f719a08db57e5d40ce2bf77e0d7c5b42de557"

HOST_BODY = r'''import hashlib,json,os,stat,sys
parent=REQUEST['hostStage'].rsplit('/',1)[0]
stage=REQUEST['hostStage']
if os.geteuid()!=1000:raise ValueError('TERTIARY_UPLOAD_USER')
def identity(i):return(i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_gid)
def generation(i):return identity(i)+(i.st_nlink,i.st_size,i.st_mtime_ns,i.st_ctime_ns)
held=[];target_fd=None;final_target_generation=None
for path in ('/','/home','/home/kardinal',parent):
 i=os.lstat(path)
 if not stat.S_ISDIR(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid not in (0,1000) or i.st_mode&0o022:raise ValueError('TERTIARY_UPLOAD_PARENT')
 d=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 if identity(os.fstat(d))!=identity(i):raise ValueError('TERTIARY_UPLOAD_PARENT_FD')
 held.append((path,d,identity(i)))
before=os.lstat(parent)
if before.st_uid!=1000 or stat.S_IMODE(before.st_mode)!=0o700:raise ValueError('TERTIARY_UPLOAD_ROOT')
v=os.statvfs(parent)
if v.f_bavail*v.f_frsize<3*(1<<30):raise ValueError('TERTIARY_UPLOAD_SPACE')
def guard():
 for path,d,pin in held:
  if identity(os.fstat(d))!=pin or identity(os.lstat(path))!=pin:raise ValueError('TERTIARY_UPLOAD_DIRECTORY_CHANGED')
 if target_fd is not None:
  f=os.fstat(target_fd);n=os.stat('target.msi',dir_fd=dfd,follow_symlinks=False)
  if not stat.S_ISREG(f.st_mode) or f.st_uid!=1000 or f.st_nlink!=1 or stat.S_IMODE(f.st_mode)!=0o600 or generation(f)!=generation(n):raise ValueError('TERTIARY_UPLOAD_FILE_CHANGED')
  if final_target_generation is not None and generation(f)!=final_target_generation:raise ValueError('TERTIARY_UPLOAD_FINAL_GENERATION_CHANGED')
guard();os.mkdir(stage,0o700)
st=os.lstat(stage);dfd=os.open(stage,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
if st.st_uid!=1000 or stat.S_IMODE(st.st_mode)!=0o700 or identity(os.fstat(dfd))!=identity(st):raise ValueError('TERTIARY_UPLOAD_STAGE_FD')
held.append((stage,dfd,identity(st)));guard()
def once(name,raw):
 guard();fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=dfd)
 with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
 os.fsync(dfd);guard()
once('binding.json',json.dumps(REQUEST,sort_keys=True).encode())
once('upload-intent.json',b'{"submitted":true,"guestAction":false,"installerAction":false,"replayAllowed":false}')
guard();target_fd=os.open('target.msi',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=dfd);guard()
h=hashlib.sha256();remaining=REQUEST['targetSize']
with os.fdopen(target_fd,'wb',closefd=False) as f:
 while remaining:
  guard();part=sys.stdin.buffer.read(min(65536,remaining));guard()
  if not part:raise ValueError('TERTIARY_UPLOAD_EOF')
  f.write(part);h.update(part);remaining-=len(part);guard()
 guard();trailing=sys.stdin.buffer.read(1);guard()
 if trailing:raise ValueError('TERTIARY_UPLOAD_TRAILING')
 f.flush();os.fsync(f.fileno());guard()
final_target_generation=generation(os.fstat(target_fd));guard()
if h.hexdigest()!=REQUEST['targetSha256']:raise ValueError('TERTIARY_UPLOAD_HASH')
if os.fstat(target_fd).st_size!=REQUEST['targetSize']:raise ValueError('TERTIARY_UPLOAD_SIZE')
# Recompute exact bytes through the original held file once, never per chunk.
os.lseek(target_fd,0,0);actual=hashlib.sha256()
while True:
 part=os.read(target_fd,65536)
 if not part:break
 actual.update(part)
guard()
if actual.hexdigest()!=h.hexdigest():raise ValueError('TERTIARY_UPLOAD_READBACK')
result={'state':'staged','sha256':h.hexdigest(),'length':REQUEST['targetSize']}
once('complete.json',json.dumps(result,sort_keys=True).encode());guard()
print(json.dumps(result,sort_keys=True),flush=True)
os.close(target_fd)
for _,d,_ in reversed(held):os.close(d)
'''

def host_stage_program(request):
    correlation=request.get("correlation")
    if (not isinstance(correlation,str) or str(uuid.UUID(correlation))!=correlation
            or request.get("hostStage")!=ROOT+"/fixture-"+correlation
            or request.get("targetSha256")!=TARGET_SHA256
            or request.get("targetSize")!=TARGET_SIZE
            or request.get("sourceSha")!=SOURCE_SHA
            or request.get("installerAuthorized") is not False):
        raise ValueError("TERTIARY_HOST_STAGE_BINDING")
    return "REQUEST="+repr(dict(request))+"\n"+HOST_BODY
