"""Static ignored inventory diagnostics component; no native/CLI dispatch."""
import dis,errno,hashlib,json,os,stat
from pathlib import Path
from . import ssh_fresh_nested_channel as channel,private_inventory_lock as private
_CLASSES={c:c.__name__ for c in (ValueError,TypeError,KeyError,OSError,FileNotFoundError,PermissionError,BlockingIOError,NotADirectoryError,IsADirectoryError)}
ROLES=frozenset(('ownership_presented_path','ownership_root_directory','ownership_lock_directory','ownership_lock_file','ownership_lock_acquisition','config_snapshot','unclassified_inventory'))
CLASSES=frozenset(_CLASSES.values())|{'Other'}
def base_detail(failure):
    codes=set()
    cursor=failure.__traceback__
    while cursor is not None:
        codes.add(cursor.tb_frame.f_code);cursor=cursor.tb_next
    def has(cls):return any(getattr(cls,n).__code__ in codes for n in ('__init__','guard'))
    if has(private.PresentedPath):role='ownership_presented_path'
    elif has(private.Snapshot):role='ownership_lock_file' if has(private.InventoryLock) else 'config_snapshot'
    elif has(private.InventoryLock):role='ownership_lock_acquisition'
    elif has(private.Directory):role='ownership_lock_directory' if private.lock_directory.__code__ in codes else 'ownership_root_directory'
    else:role='unclassified_inventory'
    return {'kind':'inventory_exception','exceptionClass':_CLASSES.get(type(failure),'Other'),'role':role,'transportStarted':False,'rawCaptureAvailable':False,'authority':False}

def base_validate(event):
 if type(event)is not dict or set(event)!={'kind','exceptionClass','role','transportStarted','rawCaptureAvailable','authority'}:raise ValueError('diagnostic_shape')
 if type(event['kind'])is not str or event['kind']!='inventory_exception' or type(event['exceptionClass'])is not str or event['exceptionClass']not in CLASSES or type(event['role'])is not str or event['role']not in ROLES:raise ValueError('diagnostic_token')
 if any(type(event[k])is not bool or event[k] is not False for k in ('transportStarted','rawCaptureAvailable','authority')):raise ValueError('diagnostic_authority')

FLOCK_LINES={187}
FLOCK_CALLS={i.offset for i in dis.get_instructions(private.InventoryLock.__init__) if i.opname=="CALL" and i.positions.lineno in FLOCK_LINES}
assert len(FLOCK_CALLS)==1
BUSY_ERRNOS=frozenset((errno.EAGAIN,errno.EWOULDBLOCK))
def detail(exc):
 event=base_detail(exc);number=getattr(exc,'errno',None)
 number=number if type(number)is int and 0<=number<=255 else None
 cursor=exc.__traceback__;proven=False
 while cursor is not None:
  if cursor.tb_frame.f_code is private.InventoryLock.__init__.__code__ and cursor.tb_lineno in FLOCK_LINES and cursor.tb_lasti in FLOCK_CALLS:proven=True
  cursor=cursor.tb_next
 event.update(phase='inventory',errno=number,inventoryOperation='config_lock_flock_nonblocking' if proven and type(exc)is BlockingIOError and number in BUSY_ERRNOS else None)
 return event


def validate(event):
 if type(event)is not dict or set(event)!= {'kind','exceptionClass','role','transportStarted','rawCaptureAvailable','authority','phase','errno','inventoryOperation'}:raise ValueError('diagnostic_schema')
 base_validate({k:v for k,v in event.items() if k not in ('phase','errno','inventoryOperation')})
 if type(event['phase'])is not str or event['phase']!='inventory' or (event['errno'] is not None and (type(event['errno'])is not int or not 0<=event['errno']<=255)):raise ValueError('diagnostic_type')
 op=event['inventoryOperation']
 if op is not None and (type(op)is not str or op!='config_lock_flock_nonblocking' or event['role']!='ownership_lock_acquisition' or event['exceptionClass']!='BlockingIOError' or event['errno'] not in BUSY_ERRNOS):raise ValueError('diagnostic_operation')


def is_busy(receipts):
 if type(receipts)is not list or len(receipts)!=1:return False
 receipt=receipts[0]
 if type(receipt)is not dict or set(receipt)!={'event','sha256','bytes'}:return False
 try:validate(receipt['event'])
 except (TypeError,ValueError):return False
 e=receipt['event']
 return e['inventoryOperation']=='config_lock_flock_nonblocking' and e['errno'] in BUSY_ERRNOS

def retain(output,index,event,*,_before_close=lambda:None):
 validate(event)
 if type(index)is not int or not 0<=index<120:raise ValueError('diagnostic_index')
 output=Path(output).absolute();name='query-%04d.inventory.json'%index
 value={'schemaVersion':1,'sourceFingerprint':channel._source(),'event':event}
 body=json.dumps(value,sort_keys=True,separators=(',',':')).encode();fd=-1
 with private.Directory(output) as directory:
  if os.fstat(directory.fd).st_mode & 0o077:raise ValueError('diagnostic_directory_private')
  try:
   fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory.fd)
   at=0
   while at<len(body):
    written=os.write(fd,body[at:])
    if written<=0:raise OSError('diagnostic_write')
    at+=written
   os.fsync(fd);pin=private._generation(os.fstat(fd))
   info=os.fstat(fd)
   if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:raise ValueError('diagnostic_file_shape')
   if os.pread(fd,len(body)+1,0)!=body:raise ValueError('diagnostic_bytes')
   os.fsync(directory.fd);_before_close();directory.guard()
   if os.pread(fd,len(body)+1,0)!=body:raise ValueError('diagnostic_bytes')
   if private._generation(os.stat(name,dir_fd=directory.fd,follow_symlinks=False))!=pin or private._generation(os.fstat(fd))!=pin:raise ValueError('diagnostic_closing')
   return {'event':event,'sha256':hashlib.sha256(body).hexdigest(),'bytes':len(body)}
  finally:
   if fd>=0:os.close(fd)
