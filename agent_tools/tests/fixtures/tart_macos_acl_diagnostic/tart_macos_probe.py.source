"""Fixed read-only macOS GUEST probe; no admission, dispatch or lifecycle actions.

Only the fixture owner may execute main in its isolated guest. Importing this
module never opens a framework or observes the coordinator host. Unqualified
launchd/job baselines deliberately leave complete idle visibility false.

Native API references:
https://developer.apple.com/documentation/systemconfiguration/scdynamicstorecopyconsoleuser(_:_:_:)
https://developer.apple.com/documentation/coregraphics/cgsessioncopycurrentdictionary()
https://developer.apple.com/documentation/coregraphics/cggetonlinedisplaylist(_:_:_:)
https://developer.apple.com/documentation/coregraphics/cgdisplayisasleep(_:)
https://developer.apple.com/documentation/iokit/1514293-ioregistryentrycreatecfproperty
https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info.h
"""
from __future__ import annotations
import ctypes as C
import json
import os
import plistlib
if os.name == 'posix':
    import pwd
else:
    pwd = None
import re
import sys
import uuid


class ProbeUnavailable(ValueError):
    pass


def _uuid(value):
    if type(value)is not str:
        raise ProbeUnavailable('macos_identity_unavailable')
    try:actual=str(uuid.UUID(value))
    except ValueError:raise ProbeUnavailable('macos_identity_unavailable') from None
    if actual!=value.lower():raise ProbeUnavailable('macos_identity_unavailable')
    return actual


def _one(row,keys,kind):
    values=[row[k] for k in keys if k in row]
    if not values or any(type(v)is not kind for v in values)or any(v!=values[0]for v in values):return None
    return values[0]


def console_facts(name,uid,rows,caller=None,global_locked=None):
    """Never interpret an absent lock key or a non-console caller as unlocked."""
    result={'name':None,'uid':None,'onConsole':None,'locked':None,'session':None}
    if (type(name)is not str or not name or len(name)>256 or any(ord(c)<32 for c in name)
            or type(uid)is not int or uid<0):return result
    result.update(name=name,uid=uid)
    if name in {'loginwindow','root','_mbsetupuser'}or uid<501:return result
    candidates=[]
    for row in rows if type(rows)is list else []:
        if type(row)is not dict:continue
        row_uid=_one(row,('kCGSSessionUserIDKey','kCGSessionUserIDKey'),int)
        row_name=_one(row,('kCGSSessionUserNameKey','kCGSessionUserNameKey'),str)
        if row_uid==uid and row_name==name:candidates.append(row)
    if type(caller)is dict:
        if (_one(caller,('kCGSSessionUserIDKey','kCGSessionUserIDKey'),int)==uid
                and _one(caller,('kCGSSessionUserNameKey','kCGSessionUserNameKey'),str)==name):candidates.append(caller)
    active=[row for row in candidates if _one(row,('kCGSSessionOnConsoleKey','kCGSessionOnConsoleKey'),bool)is True]
    if not active:return result
    sessions=[_one(row,('kSCSecuritySessionID',),int)for row in active]
    if any(s is None or s<0 for s in sessions)or len(set(sessions))!=1:return result
    result.update(onConsole=True,session=str(sessions[0]))
    locks=[]
    for row in active:
        if any(k in row for k in ('CGSSessionScreenIsLocked','IOConsoleLocked')):
            value=_one(row,('CGSSessionScreenIsLocked','IOConsoleLocked'),bool)
            if type(value)is not bool:return result
            locks.append(value)
    if global_locked is not None:
        if type(global_locked)is not bool:return result
        locks.append(global_locked)
    # A partial/ambiguous dictionary remains unknown, even on the console.
    if locks and all(type(v)is bool for v in locks)and len(set(locks))==1:result['locked']=locks[0]
    return result


def display_facts(rows):
    if (type(rows)is not list or not 1<=len(rows)<=64 or
            any(type(row)is not tuple or len(row)!=2 or type(row[0])is not int or row[0]<=0
                or type(row[1])is not bool for row in rows)or len({v[0]for v in rows})!=len(rows)):
        return 'unknown'
    return 'sleeping' if all(row[1]for row in rows)else 'ready'


_PROTECTED=re.compile(r'(sing.?box|vpn.?control|openvpn|wireguard|tailscaled|zerotier|charon|strongswan|pppd)',re.I)
_INSTALLER=re.compile(r'^(installer|installd|system_installd|softwareupdated|softwareupdate|osinstallersetupd|osinstaller|startosinstall|installassistant|packagekit)$',re.I)


def process_facts(first,second,*,observer_pid,observer_uid):
    """Root must observe every stable process; unqualified baseline blocks idle."""
    complete=observer_uid==0 and type(first)is list and type(second)is list
    def project(rows):
        seen={};facts=[]
        for row in rows if type(rows)is list else []:
            if (type(row)is not dict or set(row)!={'pid','uid','birth','path'}
                    or type(row['pid'])is not int or row['pid']<=0
                    or type(row['uid'])is not int or row['uid']<0
                    or type(row['birth'])is not tuple or len(row['birth'])!=2
                    or any(type(n)is not int or n<0 for n in row['birth']) or row['birth'][0]==0 or row['birth'][1]>=1000000
                    or type(row['path'])is not str or not row['path'].startswith('/')
                    or row['pid']in seen):raise ProbeUnavailable('macos_process_visibility_incomplete')
            seen[row['pid']]=row
            role=('verified_probe'if row['pid']==observer_pid else
                  'protected_runtime'if _PROTECTED.search(row['path'])else
                  'installer'if _INSTALLER.fullmatch(row['path'].rsplit('/',1)[-1])else 'unmanaged')
            facts.append({'pid':row['pid'],'uid':row['uid'],'birth':'darwin:'+str(row['birth'][0])+':'+str(row['birth'][1]),'executableRole':role})
        return seen,sorted(facts,key=lambda r:r['pid'])
    try:
        one,rows=project(first);two,_=project(second)
        complete=complete and one==two and observer_pid in one
    except ProbeUnavailable:complete=False;rows=[]
    protected=[row['pid']for row in rows if row['executableRole']=='protected_runtime']
    installers=[row['pid']for row in rows if row['executableRole']=='installer']
    unmanaged=[{'pid':row['pid'],'uid':row['uid'],'birth':row['birth'],'role':row['executableRole']}for row in rows if row['executableRole']!='verified_probe']
    return {'processVisibilityComplete':complete,'processes':rows,'protectedProcesses':protected,
            'installerVisibilityComplete':complete,'installerBlockers':installers,
            'jobVisibilityComplete':False,'runningJobs':unmanaged,
            'unknownJobs':[{'role':'macos_launchd_and_durable_job_baseline_unqualified'}]}


class _Bsd(C.Structure):
    _fields_=[(n,C.c_uint32)for n in ('flags','status','xstatus','pid','ppid','uid','gid','ruid','rgid','svuid','svgid','reserved')]+[
        ('comm',C.c_char*16),('name',C.c_char*32)]+[(n,C.c_uint32)for n in ('nfiles','pgid','pjobc','tdev','tpgid')]+[
        ('nice',C.c_int32),('start_seconds',C.c_uint64),('start_microseconds',C.c_uint64)]


class _Timeval(C.Structure):
    _fields_=[('seconds',C.c_long),('microseconds',C.c_int32)]


class Native:
    """Fixed read-only C entrypoints; instantiated only inside guest collect."""
    def __init__(self):
        if sys.platform!='darwin':raise ProbeUnavailable('macos_guest_required')
        self.cf=C.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
        self.cg=C.CDLL('/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics')
        self.sc=C.CDLL('/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration')
        self.io=C.CDLL('/System/Library/Frameworks/IOKit.framework/IOKit')
        self.lib=C.CDLL('/usr/lib/libSystem.B.dylib',use_errno=True)
        self.proc=C.CDLL('/usr/lib/libproc.dylib',use_errno=True)
        self._fn(self.cf,'CFRelease',None,[C.c_void_p])
        self._fn(self.cf,'CFStringCreateWithCString',C.c_void_p,[C.c_void_p,C.c_char_p,C.c_uint32])
        self._fn(self.cf,'CFPropertyListCreateData',C.c_void_p,[C.c_void_p,C.c_void_p,C.c_long,C.c_ulong,C.POINTER(C.c_void_p)])
        self._fn(self.cf,'CFDataGetLength',C.c_long,[C.c_void_p]);self._fn(self.cf,'CFDataGetBytePtr',C.c_void_p,[C.c_void_p])
        self._fn(self.sc,'SCDynamicStoreCopyConsoleUser',C.c_void_p,[C.c_void_p,C.POINTER(C.c_uint32),C.POINTER(C.c_uint32)])
        self._fn(self.cg,'CGSessionCopyCurrentDictionary',C.c_void_p,[])
        self._fn(self.cg,'CGGetOnlineDisplayList',C.c_int,[C.c_uint32,C.POINTER(C.c_uint32),C.POINTER(C.c_uint32)])
        self._fn(self.cg,'CGDisplayIsAsleep',C.c_uint32,[C.c_uint32])
        self._fn(self.io,'IORegistryGetRootEntry',C.c_uint32,[C.c_uint32])
        self._fn(self.io,'IOServiceMatching',C.c_void_p,[C.c_char_p]);self._fn(self.io,'IOServiceGetMatchingService',C.c_uint32,[C.c_uint32,C.c_void_p])
        self._fn(self.io,'IORegistryEntryCreateCFProperty',C.c_void_p,[C.c_uint32,C.c_void_p,C.c_void_p,C.c_uint32])
        self._fn(self.io,'IOObjectRelease',C.c_int,[C.c_uint32])
        self._fn(self.lib,'sysctlbyname',C.c_int,[C.c_char_p,C.c_void_p,C.POINTER(C.c_size_t),C.c_void_p,C.c_size_t])
        self._fn(self.proc,'proc_listallpids',C.c_int,[C.c_void_p,C.c_int])
        self._fn(self.proc,'proc_pidinfo',C.c_int,[C.c_int,C.c_int,C.c_uint64,C.c_void_p,C.c_int])
        self._fn(self.proc,'proc_pidpath',C.c_int,[C.c_int,C.c_void_p,C.c_uint32])
    @staticmethod
    def _fn(lib,name,result,args):
        fn=getattr(lib,name);fn.restype=result;fn.argtypes=args
    def value(self,owned):
        if not owned:return None
        data=None;error=C.c_void_p()
        try:
            data=self.cf.CFPropertyListCreateData(None,owned,100,0,C.byref(error))
            if not data:raise ProbeUnavailable('macos_property_unavailable')
            size=self.cf.CFDataGetLength(data)
            if not 0<size<=2*1024*1024:raise ProbeUnavailable('macos_property_overflow')
            return plistlib.loads(C.string_at(self.cf.CFDataGetBytePtr(data),size))
        finally:
            if error.value:self.cf.CFRelease(error)
            if data:self.cf.CFRelease(data)
            self.cf.CFRelease(owned)
    def property(self,service,key):
        text=self.cf.CFStringCreateWithCString(None,key.encode('ascii'),0x08000100)
        if not text:raise ProbeUnavailable('macos_property_unavailable')
        try:return self.value(self.io.IORegistryEntryCreateCFProperty(service,text,None,0))
        finally:self.cf.CFRelease(text)
    def machine(self):
        entry=self.io.IOServiceGetMatchingService(0,self.io.IOServiceMatching(b'IOPlatformExpertDevice'))
        if not entry:raise ProbeUnavailable('macos_identity_unavailable')
        try:return _uuid(self.property(entry,'IOPlatformUUID'))
        finally:self.io.IOObjectRelease(entry)
    def boot(self):
        buffer=C.create_string_buffer(128);size=C.c_size_t(len(buffer))
        if self.lib.sysctlbyname(b'kern.bootsessionuuid',buffer,C.byref(size),None,0)or not 1<size.value<=128:raise ProbeUnavailable('macos_boot_unavailable')
        boot=_uuid(buffer.value.decode('ascii'))
        value=_Timeval();size=C.c_size_t(C.sizeof(value))
        if self.lib.sysctlbyname(b'kern.boottime',C.byref(value),C.byref(size),None,0)or size.value!=C.sizeof(value)or value.seconds<=0 or not 0<=value.microseconds<1000000:raise ProbeUnavailable('macos_boot_unavailable')
        return boot,{'seconds':value.seconds,'microseconds':value.microseconds}
    def console(self):
        uid=C.c_uint32();gid=C.c_uint32()
        name=self.value(self.sc.SCDynamicStoreCopyConsoleUser(None,C.byref(uid),C.byref(gid)))
        entry=self.io.IORegistryGetRootEntry(0)
        try:
            rows=self.property(entry,'IOConsoleUsers')if entry else None
            locked=self.property(entry,'IOConsoleLocked')if entry else None
        finally:
            if entry:self.io.IOObjectRelease(entry)
        caller=self.value(self.cg.CGSessionCopyCurrentDictionary())
        return console_facts(name,uid.value,rows,caller,locked)
    def displays(self):
        def snapshot():
            count=C.c_uint32()
            if self.cg.CGGetOnlineDisplayList(0,None,C.byref(count))or not 1<=count.value<=64:return None
            expected=count.value;array=(C.c_uint32*expected)()
            if self.cg.CGGetOnlineDisplayList(expected,array,C.byref(count))or count.value!=expected:return None
            values=[(int(d),self.cg.CGDisplayIsAsleep(d))for d in array]
            if any(v not in (0,1)for _,v in values):return None
            return [(d,bool(v))for d,v in values]
        first=snapshot();second=snapshot()
        return display_facts(first)if first is not None and first==second else 'unknown'
    def processes(self):
        total=self.proc.proc_listallpids(None,0)
        if not 0<total<65536:raise ProbeUnavailable('macos_process_visibility_incomplete')
        capacity=min(total+256,65536);array=(C.c_int*capacity)()
        count=self.proc.proc_listallpids(array,C.sizeof(array))
        if not 0<count<capacity:raise ProbeUnavailable('macos_process_visibility_incomplete')
        result=[]
        for pid in array[:count]:
            if pid==0:continue # kernel task is outside the user-process namespace
            info=_Bsd();path=C.create_string_buffer(4096)
            if (pid<0 or self.proc.proc_pidinfo(pid,3,0,C.byref(info),C.sizeof(info))!=C.sizeof(info)
                    or info.pid!=pid):raise ProbeUnavailable('macos_process_visibility_incomplete')
            path_size=self.proc.proc_pidpath(pid,path,len(path))
            if not 0<path_size<len(path):raise ProbeUnavailable('macos_process_visibility_incomplete')
            result.append({'pid':pid,'uid':info.uid,'birth':(info.start_seconds,info.start_microseconds),'path':path.value.decode('utf-8','strict')})
        return result


def collect(ordinary_account):
    if os.name!='posix' or pwd is None:raise ProbeUnavailable('macos_guest_required')
    if type(ordinary_account)is not str or re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,63}',ordinary_account)is None:raise ProbeUnavailable('macos_ordinary_account_unavailable')
    try:account=pwd.getpwnam(ordinary_account)
    except KeyError:raise ProbeUnavailable('macos_ordinary_account_unavailable')from None
    if account.pw_uid<501 or not account.pw_dir.startswith('/Users/'):raise ProbeUnavailable('macos_ordinary_account_unavailable')
    try:native=Native()
    except (OSError,AttributeError):raise ProbeUnavailable('macos_native_api_unavailable')from None
    machine=native.machine();boot,boot_time=native.boot()
    observer=pwd.getpwuid(os.geteuid())
    try:console=native.console()
    except (OSError,ValueError,TypeError,AttributeError):console=console_facts(None,None,None)
    try:display=native.displays()
    except (OSError,ValueError,TypeError,AttributeError):display='unknown'
    try:first=native.processes();second=native.processes()
    except (OSError,ValueError,UnicodeError):first=second=None
    facts=process_facts(first,second,observer_pid=os.getpid(),observer_uid=os.geteuid())
    final_boot,final_time=native.boot()
    if final_boot!=boot or final_time!=boot_time or native.machine()!=machine:raise ProbeUnavailable('macos_identity_changed')
    return {'machine':machine,'boot':boot,'bootTime':boot_time,'uid':account.pw_uid,
            'account':account.pw_name,'home':account.pw_dir,
            'observerUid':os.geteuid(),'observerAccount':observer.pw_name,'observerHome':observer.pw_dir,
            'console':console,'display':display,**facts}


def main():
    try:value=collect(globals().get('__ordinary_account__'))
    except (ProbeUnavailable,OSError,UnicodeError)as error:
        reason=str(error)if isinstance(error,ProbeUnavailable)else 'macos_observation_unavailable'
        print(json.dumps({'state':'blocked','reason':reason},sort_keys=True));raise SystemExit(3)
    print(json.dumps(value,sort_keys=True))

if __name__=='__main__':main()
