"""Bounded, read-only ten-command Android conversation; grants no admission.

The caller owns source/device/actor/lease fences. This helper never replaces a
physical guard, runs public app commands, claims a lease, or writes guest files.
It is not integrated into CurrentGuard or OwnerAdmissionGuard.
"""
from __future__ import annotations
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import shlex
import stat
import subprocess
import sys
import time
import uuid

FRAME_LIMIT=16384
STEP_SECONDS=20
TOTAL_SECONDS=200
PROCESS_READ='for n in adbd zygote zygote64; do for p in $(pidof "$n"); do printf \'%s\\t%s\\t\' "$n" "$p"; cat /proc/$p/stat; done; done'
PROPERTIES=('ro.build.version.sdk','ro.product.cpu.abi','ro.kernel.qemu.avd_name','ro.boot.qemu.avd_name','sys.boot_completed')
UUID_PATTERN=r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}'

class ConversationUnknown(ValueError):
    """An incomplete or changed observation; never absence or replay authority."""

def _fp(info):
    return dict(device=info.st_dev,inode=info.st_ino,mode=info.st_mode,uid=info.st_uid,
                gid=info.st_gid,nlink=info.st_nlink,size=info.st_size,
                mtimeNs=info.st_mtime_ns,ctimeNs=info.st_ctime_ns)

def _parent_fp(info):
    return tuple(getattr(info,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid'))

def _chain(path):
    if os.name!='posix' or not hasattr(os,'O_NOFOLLOW'):raise ValueError('physical_posix_fd_required')
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts:raise ValueError('physical_absolute_path_required')
    rows=[]
    try:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY);rows.append((fd,_parent_fp(os.fstat(fd)),None))
        for part in path.parts[1:-1]:
            fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=rows[-1][0])
            rows.append((fd,_parent_fp(os.fstat(fd)),part))
        return rows,path.name
    except BaseException:
        for fd,_,_ in reversed(rows):os.close(fd)
        raise

def _parents(rows):
    for n,(fd,pin,name) in enumerate(rows):
        if _parent_fp(os.fstat(fd))!=pin:raise ConversationUnknown('physical_parent_changed')
        if n and _parent_fp(os.stat(name,dir_fd=rows[n-1][0],follow_symlinks=False))!=pin:
            raise ConversationUnknown('physical_parent_changed')

def _close(rows):
    for fd,_,_ in reversed(rows):os.close(fd)

def _digest(fd):
    if os.fstat(fd).st_size>64*1024*1024:raise ConversationUnknown('physical_binary_size')
    digest=hashlib.sha256();offset=0
    while True:
        raw=os.pread(fd,65536,offset)
        if not raw:break
        offset+=len(raw)
        if offset>64*1024*1024:raise ConversationUnknown('physical_binary_size')
        digest.update(raw)
    return digest.hexdigest()

def binary_pin(path):
    """Local executable snapshot, not native ownership or source admission."""
    rows,name=_chain(path);fd=None
    try:
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=rows[-1][0])
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not info.st_mode&0o111:raise ValueError('physical_binary_required')
        pin={'generation':_fp(info),'sha256':_digest(fd)}
        _binary(rows,name,fd,pin)
        return pin
    finally:
        if fd is not None:os.close(fd)
        _close(rows)

def _binary(rows,name,fd,pin):
    if type(pin)is not dict or set(pin)!={'generation','sha256'}:raise ConversationUnknown('physical_binary_pin')
    expected=pin['generation']
    if type(expected)is not dict or any(type(v)is not int for v in expected.values()):raise ConversationUnknown('physical_binary_pin')
    if type(pin['sha256'])is not str or re.fullmatch('[0-9a-f]{64}',pin['sha256'])is None:raise ConversationUnknown('physical_binary_pin')
    _parents(rows)
    if _fp(os.fstat(fd))!=expected or _fp(os.stat(name,dir_fd=rows[-1][0],follow_symlinks=False))!=expected or _digest(fd)!=pin['sha256']:
        raise ConversationUnknown('physical_binary_changed')

def _binding(nonce,source,correlation):
    return ('VCREAD-1 '+nonce+' '+source+' '+correlation).encode('ascii')

def fixed_script(nonce,source_sha256,correlation_id):
    """Closed script: nine reads, one validated path input, then sha256sum."""
    if (type(nonce)is not str or re.fullmatch('[0-9a-f]{32}',nonce)is None or
        type(source_sha256)is not str or re.fullmatch('[0-9a-f]{64}',source_sha256)is None or
        type(correlation_id)is not str or re.fullmatch(UUID_PATTERN,correlation_id)is None):
        raise ValueError('physical_binding_required')
    prefix=_binding(nonce,source_sha256,correlation_id).decode()
    # Exact stdout bytes stream without command substitution or guest spools.
    lines=["_emit() {",' i=$1; shift',' _prefix='+shlex.quote(prefix),' if [ "$i" = 10 ]; then _prefix="$_prefix HASH $hash_nonce"; fi'," printf '\\036%s %s BEGIN\\037\\n' "+'"$_prefix" "$i"',
           ' "$@"',' rc=$?'," printf '\\n\\036%s %s END %s\\037\\n' "+'"$_prefix" "$i" "$rc"','}']
    for i,prop in enumerate(PROPERTIES,1):lines.append('_emit '+str(i)+' getprop '+shlex.quote(prop))
    lines+=['_emit 6 id -u','_emit 7 cat /proc/sys/kernel/random/boot_id',
            '_emit 8 sh -c '+shlex.quote(PROCESS_READ),'_emit 9 pm path com.kardinal.vpncontrol',
            "IFS=' ' read -r hash_nonce package_path || exit 90",
            # Host closes input after its single validated path. Extra input fails.
            'if IFS= read -r extra; then exit 91; fi',
            '_emit 10 sha256sum "$package_path"']
    return '\n'.join(lines)+'\n'

def _package(raw):
    try:value=raw.decode('utf-8').strip()
    except UnicodeError as exc:raise ConversationUnknown('physical_utf8') from exc
    match=re.fullmatch(r'package:(/data/app/[A-Za-z0-9_./+~=-]+/base\.apk)',value)
    if match is None or '..' in Path(match[1]).parts:raise ConversationUnknown('physical_package_path_unknown')
    return match[1]

class _Frames:
    def __init__(self,binding):
        self.binding=binding;self.pending=bytearray();self.frames=[];self.started=False;self.hash_nonce=None
    def feed(self,raw,observed,hash_admitted=False):
        self.pending.extend(raw)
        while len(self.frames)<10:
            index=len(self.frames)+1
            if index==10 and not hash_admitted:
                if self.pending:raise ConversationUnknown('physical_hash_before_path_admission')
                return
            binding=self.binding+(b' HASH '+self.hash_nonce.encode() if index==10 else b'')
            begin=b'\x1e'+binding+b' '+str(index).encode()+b' BEGIN\x1f\n'
            if not self.started:
                if len(self.pending)<len(begin):
                    if not begin.startswith(self.pending):raise ConversationUnknown('physical_frame_begin')
                    return
                if self.pending[:len(begin)]!=begin:raise ConversationUnknown('physical_frame_begin')
                del self.pending[:len(begin)];self.started=True
            marker=b'\n\x1e'+binding+b' '+str(index).encode()+b' END '
            position=self.pending.find(marker)
            if position<0:
                # Retain a possible marker prefix while enforcing payload cap.
                if len(self.pending)>FRAME_LIMIT+len(marker)+16:raise ConversationUnknown('physical_frame_overflow')
                return
            if position>FRAME_LIMIT:raise ConversationUnknown('physical_frame_overflow')
            end=self.pending.find(b'\x1f\n',position+len(marker))
            if end<0:
                if len(self.pending)>FRAME_LIMIT+len(marker)+16:raise ConversationUnknown('physical_frame_end')
                return
            code=bytes(self.pending[position+len(marker):end])
            if code!=b'0':raise ConversationUnknown('physical_command_status')
            payload=bytes(self.pending[:position])
            if b'\x1e' in payload or b'\x1f' in payload:raise ConversationUnknown('physical_frame_ambiguous')
            try:payload.decode('utf-8')
            except UnicodeError as exc:raise ConversationUnknown('physical_utf8') from exc
            self.frames.append({'index':index,'stdout':payload,'returncode':0,'observedMonotonic':observed})
            del self.pending[:end+2];self.started=False
        if self.pending:raise ConversationUnknown('physical_trailing_bytes')

def _capture(fd,rows,name,record,expected):
    _parents(rows)
    if _fp(os.fstat(fd))!=expected or _fp(os.stat(name,dir_fd=rows[-1][0],follow_symlinks=False))!=expected:
        raise ConversationUnknown('physical_capture_changed')
    raw=(json.dumps(record,sort_keys=True,separators=(',',':'))+'\n').encode()
    offset=0
    while offset<len(raw):
        count=os.write(fd,raw[offset:])
        if count<=0:raise OSError('physical_capture_short_write')
        offset+=count
    os.fsync(fd);os.fsync(rows[-1][0]);_parents(rows)
    closing=os.fstat(fd);pin=_fp(closing)
    if (_fp(os.stat(name,dir_fd=rows[-1][0],follow_symlinks=False))!=pin or
        not stat.S_ISREG(closing.st_mode) or closing.st_nlink!=1 or closing.st_mode&0o777!=0o600 or closing.st_size!=len(raw) or
        any(pin[key]!=expected[key] for key in ('device','inode','mode','uid','gid','nlink'))):
        raise ConversationUnknown('physical_capture_changed')
    # Metadata/size alone cannot authenticate the bytes we intended to save.
    # Freeze the full FD generation across bounded readback and named closure.
    saved=bytearray();offset=0
    while offset<len(raw)+1:
        part=os.pread(fd,min(65536,len(raw)+1-offset),offset)
        if not part:break
        saved.extend(part);offset+=len(part)
    _parents(rows)
    if (_fp(os.fstat(fd))!=pin or
        _fp(os.stat(name,dir_fd=rows[-1][0],follow_symlinks=False))!=pin or
        saved!=raw or hashlib.sha256(saved).digest()!=hashlib.sha256(raw).digest()):
        raise ConversationUnknown('physical_capture_bytes_changed')

def observe(adb_path,expected_binary,*,serial,api,correlation_id,source_sha256,
            environment,capture_path,deadline=None):
    """One fixed conversation; returns raw reads, never device/lease admission.

    deadline is a caller's earlier finite host-monotonic deadline. Slot limits
    remain 20 seconds and 16KiB; no input permits increasing them.
    """
    if (type(api)is not int or api not in (29,35) or type(serial)is not str or
        serial!=({29:'emulator-5684',35:'emulator-5682'}[api]) or
        type(environment)is not dict or any(type(k)is not str or type(v)is not str or '\x00' in k+v for k,v in environment.items())):
        raise ValueError('physical_device_environment_required')
    child_environment=dict(environment)
    expected_binary=json.loads(json.dumps(expected_binary))
    nonce=uuid.uuid4().hex;script=fixed_script(nonce,source_sha256,correlation_id)
    start=time.monotonic()
    if type(start)not in (int,float) or not math.isfinite(start) or start<0:raise ValueError('physical_host_clock_required')
    if os.getuid()==0:raise ValueError('physical_nonroot_required')
    if deadline is not None and (type(deadline)not in (int,float) or not math.isfinite(deadline) or deadline<=start):
        raise ValueError('physical_deadline_required')
    stop=min(start+TOTAL_SECONDS,deadline) if deadline is not None else start+TOTAL_SECONDS
    binding=_binding(nonce,source_sha256,correlation_id);parser=_Frames(binding)
    frame_budget=sum(len(b'\x1e'+binding+b' '+str(i).encode()+b' BEGIN\x1f\n')+
                     len(b'\n\x1e'+binding+b' '+str(i).encode()+b' END 0\x1f\n') for i in range(1,11))+2*len(b' HASH '+b'0'*32)
    stdout_limit=10*FRAME_LIMIT+frame_budget
    own_path=Path(__file__).absolute();own_pin=binary_pin_source(own_path)
    rows,name=_chain(adb_path);cap_rows=[];binary_fd=cap_fd=None;child=None;failure=None
    out=bytearray();err=bytearray();eof={'stdout':False,'stderr':False};package=None;terminal=None;input_line=None;input_offset=0;path_sent=False
    record={'schema':1,'kind':'android-ten-read-conversation','nonce':nonce,'correlationId':correlation_id,
            'sourceSha256':source_sha256,'helperSourceSha256':own_pin['sha256'],'scriptSha256':hashlib.sha256(script.encode()).hexdigest(),
            'serial':serial,'api':api,'environmentSha256':hashlib.sha256(json.dumps(child_environment,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'startedMonotonic':start,'admissionGranted':False,'replayAllowed':False,'complete':False}
    try:
        cap_rows,cap_name=_chain(capture_path)
        cap_fd=os.open(cap_name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=cap_rows[-1][0])
        cap_pin=_fp(os.fstat(cap_fd))
        if cap_pin['uid']!=os.getuid() or cap_pin['nlink']!=1 or cap_pin['mode']&0o777!=0o600:raise ConversationUnknown('physical_capture_private_required')
        binary_fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=rows[-1][0]);_binary(rows,name,binary_fd,expected_binary)
        # Linux executes the held inode. macOS retains the existing named-exec
        # before/after FD fence for local regression only; native calibration
        # is explicitly the Arch/Linux route.
        fd_exec='/proc/self/fd/'+str(binary_fd) if sys.platform.startswith('linux') else str(adb_path)
        child=subprocess.Popen([str(adb_path),'-s',serial,'shell','-T','sh -c '+shlex.quote(script)],executable=fd_exec,
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=child_environment,
            pass_fds=(binary_fd,),close_fds=True)
        record['childPid']=child.pid
        with selectors.DefaultSelector() as selector:
            for channel in ('stdout','stderr'):
                stream=getattr(child,channel);os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,channel)
            slot_end=min(stop,time.monotonic()+STEP_SECONDS);last_count=0
            while selector.get_map():
                now=time.monotonic()
                if type(now)not in (int,float) or not math.isfinite(now) or now<start or now>slot_end:raise ConversationUnknown('physical_deadline_unknown')
                ready=selector.select(min(0.1,slot_end-now))
                for key,_ in ready:
                    channel=key.data
                    if channel=='stdin':
                        try:written=os.write(key.fd,input_line[input_offset:])
                        except BlockingIOError:continue
                        if written<=0:raise ConversationUnknown('physical_path_handoff_unknown')
                        input_offset+=written
                        if input_offset==len(input_line):
                            selector.unregister(key.fileobj);child.stdin.close();path_sent=True
                        continue
                    raw=os.read(key.fd,65536)
                    if not raw:
                        eof[channel]=True;selector.unregister(key.fileobj);continue
                    target=out if channel=='stdout' else err
                    cap=stdout_limit if channel=='stdout' else FRAME_LIMIT
                    target.extend(raw[:max(0,cap+1-len(target))])
                    if len(target)>cap:raise ConversationUnknown('physical_transport_overflow')
                    if channel=='stderr':raise ConversationUnknown('physical_stderr_unknown')
                    observed=time.monotonic()
                    if type(observed)not in (int,float) or not math.isfinite(observed) or not start<=observed<=slot_end:raise ConversationUnknown('physical_deadline_unknown')
                    parser.feed(raw,observed,hash_admitted=path_sent)
                    if len(parser.frames)>last_count:
                        # Child cannot start frame10 until the validated one-path handoff.
                        if len(parser.frames)>=9 and package is None:
                            package=_package(parser.frames[8]['stdout']);parser.hash_nonce=uuid.uuid4().hex
                            line=(parser.hash_nonce+' '+package+'\n').encode()
                            if len(line)>FRAME_LIMIT+34:raise ConversationUnknown('physical_package_path_unknown')
                            input_line=line;os.set_blocking(child.stdin.fileno(),False)
                            selector.register(child.stdin,selectors.EVENT_WRITE,'stdin')
                        last_count=len(parser.frames);slot_end=min(stop,observed+STEP_SECONDS)
            remaining=min(stop,slot_end)-time.monotonic()
            if remaining<=0:raise ConversationUnknown('physical_deadline_unknown')
            terminal=child.wait(timeout=remaining)
        if terminal!=0 or len(parser.frames)!=10 or parser.pending or not all(eof.values()):raise ConversationUnknown('physical_terminal_unknown')
        digest=parser.frames[9]['stdout'].decode('utf-8').strip().split()
        if len(digest)!=2 or re.fullmatch('[0-9a-f]{64}',digest[0])is None or digest[1]!=package:raise ConversationUnknown('physical_package_hash_path_unknown')
        _binary(rows,name,binary_fd,expected_binary)
        if binary_pin_source(own_path)!=own_pin:raise ConversationUnknown('physical_helper_source_changed')
        record['complete']=True
    except BaseException as exc:
        failure=exc
    finally:
        if child is not None:
            try:
                if child.poll()is None:
                    # This unreaped Popen child still owns its PID; no descendant signals.
                    child.kill()
                terminal=child.wait(timeout=5)
            except BaseException as exc:
                record['complete']=False
                if failure is None:failure=exc
            finally:
                for channel in ('stdin','stdout','stderr'):
                    stream=getattr(child,channel)
                    if stream is not None:stream.close()
        record.update(stdoutBase64=base64.b64encode(out).decode(),stderrBase64=base64.b64encode(err).decode(),
                      stdoutBytes=len(out),stderrBytes=len(err),stdoutEOF=eof['stdout'],stderrEOF=eof['stderr'],
                      returncode=terminal,endedMonotonic=time.monotonic(),frameObservations=[{'index':f['index'],'observedMonotonic':f['observedMonotonic']} for f in parser.frames],failure=type(failure).__name__+':'+str(failure) if failure else None)
        try:
            if binary_fd is not None:_binary(rows,name,binary_fd,expected_binary)
            if binary_pin_source(own_path)!=own_pin:raise ConversationUnknown('physical_helper_source_changed')
        except BaseException as exc:
            record['complete']=False;record['closingFailure']=type(exc).__name__+':'+str(exc)
            if failure is None:failure=exc;record['failure']=record['closingFailure']
        try:
            if cap_fd is not None:_capture(cap_fd,cap_rows,cap_name,record,cap_pin)
        except BaseException as exc:
            # Keep the corrupt primary unchanged. The caller receives bounded
            # raw channels in an explicitly UNKNOWN record even when durable
            # storage itself failed; no successful capture can be returned.
            record['complete']=False
            record['captureFailure']=type(exc).__name__+':'+str(exc)
            record['failure']=record['captureFailure']
            unknown=ConversationUnknown('physical_capture_unknown:'+type(exc).__name__+':'+str(exc))
            unknown.record=json.loads(json.dumps(record))
            unknown.serializedRecordBase64=base64.b64encode((json.dumps(record,sort_keys=True,separators=(',',':'))+'\n').encode()).decode()
            failure=unknown
        finally:
            if binary_fd is not None:os.close(binary_fd)
            if cap_fd is not None:os.close(cap_fd)
            _close(rows);_close(cap_rows)
    if failure is not None:
        if isinstance(failure,(FileExistsError,ConversationUnknown)):raise failure
        raise ConversationUnknown('physical_transport_unknown:'+type(failure).__name__) from failure
    return {'frames':parser.frames,'packagePath':package,'record':record}

def binary_pin_source(path):
    rows,name=_chain(path);fd=None
    try:
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=rows[-1][0])
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):raise ConversationUnknown('physical_helper_source_changed')
        pin={'generation':_fp(info),'sha256':_digest(fd)}
        if _fp(os.stat(name,dir_fd=rows[-1][0],follow_symlinks=False))!=pin['generation']:raise ConversationUnknown('physical_helper_source_changed')
        _parents(rows);return pin
    finally:
        if fd is not None:os.close(fd)
        _close(rows)
