"""Windows source handles: reject reparse points and hold names against writes.

This is source custody for trusted checkout code, not credential or guest ACL
admission. Data/credential readers retain their separate platform policies.
"""
from __future__ import annotations
import hashlib,os,sys
from pathlib import Path

_LOADED_BYTES=Path(__file__).read_bytes()
if sys._getframe().f_code!=compile(_LOADED_BYTES,__file__,'exec',dont_inherit=True,optimize=sys.flags.optimize):
    raise ValueError('Windows source backend differs from its executing bytes')
LOADED_SHA=hashlib.sha256(_LOADED_BYTES).hexdigest()


class WindowsHeld:
    def __init__(self):
        if os.name!='nt':raise ValueError('Windows source handles require Windows')
        import ctypes
        from ctypes import wintypes
        self.ct=ctypes;self.wt=wintypes;self.kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        class FileTime(ctypes.Structure):_fields_=[('low',wintypes.DWORD),('high',wintypes.DWORD)]
        class Information(ctypes.Structure):
            _fields_=[('attributes',wintypes.DWORD),('creation',FileTime),('access',FileTime),('write',FileTime),('volume',wintypes.DWORD),('sizeHigh',wintypes.DWORD),('sizeLow',wintypes.DWORD),('links',wintypes.DWORD),('indexHigh',wintypes.DWORD),('indexLow',wintypes.DWORD)]
        self.Information=Information
        self.kernel.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,wintypes.LPVOID,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
        self.kernel.CreateFileW.restype=wintypes.HANDLE
        self.kernel.GetFileInformationByHandle.argtypes=[wintypes.HANDLE,ctypes.POINTER(Information)];self.kernel.GetFileInformationByHandle.restype=wintypes.BOOL
        self.kernel.CloseHandle.argtypes=[wintypes.HANDLE];self.kernel.CloseHandle.restype=wintypes.BOOL
        self.directories={};self.files={};self.closed=False
    def _open(self,path,directory):
        # Sources deny WRITE and DELETE sharing; ancestors allow child creation
        # but deny their own replacement/rename until the adapter returns.
        handle=self.kernel.CreateFileW(str(path),0x80 if directory else 0x80000000,3 if directory else 1,None,3,0x00200000|(0x02000000 if directory else 0),None)
        if handle==self.ct.c_void_p(-1).value:raise self.ct.WinError(self.ct.get_last_error())
        try:
            value=self._information(handle)
            if value[0]&0x400 or bool(value[0]&0x10)!=directory or not directory and value[5]!=1:raise ValueError('Unsafe source file or reparse ancestor')
            return handle,value
        except BaseException:self.kernel.CloseHandle(handle);raise
    def _information(self,handle):
        result=self.Information()
        if not self.kernel.GetFileInformationByHandle(handle,self.ct.byref(result)):raise self.ct.WinError(self.ct.get_last_error())
        return (result.attributes,result.volume,result.indexHigh,result.indexLow,(result.sizeHigh<<32)|result.sizeLow,result.links,(result.creation.high<<32)|result.creation.low,(result.write.high<<32)|result.write.low)
    def read(self,path,digest,gen=None,*,max_bytes=None):
        import msvcrt
        if self.closed:raise ValueError('Closed Windows source custody')
        if gen is not None:raise ValueError('Explicit POSIX generation is unsupported for Windows source handles')
        path=Path(path)
        if not path.is_absolute() or not path.drive or path.drive.startswith('\\') or '..' in path.parts:raise ValueError('Local absolute source path required')
        key=str(path)
        if key in self.files:
            fd,pin,raw,expected=self.files[key]
            if expected!=digest:raise ValueError('Conflicting Windows source digest')
            self.finish();return raw
        for parent in reversed(path.parents):
            if str(parent) not in self.directories:self.directories[str(parent)]=self._open(parent,True)
        handle,pin=self._open(path,False)
        try:fd=msvcrt.open_osfhandle(handle,os.O_RDONLY|os.O_BINARY)
        except BaseException:self.kernel.CloseHandle(handle);raise
        try:
            limit=4*1024**2 if max_bytes is None else max_bytes
            if type(limit)is not int or not 0<pin[4]<=limit:raise ValueError('Windows source byte bound')
            pieces=[];size=0
            while True:
                chunk=os.read(fd,min(65536,limit+1-size))
                if not chunk:break
                pieces.append(chunk);size+=len(chunk)
                if size>limit:raise ValueError('Windows source byte bound')
            raw=b''.join(pieces)
            if len(raw)!=pin[4] or hashlib.sha256(raw).hexdigest()!=digest:raise ValueError('Windows source digest changed')
            self.files[key]=(fd,pin,raw,digest);self.finish();return raw
        except BaseException:
            if key not in self.files:os.close(fd)
            raise
    def finish(self):
        import msvcrt
        if self.closed:raise ValueError('Closed Windows source custody')
        for handle,pin in self.directories.values():
            current=self._information(handle)
            identity=lambda v:(v[0]&0x410,v[1],v[2],v[3],v[6])
            if identity(current)!=identity(pin):raise ValueError('Windows source ancestor changed')
        for path,(fd,pin,raw,digest) in self.files.items():
            if self._information(msvcrt.get_osfhandle(fd))!=pin:raise ValueError('Windows source identity changed')
            os.lseek(fd,0,os.SEEK_SET);parts=[];remaining=len(raw)
            while remaining:
                chunk=os.read(fd,min(65536,remaining))
                if not chunk:raise ValueError('Windows source truncated')
                parts.append(chunk);remaining-=len(chunk)
            if os.read(fd,1) or hashlib.sha256(b''.join(parts)).hexdigest()!=digest:raise ValueError('Windows source bytes changed')
    def final_identity_pass(self):self.finish()
    def close(self):
        if not self.closed:
            self.closed=True
            for fd,*_ in self.files.values():os.close(fd)
            for handle,_ in reversed(list(self.directories.values())):self.kernel.CloseHandle(handle)
