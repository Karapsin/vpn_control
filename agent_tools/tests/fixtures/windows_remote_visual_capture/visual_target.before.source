"""Explicit configured VM selectors and local disk/QMP identity admission."""
from contextlib import ExitStack
import ctypes
import json
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from agent_tools import durable_remote_job as jobs
from agent_tools import private_inventory_lock as private


class TargetError(ValueError):pass


def need(value):
    if not value:raise TargetError('explicit visual target missing or mismatched')


def select(platform,target,config):
    """Selection is explicit; configuration is an allowlist, never a fallback."""
    need(type(target)is str and target and not any(ord(c)<32 for c in target))
    family,separator,name=target.partition(':');need(separator and name)
    if platform=='android':need(family=='android' and name==config['avd_name']);backend='android-emulator'
    elif family=='tart':need(platform in {'linux','macos'} and name==config['vm_name']);backend='tart-'+platform
    elif family=='libvirt':need(platform=='windows' and name==config['libvirt_name']);backend='libvirt-windows'
    elif family=='qemu':
        disk=Path(config['qemu_disk']);disk=disk if disk.is_absolute() else ROOT/disk
        need(platform=='windows' and Path(name).is_absolute() and name==str(disk.resolve()) and ',' not in name)
        backend='qemu-windows'
    elif family=='native':need(platform in {'linux','windows','macos'} and name==platform);backend='native-'+platform
    else:raise TargetError('explicit visual target missing or mismatched')
    return backend,name


def peer(connection):
    if sys.platform.startswith('linux'):
        pid,uid,_=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
    elif sys.platform=='darwin':
        # Installed SDK sys/un.h: SOL_LOCAL=0, LOCAL_PEERPID=2.
        pid=struct.unpack('i',connection.getsockopt(0,2,4))[0]
        uid=ctypes.c_uint();gid=ctypes.c_uint();libc=ctypes.CDLL(None,use_errno=True)
        need(libc.getpeereid(connection.fileno(),ctypes.byref(uid),ctypes.byref(gid))==0);uid=uid.value
    else:raise TargetError('visual QMP peer identity unavailable')
    need(pid>0 and uid==os.geteuid());return pid


class QmpDisk:
    """Hold the selected disk while checking the actual connected Unix peer."""
    def __init__(self,disk,connection,expected_actor=None):
        self.stack=ExitStack()
        try:
            self.disk=Path(disk);need(self.disk.is_absolute())
            self.presented=private.PresentedPath(self.disk.parent)
            self.directory=self.stack.enter_context(private.Directory(self.presented.canonical))
            self.fd=os.open(self.disk.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.directory.fd)
            self.stack.callback(os.close,self.fd)
            info=os.fstat(self.fd);need(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and info.st_nlink==1 and not info.st_mode&0o022)
            self.identity=private._generation(info)[:6]
            self.actor={'pid':peer(connection),'birth':None};self.actor['birth']=jobs._birth(self.actor['pid'])
            need(self.actor['birth'] is not None and (expected_actor is None or self.actor==expected_actor))
            self.guard()
        except TargetError:self.stack.close();raise
        except (OSError,ValueError):
            self.stack.close();raise TargetError('visual QMP custody unavailable')from None
        except BaseException:self.stack.close();raise

    def guard(self):
        try:self._guard()
        except TargetError:raise
        except (OSError,ValueError):raise TargetError('visual QMP custody unavailable')from None

    def _guard(self):
        self.presented.guard();self.directory.guard()
        need(private._generation(os.fstat(self.fd))[:6]==self.identity==private._generation(
            os.stat(self.disk.name,dir_fd=self.directory.fd,follow_symlinks=False))[:6]
            and jobs._birth(self.actor['pid'])==self.actor['birth'])
        # lsof reports actual kernel-open device/inode, not a command-line path.
        result=subprocess.run(['lsof','-a','-p',str(self.actor['pid']),'-F','pDfi','--',str(self.disk)],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5)
        need(result.returncode==0 and len(result.stdout)<=65536)
        rows=result.stdout.decode('ascii','strict').splitlines();current={};matched=False
        for row in [*rows,'fEND']:
            if row.startswith('f'):
                if 'D'in current and 'i'in current:
                    matched|=(int(current['D'],16),int(current['i']))==self.identity[:2]
                current={}
            elif row[:1] in {'D','i'}:current[row[0]]=row[1:]
        need(matched and jobs._birth(self.actor['pid'])==self.actor['birth'])

    def close(self):self.stack.close()
    def __enter__(self):return self
    def __exit__(self,*_):self.close()


def main():
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--platform',required=True);parser.add_argument('--target',required=True)
    args=parser.parse_args();config=json.loads((ROOT/'visual-tests/environments.json').read_text())['platforms'][args.platform]['local']
    try:
        backend,name=select(args.platform,args.target,config)
        need(backend=='qemu-windows');print(name)
    except (ValueError,KeyError,OSError):return 2
    return 0


if __name__=='__main__':raise SystemExit(main())
