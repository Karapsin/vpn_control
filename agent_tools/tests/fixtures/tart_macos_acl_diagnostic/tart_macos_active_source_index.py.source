"""Staged protected SSV source index; no routing, idle or power authority.

Paths, labels, arguments and accounts are private matching material. A source
match proves source custody only, never that its process or service is idle.
"""
from __future__ import annotations
from dataclasses import dataclass
import os
from pathlib import PurePosixPath
import plistlib
import posixpath
if os.name=='posix':
    import pwd
else:
    pwd=None
import stat

from agent_tools import tart_macos_service_census as service

_SOURCE_ROOT='/System/Library'
_SOURCE_DIRECTORIES=(('/System/Library/LaunchDaemons','system_daemon'),
                     ('/System/Library/LaunchAgents','system_agent'))
_EXECUTABLE_ROOTS=('/System/Library','/System/Applications','/usr/libexec','/usr/sbin','/usr/bin','/bin','/sbin')


class SourceUnavailable(ValueError):
    """Finite source-custody reason only."""


def need(value,reason):
    if not value:raise SourceUnavailable(reason)


def _inside(path,roots):
    return any(path==root or path.startswith(root+'/')for root in roots)


def _absolute(path,roots):
    need(type(path)is str and path.startswith('/')and '\x00'not in path,
         'source_namespace_unqualified')
    canonical=posixpath.normpath(path)
    need(_inside(canonical,roots),'source_namespace_unqualified')
    need(len(PurePosixPath(canonical).parts)<=128,'source_walk_overflow')
    return canonical


@dataclass(frozen=True)
class ProtectedRead:
    raw:bytes
    identity:tuple


class NativeSSVReader:
    """Fixed-namespace reader deriving policy from the actual native getter.

    No caller supplied trust flag, alternate root, volume or ownership policy.
    Tests may replace native getters; this type grants no public authority.
    """
    def __init__(self,native):
        need(type(native)is service.NativeServices,'source_volume_unqualified')
        self.native=native;self.volume=self._volume()

    def _volume(self):
        try:value=self.native.volume()
        except Exception:raise SourceUnavailable('source_volume_unqualified')from None
        need(type(value)is service.Volume and value.source_eligible,
             'source_volume_unqualified')
        return value

    def _volume_stable(self):
        need(self._volume()==self.volume,'source_volume_changed')

    def _walk(self,path,roots,*,content,directory=False):
        self._volume_stable();path=_absolute(path,roots)
        held=[];entries=[];links=0;steps=0
        try:
            while True:
                root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                root_info=os.fstat(root)
                need(stat.S_ISDIR(root_info.st_mode)and root_info.st_uid==0
                     and not root_info.st_mode&0o022 and root_info.st_dev==self.volume.device,
                     'source_component_unqualified')
                held.append((root,service.generation(root_info)))
                parent=root;parts=PurePosixPath(path).parts[1:];prefix=[];restart=False
                for offset,name in enumerate(parts):
                    steps+=1;need(steps<=256,'source_walk_overflow')
                    info=os.stat(name,dir_fd=parent,follow_symlinks=False)
                    need(info.st_uid==0 and info.st_dev==self.volume.device,
                         'source_component_unqualified')
                    identity=service.generation(info);entries.append((parent,name,identity))
                    prefix.append(name)
                    if stat.S_ISLNK(info.st_mode):
                        links+=1;need(links<=16,'source_symlink_overflow')
                        target=os.readlink(name,dir_fd=parent)
                        need(service.generation(os.stat(name,dir_fd=parent,follow_symlinks=False))==identity,
                             'source_changed')
                        need(type(target)is str and target and '\x00'not in target,
                             'source_namespace_unqualified')
                        base='/'+'/'.join(prefix[:-1])
                        target=target if target.startswith('/')else posixpath.join(base,target)
                        path=_absolute(posixpath.join(target,*parts[offset+1:]),roots)
                        restart=True;break
                    need(not info.st_mode&0o022,'source_component_unqualified')
                    final=offset==len(parts)-1
                    if not final:
                        need(stat.S_ISDIR(info.st_mode),'source_component_unqualified')
                        child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                        held.append((child,service.generation(os.fstat(child))))
                        need(held[-1][1]==identity,'source_changed');parent=child
                    else:
                        regular=stat.S_ISREG(info.st_mode)
                        need(stat.S_ISDIR(info.st_mode)if directory else regular,
                             'source_file_unqualified')
                        if content:need(info.st_nlink>=1 and 0<info.st_size<=1048576,'source_file_unqualified')
                        flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK
                        if directory:flags|=os.O_DIRECTORY
                        fd=os.open(name,flags,dir_fd=parent)
                        held.append((fd,service.generation(os.fstat(fd))))
                        need(held[-1][1]==identity,'source_changed')
                        raw=os.read(fd,info.st_size+1)if content else b''
                        need(not content or len(raw)==info.st_size,'source_changed')
                if not restart:break
            for fd,identity in held:
                need(service.generation(os.fstat(fd))==identity,'source_changed')
            for fd,name,identity in entries:
                need(service.generation(os.stat(name,dir_fd=fd,follow_symlinks=False))==identity,
                     'source_changed')
            self._volume_stable()
            # Identity contains only private matching material; never publish it.
            return ProtectedRead(raw,(path,tuple(identity for _,identity in held),
                                      tuple((name,identity)for _,name,identity in entries)))
        except SourceUnavailable:raise
        except (OSError,ValueError,TypeError):raise SourceUnavailable('source_read_unavailable')from None
        finally:
            for fd,_ in reversed(held):os.close(fd)

    def read(self,path):
        need(type(path)is str and any(path.startswith(root+'/')and '/'not in path[len(root)+1:]
                 and path.endswith('.plist')for root,_ in _SOURCE_DIRECTORIES),
             'source_namespace_unqualified')
        return self._walk(path,(_SOURCE_ROOT,),content=True)

    def executable(self,path):
        return self._walk(path,_EXECUTABLE_ROOTS,content=False).identity

    def paths(self):
        self._volume_stable();result=[];directories=[]
        for name,origin in _SOURCE_DIRECTORIES:
            proof=self._walk(name,(_SOURCE_ROOT,),content=False,directory=True)
            fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:
                before=os.fstat(fd)
                need(service.generation(before)==proof.identity[1][-1], 'source_changed')
                names=os.listdir(fd);need(len(names)<=service.MAX_SERVICES,'source_index_overflow')
                result.extend((name+'/'+leaf,origin)for leaf in names if leaf.endswith('.plist'))
                need(service.generation(os.fstat(fd))==service.generation(before)
                     and service.generation(os.lstat(name))==service.generation(before),'source_changed')
            finally:os.close(fd)
            need(self._walk(name,(_SOURCE_ROOT,),content=False,directory=True)==proof,'source_changed')
            directories.append((name,proof))
        self._volume_stable();return tuple(result),tuple(directories)

    def stable(self,directories):
        self._volume_stable()
        return all(self._walk(name,(_SOURCE_ROOT,),content=False,directory=True)==proof
                   for name,proof in directories)



@dataclass(frozen=True)
class IndexedSource:
    path:str
    origin:str
    value:dict
    protected:ProtectedRead


class ActiveSourceIndex:
    """Retain labelled inactive errors; resolve only actual active joins.

    Unreadable or unlabelled records prevent complete label coverage. They are
    never assumed inactive, nor ignored because another matching file exists.
    """
    def __init__(self,reader):
        need(type(reader)is NativeSSVReader,'source_reader_unqualified')
        self.reader=reader;self.sources={};self.coverage=set()
        paths,self.directories=reader.paths()
        for path,origin in paths:
            try:
                protected=reader.read(path);value=plistlib.loads(protected.raw)
                need(type(value)is dict and type(value.get('Label'))is str and value['Label'],
                     'source_label_unavailable')
                entry=IndexedSource(path,origin,value,protected)
                self.sources.setdefault((origin,value['Label']),[]).append(entry)
            except (SourceUnavailable,ValueError,TypeError):self.coverage.add('source_index_coverage_incomplete')
        need(reader.stable(self.directories),'source_changed')

    def public(self):
        return {'state':'diagnostic','nativeQualified':False,'idleAuthority':False,
                'indexedSourceCount':sum(map(len,self.sources.values())),
                'coverageComplete':not self.coverage,'reasons':sorted(self.coverage)}

    def match(self,row,actor,native,*,domain):
        need(not self.coverage,'source_index_coverage_incomplete')
        need(type(domain)is service.Domain and domain.kind in {'system','caller_user'}and type(domain.uid)is int,
             'source_domain_unqualified')
        need(type(actor)is tuple and len(actor)==5 and all(type(v)is int for v in actor)
             and actor[0]>0 and actor[1]>=0 and actor[2]>0 and actor[3]>0 and 0<=actor[4]<1000000,
             'loaded_source_unqualified')
        need(type(row)is dict and type(row.get('Label'))is str and type(row.get('PID'))is int and row['PID']==actor[0],
             'loaded_source_unqualified')
        need(type(domain.rows)is list and sum(type(item)is dict and item.get('PID')==actor[0]
             for item in domain.rows)==1 and any(item is row for item in domain.rows),
             'loaded_source_domain_unmatched')
        origin='system_daemon'if domain.kind=='system'else'system_agent'
        matches=self.sources.get((origin,row['Label']),[])
        need(len(matches)==1,'active_source_missing_or_ambiguous');entry=matches[0]
        need(self.reader.read(entry.path)==entry.protected,'source_changed')
        value=entry.value;arguments=value.get('ProgramArguments');program=value.get('Program')
        if arguments is None and type(program)is str:arguments=[program]
        need(type(arguments)is list and 0<len(arguments)<=4096 and all(type(v)is str for v in arguments),
             'active_source_arguments_unqualified')
        if program is None:program=arguments[0]
        need(type(program)is str and program.startswith('/'),'active_source_arguments_unqualified')
        expected=0 if origin=='system_daemon'else domain.uid
        need((domain.kind=='system'and domain.uid==0)or(domain.kind=='caller_user'and type(domain.uid)is int and domain.uid>=501),
             'source_domain_unqualified')
        if 'UserName'in value:
            need(type(value['UserName'])is str and pwd is not None,'active_source_account_unavailable')
            try:declared=pwd.getpwnam(value['UserName']).pw_uid
            except KeyError:raise SourceUnavailable('active_source_account_unavailable')from None
            if origin=='system_agent':need(declared==domain.uid,'active_source_account_unqualified')
            expected=declared
        need(actor[1]==expected and actor[2]==1,'active_source_account_or_parent_unqualified')
        executable_identity=self.reader.executable(program)
        argv=tuple(os.fsencode(v)for v in arguments)
        need(native.argv(actor)==(os.fsencode(program),argv),'active_source_arguments_unqualified')
        if 'Program'in row:need(row['Program']==program,'loaded_source_unqualified')
        if 'ProgramArguments'in row:need(row['ProgramArguments']==arguments,'loaded_source_unqualified')
        need(self.reader.executable(program)==executable_identity and self.reader.read(entry.path)==entry.protected
             and self.reader.stable(self.directories),
             'source_changed')
        return entry

    def match_active(self,processes,domains,native):
        """Complete native domain/PID join; returns private source matches only.

        This is not a process-idle review. Missing system/user domains, duplicate
        PID ownership and active services absent from the actual actor census
        all block before any source is selected.
        """
        need(type(processes)is dict and type(domains)is list,'active_census_unqualified')
        active={};keys=set()
        for domain in domains:
            need(type(domain)is service.Domain and domain.kind in {'system','caller_user'}
                 and type(domain.uid)is int and type(domain.rows)is list,'source_domain_unqualified')
            key=(domain.kind,domain.uid);need(key not in keys,'source_domain_duplicate');keys.add(key)
            for row in domain.rows:
                need(type(row)is dict and type(row.get('PID',0))is int and row.get('PID',0)>=0,
                     'loaded_source_unqualified')
                pid=row.get('PID',0)
                if pid:
                    need(pid not in active,'loaded_source_pid_ambiguous');active[pid]=(row,domain)
        need(('system',0)in keys,'system_source_domain_unobserved')
        need(all(('caller_user',actor[1])in keys for actor in processes.values()if actor[1]>=501),
             'user_source_domain_unobserved')
        need(set(active)<=set(processes),'loaded_source_process_changed')
        return {pid:self.match(row,processes[pid],native,domain=domain)
                for pid,(row,domain)in active.items()}
