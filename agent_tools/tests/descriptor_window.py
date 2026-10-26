"""Exact FD windows that deferred finalizers of earlier cases cannot counterfeit.

Non-isolated modules share one serial worker. Earlier cases can leave cyclic
garbage whose finalizer closes descriptors (PrivateConfigCustody.__del__), and
an allocation-triggered collection may run inside any later measurement. A
window therefore finalizes pending garbage first, keeps the automatic collector
off until its final table and compares exact kernel identities. Only the
measured code can change that table: a descriptor it keeps, one whose release
it leaves to the collector, a pre-existing one it closes and one it replaces
under the same number each still fail.
"""
import gc,json,os,stat,sys,threading
from contextlib import contextmanager


def descriptor_target(fd,info):
    for link in ('/proc/self/fd/%d'%fd,'/dev/fd/%d'%fd):
        try:return os.readlink(link)
        except OSError:pass
    try:
        import fcntl
        if stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode):
            return fcntl.fcntl(fd,fcntl.F_GETPATH,bytes(1024)).split(b'\0',1)[0].decode('utf-8','replace')
    except (AttributeError,ImportError,OSError):pass
    return stat.filemode(info.st_mode)


def descriptor_table():
    """Kernel identity and target of every open FD; the closed listing FD is absent."""
    table={}
    for name in os.listdir('/dev/fd'):
        try:info=os.fstat(int(name))
        except OSError:continue
        table[int(name)]=(stat.S_IFMT(info.st_mode),info.st_dev,info.st_ino,descriptor_target(int(name),info))
    return table


def difference(before,after):
    opened={fd:row for fd,row in after.items() if before.get(fd,(None,))[:3]!=row[:3]}
    closed={fd:row for fd,row in before.items() if after.get(fd,(None,))[:3]!=row[:3]}
    return opened,closed


def summary(rows):
    kinds={}
    for kind,_,_,target in rows.values():
        key='directory' if stat.S_ISDIR(kind) else os.path.basename(target) if stat.S_ISREG(kind) else target
        kinds[key]=kinds.get(key,0)+1
    return kinds


def begin():
    """Stop the automatic collector, finalize pending cyclic garbage, then take the baseline."""
    enabled=gc.isenabled();gc.disable()
    try:pending=descriptor_table();gc.collect();window={'enabled':enabled,'before':descriptor_table()}
    except BaseException:
        if enabled:gc.enable()
        raise
    window['finalized']=difference(pending,window['before'])[1]
    if window['finalized']:
        # One line even when the window passes, so a hosted run names the earlier owners.
        sys.stderr.write('descriptor window: pre-baseline collection finalized %d earlier descriptors %s\n'
                         %(len(window['finalized']),json.dumps(summary(window['finalized']),sort_keys=True)))
    return window


def end(window):
    """Final table, collector state and threads before the collector is restored."""
    if 'after' not in window:
        window.update(after=descriptor_table(),gcEnabled=gc.isenabled(),threads=[thread.name for thread in threading.enumerate()])
    restore(window)
    return window


def restore(window):
    if window.pop('enabled',False):gc.enable()


@contextmanager
def measured():
    window=begin()
    try:
        yield window
        end(window)
    finally:
        restore(window)


def check(case,window,label='operation'):
    opened,closed=difference(window['before'],window['after'])
    if opened or closed:
        case.fail(label+' FD table changed: '+json.dumps({'opened':opened,'closed':closed,'before':window['before'],'after':window['after'],
            'threads':window['threads'],'gcEnabled':window['gcEnabled'],'finalizedBeforeBaseline':window['finalized']},indent=1,sort_keys=True))
