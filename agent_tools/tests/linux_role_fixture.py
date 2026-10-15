"""Declared OS/account boundary for a whole, unchanged Linux role programme."""
import inspect


def _boundary():
    import builtins, os, pwd, types
    real_open=builtins.open;real_lstat=os.lstat;real_stat=os.stat
    real_listdir=os.listdir;real_readlink=os.readlink;real_os_open=os.open
    uid=os.getuid()
    def mapped(path):
        if isinstance(path,(str,bytes,os.PathLike)):
            text=os.fsdecode(path)
            if text=='/proc' or text.startswith('/proc/'):return PROC+text[5:]
        return path
    def lstat(path,*args,**kwargs):
        info=real_lstat(mapped(path),*args,**kwargs)
        text=os.fsdecode(path)
        if text==ROOT_OWNED or text.startswith(ROOT_OWNED+'/'):
            fields={name:getattr(info,name) for name in dir(info) if name.startswith('st_')}
            fields['st_uid']=0;return types.SimpleNamespace(**fields)
        return info
    builtins.open=lambda path,*a,**k:real_open(mapped(path),*a,**k)
    os.open=lambda path,*a,**k:real_os_open(mapped(path),*a,**k)
    os.stat=lambda path,*a,**k:real_stat(mapped(path),*a,**k)
    os.lstat=lstat
    os.listdir=lambda path:real_listdir(mapped(path))
    os.readlink=lambda path,*a,**k:real_readlink(mapped(path),*a,**k)
    os.geteuid=lambda:0
    os.environ['SUDO_UID']=str(uid)
    pwd.getpwuid=lambda value:types.SimpleNamespace(pw_uid=uid,pw_dir=HOME) if value==uid else None


def program(source,home,proc,root_owned):
    return ('HOME='+repr(str(home))+'\nPROC='+repr(str(proc))+'\nROOT_OWNED='+repr(str(root_owned))+'\n'
            +inspect.getsource(_boundary)+'\n_boundary()\n'+source)
