"""Real private Unix stream dialogue for the guest-agent sync counterfactual."""
import json
import os
import socket
import stat
import struct
import tempfile
import textwrap
import threading
import time
import types
from pathlib import Path


def observe(source,*,case='dirty',exchange=False):
    with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve()) as temporary:
        root=Path(temporary);server=socket.socket(socket.AF_UNIX);server.bind(str(root/'qga.sock'));server.listen(1)
        replacement=socket.socket(socket.AF_UNIX);replacement.bind(str(root/'replacement.sock'))
        errors=[];commands=[]
        def serve():
            try:
                connection,_=server.accept();connection.settimeout(2)
                with connection,connection.makefile('rwb',buffering=0) as stream:
                    request=json.loads(stream.readline(65537).lstrip(b'\xff'));nonce=request['arguments']['id']
                    if case=='bound':stream.write(b'x'*65537);return
                    if case=='wrong':stream.write(b'\xff'+(json.dumps({'return':nonce+1})+'\n').encode());return
                    if case=='marker-missing':stream.write((json.dumps({'return':nonce})+'\n').encode());return
                    stream.write(b'{"error":{"class":"GenericError","desc":"flush parse error"}}\n')
                    stream.write(b'\xff'+(json.dumps({'return':nonce+1})+'\n').encode())
                    stream.write(b'stale-partial{'+b'\xff'+(json.dumps({'return':nonce})+'\n').encode())
                    while True:
                        raw=stream.readline(65537)
                        if not raw:return
                        command=json.loads(raw)['execute'];commands.append(command)
                        value={}if command=='guest-ping'else {'pretty-name':'Windows fixture'}if command=='guest-get-osinfo'else[{'user':'ordinary'}]
                        if command=='guest-get-users'and exchange:os.replace(root/'replacement.sock',root/'qga.sock')
                        stream.write((json.dumps({'return':value})+'\n').encode())
                        if command=='guest-get-users':return
            except (OSError,ValueError)as error:errors.append(type(error).__name__)
        worker=threading.Thread(target=serve);worker.start()
        def require(value,reason):
            if not value:raise ValueError(reason)
        def owns(pid,path,is_socket):
            require(pid==os.getpid()and is_socket and stat.S_ISSOCK(os.lstat(path).st_mode),'fixture_socket')
        actual_socket=socket
        # Darwin lacks Linux SO_PEERCRED. Only that credential syscall is an
        # explicit seam there; the byte stream and socket exchange remain real.
        if not hasattr(socket,'SO_PEERCRED'):
            class Client:
                def __init__(self,*args):self.value=actual_socket.socket(actual_socket.AF_UNIX)
                def __getattr__(self,name):return getattr(self.value,name)
                def getsockopt(self,*_):return struct.pack('3i',os.getpid(),os.geteuid(),os.getegid())
            protocol=types.SimpleNamespace(socket=Client,AF_UNIX=socket.AF_UNIX,SOL_SOCKET=socket.SOL_SOCKET,SO_PEERCRED=-1)
        else:protocol=socket
        namespace={'os':os,'json':json,'struct':struct,'time':time,'socket':protocol,'require':require,'owns':owns,'root':root,'SETUP':{'user':'ordinary'}}
        try:
            exec(compile(textwrap.dedent(source),'actual guest-agent observer','exec'),namespace)
            value=namespace['guest_state'](os.getpid())
        finally:
            worker.join(timeout=3);server.close();replacement.close()
        if worker.is_alive():raise AssertionError('owned protocol thread leaked')
        if any(name not in ('BrokenPipeError','ConnectionResetError')for name in errors):raise AssertionError(errors)
        return value,commands
