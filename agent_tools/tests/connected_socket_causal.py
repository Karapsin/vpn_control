"""Actual Linux listening/accepted stream fixture for the VM observer."""
import os
import socket
import tempfile
import textwrap
from pathlib import Path


def prove(before,after):
    def require(value,reason):
        if not value:raise ValueError(reason)
    def observer(source):
        namespace={'os':os,'require':require}
        exec(compile(textwrap.dedent(source),'socket ownership observer','exec'),namespace)
        return namespace['owns']
    with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve()) as temporary:
        path=Path(temporary)/'tpm.sock'
        with socket.socket(socket.AF_UNIX) as listener,socket.socket(socket.AF_UNIX) as client:
            listener.bind(str(path));listener.listen(1);client.connect(str(path))
            accepted,_=listener.accept()
            with accepted:
                try:observer(before)(os.getpid(),path,True)
                except ValueError as error:require(str(error)=='instance_socket_identity','unexpected_before_failure')
                else:raise AssertionError('preserved observer did not reproduce failure')
                observer(after)(os.getpid(),path,True)
                # A process with a different identity must still be rejected.
                import subprocess,sys
                child=subprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(30)'],close_fds=True)
                try:
                    try:observer(after)(child.pid,path,True)
                    except ValueError as error:require(str(error)=='instance_socket_owner','unexpected_owner_failure')
                    else:raise AssertionError('foreign listener was accepted')
                finally:child.terminate();child.wait(timeout=5)
    return {'before':'RED:instance_socket_identity','after':'GREEN','foreignOwnerRejected':True}
