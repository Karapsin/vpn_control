"""Fixed persistent read-only observer; every check obtains fresh native facts.

No caller-selected command, file, callback, input or credentials are accepted.
The provider owns the original framed Tart process and validates every reply
against the admitted group; disconnects do not authorize another input event.
"""
from __future__ import annotations

import inspect
import hashlib
import textwrap

from . import readiness_tart_macos_session as session


def session_stream_command(binding):
    """Only this fixed observer; exact source frame leaves subsequent input open."""
    raw = guest_session_stream_source(binding)
    gate = ("import hashlib,sys;raw=sys.stdin.buffer.read(" + str(len(raw)) + ");"
            "assert len(raw)==" + str(len(raw)) + " and hashlib.sha256(raw).hexdigest()==" +
            repr(hashlib.sha256(raw).hexdigest()) + ", 'guest_source_changed';"
            "exec(compile(raw,'<registered-session-observer>','exec'),{'__name__':'__main__'})")
    return (binding.guest_python, "-I", "-B", "-c", gate), raw


def guest_session_stream_source(binding):
    complete = session.guest_session_source(binding).decode("utf-8")
    parameters = complete.splitlines()[0]
    init, observe = session._OBSERVER.split("native=module.Native();boot,_=native.boot()\n")
    # Retain the exact qualified getter; only its print becomes a returned fact.
    marker = "print(json.dumps("
    start = observe.index(marker)
    tail = observe[start + len(marker):]
    if not tail.endswith(",sort_keys=True))\n"):
        raise session.backend.MacBlocked("macos_session_stream_source_changed")
    observe = observe[:start] + "return " + tail[:-len(",sort_keys=True))\n")] + "\n"
    observer = ("def _observe():\n" + textwrap.indent(
        "boot,_=native.boot()\n" + observe, " "))
    return (parameters + "\n" + inspect.getsource(session.registry._console_login_done) + "\n" +
            inspect.getsource(session._load_verified_probe) + "\n" + init +
            "native=module.Native()\n" + observer + "\n" + _STREAM).encode()


_STREAM = r'''import signal,sys
def _expired(signum,frame):raise SystemExit(73)
signal.signal(signal.SIGALRM,_expired);signal.setitimer(signal.ITIMER_REAL,180)
def _generation(path):
 info=path.lstat()
 return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
agent=prefix/'tart-guest-agent';protected(agent)
probe_generation=_generation(probe);agent_generation=_generation(agent)
need(probe_generation==(before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_gid,before.st_nlink,
                        before.st_size,before.st_mtime_ns,before.st_ctime_ns))
initial=_observe()
need(_generation(probe)==probe_generation and _generation(agent)==agent_generation)
def _fresh():
 user=pwd.getpwuid(os.geteuid())
 need((user.pw_uid,user.pw_name,user.pw_dir)==(p['uid'],p['principal'],p['home']))
 need(80 not in os.getgrouplist(user.pw_name,user.pw_gid))
 need(_generation(probe)==probe_generation and _generation(agent)==agent_generation)
 actual=_observe()
 need(_generation(probe)==probe_generation and _generation(agent)==agent_generation)
 need(actual['agent']==initial['agent'] and actual['boot']==initial['boot'] and actual['rawBoot']==initial['rawBoot'])
 return actual
print(json.dumps({'state':'observer_ready','observation':initial},sort_keys=True),flush=True)
for _ in range(1024):
 line=sys.stdin.buffer.readline(16)
 if not line:break
 need(line==b'check\n')
 print(json.dumps({'state':'observed','observation':_fresh()},sort_keys=True),flush=True)
signal.setitimer(signal.ITIMER_REAL,0)
'''
