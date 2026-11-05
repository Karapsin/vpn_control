"""Execute an unchanged emitted owner with an inert host-boot probe.

Only the Darwin-specific boot observation is supplied here. Directory custody,
process generations, private records, PTY output and the owned executable run
through the actual emitted implementation on both Linux and macOS hosts.
"""
from pathlib import Path
import runpy
import subprocess
import sys


owner = Path(sys.argv[1])
host_boot = sys.argv[2]
original_run = subprocess.run


def owned_run(argv, *args, **kwargs):
    if argv == ["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"]:
        return subprocess.CompletedProcess(argv, 0, (host_boot + "\n").encode(), b"")
    return original_run(argv, *args, **kwargs)


subprocess.run = owned_run
runpy.run_path(str(owner), run_name="__main__")
