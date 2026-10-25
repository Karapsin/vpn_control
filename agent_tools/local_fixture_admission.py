"""Actual host memory admission before owned local VM writers are submitted."""
import os
import platform
import re
import subprocess
import time

from . import vm_workflow
from scripts import visual_platform as visual


class LocalAdmissionError(ValueError):
    pass


def memory_plan(requested_mib, deadline, *, runner=subprocess.run, clock=time.monotonic,
                sleep=time.sleep, epoch_ns=time.time_ns):
    """Use the existing admission policy with two actual Darwin paging samples.

    This function neither reserves resources nor starts a guest. Other host
    providers retain their existing platform-specific admission boundary.
    """
    if platform.system() != "Darwin" or type(requested_mib) is not int or requested_mib <= 0:
        raise LocalAdmissionError("local_fixture_admission_platform_unavailable")
    def run(argv):
        remaining = deadline - clock()
        if remaining <= 0:
            raise LocalAdmissionError("local_fixture_admission_deadline")
        value = runner(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                       timeout=min(5, remaining), check=False)
        if value.returncode != 0 or not isinstance(value.stdout, bytes) or len(value.stdout) > 65536:
            raise LocalAdmissionError("local_fixture_memory_observation_unavailable")
        try:
            return value.stdout.decode("ascii")
        except UnicodeError:
            raise LocalAdmissionError("local_fixture_memory_observation_unavailable") from None
    samples = []
    for index in range(2):
        raw = {"vmstat": run(["vm_stat"]), "pressure": run(["memory_pressure", "-Q"]),
               "level": run(["sysctl", "-n", "kern.memorystatus_vm_pressure_level"]),
               "swap": run(["sysctl", "-n", "vm.swapusage"])}
        free = re.search(r"System-wide memory free percentage:\s*(\d+)%", raw["pressure"])
        pageouts = re.search(r"Pageouts:\s*(\d+)", raw["vmstat"])
        swap = re.search(r"used = ([0-9.]+)([MGT])", raw["swap"])
        if raw["level"].strip() != "1" or not all((free, pageouts, swap)):
            raise LocalAdmissionError("local_fixture_memory_pressure_unavailable")
        used = int(float(swap.group(1)) * {"M": 1024**2, "G": 1024**3, "T": 1024**4}[swap.group(2)])
        samples.append({"observedAtUnixMs": epoch_ns() // 1000000, "freePercent": int(free.group(1)),
                        "pageouts": int(pageouts.group(1)), "swapUsedBytes": used, "pressure": "normal", "raw": raw})
        if index == 0:
            if clock() + 2 >= deadline:
                raise LocalAdmissionError("local_fixture_admission_deadline")
            sleep(2)
    physical = run(["sysctl", "-n", "hw.memsize"]).strip()
    if not physical.isdigit():
        raise LocalAdmissionError("local_fixture_memory_observation_unavailable")
    reservations = visual._read_reservations()
    running_mib = sum(visual._tart_running_allocations())
    running_mib += sum(visual._reservation_allocations(reservations))
    measurement = {"platform": "darwin", "physicalMemoryBytes": int(physical),
                   "runningConfiguredMemoryBytes": running_mib * 1024**2, "pressure": "normal",
                   "swapUsedBytes": samples[-1]["swapUsedBytes"],
                   "samples": [{key: value for key, value in sample.items() if key != "raw"} for sample in samples]}
    policy, _ = visual._resource_policy()
    plan = vm_workflow.admit_plan(measurement, requested_memory_bytes=requested_mib * 1024**2,
                                 headroom_bytes=policy["build_headroom_mib"] * 1024**2)
    return {"samples": samples, "measurement": measurement, "plan": plan}
