#!/usr/bin/env python3
"""Exercise the real Darwin worker's admission locks in an opted-in disposable VM."""

import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest
import uuid
import shutil
import plistlib
import sys
import time

if platform.system() == "Darwin":
    import fcntl


@unittest.skipUnless(os.name == "posix", "POSIX process-group contract")
class InstallWatcherGroupTest(unittest.TestCase):
    def test_return_watcher_survives_owner_group_cleanup_without_changing_session(self):
        # Compile only the exact portable worker primitive: no installation,
        # launchd registration, privilege request or application runtime.
        compiler = shutil.which("cc")
        self.assertIsNotNone(compiler, "A C compiler is required for the native helper regression")
        with tempfile.TemporaryDirectory(prefix="vpn-watcher-group-") as directory:
            root = Path(directory)
            header = Path(__file__).resolve().parent / "native/install_watcher_group.h"
            source = root / "probe.c"
            source.write_text('#define _POSIX_C_SOURCE 200809L\n#include <stdio.h>\n#include ' +
                              json.dumps(str(header)) + '\n' + r'''
int main(void) {
    pid_t before = getpgrp(), session = getsid(0);
    uid_t user = getuid(), effective = geteuid();
    if (install_watcher_group() != 0) return 2;
    printf("%ld %ld %ld %ld %ld %ld %ld %ld %ld\n", (long)getpid(),
           (long)before, (long)getpgrp(), (long)session, (long)getsid(0),
           (long)user, (long)getuid(), (long)effective, (long)geteuid());
    return 0;
}
''', encoding="utf-8")
            executable = root / "probe"
            subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", str(source),
                            "-o", str(executable)], check=True, capture_output=True)
            result = subprocess.run([str(executable)], check=True, capture_output=True, text=True)
            pid, before, after, session, current_session, uid, current_uid, euid, current_euid = map(int, result.stdout.split())
            self.assertNotEqual(before, after, "Watcher remains subject to owner process-group cleanup")
            self.assertEqual(pid, after)
            self.assertEqual((session, uid, euid), (current_session, current_uid, current_euid))


@unittest.skipUnless(platform.system() == "Darwin" and os.environ.get("VPN_CONTROL_MAC_INSTALL_GATE_TEST_ROOT"),
                     "Requires an explicitly assigned macOS VM temporary directory")
class MacInstallGateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        parent = Path(os.environ["VPN_CONTROL_MAC_INSTALL_GATE_TEST_ROOT"]).resolve(strict=True)
        if parent.parent != Path("/private/tmp") or not parent.name.startswith("vpn-parity-"):
            raise ValueError("Native fixture must be an existing task-owned /private/tmp/vpn-parity-* directory")
        cls.fixture = tempfile.TemporaryDirectory(prefix="gate-test-", dir=parent)
        cls.root = Path(cls.fixture.name)
        worker = Path(__file__).resolve().parent / "native/macos_install_worker.c"
        source = cls.root / "gate-probe.c"
        source.write_text("#define main packaged_worker_main\n#include " + json.dumps(str(worker)) + "\n#undef main\n" + r'''
int main(int argc, char **argv) {
    if (argc >= 3 && !strcmp(argv[1], "--state-dir")) {
        printf("%s:%s\n", argv[2], argc == 4 ? argv[3] : "gui");
        return 0;
    }
    require(argc == 2, "INVALID_ARGUMENT");
    if (!strcmp(argv[1], "watcher-group")) {
        struct request request = {0};
        struct proc_bsdinfo owner;
        require(generation_snapshot(getppid(), &owner), "UNAVAILABLE");
        request.owner = (struct generation){getppid(), getuid(), owner.pbi_start_tvsec, owner.pbi_start_tvusec};
        require(proc_pidpath(getppid(), request.launcher, sizeof(request.launcher)) > 0, "UNAVAILABLE");
        const char *job = getenv("VPN_CONTROL_WATCHER_PROBE_JOB");
        require(job != NULL, "INVALID_ARGUMENT"); job_check(job);
        text_copy(request.job, sizeof(request.job), job);
        watcher(&request); return 0;
    }
    if (!strcmp(argv[1], "headless-return") || !strcmp(argv[1], "gui-return")) {
        struct request request = {0};
        request.frontend.pid = !strcmp(argv[1], "gui-return") ? 1 : 0;
        text_copy(request.launcher, sizeof(request.launcher), argv[0]);
        text_copy(request.workspace, sizeof(request.workspace), "/private/tmp/isolated-workspace");
        relaunch(&request);
        return 2;
    }
    int root = open(argv[1], O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    require(root >= 0, "UNAVAILABLE");
    struct request request = {0};
    request.owner.uid = getuid();
    text_copy(request.bundle, sizeof(request.bundle), "/Applications/vpn-control-native-test.app");
    struct pins pins = {0};
    int gate = gate_open(root, &request, &pins);
    gate_pending(gate, true);
    puts("ready"); fflush(stdout);
    struct pollfd input = {.fd=STDIN_FILENO, .events=POLLIN};
    while (poll(&input, 1, 15000) > 0) {
        char command;
        if (read(STDIN_FILENO, &command, 1) != 1 || command == 'q') break;
        if (command == 'c') {
            int result = flock(gate, LOCK_EX|LOCK_NB);
            require(result == 0 || errno == EWOULDBLOCK, "UNAVAILABLE");
            puts(result == 0 ? "exclusive" : "blocked"); fflush(stdout);
        }
    }
    gate_pending(gate, false);
    release(&pins); close(root);
    return 0;
}
''', encoding="utf-8")
        cls.probe = cls.root / "gate-probe"
        subprocess.run(["xcrun", "clang", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                        "-Wno-deprecated-declarations", "-framework", "CoreFoundation", str(source),
                        "-o", str(cls.probe)], check=True, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls):
        cls.fixture.cleanup()

    def test_preparation_allows_pending_inspection_but_excludes_other_workers_and_replacement(self):
        jobs = self.root / "jobs"
        jobs.mkdir(mode=0o700)
        gate = jobs / ("gate-" + hashlib.sha256(b"/Applications/vpn-control-native-test.app").hexdigest()[:32])
        process = subprocess.Popen([str(self.probe), str(jobs)], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        reader = None
        try:
            self.assertEqual("ready\n", process.stdout.readline())
            reader = os.open(gate, os.O_RDONLY | os.O_NOFOLLOW)
            fcntl.flock(reader, fcntl.LOCK_SH | fcntl.LOCK_NB)
            self.assertEqual(bytes([0] * 8 + [1] + [0] * 8), os.pread(reader, 18, 0))
            duplicate = subprocess.run([str(self.probe), str(jobs)], input="q", capture_output=True, text=True, timeout=20)
            self.assertEqual(2, duplicate.returncode)
            self.assertEqual("BUSY\n", duplicate.stderr)
            process.stdin.write("c"); process.stdin.flush()
            self.assertEqual("blocked\n", process.stdout.readline())
            os.close(reader); reader = None
            process.stdin.write("c"); process.stdin.flush()
            self.assertEqual("exclusive\n", process.stdout.readline())
            reader = os.open(gate, os.O_RDONLY | os.O_NOFOLLOW)
            with self.assertRaises(BlockingIOError):
                fcntl.flock(reader, fcntl.LOCK_SH | fcntl.LOCK_NB)
        finally:
            if reader is not None:
                os.close(reader)
            output, error = process.communicate("q", timeout=20)
            self.assertEqual(0, process.returncode, error)
        self.assertEqual(bytes(17), gate.read_bytes())
        retry = subprocess.run([str(self.probe), str(jobs)], input="q", capture_output=True, text=True, timeout=20)
        self.assertEqual(0, retry.returncode, retry.stderr)
        self.assertEqual("ready\n", retry.stdout)

    def test_untrusted_reservation_never_creates_or_changes_an_admission_gate(self):
        identity = hashlib.sha256(b"/Applications/vpn-control-native-test.app").hexdigest()[:32]
        for kind in ("symlink", "hardlink", "nonempty", "public"):
            with self.subTest(kind=kind):
                jobs = self.root / ("untrusted-" + kind)
                jobs.mkdir(mode=0o700)
                reservation = jobs / ("reserve-" + identity)
                sentinel = jobs / "preserved"
                sentinel.write_bytes(b"preserve this file")
                sentinel.chmod(0o600)
                if kind == "symlink":
                    reservation.symlink_to(sentinel)
                elif kind == "hardlink":
                    os.link(sentinel, reservation)
                else:
                    reservation.write_bytes(b"invalid" if kind == "nonempty" else b"")
                    reservation.chmod(0o600 if kind == "nonempty" else 0o666)
                attempt = subprocess.run([str(self.probe), str(jobs)], input="q", capture_output=True,
                                         text=True, timeout=20)
                self.assertEqual(2, attempt.returncode)
                self.assertIn(attempt.stderr, ("INVALID_ARGUMENT\n", "UNAVAILABLE\n"))
                self.assertEqual("", attempt.stdout)
                self.assertFalse((jobs / ("gate-" + identity)).exists())
                self.assertEqual(b"preserve this file", sentinel.read_bytes())

    def test_relaunch_preserves_headless_or_gui_intent_and_the_exact_workspace(self):
        for mode, expected in (("headless-return", "serve"), ("gui-return", "gui")):
            with self.subTest(mode=mode):
                result = subprocess.run([str(self.probe), mode], capture_output=True, text=True, timeout=20)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual("/private/tmp/isolated-workspace:" + expected + "\n", result.stdout)

    def test_original_user_watcher_leaves_the_owners_process_group_before_readiness(self):
        # A UUID without any job/receipt means this real watcher can only wait;
        # it cannot install or relaunch. launchd kills the owner's remaining
        # process group when the authorized owner exits after handoff.
        job = str(uuid.uuid4())
        process = subprocess.Popen([str(self.probe), "watcher-group"],
                                   env=dict(os.environ, VPN_CONTROL_WATCHER_PROBE_JOB=job),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(job + "\n", process.stdout.readline())
            self.assertNotEqual(os.getpgrp(), os.getpgid(process.pid),
                                "Return watcher remains in the owner's launchd cleanup group")
            self.assertEqual(os.getsid(0), os.getsid(process.pid), "Login/session context changed")
        finally:
            # This exact probe has no job and cannot run an installer.
            process.terminate()
            process.communicate(timeout=10)

    def test_watcher_survives_actual_launchd_owner_exit(self):
        job = str(uuid.uuid4())
        label = "com.vpncontrol.parity.watcher." + job
        record = self.root / (job + ".json")
        owner = self.root / (job + "-owner.py")
        owner.write_text(
            "import json,os,pathlib,subprocess\n"
            f"p=subprocess.Popen([{str(self.probe)!r},'watcher-group'],"
            f"env=dict(os.environ,VPN_CONTROL_WATCHER_PROBE_JOB={job!r}),"
            "stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)\n"
            "lines=[p.stdout.readline() for _ in range(4)]\n"
            f"assert lines[0]=={(job + chr(10))!r}\n"
            f"pathlib.Path({str(record)!r}).write_text(json.dumps({{'pid':p.pid,'ownerPid':os.getpid()}}))\n",
            encoding="utf-8")
        plist = self.root / (label + ".plist")
        plist.write_bytes(plistlib.dumps({"Label": label, "RunAtLoad": True,
                                         "ProgramArguments": [sys.executable, str(owner)]}))
        domain = "gui/" + str(os.getuid())
        watcher_pid = None
        try:
            subprocess.run(["launchctl", "bootstrap", domain, str(plist)], check=True, capture_output=True)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if record.exists():
                    observation = json.loads(record.read_text())
                    watcher_pid = observation["pid"]
                    status = subprocess.run(["launchctl", "print", domain + "/" + label],
                                            capture_output=True, text=True, check=True).stdout
                    if "state = not running" in status and "last exit code = 0" in status:
                        break
                time.sleep(.05)
            else:
                self.fail("The exact diagnostic owner did not exit normally")
            # This is a real launchd exit, without AbandonProcessGroup. The
            # return watcher itself must survive; it has no install job.
            try:
                group = os.getpgid(watcher_pid)
            except ProcessLookupError:
                self.fail("launchd killed the return watcher when its owner exited")
            self.assertEqual(watcher_pid, group)
        finally:
            if watcher_pid is not None:
                image = subprocess.run(["ps", "-p", str(watcher_pid), "-o", "comm="],
                                       capture_output=True, text=True).stdout.strip()
                if image == str(self.probe):
                    os.kill(watcher_pid, 15)  # Exact harmless no-job probe only.
            subprocess.run(["launchctl", "bootout", domain + "/" + label], capture_output=True)


if __name__ == "__main__":
    unittest.main()
