#!/usr/bin/env python3
"""DESTRUCTIVE TO THE INSTALLED APP: run ONLY in an owned disposable Linux VM.

Uses the installed public launcher and unchanged production update URL/trust/hash
checks. Keeps evidence and never kills a package manager, installer, or owner.
Run as the ordinary VM user.  Native SSH automation with upstream stdin closed
must use --retained-fixture-auth; it keeps the private fixture credential out of
arguments and logs.  Direct local terminal use remains available for a human.
"""
import argparse
import base64
import hashlib
import errno
import inspect
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

from prepare_desktop_update_fixture import image_identity
from arch_public_update import verify_arch_bundle_base
from rpm_public_update import verify_rpm_bundle_base


def timed_update_command(action, seconds):
    return ("--timeout-seconds", str(seconds), "updates", action)


def require_human_terminal(retained_fixture_auth, opener=None):
    """Only direct human prompting depends on the caller's controlling TTY."""
    if not retained_fixture_auth:
        opener = open if opener is None else opener
        with opener("/dev/tty", "rb"):
            pass


def require(value, message):
    if not value:
        raise RuntimeError(message)


def protected_receipt(job):
    require(str(uuid.UUID(job)) == job, "Noncanonical job identity")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in ("var", "lib", "vpn-control-install-jobs", job):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            require(info.st_uid == 0 and not info.st_mode & 0o022, "Untrusted protected receipt ancestry")
        leaf = os.open("status.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        try:
            info = os.fstat(leaf)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                    and not info.st_mode & 0o022, "Untrusted protected receipt")
            raw = os.read(leaf, 4097)
            require(len(raw) <= 4096, "Receipt exceeds bound")
            result = json.loads(raw)
            require(result.get("jobId") == job and result.get("version") == 1, "Receipt identity mismatch")
            return result
        finally:
            os.close(leaf)
    finally:
        os.close(descriptor)


def verify_recovered_install(accepted, receipt, recovery):
    require(receipt.get("phase") == "SUCCEEDED" and receipt.get("code") == "OK"
            and receipt.get("jobId") == accepted.get("data", {}).get("jobId"), "Missing correlated protected success")
    require(recovery.get("ok") is True and recovery.get("code") == "OK" and recovery.get("final") is True,
            "Replacement owner did not recover terminal installation success")
    require(recovery.get("operationId") == accepted.get("operationId") and recovery.get("controllerId")
            and recovery["controllerId"] != accepted.get("controllerId"), "Recovery must belong to the new owner and exact operation")
    data = recovery.get("data", {})
    require(data.get("jobId") == receipt["jobId"] and data.get("originControllerId") == accepted.get("controllerId")
            and data.get("originRequestId") == accepted.get("requestId"), "Recovery correlation differs from the accepted handoff")


def installed_debian_packages():
    result = subprocess.run(["dpkg-query", "-W", "-f=${binary:Package}\t${db:Status-Abbrev}\t${Version}\n"],
                            capture_output=True, text=True, timeout=30, check=True)
    return {fields[0]: fields[2] for line in result.stdout.splitlines()
            if len(fields := line.split("\t")) == 3 and fields[1].startswith("ii")}


def require_package_managed_launcher(launcher):
    """Reject a copied fixture image before it can be counted as an update recovery."""
    checks = (
        (["dpkg-query", "--search", str(launcher)], r"(?m)^vpn-control(?::[^\s:]+)?:\s"),
        (["rpm", "--query", "--file", "--queryformat", "%{NAME}\\n", str(launcher)], r"\Avpn-control\n?\Z"),
        (["pacman", "--query", "--owns", "--quiet", str(launcher)], r"\Avpn-control\n?\Z"),
    )
    unavailable = 0
    for command, expected in checks:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
        except FileNotFoundError:
            unavailable += 1
            continue
        if result.returncode == 0 and re.search(expected, result.stdout):
            return
    require(unavailable != len(checks), "No supported Linux package ownership query is available")
    raise RuntimeError("Same-source recovery requires the base launcher to be owned by vpn-control package metadata")


def launch_fixture_owner(launcher, workspace, log, environment):
    # Keep the owner's lifetime independent of the native-prompt driver's
    # controlling session. The CLI still registers its exact-owner tty agent.
    # macOS development hosts can inject diagnostics into every child through
    # DYLD_INSERT_LIBRARIES; the public harness records this owner's output as
    # one exact JSON stream, so do not pass that host-only injection onward.
    child_environment = dict(environment)
    child_environment.pop("DYLD_INSERT_LIBRARIES", None)
    return subprocess.Popen([str(launcher), "--state-dir", str(workspace), "serve"],
                            stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=child_environment,
                            start_new_session=True)


def _owned_synthetic_workspace(workspace, evidence):
    """Open the exact workspace child without trusting a replaced pathname."""
    workspace = Path(workspace)
    evidence = Path(evidence)
    require(workspace.parent == evidence and workspace.name == "workspace",
            "Cleanup target is not the owned synthetic workspace")
    # Normalize pre-existing host aliases such as macOS /var -> /private/var
    # before detecting a replacement below.  The Linux harness itself creates
    # its evidence below /tmp, but portable focused tests use the host tmpdir.
    evidence = evidence.resolve(strict=True)
    workspace = workspace.resolve(strict=True)
    require(workspace.parent == evidence and workspace.name == "workspace",
            "Synthetic workspace was replaced")
    # Check each named ancestor before using it.  A symlink introduced at any
    # point makes recursive removal unsafe, even if its current target looks
    # plausible.
    current = Path("/")
    for part in evidence.parts[1:]:
        current /= part
        info = os.lstat(current)
        require(not stat.S_ISLNK(info.st_mode), "Synthetic workspace ancestry was replaced")
    evidence_info = os.lstat(evidence)
    require(stat.S_ISDIR(evidence_info.st_mode) and evidence_info.st_uid == os.geteuid()
            and not evidence_info.st_mode & 0o077, "Synthetic evidence directory is untrusted")
    evidence_fd = os.open(evidence, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    workspace_fd = None
    try:
        workspace_fd = os.open("workspace", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=evidence_fd)
        workspace_info = os.fstat(workspace_fd)
        named_info = os.lstat(workspace)
        require(stat.S_ISDIR(workspace_info.st_mode) and workspace_info.st_uid == os.geteuid()
                and (workspace_info.st_dev, workspace_info.st_ino) == (named_info.st_dev, named_info.st_ino),
                "Synthetic workspace was replaced")
        return evidence_fd, workspace_fd
    except Exception:
        if workspace_fd is not None:
            os.close(workspace_fd)
        os.close(evidence_fd)
        raise


def _no_process_uses_workspace(workspace, proc=Path("/proc"), owned_cleanup_fd=None):
    """Reject same-UID references while terminal protected state closes privileged work.

    The protected terminal receipt is the ownership proof for the privileged
    installer. Foreign-UID processes are outside this fixture's ownership;
    every same-UID cwd/fd observation must succeed, except the exact descriptor
    this cleanup invocation holds for descriptor-relative removal.
    """
    require(proc.is_dir(), "Cannot prove synthetic workspace has no process owner")
    workspace_text = str(Path(workspace))
    prefix = workspace_text + "/"
    own_pid = str(os.getpid())
    require(owned_cleanup_fd is None or isinstance(owned_cleanup_fd, int) and owned_cleanup_fd >= 0,
            "Cleanup workspace descriptor is invalid")
    def require_process_gone(entry):
        # A missing cwd/fd does not prove exit: procfs can withhold those
        # entries while the thread group still exists. Only a missing PID
        # directory permits treating that observation as a completed exit.
        try:
            os.stat(entry, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError as error:
            raise RuntimeError("Cannot inspect process ownership of synthetic workspace") from error
        raise RuntimeError("Cannot inspect process ownership of synthetic workspace")
    try:
        entries = list(proc.iterdir())
    except OSError as error:
        raise RuntimeError("Cannot inspect process ownership of synthetic workspace") from error
    for entry in entries:
        if not entry.name.isdecimal():
            continue
        try:
            process_info = os.stat(entry, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise RuntimeError("Cannot inspect process ownership of synthetic workspace") from error
        if process_info.st_uid != os.geteuid():
            continue
        for target in (entry / "cwd",):
            try:
                reference = os.readlink(target)
            except FileNotFoundError:
                require_process_gone(entry)
                continue
            except OSError as error:
                raise RuntimeError("Cannot inspect process ownership of synthetic workspace") from error
            require(reference != workspace_text and not reference.startswith(prefix),
                    "A process still owns the synthetic workspace")
        fds = entry / "fd"
        try:
            descriptors = list(fds.iterdir())
        except FileNotFoundError:
            require_process_gone(entry)
            continue
        except OSError as error:
            raise RuntimeError("Cannot inspect process ownership of synthetic workspace") from error
        for descriptor in descriptors:
            # Exempt only the stable directory handle held by this invocation.
            if entry.name == own_pid and owned_cleanup_fd is not None and descriptor.name == str(owned_cleanup_fd):
                continue
            try:
                reference = os.readlink(descriptor)
            except FileNotFoundError:
                continue
            except OSError as error:
                raise RuntimeError("Cannot inspect process ownership of synthetic workspace") from error
            require(reference != workspace_text and not reference.startswith(prefix),
                    "A process still owns the synthetic workspace")


def _privileged_workspace_observation(proc, workspace, uid, own_pid, own_start_ticks, own_fd, expected_identity):
    """Inspect every target-UID process; exempt only the verified cleanup descriptor."""
    proc, workspace = Path(proc), Path(workspace)
    workspace_text = str(workspace)
    prefix = workspace_text + "/"
    def unknown(reason):
        return {'state': 'unknown', 'reason': reason}
    try:
        if (not workspace.is_absolute() or type(uid) is not int or uid <= 0
                or any(type(value) is not int or value < 0 for value in (own_pid, own_start_ticks, own_fd))
                or not proc.is_dir()):
            return unknown('invalid-input')
        identity = os.stat(workspace)
        if not stat.S_ISDIR(identity.st_mode) or (identity.st_dev, identity.st_ino) != tuple(expected_identity):
            return unknown('workspace-identity')
        parent = proc / str(own_pid)
        parent_fields = (parent / 'stat').read_text(encoding='ascii').rsplit(')', 1)[1].split()
        if int(parent_fields[19]) != own_start_ticks:
            return unknown('owner-generation')
        owned_descriptor = parent / 'fd' / str(own_fd)
        held = os.stat(owned_descriptor)
        if (held.st_dev, held.st_ino) != tuple(expected_identity) or os.readlink(owned_descriptor) != workspace_text:
            return unknown('owner-descriptor')
        processes = [entry for entry in proc.iterdir() if entry.name.isdecimal()]
        if len(processes) > 4096:
            return unknown('process-count')
        seen = 0
        for entry in processes:
            try:
                lines = (entry / 'status').read_text(encoding='ascii').splitlines()
                matches = [line.split()[1:] for line in lines if line.startswith('Uid:')]
                if len(matches) != 1 or len(matches[0]) != 4:
                    return unknown('process-status-invalid')
                uids = tuple(int(value) for value in matches[0])
            except FileNotFoundError:
                if not entry.exists():
                    continue
                return unknown('process-status-unavailable')
            except (OSError, ValueError):
                return unknown('process-status-unavailable')
            if uid not in uids:
                continue
            seen += 1
            try:
                fields = (entry / 'stat').read_text(encoding='ascii').rsplit(')', 1)[1].split()
                state, start_ticks = fields[0], int(fields[19])
                if len(state) != 1 or start_ticks <= 0:
                    return unknown('process-generation')
                if state in ('Z', 'X'):
                    continue
                cwd = os.readlink(entry / 'cwd')
                root = os.readlink(entry / 'root')
                descriptors = list((entry / 'fd').iterdir())
                if len(descriptors) > 8192:
                    return unknown('descriptor-count')
            except FileNotFoundError:
                if not entry.exists():
                    continue
                return unknown('process-links-unavailable')
            except (OSError, ValueError, IndexError):
                return unknown('process-links-unavailable')
            if any(value == workspace_text or value.startswith(prefix) for value in (cwd, root)):
                return {'state': 'referenced', 'pid': int(entry.name), 'startTicks': start_ticks}
            for descriptor in descriptors:
                if not descriptor.name.isdecimal():
                    continue
                if entry.name == str(own_pid) and descriptor.name == str(own_fd):
                    continue
                try:
                    reference = os.readlink(descriptor)
                except FileNotFoundError:
                    continue
                except OSError:
                    return unknown('descriptor-unavailable')
                if reference == workspace_text or reference.startswith(prefix):
                    return {'state': 'referenced', 'pid': int(entry.name), 'startTicks': start_ticks}
        final = os.stat(workspace)
        if (final.st_dev, final.st_ino) != tuple(expected_identity):
            return unknown('workspace-changed')
        return {'state': 'absent', 'sameUidCount': seen}
    except (OSError, ValueError, IndexError, TypeError):
        return unknown('observer-exception')


_PRIVILEGED_WORKSPACE_PROGRAM = (
    'import json,os,pwd,stat,sys\nfrom pathlib import Path\n'
    + inspect.getsource(_privileged_workspace_observation)
    + "\nif os.geteuid()!=0: raise SystemExit(3)\n"
      "workspace,uid,pid,ticks,fd,dev,ino=sys.argv[1:]\n"
      "if pwd.getpwnam('vpnfixture').pw_uid!=int(uid): raise SystemExit(4)\n"
      "result=_privileged_workspace_observation(Path('/proc'),Path(workspace),int(uid),int(pid),int(ticks),int(fd),(int(dev),int(ino)))\n"
      "print(json.dumps(result,separators=(',',':')))\n")


def _privileged_no_process_uses_workspace(workspace, owned_cleanup_fd):
    """Use the guest's fixed passwordless sudo only for read-only proc proof."""
    if sys.platform != 'linux':
        raise RuntimeError('Privileged process ownership observation is unavailable')
    identity = os.fstat(owned_cleanup_fd)
    parent_fields = Path('/proc/self/stat').read_text(encoding='ascii').rsplit(')', 1)[1].split()
    args = [str(workspace), str(os.geteuid()), str(os.getpid()), str(int(parent_fields[19])),
            str(owned_cleanup_fd), str(identity.st_dev), str(identity.st_ino)]
    try:
        observed = subprocess.run(['sudo', '-n', '--', 'python3', '-I', '-B', '-c',
                                   _PRIVILEGED_WORKSPACE_PROGRAM, *args],
                                  stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                  timeout=30, check=False)
        if observed.returncode != 0 or len(observed.stdout) > 4096:
            raise RuntimeError('Privileged process ownership observation is unavailable')
        result = json.loads(observed.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise RuntimeError('Privileged process ownership observation is unavailable') from error
    require(isinstance(result, dict) and result.get('state') == 'absent'
            and type(result.get('sameUidCount')) is int and 0 < result['sameUidCount'] <= 4096,
            'Privileged process ownership observation is unknown or still referenced')


def _remove_owned_workspace_tree(directory_fd):
    """Remove a current-user directory tree through descriptor-relative names."""
    for entry in os.scandir(directory_fd):
        info = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
        require(info.st_uid == os.geteuid() and not stat.S_ISLNK(info.st_mode),
                "Synthetic workspace contains an untrusted entry")
        if stat.S_ISDIR(info.st_mode):
            child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
            try:
                _remove_owned_workspace_tree(child)
            finally:
                os.close(child)
            os.rmdir(entry.name, dir_fd=directory_fd)
        else:
            require(stat.S_ISREG(info.st_mode), "Synthetic workspace contains a non-file entry")
            os.unlink(entry.name, dir_fd=directory_fd)


def cleanup_synthetic_workspace(workspace, evidence, owner, protected_success, recovered, credential_restored):
    """Remove only the terminal, recovered RPM synthetic workspace.

    Any missing proof leaves the workspace and all evidence intact.  This never
    signals an owner or installer; it merely rejects a still-live owner.
    """
    require(protected_success and recovered and credential_restored,
            "Synthetic workspace cleanup requires terminal protected recovery and restored credential")
    require(owner.poll() is not None, "Fixture owner is still running; workspace retained")
    evidence_fd, workspace_fd = _owned_synthetic_workspace(workspace, evidence)
    try:
        try:
            try:
                _no_process_uses_workspace(workspace, owned_cleanup_fd=workspace_fd)
            except RuntimeError as error:
                cause = error.__cause__
                if not isinstance(cause, PermissionError) or cause.errno not in (errno.EACCES, errno.EPERM):
                    raise
                _privileged_no_process_uses_workspace(workspace, workspace_fd)
            _remove_owned_workspace_tree(workspace_fd)
        finally:
            os.close(workspace_fd)
        os.rmdir("workspace", dir_fd=evidence_fd)
    finally:
        os.close(evidence_fd)
    require(not os.path.lexists(workspace), "Synthetic workspace removal is uncertain")


_ANSI_TERMINAL_ESCAPE = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")
_PASSWORD_PROMPT = re.compile(rb"(?:^|[\r\n])Password:[ \t]*$")
_IDENTITY_SELECTOR = re.compile(
    rb"(?:^|[\r\n])Multiple identities can be used for authentication:\r?\n"
    rb"(?P<entries>(?:[ \t]*[1-9][0-9]*\.[^\r\n]*\r?\n)+)"
    rb"Choose identity to authenticate as \((?P<first>[1-9][0-9]*)-"
    rb"(?P<last>[1-9][0-9]*)\):[ \t]*$"
)
_IDENTITY_ENTRY = re.compile(rb"[ \t]*(?P<choice>[1-9][0-9]*)\.[ \t]+(?P<identity>[^\r\n]*?)[ \t]*$")
_FIXTURE_ACCOUNT = re.compile(r"[a-z_][a-z0-9_-]*\$?\Z")


def terminal_password_prompt_seen(terminal_bytes):
    """Recognize only a current terminal password prompt, never diagnostics.

    This checks prompt text only. Automated callers must additionally use
    terminal_password_input_ready before writing a response. In particular,
    JVM options such as ``trustStorePassword=...`` are not a prompt.
    """
    return _PASSWORD_PROMPT.search(_ANSI_TERMINAL_ESCAPE.sub(b"", terminal_bytes)) is not None


def terminal_authorized_identity_choice(terminal_bytes, authorized_identity):
    """Return only polkit's numbered choice for one explicitly authorized account.

    An identity selector precedes the password prompt on guests with multiple
    fixture accounts.  It is not credential input: callers must still use
    ``terminal_password_input_ready`` before writing a password.  The complete,
    current selector and its contiguous bounded choices are required so text in
    diagnostics or a partial selector cannot trigger a response.
    """
    if not isinstance(authorized_identity, str) or not _FIXTURE_ACCOUNT.fullmatch(authorized_identity):
        return None
    selector = _IDENTITY_SELECTOR.search(_ANSI_TERMINAL_ESCAPE.sub(b"", terminal_bytes))
    if selector is None:
        return None
    first, last = int(selector["first"]), int(selector["last"])
    if first > last or last - first > 32:
        return None
    choices = []
    for line in selector["entries"].splitlines():
        entry = _IDENTITY_ENTRY.fullmatch(line)
        if entry is None:
            return None
        choices.append((int(entry["choice"]), entry["identity"]))
    if [choice for choice, _ in choices] != list(range(first, last + 1)):
        return None
    expected = authorized_identity.encode("ascii")
    matches = [choice for choice, identity in choices if identity == expected]
    return str(matches[0]).encode("ascii") if len(matches) == 1 else None


def terminal_password_input_ready(terminal_bytes, terminal_fd):
    """Admit a fixture response after polkit's post-prompt input flush.

    Poll this even when no new output arrives. Polkit prints its prompt before
    TCSAFLUSH disables echo; writing immediately can lose or echo the response.
    This only inspects terminal attributes and never reads a credential.
    """
    if not terminal_password_prompt_seen(terminal_bytes):
        return False
    try:
        import termios
    except ImportError:
        return False
    try:
        # ECHOE and ECHOK only modify canonical echo behavior when ECHO is
        # enabled.  Programs commonly leave those inert flags set when they
        # disable input echo.  ECHONL can still emit the submitted newline.
        echo_flags = termios.ECHO | termios.ECHONL
        return termios.tcgetattr(terminal_fd)[3] & echo_flags == 0
    except (termios.error, OSError, ValueError):
        return False


def write_password_to_original_master(master_fd, password):
    """Write only through the PTY master retained by the observing driver."""
    require(isinstance(password, bytes) and password and b"\n" not in password and b"\r" not in password,
            "Credential input is invalid")
    payload = password + b"\n"
    written = os.write(master_fd, payload)
    require(written == len(payload), "Credential delivery was partial")


def launch_with_controlling_tty(arguments, slave_fd, **kwargs):
    """Give a single-threaded Linux fixture driver's child its own controlling PTY."""
    import sys
    require(sys.platform.startswith("linux"), "Controlling terminal fixture requires Linux")
    import fcntl
    import termios

    def attach_tty():
        os.setsid()
        fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
    stdout = kwargs.pop("stdout", slave_fd)
    return subprocess.Popen(arguments, stdin=slave_fd, stdout=stdout, stderr=slave_fd,
                            preexec_fn=attach_tty, **kwargs)


def terminal_install_handoff(observation):
    """Validate a complete public handoff response without replaying work."""
    # PTY EOF can race process reaping. A complete response plus successful
    # client exit remains authoritative; the observation-loss flag is retained
    # separately as evidence and never erases an acknowledged handoff.
    accepted = observation.get("envelope") or {}
    require(observation.get("childExit") == 0 and accepted.get("code") == "ACCEPTED"
            and accepted.get("final") is False and accepted.get("data", {}).get("handoffReady") is True,
            "Installation handoff is not proven; preserve evidence without replay")
    job, operation = accepted["data"].get("jobId"), accepted.get("operationId")
    require(isinstance(job, str) and str(uuid.UUID(job)) == job, "Missing durable job identity")
    require(isinstance(operation, str) and str(uuid.UUID(operation)) == operation,
            "Missing durable operation identity")
    return job, operation


def observe_terminal_process(process, terminal_fd, on_output, timeout_seconds=None):
    """Observe a single already-started terminal process without replaying it.

    Linux reports EIO when the final PTY slave closes.  Preserve that as an
    unknown observation outcome; callers must inspect durable receipts rather
    than retrying the action they were observing.
    """
    deadline = None if timeout_seconds is None else time.monotonic() + timeout_seconds
    observation_lost = False

    def drain():
        nonlocal observation_lost
        while select.select([terminal_fd], [], [], 0)[0]:
            try:
                data = os.read(terminal_fd, 4096)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                observation_lost = True
                return
            if not data:
                return
            on_output(data)

    while True:
        # Read before checking poll so a child that has just exited cannot lose
        # terminal bytes that were already buffered by the PTY master.
        drain()
        exit_code = process.poll()
        if exit_code is not None:
            drain()
            return {"exit": exit_code, "observationLost": observation_lost, "timedOut": False}
        if observation_lost:
            return {"exit": None, "observationLost": True, "timedOut": False}
        if deadline is not None and time.monotonic() >= deadline:
            return {"exit": None, "observationLost": False, "timedOut": True}
        wait = 0.25 if deadline is None else min(0.25, max(0.0, deadline - time.monotonic()))
        select.select([terminal_fd], [], [], wait)


def retained_terminal_master():
    """Create the one PTY whose master remains owned by this guest-side driver."""
    import pty
    master, slave = pty.openpty()
    try:
        require(os.isatty(master) and os.isatty(slave), "Retained terminal is not a PTY")
        require(stat.S_ISCHR(os.fstat(master).st_mode), "Retained terminal master is not a character device")
        return master, slave
    except BaseException:
        os.close(master)
        os.close(slave)
        raise


def _terminal_json_envelope(public_stdout):
    """Decode exactly one CLI stdout document, never terminal prompt text."""
    if not public_stdout.strip():
        raise RuntimeError("Retained CLI stdout did not contain one public result envelope (empty)")
    try:
        candidate = json.loads(public_stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError("Retained CLI stdout did not contain one public result envelope (invalid JSON)") from None
    require(isinstance(candidate, dict) and candidate.get("schemaVersion") == 1,
            "Retained CLI stdout did not contain one public result envelope (wrong schema)")
    return candidate


def prepare_retained_fixture_auth(evidence, correlation, preserve_existing_password=False):
    """Create and re-admit the private input before any owner or install starts."""
    require(preserve_existing_password is True or preserve_existing_password is False,
            "Existing-password preservation must be explicitly boolean")
    from linux_fixture_auth import (FIXTURE_ACCOUNT, OWNED_GUEST_CONFIRMATION, PURPOSE, prepare, status)

    credential_directory = evidence / "private-fixture-auth"
    prepared = prepare(credential_dir=credential_directory, correlation=correlation, purpose=PURPOSE,
                       guest_confirmation=OWNED_GUEST_CONFIRMATION,
                       preserve_existing_password=preserve_existing_password)
    admitted = status(credential_dir=credential_directory, correlation=correlation, purpose=PURPOSE)
    require(prepared == admitted and admitted.get("account") == FIXTURE_ACCOUNT,
            "Private fixture credential account admission failed")
    return credential_directory, correlation, FIXTURE_ACCOUNT, PURPOSE


def invoke_retained_install(launcher, workspace, environment, arguments, credential_directory, correlation,
                            purpose, authorized_identity, evidence, seconds=270, retained_fds=None):
    """Run the fixed public install command through one retained guest PTY.

    The driver never forwards an arbitrary command or a PTY slave.  It keeps the
    original master open until the already-started command reaches a terminal
    result, and it records only a safe observation receipt rather than terminal
    text. It protects input while this guest-side process remains alive; a
    separate supervisor is still required to survive process termination.
    """
    from linux_fixture_auth import read_credential_after_prompt, status

    require(tuple(arguments) == timed_update_command("install", 240),
            "Retained terminal driver permits only the fixed public install command")
    # Reject invalid credentials before allocating platform resources or changing signals.
    # Status returns metadata only and never materializes the credential.
    credential = status(credential_dir=credential_directory, correlation=correlation, purpose=purpose)
    require(credential.get("correlation") == correlation and credential.get("purpose") == purpose
            and credential.get("account") == authorized_identity,
            "Credential admission differs from the retained terminal identity")
    public_output = tempfile.TemporaryFile(mode="w+b")
    try:
        master, slave = retained_fds if retained_fds is not None else retained_terminal_master()
    except BaseException:
        public_output.close()
        raise
    output = bytearray()
    selected = False
    password_written = False
    deadline_elapsed = False
    old_hup = signal.signal(signal.SIGHUP, signal.SIG_IGN)
    try:
        process = launch_with_controlling_tty(
            [str(launcher), "--state-dir", str(workspace), "--json", *arguments], slave,
            env=environment, stdout=public_output)
        os.close(slave)
        slave = None
        deadline = time.monotonic() + seconds
        while True:
            def observe(data):
                # Do not append unbounded data or write a terminal transcript.
                output.extend(data)
                del output[:-65536]

            result = observe_terminal_process(process, master, observe, timeout_seconds=0)
            if not selected:
                choice = terminal_authorized_identity_choice(bytes(output), authorized_identity)
                if choice is not None:
                    require(os.write(master, choice + b"\n") == len(choice) + 1,
                            "Identity selection delivery was partial")
                    selected = True
            if not password_written and terminal_password_input_ready(bytes(output), master):
                password = read_credential_after_prompt(credential_dir=credential_directory, correlation=correlation,
                                                        purpose=purpose, prompt_confirmed=True)
                try:
                    require(isinstance(password, str), "Private fixture credential is not text")
                    write_password_to_original_master(master, password.encode("utf-8"))
                finally:
                    # The private byte object is not copied to output/evidence.
                    del password
                password_written = True
            if result["exit"] is not None or result["observationLost"]:
                break
            if not deadline_elapsed and time.monotonic() >= deadline:
                # This deadline ends the caller's expected observation window,
                # not the already-authorized native command.  Keep the one
                # master and child owner until a terminal observation arrives.
                deadline_elapsed = True
                (evidence / "retained-terminal-observation.json").write_text(json.dumps({
                    "correlation": correlation, "exit": None, "observationLost": False,
                    "timedOut": True, "identitySelected": selected,
                    "credentialWritten": password_written,
                }, indent=2))
            time.sleep(0.05)
        envelope = None
        envelope_error = None
        if result["exit"] is not None:
            try:
                public_output.seek(0)
                public_stdout = public_output.read(65537)
                require(len(public_stdout) <= 65536, "Retained CLI stdout exceeded the public result limit")
                envelope = _terminal_json_envelope(public_stdout)
            except RuntimeError as error:
                envelope_error = str(error)
        receipt = {"correlation": correlation, "exit": result["exit"],
                   "observationLost": result["observationLost"], "timedOut": result["timedOut"],
                   "deadlineElapsed": deadline_elapsed,
                   "identitySelected": selected, "credentialWritten": password_written}
        if envelope is not None:
            # This is a public correlation record, not the raw terminal stream.
            receipt["envelope"] = envelope
        if envelope_error is not None:
            receipt["envelopeError"] = envelope_error
        (evidence / "retained-terminal-observation.json").write_text(json.dumps(receipt, indent=2))
        if result["observationLost"] and result["exit"] is None:
            raise RuntimeError(f"Retained terminal outcome UNKNOWN; process/evidence retained at {evidence}")
        require(envelope is not None, envelope_error)
        return result["exit"], envelope
    finally:
        signal.signal(signal.SIGHUP, old_hup)
        if slave is not None:
            os.close(slave)
        os.close(master)
        public_output.close()


def close_recovered_fixture_owner(ok, recovery):
    """Quit only the recovered synthetic OFF owner before workspace cleanup."""
    controller = recovery.get("controllerId")
    require(isinstance(controller, str) and str(uuid.UUID(controller)) == controller,
            "Cleanup requires the exact recovered owner")
    status = ok("--controller-id", controller, "status")
    require(status.get("controllerId") == controller and
            status.get("data", {}).get("runtimeRunning") is False,
            "Cleanup must preserve a running or changed owner")
    stopped = ok("--controller-id", controller, "quit")
    require(stopped.get("controllerId") == controller and stopped.get("final") is True,
            "Recovered owner quit is not proven; workspace retained")
    return {"controllerId": controller, "runtimeOff": True, "quitAcknowledged": True}


def _unique_endpoint_object(pairs):
    value={}
    for key,item in pairs:
        if key in value:raise ValueError()
        value[key]=item
    return value
def endpoint_port(path,controller):
    """Read the owned schema1 endpoint; never return or log its token."""
    fd=-1
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        before=os.fstat(fd)
        if not(stat.S_ISREG(before.st_mode)and before.st_uid==os.geteuid()and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=4096):raise RuntimeError()
        raw=os.read(fd,4097);value=json.loads(raw,object_pairs_hook=_unique_endpoint_object)
        fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        if tuple(getattr(before,k)for k in fields)!=tuple(getattr(os.fstat(fd),k)for k in fields):raise RuntimeError()
        if len(raw)!=before.st_size or not isinstance(value,dict)or type(value.get('schemaVersion'))is not int or value.get('schemaVersion')!=1:raise RuntimeError()
        port=value.get('port');cid=value.get('controllerId');token=value.get('token')
        if type(port)is not int or not 1<=port<=65535 or cid!=controller or str(uuid.UUID(cid))!=cid:raise RuntimeError()
        if not isinstance(token,str)or not re.fullmatch(r'[A-Za-z0-9_-]{43}',token)or len(base64.urlsafe_b64decode(token+'='))!=32:raise RuntimeError()
        if 'documentTransfers'in value and type(value['documentTransfers'])is not bool:raise RuntimeError()
        return port
    except Exception:
        raise RuntimeError('private_endpoint_admission_failed')from None
    finally:
        if fd>=0:os.close(fd)


def _download_intent(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())


def _process_birth(pid, proc=Path("/proc")):
    return int((proc / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()[19])


def _wait_client_socket_observation(proc, pid, birth, uid, port, expected_argv):
    """Read only the exact wait process; credentials never enter the result."""
    p = proc / str(pid)
    require(p.stat().st_uid == uid and _process_birth(pid, proc) == birth,
            "Wait client identity differs")
    argv = (p / "cmdline").read_bytes().rstrip(b"\0").split(b"\0")
    expected = [part.encode() for part in expected_argv]
    require(argv[-len(expected):] == expected, "Wait client argv differs")
    inodes = set()
    for fd in (p / "fd").iterdir():
        try:
            link = os.readlink(fd)
        except FileNotFoundError:
            continue
        if link.startswith("socket:[") and link.endswith("]"):
            inodes.add(link[8:-1])
    require(len(inodes) < 256, "Wait client socket bound exceeded")
    connected = False
    for name in ("tcp", "tcp6"):
        for line in (p / "net" / name).read_text().splitlines()[1:]:
            fields = line.split()
            if (len(fields) >= 10 and fields[3] == "01" and fields[9] in inodes
                    and int(fields[2].rsplit(":", 1)[1], 16) == port):
                connected = True
    require(p.stat().st_uid == uid and _process_birth(pid, proc) == birth,
            "Wait client identity changed")
    require((p / "cmdline").read_bytes().rstrip(b"\0").split(b"\0")[-len(expected):] == expected,
            "Wait client argv changed")
    return {"connectedToOwnedActivationPort": connected, "pid": pid,
            "startTicks": birth, "uid": uid}


_WAIT_CLIENT_PROGRAM = (
    "import json,os,sys\nfrom pathlib import Path\n"
    + inspect.getsource(require) + inspect.getsource(_process_birth)
    + inspect.getsource(_wait_client_socket_observation)
    + "assert os.geteuid()==0\n"
      "pid,birth,uid,port=map(int,sys.argv[1:5])\n"
      "print(json.dumps(_wait_client_socket_observation(Path('/proc'),pid,birth,uid,port,json.loads(sys.argv[5]))))\n"
)


def recover_download_after_wait_client_loss(launcher, workspace, evidence, environment,
                                           owner, invoke, ok, target_bytes, target_sha256):
    """Native-proven procedure; preserve one accepted download on uncertainty."""
    require(type(target_bytes) is int and 0 < target_bytes <= 1_000_000_000
            and isinstance(target_sha256, str) and re.fullmatch('[0-9a-f]{64}', target_sha256),
            "Download target identity is invalid")
    baseline = ok("status")
    cid = baseline.get("controllerId")
    require(isinstance(cid, str) and str(uuid.UUID(cid)) == cid
            and baseline.get("data", {}).get("runtimeRunning") is False,
            "Download recovery requires a synthetic OFF owner")
    owner_birth = _process_birth(owner.pid)
    require(owner.poll() is None, "Download owner exited")
    code, accepted = invoke("--controller-id", cid, "--async", "updates", "download")
    op = accepted.get("operationId")
    require(code == 0 and accepted.get("code") == "ACCEPTED" and accepted.get("final") is False
            and accepted.get("controllerId") == cid and isinstance(op, str) and str(uuid.UUID(op)) == op,
            "Download acceptance is unknown; do not retry")
    _download_intent(evidence / "download-accepted.public.json",
                     {"controllerId": cid, "operationId": op, "requestId": accepted.get("requestId"),
                      "replayAllowed": False, "targetBytes": target_bytes, "targetSha256": target_sha256})
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        progress = ok("--controller-id", cid, "updates", "status")["data"]
        if progress.get("phase") == "downloading" and 0 < progress.get("downloadedBytes", 0) < target_bytes:
            break
        time.sleep(0.1)
    else:
        raise RuntimeError("In-flight download not observed; retained operation must be recovered without replay")
    arguments = ["--state-dir", str(workspace), "--json", "--controller-id", cid, "operations", "wait", op]
    with (evidence / "lost-wait.stdout.private").open("xb") as stdout, \
            (evidence / "lost-wait.stderr.private").open("xb") as stderr:
        waiter = subprocess.Popen([str(launcher), *arguments], stdin=subprocess.DEVNULL,
                                  stdout=stdout, stderr=stderr, env=environment)
        birth, uid = _process_birth(waiter.pid), os.geteuid()
        _download_intent(evidence / "lost-wait.handle.public.json",
                         {"pid": waiter.pid, "startTicks": birth, "uid": uid, "role": "operation-wait-client"})
        port = endpoint_port(workspace / "activation.port", cid)
        deadline = time.monotonic() + 8
        connected = False
        while waiter.poll() is None and time.monotonic() < deadline:
            observed = subprocess.run(["sudo", "-n", "python3", "-I", "-B", "-c", _WAIT_CLIENT_PROGRAM,
                                       str(waiter.pid), str(birth), str(uid), str(port), json.dumps(arguments)],
                                      capture_output=True, timeout=5, check=False)
            require(observed.returncode == 0 and not observed.stderr and len(observed.stdout) <= 4096,
                    "Wait client socket identity is unknown; process retained")
            socket = json.loads(observed.stdout)
            require(socket.get("pid") == waiter.pid and socket.get("startTicks") == birth
                    and socket.get("uid") == uid and type(socket.get("connectedToOwnedActivationPort")) is bool,
                    "Wait client socket receipt differs")
            if socket["connectedToOwnedActivationPort"]:
                connected = True
                break
            time.sleep(0.1)
        require(connected and waiter.poll() is None and owner.poll() is None and waiter.pid != owner.pid,
                "Exact connected wait client is unavailable; process retained")
        status = ok("--controller-id", cid, "status")
        require(status.get("controllerId") == cid and status.get("data", {}).get("runtimeRunning") is False
                and _process_birth(owner.pid) == owner_birth and owner.poll() is None
                and _process_birth(waiter.pid) == birth
                and (Path('/proc') / str(waiter.pid)).stat().st_uid == uid
                and (Path('/proc') / str(waiter.pid) / 'cmdline').read_bytes().rstrip(b'\0').split(b'\0')[-len(arguments):]
                    == [part.encode() for part in arguments],
                "Owner or wait client changed before loss; processes retained")
        _download_intent(evidence / "lost-wait-termination.intent.public.json",
                         {"pid": waiter.pid, "startTicks": birth, "uid": uid, "role": "operation-wait-client",
                          "ownerPid": owner.pid, "ownerStartTicks": owner_birth, "controllerId": cid,
                          "operationId": op, "signal": "SIGTERM", "runtimeOff": True, "socketConnected": True})
        waiter.terminate()
        wait_exit = waiter.wait(timeout=15)
        require(wait_exit in (-signal.SIGTERM, 128 + signal.SIGTERM), "Wait client terminal exit differs")
    code, terminal = invoke("--controller-id", cid, "--timeout-seconds", "600", "operations", "wait", op, seconds=630)
    require(code == 0 and terminal.get("code") == "OK" and terminal.get("final") is True
            and terminal.get("operationId") == op and terminal.get("controllerId") == cid,
            "Original download recovery is incomplete; do not retry")
    ready = ok("--controller-id", cid, "updates", "status")["data"]
    status = ok("--controller-id", cid, "status")
    require(ready.get("phase") == "ready" and status.get("controllerId") == cid
            and status.get("data", {}).get("runtimeRunning") is False
            and owner.poll() is None and _process_birth(owner.pid) == owner_birth,
            "Download owner or OFF intent differs after recovery")
    matches = []
    for path in workspace.rglob('*'):
        info = path.lstat()
        if stat.S_ISREG(info.st_mode) and info.st_size == target_bytes:
            with path.open('rb') as stream:
                digest = hashlib.sha256()
                for chunk in iter(lambda: stream.read(65536), b''):
                    digest.update(chunk)
            if digest.hexdigest() == target_sha256:
                matches.append(path)
    require(len(matches) == 1, "Recovered download target length/hash differs")
    operations = ok("--controller-id", cid, "operations", "list")["data"]["operations"]
    downloads = [item for item in operations if item.get("operation") == "updates.download"]
    require(len(downloads) == 1 and downloads[0].get("id") == op, "Download was duplicated")
    result = {"operationId": op, "controllerId": cid, "waitClientPid": waiter.pid,
              "waitClientStartTicks": birth, "waitClientExit": wait_exit, "socketConnectedBeforeLoss": True,
              "ownerPid": owner.pid, "ownerStartTicks": owner_birth, "ownerUnaffected": True,
              "runtimeStayedOff": True, "targetBytesVerified": True, "singleDownloadOperation": True,
              "downloadTerminalCode": terminal['code'], "downloadTerminalExit": code, "downloadTerminalFinal": True}
    _download_intent(evidence / "download-recovery.public.json", result)
    return result


def run(launcher, target_version, confirmed, same_source_recovery=False, fresh_deb_dependencies=False,
        arch_source_fixture=None, rpm_source_fixture=None, retained_fixture_auth=False,
        preserve_existing_fixture_password=False, cleanup_synthetic_workspace_after_success=False,
        download_wait_client_loss=False, download_target_bytes=None, download_target_sha256=None):
    require(confirmed and os.uname().sysname == "Linux" and os.getuid() != 0,
            "Explicit owned-disposable-VM confirmation and non-root Linux user required")
    require(not download_wait_client_loss or (same_source_recovery and retained_fixture_auth),
            "Wait client loss requires source-matched retained native fixture admission")
    require_human_terminal(retained_fixture_auth)
    require(not (arch_source_fixture is not None and rpm_source_fixture is not None),
            "Arch and RPM source fixtures are mutually exclusive")
    require(not preserve_existing_fixture_password or retained_fixture_auth,
            "Existing fixture password preservation requires retained fixture authentication")
    require(not cleanup_synthetic_workspace_after_success or
            (same_source_recovery and retained_fixture_auth),
            "Synthetic workspace cleanup requires same-source recovery and retained fixture credentials")
    if arch_source_fixture is not None:
        # The privileged Arch adapter admits only this fixed installation root.
        # Reject alternate fixture paths before launching any owner or authorization.
        require(launcher == Path("/opt/vpn-control/bin/vpn-control"),
                "Arch public installation requires /opt/vpn-control/bin/vpn-control")
        require(same_source_recovery and not fresh_deb_dependencies,
                "Arch fixture requires same-source recovery without DEB dependency checks")
        fixture = verify_arch_bundle_base(launcher, arch_source_fixture)
    elif rpm_source_fixture is not None:
        require(launcher == Path("/opt/vpn-control/bin/vpn-control"),
                "RPM public installation requires /opt/vpn-control/bin/vpn-control")
        require(same_source_recovery and not fresh_deb_dependencies,
                "RPM fixture requires same-source recovery without DEB dependency checks")
        fixture = verify_rpm_bundle_base(launcher, rpm_source_fixture)
    else:
        launcher = launcher.resolve(strict=True)
        marker = launcher.parent.parent / "TEST-ONLY-INSTALL-FIXTURE.json"
        fixture = json.loads(marker.read_text())
    require(fixture.get("testOnly") is True and fixture.get("productionTrustChanged") is False,
            "Requires the marked metadata-only cloned app image, installed root-owned in the VM")
    require(launcher.read_bytes()[:4] == b"\x7fELF", "Requires the native packaged launcher")
    for path in (launcher, *launcher.parents):
        info = path.stat()
        require(info.st_uid == 0 and not info.st_mode & 0o022, "Installed image ancestry must be root-owned/non-writable")
    if same_source_recovery:
        require(fixture.get("sameSourceBuild") is True and len(fixture.get("sourceFingerprint", "")) == 64,
                "Same-source recovery requires the property-built immutable source fixture")
        require(image_identity(launcher.parent.parent, fixture["version"]) ==
                {key: fixture[key] for key in ("codeFingerprint", "mainJar", "mainJarSha256")}, "Installed base image differs from source fixture")
        if arch_source_fixture is None:
            require_package_managed_launcher(launcher)
    before_packages = None
    if fresh_deb_dependencies:
        before_packages = installed_debian_packages()
        require("xdg-utils" not in before_packages and not Path("/usr/share/desktop-directories").exists(),
                "Fresh dependency evidence requires absent xdg-utils and desktop-directories before the public install")
        audit = subprocess.run(["dpkg", "--audit"], capture_output=True, text=True, timeout=30, check=True)
        require(not audit.stdout.strip(), "Use a fresh guest with no interrupted package configuration")
    evidence = Path(tempfile.mkdtemp(prefix="vpn-public-install-evidence-"))
    workspace = evidence / "workspace"
    print(json.dumps({"evidence": str(evidence), "workspace": str(workspace)}), flush=True)
    environment = dict(os.environ)
    environment.pop("DISPLAY", None)
    environment.pop("WAYLAND_DISPLAY", None)
    credential_directory = None
    credential_correlation = None
    retained_fds = None
    if retained_fixture_auth:
        credential_correlation = str(uuid.uuid4())
        # This admission happens before the owner can start or an install can
        # mutate the guest.  The module's receipt is metadata only.
        credential_directory, credential_correlation, FIXTURE_ACCOUNT, PURPOSE = prepare_retained_fixture_auth(
            evidence, credential_correlation, preserve_existing_fixture_password)
        # Retain exactly this master across owner startup and the install handoff.
        retained_fds = retained_terminal_master()
        # The remote observer may disappear while polkit is active. The
        # guest-side driver owns the master and ignores that observer HUP until
        # it has written its correlation receipt and restored the fixture lock.
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
    count = 0

    def invoke(*arguments, seconds=90):
        nonlocal count
        count += 1
        out = evidence / f"cli-{count}.json"
        err = evidence / f"cli-{count}.stderr"
        with out.open("wb") as stdout, err.open("wb") as stderr:
            process = subprocess.Popen([str(launcher), "--state-dir", str(workspace), "--json", *arguments],
                                       stdout=stdout, stderr=stderr, env=environment)
        try:
            process.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"CLI timeout; retained process {process.pid}, evidence {evidence}; outcome UNKNOWN") from None
        (evidence / f"cli-{count}.exit").write_text(str(process.returncode) + "\n")
        require(out.stat().st_size <= 1024 * 1024 and err.stat().st_size <= 65536, "CLI output exceeds bound")
        result = json.loads(out.read_text())
        require(result.get("schemaVersion") == 1, "Invalid public result envelope")
        return process.returncode, result

    def ok(*arguments, seconds=90):
        exit_code, result = invoke(*arguments, seconds=seconds)
        require(exit_code == 0 and result.get("code") == "OK" and result.get("final") is True,
                f"Public command failed: {arguments}: {result}")
        return result

    def start_owner():
        with (evidence / f"serve-{time.time_ns()}.log").open("wb") as log:
            process = launch_fixture_owner(launcher, workspace, log, environment)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            require(process.poll() is None, "Fixture owner exited before activation")
            if (workspace / "activation.port").exists():
                return process
            time.sleep(0.1)
        raise RuntimeError("Fixture owner readiness timeout; processes/evidence retained")

    owner = start_owner()
    baseline = ok("status")
    require(baseline["data"].get("runtimeRunning") is False, "Synthetic workspace unexpectedly connected")
    ok("updates", "check", seconds=180)
    checked = ok("updates", "status")["data"]
    require(checked.get("available") is True and checked.get("compatible") is True
            and checked.get("availableVersion") == target_version,
            f"No newer trusted matching asset for the specified version/VM architecture: {checked}")
    download_recovery = None
    if download_wait_client_loss:
        download_recovery = recover_download_after_wait_client_loss(
            launcher, workspace, evidence, environment, owner, invoke, ok, download_target_bytes, download_target_sha256)
    else:
        ok(*timed_update_command("download", 600), seconds=630)
    require(ok("updates", "status")["data"].get("phase") == "ready", "Download did not become verified/ready")
    if retained_fixture_auth:
        exit_code, accepted = invoke_retained_install(
            launcher, workspace, environment, timed_update_command("install", 240), credential_directory,
            credential_correlation, PURPOSE, FIXTURE_ACCOUNT, evidence, retained_fds=retained_fds)
        retained_fds = None
    else:
        exit_code, accepted = invoke(*timed_update_command("install", 240), seconds=270)
    job, operation = terminal_install_handoff({"childExit": exit_code, "envelope": accepted})
    owner.wait(timeout=30)
    require(owner.poll() is not None, "Fixture owner did not stop; workspace retained")
    # Never hold an app admission lock while waiting for replacement, and never kill the installer.
    deadline = time.monotonic() + 600
    receipt = None
    while time.monotonic() < deadline:
        try:
            receipt = protected_receipt(job)
        except FileNotFoundError:
            pass
        if receipt and receipt.get("phase") in ("SUCCEEDED", "FAILED", "CANCELLED"):
            break
        time.sleep(0.5)
    credential_restored = not retained_fixture_auth
    if retained_fixture_auth:
        from linux_fixture_auth import restore
        # Only a final protected receipt may relock the account.  Failed and
        # cancelled terminal outcomes are equally authoritative for cleanup;
        # missing, pending, or disconnected observations preserve the private
        # credential directory for exact recovery instead of guessing.
        terminal_result = {"jobId": receipt.get("jobId") if receipt else None,
                           "correlation": credential_correlation, "final": bool(receipt),
                           "phase": receipt.get("phase") if receipt else None}

        def terminal_validator(candidate, expected_correlation):
            return (isinstance(candidate, dict) and expected_correlation == credential_correlation
                    and candidate.get("correlation") == credential_correlation
                    and candidate.get("jobId") == job and candidate.get("final") is True
                    and candidate.get("phase") in {"SUCCEEDED", "FAILED", "CANCELLED"})

        if receipt and receipt.get("phase") in {"SUCCEEDED", "FAILED", "CANCELLED"}:
            restore(credential_dir=credential_directory, correlation=credential_correlation,
                    terminal_receipt=terminal_result, terminal_validator=terminal_validator)
            credential_restored = True
    require(receipt and receipt.get("phase") == "SUCCEEDED" and receipt.get("code") == "OK",
            f"No protected installation success; do not retry/kill pending worker: {receipt}")
    version = subprocess.run([str(launcher), "--version"], capture_output=True, text=True, timeout=30)
    require(version.returncode == 0 and target_version in version.stdout, "Replacement does not report target product version")
    # A published old replacement is separate evidence. The source-matched path
    # requires exact next-owner correlation; missing support cannot count as OK.
    try:
        exit_code, recovery = invoke("operations", "status", operation)
    except (RuntimeError, ValueError) as error:
        recovery = {"unavailable": str(error)}
    recovery_proven = False
    if same_source_recovery:
        require(image_identity(launcher.parent.parent, target_version)["codeFingerprint"] == fixture["codeFingerprint"],
                "Replacement code differs from the frozen source pair")
        verify_recovered_install(accepted, receipt, recovery)
        recovery_proven = True
    dependency_evidence = None
    if fresh_deb_dependencies:
        after_packages = installed_debian_packages()
        require("xdg-utils" in after_packages and Path("/usr/share/desktop-directories").is_dir(),
                "The package transaction did not acquire/register desktop prerequisites")
        require(all(name in after_packages for name in before_packages), "The package transaction removed an existing package")
        dependency_evidence = {"installed": {name: value for name, value in after_packages.items() if name not in before_packages},
                               "changed": {name: [before_packages[name], value] for name, value in after_packages.items()
                                           if name in before_packages and before_packages[name] != value}}
    result = {"downloadWaitClientLoss": download_recovery, "productionTrustedInstallSucceeded": True, "targetVersion": target_version,
              "accepted": accepted, "protectedReceipt": receipt, "replacementRecoveryObservation": recovery,
              "sameSourceRecoveryProven": same_source_recovery, "sourceFingerprint": fixture.get("sourceFingerprint"),
              "freshDependencyEvidence": dependency_evidence, "evidence": str(evidence),
              "retainedFixtureAuth": retained_fixture_auth,
              "preservesExistingFixturePassword": preserve_existing_fixture_password}
    if cleanup_synthetic_workspace_after_success:
        # The fixed RPM collector requires an absent workspace, but cleanup is
        # deliberately late: terminal receipt, replacement recovery, credential
        # restoration and the original owner must all already be proven.
        try:
            result["replacementOwnerQuit"] = close_recovered_fixture_owner(ok, recovery)
            cleanup_synthetic_workspace(workspace, evidence, owner,
                                        protected_success=True,
                                        recovered=recovery_proven,
                                        credential_restored=credential_restored)
            result["syntheticWorkspaceCleanup"] = {"requested": True, "workspaceRemoved": True}
        except Exception as error:
            result["syntheticWorkspaceCleanup"] = {"requested": True, "workspaceRemoved": False,
                                                   "error": str(error)}
            (evidence / "install-result.json").write_text(json.dumps(result, indent=2))
            raise
    else:
        result["syntheticWorkspaceCleanup"] = {"requested": False, "workspaceRemoved": False}
    (evidence / "install-result.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launcher", type=Path, required=True)
    parser.add_argument("--expected-target-version", required=True)
    parser.add_argument("--confirm-owned-disposable-vm", action="store_true")
    parser.add_argument("--require-same-source-recovery", action="store_true")
    parser.add_argument("--require-fresh-deb-dependencies", action="store_true")
    parser.add_argument("--arch-source-fixture", type=Path,
                        help="Verify an Arch bundle-installed base against this immutable source-pair fixture")
    parser.add_argument("--rpm-source-fixture", type=Path,
                        help="Verify an RPM-installed base against this immutable source-pair fixture")
    parser.add_argument("--retained-fixture-auth", action="store_true",
                        help="Use the private disposable-guest credential path and retained polkit PTY")
    parser.add_argument("--preserve-existing-fixture-password", action="store_true",
                        help="Explicitly restore a pre-existing P-baseline after retained fixture authentication")
    parser.add_argument("--cleanup-synthetic-workspace", action="store_true",
                        help="After terminal protected success/recovery, remove only the owned synthetic workspace")
    parser.add_argument("--download-wait-client-loss", action="store_true")
    parser.add_argument("--download-target-bytes", type=int)
    parser.add_argument("--download-target-sha256")
    args = parser.parse_args()
    run(args.launcher, args.expected_target_version, args.confirm_owned_disposable_vm,
        args.require_same_source_recovery, args.require_fresh_deb_dependencies, args.arch_source_fixture,
        args.rpm_source_fixture, args.retained_fixture_auth, args.preserve_existing_fixture_password,
        args.cleanup_synthetic_workspace, args.download_wait_client_loss,
        args.download_target_bytes, args.download_target_sha256)
