"""Private, immutable completion logs for managed checks; never runs commands."""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid


class RetentionError(ValueError):
    pass


_IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+"
_HEADER = re.compile(r"^(FAIL|ERROR): ([A-Za-z_][A-Za-z0-9_.]*) \((" + _IDENTIFIER + r")\)(?: \([^\r\n]*\))?$")
_SIMPLE = re.compile(r"^(FAIL|ERROR): (" + _IDENTIFIER + r")$")


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def _generation(info):
    return _identity(info) + (info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _tests(raw):
    identities = []
    seen = set()
    headers = parsed = 0
    for line in raw.decode("ascii", "replace").splitlines():
        if not line.startswith(("FAIL: ", "ERROR: ")):
            continue
        headers += 1
        match = _HEADER.fullmatch(line)
        identifier = None
        if match and match[3].endswith("." + match[2]):
            identifier = match[3]
        else:
            match = _SIMPLE.fullmatch(line)
            if match:
                identifier = match[2]
        if identifier is None:
            continue
        parsed += 1
        if identifier not in seen:
            seen.add(identifier)
            if len(identities) < 512:
                identities.append(identifier)
    return {"identities": identities, "count": len(identities), "total": parsed,
            "truncated": len(seen) > len(identities), "unparsedHeaders": headers - parsed}


def retain_completed_output(root, *, label, returncode, stdout, stderr, source_fingerprint):
    """Retain completed streams before deriving any public diagnostic metadata."""
    if (not isinstance(label, str) or not re.fullmatch(r"[A-Za-z0-9._ -]{1,128}", label)
            or type(returncode) is not int or type(stdout) is not bytes or type(stderr) is not bytes
            or not isinstance(source_fingerprint, str)
            or not re.fullmatch(r"[0-9a-f]{64}", source_fingerprint)):
        raise RetentionError("input")
    return _retain_streams(root, label, stdout, stderr, source_fingerprint,
                           "check-runs", lambda: {"returncode": returncode,
                           "tests": _tests(stdout + b"\n" + stderr)})


def retain_observation_capture(root, *, label, capture, source_fingerprint):
    """Save original bounded observation bytes, including incomplete captures.

    Observed counts describe bytes read, not necessarily the retained prefix.
    No native body is interpreted or returned as public diagnostics.
    """
    required = {"stdout", "stderr", "counts", "eof", "returnCode",
                "complete", "overflow", "timeout", "readError"}
    if (type(capture) is not dict or set(capture) not in (required, required | {"pid"})
            or type(label) is not str or not re.fullmatch(r"[A-Za-z0-9._ -]{1,128}", label)
            or type(source_fingerprint) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", source_fingerprint)):
        raise RetentionError("input")
    if (any(type(capture[k]) is not bytes for k in ("stdout", "stderr"))
            or any(type(capture[k]) is not bool for k in ("complete", "overflow", "timeout", "readError"))
            or (capture["returnCode"] is not None and type(capture["returnCode"]) is not int)
            or ("pid" in capture and (type(capture["pid"]) is not int or capture["pid"] <= 0))):
        raise RetentionError("input")
    for field in ("counts", "eof"):
        if type(capture[field]) is not dict or set(capture[field]) != {"stdout", "stderr"}:
            raise RetentionError("input")
    for name in ("stdout", "stderr"):
        count = capture["counts"][name]
        if (type(count) is not int or count < len(capture[name])
                or type(capture["eof"][name]) is not bool
                or (count > len(capture[name]) and not capture["overflow"])):
            raise RetentionError("input")
    complete = (all(capture["eof"].values()) and type(capture["returnCode"]) is int
                and not any(capture[k] for k in ("overflow", "timeout", "readError")))
    if capture["complete"] != complete:
        raise RetentionError("input")
    metadata = {key: (dict(value) if type(value) is dict else value)
                for key, value in capture.items() if key not in {"stdout", "stderr"}}
    return _retain_streams(root, label, capture["stdout"], capture["stderr"], source_fingerprint,
                           "observation-runs", lambda: metadata)


def _retain_streams(root, label, stdout, stderr, source_fingerprint, namespace, metadata):
    if os.name != "posix" or any(not hasattr(os, name) for name in
                                  ("O_NOFOLLOW", "O_DIRECTORY", "geteuid", "fsync")):
        raise RetentionError("unsupported_private_retention")
    root = Path(root).absolute()
    directories = []
    files = []
    with ExitStack() as stack:
        root_info = root.lstat()
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, root_fd)
        if _identity(root_info) != _identity(os.fstat(root_fd)):
            raise RetentionError("root_changed")

        def open_directory(parent, name, private):
            try:
                os.mkdir(name, 0o700, dir_fd=parent)
                os.fsync(parent)
            except FileExistsError:
                pass
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            stack.callback(os.close, fd)
            info = os.fstat(fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & (0o077 if private else 0o022)):
                raise RetentionError("directory_shape")
            pin = _identity(info)
            if _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != pin:
                raise RetentionError("directory_changed")
            directories.append((parent, name, fd, pin))
            return fd

        index_fd = open_directory(root_fd, ".rag_index", False)
        base_fd = open_directory(index_fd, namespace, True)
        run_id = str(uuid.uuid4())
        os.mkdir(run_id, 0o700, dir_fd=base_fd)
        os.fsync(base_fd)
        directory_fd = open_directory(base_fd, run_id, True)

        def closing():
            if (_identity(os.fstat(root_fd)) != _identity(root_info)
                    or _identity(root.lstat()) != _identity(root_info)):
                raise RetentionError("root_changed")
            for parent, name, fd, pin in directories:
                if (_identity(os.fstat(fd)) != pin
                        or _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != pin):
                    raise RetentionError("directory_changed")
            for name, fd, pin in files:
                if (_generation(os.fstat(fd)) != pin
                        or _generation(os.stat(name, dir_fd=directory_fd, follow_symlinks=False)) != pin):
                    raise RetentionError("raw_changed")

        def raw(name, body):
            closing()
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory_fd)
            stack.callback(os.close, fd)
            view = memoryview(body)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise RetentionError("raw_write")
                view = view[written:]
            os.fsync(fd)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise RetentionError("raw_shape")
            pin = _generation(info)
            os.lseek(fd, 0, os.SEEK_SET)
            digest = hashlib.sha256()
            length = 0
            while length <= len(body):
                chunk = os.read(fd, min(65536, len(body) + 1 - length))
                if not chunk:
                    break
                digest.update(chunk)
                length += len(chunk)
            if length != len(body) or digest.hexdigest() != hashlib.sha256(body).hexdigest():
                raise RetentionError("raw_bytes_changed")
            files.append((name, fd, pin))
            closing()
            return {"name": name, "bytes": length, "sha256": digest.hexdigest()}

        output = raw("stdout.private", stdout)
        errors = raw("stderr.private", stderr)
        closing()
        details = metadata()
        closing()
        result = {"schemaVersion": 1, "runId": run_id, "label": label,
                  "sourceFingerprint": source_fingerprint,
                  "stdout": output, "stderr": errors, **details}
        body = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        receipt = raw("receipt.json", body)
        os.fsync(directory_fd)
        closing()
        return {**result, "receipt": receipt}
