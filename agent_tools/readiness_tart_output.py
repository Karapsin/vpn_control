"""Private first-RUN output redactor for the exact Tart 2.32.1 VNC line.

Raw child stdout/stderr must be piped directly into this consumer, never into a
durable execution owner's retained streams. Only the bound port and finite byte
counts may be published. The random server credential is written once into the
original owner's protected file; it is never hashed, logged or returned as text.
This module launches no process and grants no VM/endpoint ownership.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import selectors
import stat
import time

_PREFIX = b"VNC server is running at "
_LINE = re.compile(rb"VNC server is running at vnc://:([a-z]{1,8}(?:-[a-z]{1,8}){3})@127\.0\.0\.1:([1-9][0-9]{0,4})")
_NAME = "vnc-auth.bin"
_STREAM_LIMIT = 65_536
_LINE_LIMIT = 512


class OutputBlocked(RuntimeError):
    """Finite codes only, including all parser and private filesystem errors."""


def _platform():
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise OutputBlocked("tart_output_platform_unsupported")


def _generation(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class ProtectedRunOutput:
    def __init__(self, directory):
        _platform()
        from . import private_inventory_lock as private
        self._directory = None
        self._buffer = bytearray()
        self._counts = {"stdout": 0, "stderr": 0}
        self._port = None
        self._generation = None
        self._closed = False
        self._failed = False
        try:
            self._directory = private.Directory(Path(directory))
            if stat.S_IMODE(os.fstat(self._directory.fd).st_mode) != 0o700:
                raise OutputBlocked("tart_output_directory_invalid")
            try:
                os.stat(_NAME, dir_fd=self._directory.fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise OutputBlocked("tart_output_original_exists")
        except OutputBlocked:
            self.close()
            raise
        except Exception:
            self.close()
            raise OutputBlocked("tart_output_directory_unavailable") from None

    def _guard(self):
        if self._closed or self._failed:
            raise OutputBlocked("tart_output_original_unavailable")
        try:
            self._directory.guard()
            if self._generation is not None:
                actual = os.stat(_NAME, dir_fd=self._directory.fd, follow_symlinks=False)
                if _generation(actual) != self._generation:
                    raise OutputBlocked("tart_output_credential_changed")
        except OutputBlocked:
            raise
        except Exception:
            raise OutputBlocked("tart_output_custody_changed") from None

    def _line(self, line):
        if not line.startswith(_PREFIX):
            return  # Includes arbitrary private echo/error text: discard it.
        matched = _LINE.fullmatch(line)
        if matched is None or not 1 <= int(matched[2]) <= 65535:
            raise OutputBlocked("tart_output_vnc_line_malformed")
        if self._port is not None:
            raise OutputBlocked("tart_output_vnc_line_duplicate")
        descriptor = -1
        try:
            self._directory.guard()
            descriptor = os.open(_NAME, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=self._directory.fd)
            os.fchmod(descriptor, 0o600)
            secret = matched[1]
            written = 0
            while written < len(secret):
                count = os.write(descriptor, secret[written:])
                if count <= 0:
                    raise OutputBlocked("tart_output_credential_unavailable")
                written += count
            os.fsync(descriptor)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
                raise OutputBlocked("tart_output_credential_invalid")
            self._generation = _generation(info)
            self._port = int(matched[2])
            self._directory.guard()
            os.fsync(self._directory.fd)
            self._guard()
        except FileExistsError:
            raise OutputBlocked("tart_output_original_exists") from None
        except OutputBlocked:
            raise
        except Exception:
            raise OutputBlocked("tart_output_credential_unavailable") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def feed(self, stream, block):
        """No raw output is returned, including when a parser error occurs."""
        try:
            self._guard()
            if stream not in self._counts or type(block) is not bytes:
                raise OutputBlocked("tart_output_chunk_invalid")
            self._counts[stream] += len(block)
            if self._counts[stream] > _STREAM_LIMIT:
                raise OutputBlocked("tart_output_stream_overflow")
            if stream == "stderr":
                return
            for value in block:
                if value == 10:
                    line = bytes(self._buffer)
                    self._buffer.clear()
                    if line.endswith(b"\r"):
                        line = line[:-1]
                    self._line(line)
                else:
                    self._buffer.append(value)
                    if len(self._buffer) > _LINE_LIMIT:
                        raise OutputBlocked("tart_output_line_overflow")
        except OutputBlocked:
            self._failed = True
            self._buffer.clear()
            raise
        except Exception:
            self._failed = True
            self._buffer.clear()
            raise OutputBlocked("tart_output_parser_blocked") from None

    def endpoint(self):
        self._guard()
        return None if self._port is None else {"port": self._port}

    def credential_metadata(self):
        self._guard()
        if self._generation is None:
            raise OutputBlocked("tart_output_endpoint_unavailable")
        return {"name": _NAME, "generation": list(self._generation)}

    def credential_fd(self):
        """Return a new protected reader; caller closes it. No content digest."""
        self._guard()
        if self._generation is None:
            raise OutputBlocked("tart_output_endpoint_unavailable")
        descriptor = -1
        try:
            descriptor = os.open(_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self._directory.fd)
            if _generation(os.fstat(descriptor)) != self._generation:
                raise OutputBlocked("tart_output_credential_changed")
            self._guard()
            return descriptor
        except Exception:
            if descriptor >= 0:
                os.close(descriptor)
            raise OutputBlocked("tart_output_credential_unavailable") from None

    def finish(self):
        self._guard()
        if self._buffer.startswith(_PREFIX):
            self._failed = True
            self._buffer.clear()
            raise OutputBlocked("tart_output_vnc_line_incomplete")
        self._buffer.clear()
        if self._port is None:
            raise OutputBlocked("tart_output_endpoint_unavailable")
        return {"port": self._port, "stdoutBytes": self._counts["stdout"], "stderrBytes": self._counts["stderr"]}

    def close(self):
        self._buffer.clear()
        if self._directory is not None:
            self._directory.close()
            self._directory = None
        self._closed = True

    def __enter__(self):
        self._guard()
        return self

    def __exit__(self, *_):
        self.close()


def consume(stdout, stderr, output, *, deadline, on_endpoint=lambda public: None):
    """Drain caller-owned child pipes; never retain or forward raw streams.

    The native wrapper owns process generations, terminal receipts and every
    cancellation decision. Timeout/client loss does not start/stop a VM here.
    """
    try:
        if type(deadline) not in {int, float} or not time.monotonic() < deadline <= time.monotonic() + 600:
            raise OutputBlocked("tart_output_deadline_invalid")
        published = False
        with selectors.DefaultSelector() as selector:
            selector.register(stdout, selectors.EVENT_READ, "stdout")
            selector.register(stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise OutputBlocked("tart_output_deadline")
                for key, _ in selector.select(min(remaining, .25)):
                    data = os.read(key.fd, 4096)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    output.feed(key.data, data)
                    endpoint = output.endpoint()
                    if endpoint is not None and not published:
                        published = True
                        on_endpoint(endpoint)
                        if time.monotonic() >= deadline:
                            raise OutputBlocked("tart_output_deadline")
        if time.monotonic() >= deadline:
            raise OutputBlocked("tart_output_deadline")
        return output.finish()
    except OutputBlocked:
        raise
    except Exception:
        raise OutputBlocked("tart_output_consumer_unknown") from None


def standalone_source():
    """Embed only public verified helper/dependency bytes in a durable owner.

    The caller retains and verifies this generated program before launching its
    owned Tart actor. The generated namespace `_tart_output` has no repository
    imports and survives client exit or later repository source changes.
    """
    own = Path(__file__).read_text()
    custody = Path(__file__).with_name("private_inventory_lock.py").read_text()
    return ("import sys,types\n"
            "_output_package=types.ModuleType('_fixed_tart_output_package');_output_package.__path__=[]\n"
            "sys.modules[_output_package.__name__]=_output_package\n"
            "_output_private=types.ModuleType(_output_package.__name__+'.private_inventory_lock')\n"
            "sys.modules[_output_private.__name__]=_output_private\n"
            "exec(compile(" + repr(custody) + ",'<fixed-output-directory-custody>','exec'),_output_private.__dict__)\n"
            "_output_package.private_inventory_lock=_output_private\n"
            "_tart_output=types.ModuleType(_output_package.__name__+'.redactor');_tart_output.__package__=_output_package.__name__\n"
            "_tart_output.__file__='<fixed-tart-output>';sys.modules[_tart_output.__name__]=_tart_output\n"
            "exec(compile(" + repr(own) + ",_tart_output.__file__,'exec'),_tart_output.__dict__)\n")
