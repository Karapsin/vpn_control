"""One nonblocking managed validation lease per checkout.

The lock file persists. Never unlink or replace it: every process must lock the
same inode. Closing the descriptor (including process exit) releases the lease.
This coordinates managed checks; direct Gradle invocations need their own owner.
"""

from __future__ import annotations

from contextlib import contextmanager
import errno
import importlib
import os
from pathlib import Path
import stat


class ManagedCheckLeaseError(RuntimeError):
    def __init__(self, state: str, message: str):
        super().__init__(message)
        self.state = state


def _backend():
    if os.name not in {"posix", "nt"}:
        raise ManagedCheckLeaseError("unknown", "Managed check locking is unsupported on this platform.")
    try:
        module = importlib.import_module("fcntl" if os.name == "posix" else "msvcrt")
        required = ("flock", "LOCK_EX", "LOCK_NB") if os.name == "posix" else ("locking", "LK_NBLCK", "open_osfhandle")
        if any(not hasattr(module, name) for name in required):
            raise ImportError
        return module
    except ImportError as error:
        raise ManagedCheckLeaseError("unknown", "Managed check locking APIs are unavailable.") from error


def _directory(root: Path) -> Path:
    parent = root.resolve(strict=True) / ".rag_index"
    parent.mkdir(mode=0o700, exist_ok=True)
    info = parent.lstat()
    if (not stat.S_ISDIR(info.st_mode) or parent.is_symlink() or
            getattr(info, "st_file_attributes", 0) & 0x400):
        raise ManagedCheckLeaseError("unknown", "Managed check state directory is unsafe.")
    if os.name == "posix" and (not hasattr(os, "getuid") or info.st_uid != os.getuid() or info.st_mode & 0o022):
        raise ManagedCheckLeaseError("unknown", "Managed check state directory is not privately controlled.")
    directory = parent / "managed-checks"
    if os.name == "posix":
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise ManagedCheckLeaseError("unknown", "Managed check lease directory must be owner-only.")
    # Windows creates and verifies this directory with the same protected DACL
    # as the lock, before opening either pathname for use.
    return directory


def _posix_open(path: Path) -> int:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "getuid"):
        raise ManagedCheckLeaseError("unknown", "Managed check file ownership APIs are unavailable.")
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                info.st_mode & 0o077 or info.st_nlink != 1):
            raise ManagedCheckLeaseError("unknown", "Managed check lock must be an owner-only regular file.")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _windows_open(path: Path, backend) -> int:
    """Create/verify an exact-user protected DACL before transferring the handle."""
    import ctypes
    from ctypes import wintypes as wt

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    pointer = ctypes.c_void_p

    def api(library, name, result, *arguments):
        function = getattr(library, name)
        function.restype = result
        function.argtypes = list(arguments)
        return function

    close = api(kernel, "CloseHandle", wt.BOOL, wt.HANDLE)
    free = api(kernel, "LocalFree", pointer, pointer)
    current_process = api(kernel, "GetCurrentProcess", wt.HANDLE)
    open_token = api(security, "OpenProcessToken", wt.BOOL, wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE))
    token_info = api(security, "GetTokenInformation", wt.BOOL, wt.HANDLE, ctypes.c_int, pointer, wt.DWORD, ctypes.POINTER(wt.DWORD))
    sid_string = api(security, "ConvertSidToStringSidW", wt.BOOL, pointer, ctypes.POINTER(wt.LPWSTR))
    descriptor_from_string = api(security, "ConvertStringSecurityDescriptorToSecurityDescriptorW", wt.BOOL,
                                 wt.LPCWSTR, wt.DWORD, ctypes.POINTER(pointer), ctypes.POINTER(wt.DWORD))
    security_info = api(security, "GetSecurityInfo", wt.DWORD, wt.HANDLE, ctypes.c_int, wt.DWORD,
                        ctypes.POINTER(pointer), pointer, ctypes.POINTER(pointer), pointer, ctypes.POINTER(pointer))
    descriptor_control = api(security, "GetSecurityDescriptorControl", wt.BOOL, pointer,
                             ctypes.POINTER(wt.WORD), ctypes.POINTER(wt.DWORD))
    equal_sid = api(security, "EqualSid", wt.BOOL, pointer, pointer)
    get_ace = api(security, "GetAce", wt.BOOL, pointer, wt.DWORD, ctypes.POINTER(pointer))

    class Attributes(ctypes.Structure):
        _fields_ = [("length", wt.DWORD), ("descriptor", pointer), ("inherit", wt.BOOL)]

    class Acl(ctypes.Structure):
        _fields_ = [("revision", wt.BYTE), ("reserved", wt.BYTE), ("size", wt.WORD),
                    ("count", wt.WORD), ("reserved2", wt.WORD)]

    class Ace(ctypes.Structure):
        _fields_ = [("kind", wt.BYTE), ("flags", wt.BYTE), ("size", wt.WORD), ("mask", wt.DWORD)]

    class FileInfo(ctypes.Structure):
        _fields_ = [("attributes", wt.DWORD), ("created", wt.FILETIME), ("accessed", wt.FILETIME),
                    ("written", wt.FILETIME), ("volume", wt.DWORD), ("size_high", wt.DWORD),
                    ("size_low", wt.DWORD), ("links", wt.DWORD), ("index_high", wt.DWORD), ("index_low", wt.DWORD)]

    create_file = api(kernel, "CreateFileW", wt.HANDLE, wt.LPCWSTR, wt.DWORD, wt.DWORD,
                      ctypes.POINTER(Attributes), wt.DWORD, wt.DWORD, wt.HANDLE)
    create_directory = api(kernel, "CreateDirectoryW", wt.BOOL, wt.LPCWSTR, ctypes.POINTER(Attributes))
    file_info = api(kernel, "GetFileInformationByHandle", wt.BOOL, wt.HANDLE, ctypes.POINTER(FileInfo))

    token = wt.HANDLE()
    sid_text = wt.LPWSTR()
    creation_descriptor = pointer()
    handle = None
    directory_handle = None

    def require(accepted):
        if not accepted:
            raise ManagedCheckLeaseError("unknown", "Managed check lock ownership cannot be verified.")

    def verify(handle, user_sid, *, directory=False):
        require(handle != pointer(-1).value)
        observed_file = FileInfo()
        require(file_info(handle, ctypes.byref(observed_file)))
        require(not observed_file.attributes & 0x400 and bool(observed_file.attributes & 0x10) == directory)
        require(directory or observed_file.links == 1)
        owner, dacl, observed_descriptor = pointer(), pointer(), pointer()
        try:
            require(security_info(handle, 1, 0x5, ctypes.byref(owner), None, ctypes.byref(dacl), None,
                                  ctypes.byref(observed_descriptor)) == 0)
            control, revision = wt.WORD(), wt.DWORD()
            require(descriptor_control(observed_descriptor, ctypes.byref(control), ctypes.byref(revision)))
            require(control.value & 0x1000 and equal_sid(owner, user_sid) and dacl.value)
            require(ctypes.cast(dacl, ctypes.POINTER(Acl)).contents.count == 1)
            ace_pointer = pointer()
            require(get_ace(dacl, 0, ctypes.byref(ace_pointer)))
            ace = ctypes.cast(ace_pointer, ctypes.POINTER(Ace)).contents
            require(ace.kind == 0 and ace.flags == 0 and ace.mask == 0x1F01FF)
            require(equal_sid(ace_pointer.value + ctypes.sizeof(Ace), user_sid))
        finally:
            if observed_descriptor:
                free(observed_descriptor)

    try:
        require(open_token(current_process(), 0x8, ctypes.byref(token)))
        length = wt.DWORD()
        token_info(token, 1, None, 0, ctypes.byref(length))
        require(length.value)
        user_buffer = ctypes.create_string_buffer(length.value)
        require(token_info(token, 1, user_buffer, length.value, ctypes.byref(length)))
        user_sid = ctypes.cast(user_buffer, ctypes.POINTER(pointer)).contents.value
        require(sid_string(user_sid, ctypes.byref(sid_text)))
        require(descriptor_from_string(f"O:{sid_text.value}D:P(A;;FA;;;{sid_text.value})", 1,
                                       ctypes.byref(creation_descriptor), None))
        attributes = Attributes(ctypes.sizeof(Attributes), creation_descriptor, False)
        created_directory = create_directory(str(path.parent), ctypes.byref(attributes))
        require(created_directory or ctypes.get_last_error() == 183)
        directory_handle = create_file(str(path.parent), 0x20080, 0x3, None, 3, 0x02200000, None)
        verify(directory_handle, user_sid, directory=True)
        # Sharing excludes deletion; OPEN_REPARSE_POINT prevents following a link.
        handle = create_file(str(path), 0xC0020000, 0x3, ctypes.byref(attributes), 4, 0x00200000, None)
        verify(handle, user_sid)
        descriptor = backend.open_osfhandle(handle, os.O_RDWR | os.O_BINARY | os.O_NOINHERIT)
        handle = None  # The CRT descriptor now owns the handle.
        return descriptor
    finally:
        if handle is not None and handle != pointer(-1).value:
            close(handle)
        if directory_handle is not None and directory_handle != pointer(-1).value:
            close(directory_handle)
        for allocation in (creation_descriptor, sid_text):
            if allocation:
                free(ctypes.cast(allocation, pointer))
        if token:
            close(token)


def _try_lock(descriptor: int, backend) -> None:
    try:
        if os.name == "posix":
            backend.flock(descriptor, backend.LOCK_EX | backend.LOCK_NB)
        else:
            os.lseek(descriptor, 0, os.SEEK_SET)
            backend.locking(descriptor, backend.LK_NBLCK, 1)
    except OSError as error:
        if error.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
            raise ManagedCheckLeaseError("busy", "Another managed validation is already running for this checkout.") from error
        raise


@contextmanager
def acquire(root: Path | str):
    """Hold the checkout lease, or immediately raise a busy/unknown error."""
    descriptor = None
    try:
        backend = _backend()
        path = _directory(Path(root)) / "lease.lock"
        descriptor = _posix_open(path) if os.name == "posix" else _windows_open(path, backend)
        os.set_inheritable(descriptor, False)
        _try_lock(descriptor, backend)
    except BaseException as error:
        if descriptor is not None:
            os.close(descriptor)
        if isinstance(error, (ManagedCheckLeaseError, KeyboardInterrupt, SystemExit)):
            raise
        raise ManagedCheckLeaseError("unknown", "Managed check lease could not be acquired safely.") from error
    try:
        yield
    finally:
        os.close(descriptor)
