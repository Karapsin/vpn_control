"""Fixture-only native environment checks; never used by product packaging."""
import re
import os
import shutil
import subprocess
import tarfile
from pathlib import Path


def require_jdk17(java=None, runner=subprocess.run, environment=None):
    """Validate the JVM Gradle will use, preferring JAVA_HOME over PATH."""
    environment = os.environ if environment is None else environment
    if java is None:
        executable = "java.exe" if os.name == "nt" else "java"
        java = str(Path(environment["JAVA_HOME"]) / "bin" / executable) if environment.get("JAVA_HOME") else executable
    result = runner([java, "-version"], text=True, capture_output=True, check=False)
    text = result.stdout + result.stderr
    match = re.search(r'(?:openjdk|java) version "(\d+)(?:[._][^"]*)?"', text)
    if result.returncode or match is None or match.group(1) != "17":
        raise ValueError("Native fixture build requires JDK 17: " + (text.splitlines() or ["no version output"])[0])
    return text.splitlines()[0]


def extract_readonly_archive(archive, destination):
    """Extract fixture inputs, deferring directory modes until children exist."""
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError("Use a new fixture extraction destination")
    destination.mkdir(mode=0o700)
    root = destination.resolve(strict=True)

    reserved_windows_names = {"con", "prn", "aux", "nul", *("com" + str(value) for value in range(1, 10)),
                              *("lpt" + str(value) for value in range(1, 10))}

    def portable_component(value, kind):
        if not value or value in (".", "..") or value.rstrip(". ") != value:
            raise ValueError("Unsafe fixture archive " + kind)
        if value.split(".", 1)[0].casefold() in reserved_windows_names:
            raise ValueError("Unsafe fixture archive " + kind)
        return value

    def windows_key(parts):
        return tuple(value.casefold().rstrip(". ") for value in parts)

    def member_parts(name, directory=False):
        # Backslashes, drive prefixes, and ADS separators have platform-specific
        # meanings. Fixture member names use one canonical POSIX spelling.
        if not name or "\\" in name or ":" in name or name.startswith("/"):
            raise ValueError("Unsafe fixture archive path")
        parts = name.split("/")
        if directory and parts[-1] == "":
            parts.pop()
        if not parts:
            raise ValueError("Unsafe fixture archive path")
        return tuple(portable_component(value, "path") for value in parts)

    def link_parts(name):
        if not name or "\\" in name or ":" in name or name.startswith("/"):
            raise ValueError("Unsafe fixture archive link")
        parts = name.split("/")
        return [value if value in (".", "..") else portable_component(value, "link") for value in parts]

    def archive_path(parts):
        return root.joinpath(*parts)

    def validated_members(bundle):
        members = bundle.getmembers()
        entries = []
        names = set()
        links = {}
        for member in members:
            parts = member_parts(member.name, member.isdir())
            key = windows_key(parts)
            if key in names:
                raise ValueError("Duplicate fixture archive member")
            names.add(key)
            if member.issym():
                links[key] = link_parts(member.linkname)
            elif not (member.isdir() or member.isfile() or member.islnk()):
                raise ValueError("Unsafe fixture archive member type")
            entries.append((member, parts))
        for _, parts in entries:
            if any(windows_key(parts[:index]) in links for index in range(1, len(parts))):
                raise ValueError("Fixture archive member is below a symbolic link")

        def resolve_link(parent, target):
            pending = [*parent, *target]
            resolved = []
            expanded = set()
            while pending:
                component = pending.pop(0)
                if component == ".":
                    continue
                if component == "..":
                    if not resolved:
                        raise ValueError("Fixture archive link escapes destination")
                    resolved.pop()
                    continue
                candidate = tuple([*resolved, component])
                key = windows_key(candidate)
                if key in links:
                    if key in expanded:
                        raise ValueError("Fixture archive link cycle is unsafe")
                    expanded.add(key)
                    pending = [*links[key], *pending]
                    continue
                resolved.append(component)
            return tuple(resolved)

        for member, parts in entries:
            if member.issym():
                resolve_link(parts[:-1], links[windows_key(parts)])
            elif member.islnk():
                resolve_link((), link_parts(member.linkname))
        return entries

    with tarfile.open(archive, "r:gz") as bundle:
        # Some supported Python builds lack extractall(filter=...). Extract
        # explicitly instead of falling back to unfiltered extraction. Directory
        # modes are restored last so readonly source trees remain usable.
        members = validated_members(bundle)
        directories = []
        files = []
        symbolic_links = []
        hard_links = []
        for member, parts in members:
            if member.isdir():
                directories.append((member, parts))
            elif member.isfile():
                files.append((member, parts))
            elif member.issym():
                symbolic_links.append((member, parts))
            else:
                hard_links.append((member, parts))
        for _, parts in directories:
            archive_path(parts).mkdir(parents=True, exist_ok=True, mode=0o700)
        for member, parts in files:
            path = archive_path(parts)
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            source = bundle.extractfile(member)
            if source is None:
                raise ValueError("Fixture archive regular file has no data")
            with source, path.open("xb") as output:
                shutil.copyfileobj(source, output, 1024 * 1024)
            path.chmod(member.mode & 0o777)
        for member, parts in hard_links:
            path = archive_path(parts)
            target = archive_path(member_parts(member.linkname))
            if not target.is_file() or target.is_symlink():
                raise ValueError("Fixture archive hard link target is unsafe")
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.link(target, path)
            path.chmod(member.mode & 0o777)
        for member, parts in symbolic_links:
            path = archive_path(parts)
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # The validated target stays under root; do not resolve it here,
            # because fixture snapshots may intentionally contain a broken link.
            path.symlink_to(member.linkname)
        for member, parts in sorted(directories, key=lambda value: len(value[1]), reverse=True):
            archive_path(parts).chmod(member.mode & 0o777)


def validate_qemu_argv(argv):
    try:
        serial = argv[argv.index("-serial") + 1]
    except (ValueError, IndexError) as error:
        raise ValueError("QEMU launch is missing serial backend") from error
    if not serial.startswith("file:"):
        raise ValueError("QEMU serial backend must use file:")
