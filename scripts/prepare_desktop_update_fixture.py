#!/usr/bin/env python3
"""Prepare and build immutable desktop update inputs from one source snapshot.

This never installs a package, changes system trust, or starts a VPN. Build only
inside the coordinator's identified disposable native guest. Both builds use the
existing vpnControlVersion Gradle property; canonical source metadata is intact.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socketserver
import ssl
import stat
import subprocess
import tarfile
import zipfile


MANIFEST_PATH = "/Karapsin/vpn_control/releases/latest/download/update-manifest.json"
RELEASE = "disposable-desktop-fixture"
VERSION_RESOURCE = "vpn-control-version.properties"
MAIN_CLASS = "com/kardinal/vpncontrol/desktop/MainKt.class"
PLATFORMS = {
    "linux": {"os": "Linux", "tasks": ["packageDeb", "packageRpm"], "extension": ("deb", "rpm")},
    "windows": {"os": "Windows", "tasks": ["packageMsi"], "extension": ("msi",)},
    "macos": {"os": "Darwin", "tasks": ["packageDmg"], "extension": ("dmg",)},
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def version_build(version):
    require(re.fullmatch(r"[1-9][0-9]?\.(?:0|[1-9][0-9]?)\.(?:0|[1-9][0-9]?)", version) is not None,
            "Use a canonical three-component product version")
    components = [int(value) for value in version.split(".")]
    require(all(value <= 19 for value in components), "Product version components must be below 20")
    value = 0
    for component in (*components, 0):
        value = value * 20 + component
    return value


def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def json_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def write_json(path, value):
    with path.open("x", encoding="utf-8") as destination:
        json.dump(value, destination, sort_keys=True, indent=2, ensure_ascii=False)
        destination.write("\n")


def gitlink_identity(path, index_commit):
    # Native sources are provenance, not inputs to these desktop builds: the
    # separately captured executable remains the only bundled runtime input.
    require(not path.is_symlink(), "Gitlink checkout must not be a symlink")
    identity = {"indexCommit": index_commit, "initialized": False, "headCommit": None,
                "dirty": None, "workingTreeFingerprint": None, "statusSha256": None}
    if not path.exists():
        return identity
    require(path.is_dir(), "Gitlink checkout must be a directory")
    if not (path / ".git").exists():
        require(not any(path.iterdir()), "Uninitialized gitlink contains unaccounted files")
        return identity
    top = subprocess.run(["git", "-C", str(path), "rev-parse", "--show-toplevel"],
                         check=True, capture_output=True, text=True).stdout.strip()
    require(Path(top).resolve() == path.resolve(), "Gitlink does not identify its own checkout")
    head = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"],
                          check=True, capture_output=True, text=True).stdout.strip()
    status_output = subprocess.run(["git", "-C", str(path), "status", "--porcelain=v1", "-z",
                                    "--untracked-files=all"], check=True, capture_output=True).stdout
    identity.update(initialized=True, headCommit=head, dirty=bool(status_output),
                    workingTreeFingerprint=json_hash(source_entries(path)),
                    statusSha256=hashlib.sha256(status_output).hexdigest())
    return identity


def source_entries(repository):
    listed = subprocess.run(["git", "-C", str(repository), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                            check=True, capture_output=True).stdout
    indexed = subprocess.run(["git", "-C", str(repository), "ls-files", "--stage", "-z"],
                             check=True, capture_output=True).stdout
    gitlinks = {}
    for record in indexed.decode("utf-8").rstrip("\0").split("\0"):
        if not record:
            continue
        attributes, name = record.split("\t", 1)
        mode, commit, stage = attributes.split()
        require(stage == "0", "Resolve source index conflicts before freezing")
        if mode == "160000":
            gitlinks[name] = commit
    entries = []
    for name in sorted(set(listed.decode("utf-8").rstrip("\0").split("\0")) - {""}):
        relative = Path(name)
        require(not relative.is_absolute() and all(part not in (".", "..") for part in relative.parts), "Noncanonical source path")
        require(not any(part in (".git", ".gradle", ".cxx", "build", "dist", ".runtime", ".agent_venv", ".rag_index")
                        for part in relative.parts), "Generated files must not be source inputs: " + name)
        require(not name.startswith("desktopApp/src/main/resources/bin/"), "Generated runtime is a separate frozen input")
        path = repository / relative
        if name in gitlinks:
            entries.append({"path": name, "gitlink": gitlink_identity(path, gitlinks[name]), "excludedFromBuild": True})
            continue
        if not path.exists() and not path.is_symlink():
            continue  # A tracked deletion is part of this working source snapshot.
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode), "Unsupported source object: " + name)
        entry = {"path": name, "mode": stat.S_IMODE(before.st_mode)}
        if path.is_symlink():
            target = os.readlink(path)
            require(not Path(target).is_absolute() and path.resolve(strict=True).is_relative_to(repository),
                    "Source symlink escapes the snapshot: " + name)
            entry["symlink"] = target
        else:
            entry["sha256"] = file_hash(path)
            entry["sizeBytes"] = before.st_size
        after = path.lstat()
        unchanged = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_size,
                                   value.st_mtime_ns, value.st_ctime_ns)
        require(unchanged(before) == unchanged(after), "Source changed while being frozen: " + name)
        entries.append(entry)
    require(entries, "Source snapshot is empty")
    return entries


def copy_sources(repository, destination, entries):
    destination.mkdir(mode=0o700)
    # Create regular files before symlinks so no input can redirect a later copy.
    for entry in sorted(entries, key=lambda value: "symlink" in value):
        if "gitlink" in entry:
            require(entry.get("excludedFromBuild") is True, "Gitlink build inputs are unsupported")
            continue
        source, target = repository / entry["path"], destination / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        if "symlink" in entry:
            target.symlink_to(entry["symlink"])
        else:
            with source.open("rb") as input_file, target.open("xb") as output_file:
                shutil.copyfileobj(input_file, output_file, 1024 * 1024)
            require(file_hash(target) == entry["sha256"], "Source changed while being copied")
            target.chmod(entry["mode"])


def verify_sources(repository, entries):
    for entry in entries:
        path = repository / entry["path"]
        if "gitlink" in entry:
            require(entry.get("excludedFromBuild") is True and not path.exists() and not path.is_symlink(),
                    "Excluded gitlink appeared in build inputs")
            continue
        if "symlink" in entry:
            require(path.is_symlink() and os.readlink(path) == entry["symlink"], "Snapshot symlink changed")
        else:
            require(path.is_file() and not path.is_symlink() and file_hash(path) == entry["sha256"],
                    "Snapshot source changed: " + entry["path"])


def runtime_identity(runtime, platform, architecture):
    require(architecture in ("x86_64", "arm64"), "Unsupported fixture architecture")
    require(runtime.is_file() and not runtime.is_symlink(), "Use a captured regular runtime file")
    with runtime.open("rb") as source:
        header = source.read(64)
    if platform == "linux":
        require(header[:6] == b"\x7fELF\x02\x01", "Linux fixture requires a 64-bit little-endian ELF runtime")
        require(int.from_bytes(header[18:20], "little") == {"x86_64": 62, "arm64": 183}[architecture],
                "Runtime executable architecture disagrees with fixture architecture")
    elif platform == "windows":
        require(header[:2] == b"MZ", "Windows fixture requires a native PE runtime")
        with runtime.open("rb") as source:
            source.seek(int.from_bytes(header[60:64], "little"))
            pe = source.read(6)
        require(pe[:4] == b"PE\0\0" and int.from_bytes(pe[4:6], "little") == {"x86_64": 0x8664, "arm64": 0xAA64}[architecture],
                "Runtime executable architecture disagrees with fixture architecture")
    else:
        require(header[:4] == b"\xcf\xfa\xed\xfe" and int.from_bytes(header[4:8], "little") ==
                {"x86_64": 0x1000007, "arm64": 0x100000C}[architecture], "Use an actual-architecture Mach-O runtime")
    return {"sha256": file_hash(runtime), "sizeBytes": runtime.stat().st_size}


def prepare(repository, output, base_version, target_version, runtime, platform, architecture):
    repository = repository.resolve(strict=True)
    output = output.absolute()
    require(platform in PLATFORMS, "Unsupported desktop platform")
    require(version_build(target_version) > version_build(base_version), "Target must be newer than the base")
    require(not output.exists() and not output.is_symlink() and output.parent.is_dir(), "Use a new output directory")
    require(not output.is_relative_to(repository), "Keep generated fixture output outside the source repository")
    captured_runtime = runtime_identity(runtime, platform, architecture)
    entries = source_entries(repository)
    properties = (repository / "gradle.properties").read_text()
    canonical = re.search(r"(?m)^vpnControlVersion=(\S+)$", properties)
    require(canonical is not None, "Missing canonical product version")
    version_build(canonical.group(1))
    output.mkdir(mode=0o700)
    head = subprocess.run(["git", "-C", str(repository), "rev-parse", "--verify", "HEAD"],
                          check=False, capture_output=True, text=True)
    snapshot = {"schemaVersion": 1, "sourceFingerprint": json_hash(entries), "canonicalVersion": canonical.group(1),
                "sourceHead": head.stdout.strip() if head.returncode == 0 else None, "files": entries}
    source = output / "source"
    copy_sources(repository, source, entries)
    require(source_entries(repository) == entries, "Source changed during snapshot; do not build this fixture")
    saved_runtime = output / ("sing-box.exe" if platform == "windows" else "sing-box")
    shutil.copyfile(runtime, saved_runtime)
    require(file_hash(saved_runtime) == captured_runtime["sha256"], "Runtime changed during snapshot")
    saved_runtime.chmod(0o500)
    write_json(output / "snapshot.json", snapshot)
    stages = []
    for label, version in (("base", base_version), ("target", target_version)):
        stages.append({"label": label, "version": version, "buildNumber": version_build(version),
                       "directory": "build-" + label,
                       "preparation": [["bash", "./scripts/prepare_macos_install_worker.sh"]] if platform == "macos" else [],
                       "command": [("gradlew.bat" if platform == "windows" else "./gradlew"), "--no-daemon",
                                   "-PvpnControlVersion=" + version, ":desktopApp:createDistributable",
                                   *[":desktopApp:" + task for task in PLATFORMS[platform]["tasks"]]]})
    plan = {"schemaVersion": 1, "testOnly": True, "productionTrustChanged": False,
            "sourceFingerprint": snapshot["sourceFingerprint"], "platform": platform, "architecture": architecture,
            "runtime": {"file": saved_runtime.name, **captured_runtime}, "stages": stages}
    write_json(output / "build-plan.json", plan)
    # The source copy is a content-addressed input; builders make writable copies.
    for path in source.rglob("*"):
        if not path.is_symlink():
            path.chmod(0o500 if path.is_dir() or path.stat().st_mode & 0o111 else 0o400)
    source.chmod(0o500)
    return plan


def image_identity(image, expected_version):
    app = image / ("Contents/app" if image.suffix == ".app" else "app" if (image / "app").is_dir() else "lib/app")
    jars = sorted(app.glob("*.jar"))
    require(jars, "Packaged application JARs missing")
    main_jars = []
    contents = {}
    for path in jars:
        with zipfile.ZipFile(path) as jar:
            names = jar.namelist()
            require(len(names) == len(set(names)), "Duplicate packaged JAR entries")
            main = MAIN_CLASS in names
            if main:
                main_jars.append(path)
                metadata = dict(line.split("=", 1) for line in jar.read(VERSION_RESOURCE).decode().splitlines() if "=" in line)
                require(metadata.get("displayVersion") == expected_version and
                        metadata.get("buildNumber") == str(version_build(expected_version)), "Packaged version resource disagrees with build")
            entries = []
            for name in sorted(names):
                if not (main and name == VERSION_RESOURCE):
                    with jar.open(name) as entry:
                        digest = hashlib.sha256()
                        for chunk in iter(lambda: entry.read(1024 * 1024), b""):
                            digest.update(chunk)
                    entries.append([name, digest.hexdigest()])
            contents[path.name] = entries
    require(len(main_jars) == 1, "Resolve exactly one packaged main JAR")
    # jpackage can repack native JARs after Compose assigns digest filenames.
    # Compare logical JAR bytes in each public launcher's actual classpath order;
    # ZIP timestamps, comments and names cannot hide changed code or precedence.
    configs = sorted(app.glob("*.cfg"))
    require(configs, "Packaged launcher classpath configuration missing")
    code = []
    for config in configs:
        classpath = []
        main_classes = []
        section = None
        for line in config.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("["):
                section = line
            if section != "[Application]":
                continue
            if line.startswith("app.mainclass="):
                main_classes.append(line.removeprefix("app.mainclass="))
            if line.startswith("app.classpath="):
                value = line.removeprefix("app.classpath=")
                prefix = "$APPDIR/" if value.startswith("$APPDIR/") else "$APPDIR\\"
                require(value.startswith(prefix), "Nonlocal packaged classpath entry")
                name = value[len(prefix):]
                require(name in contents and "/" not in name and "\\" not in name,
                        "Missing or escaped packaged classpath entry")
                classpath.append(name)
        require(len(classpath) == len(set(classpath)) and set(classpath) == set(contents),
                "Packaged classpath must reference every JAR exactly once")
        require(main_classes == ["com.kardinal.vpncontrol.desktop.MainKt"], "Packaged main class disagrees with public launcher")
        code.append([config.name, main_classes[0], [contents[name] for name in classpath]])
    main = main_jars[0]
    return {"codeFingerprint": json_hash(code), "mainJar": str(main.relative_to(image)), "mainJarSha256": file_hash(main)}


def package_asset(path, platform, architecture, version):
    extension = "arch-bundle" if path.name.endswith(".tar.gz") else path.suffix.lstrip(".")
    require(extension in PLATFORMS[platform]["extension"] or platform == "linux" and extension == "arch-bundle",
            "Wrong package type for native build")
    require(path.is_file() and not path.is_symlink() and path.stat().st_size > 0, "Missing regular package")
    require(re.fullmatch(r"[A-Za-z0-9_.+-]+", path.name) is not None, "Unsafe package filename")
    return {"platform": platform, "architecture": architecture, "packageType": extension,
            "displayVersion": version, "fileName": path.name,
            "downloadUrl": "https://github.com/Karapsin/vpn_control/releases/download/" + RELEASE + "/" + path.name,
            "sha256": file_hash(path), "sizeBytes": path.stat().st_size}


def arch_fixture_package(checkout, image, runtime, output, version, architecture):
    # Match the production bundle layout, using the already property-built image
    # and its matching version. No mutation of canonical gradle.properties.
    staging = checkout / "desktopApp/build/compose/arch-fixture/vpn-control-arch-update"
    staging.mkdir(parents=True)
    shutil.copytree(image, staging / "app", symlinks=True)
    shutil.copyfile(runtime, staging / "sing-box")
    (staging / "sing-box").chmod(0o755)
    shutil.copyfile(checkout / "scripts/install_arch_desktop_update.sh", staging / "install.sh")
    (staging / "install.sh").chmod(0o755)
    (staging / "VERSION").write_text(version + "\n")
    require((staging / "app/bin/vpn-control").is_file(), "Arch fixture is missing the public launcher")
    target = output / ("vpn-control-arch-" + architecture + "-" + version + ".tar.gz")
    with tarfile.open(target, "x:gz", format=tarfile.GNU_FORMAT) as archive:
        archive.add(staging, arcname=staging.name)
    target.chmod(0o400)
    return package_asset(target, "linux", architecture, version)


def native_build(directory, confirmed, run_command=None):
    import platform as host_platform
    require(confirmed, "Explicit owned-disposable-guest confirmation required")
    directory = directory.resolve(strict=True)
    plan = json.loads((directory / "build-plan.json").read_text())
    snapshot = json.loads((directory / "snapshot.json").read_text())
    require(plan["testOnly"] is True and plan["productionTrustChanged"] is False, "Not a fixture build plan")
    require(snapshot["sourceFingerprint"] == plan["sourceFingerprint"] == json_hash(snapshot["files"]), "Source fingerprint mismatch")
    require(host_platform.system() == PLATFORMS[plan["platform"]]["os"], "Build only on the native target OS")
    host_arch = {"AMD64": "x86_64", "aarch64": "arm64", "arm64": "arm64", "x86_64": "x86_64"}.get(host_platform.machine())
    require(host_arch == plan["architecture"], "Native build architecture mismatch; do not spoof os.arch")
    runtime = directory / plan["runtime"]["file"]
    require(runtime_identity(runtime, plan["platform"], plan["architecture"]) ==
            {key: plan["runtime"][key] for key in ("sha256", "sizeBytes")}, "Frozen runtime mismatch")
    run_command = run_command or subprocess.run
    product = directory / "packages"
    product.mkdir(mode=0o700)  # Never resume by rebuilding a partially used fixture.
    built = []
    for stage in plan["stages"]:
        verify_sources(directory / "source", snapshot["files"])
        checkout = directory / stage["directory"]
        copy_sources(directory / "source", checkout, snapshot["files"])
        os_tag = {"linux": "linux", "windows": "windows", "macos": "darwin"}[plan["platform"]]
        arch_tag = {"x86_64": "amd64", "arm64": "arm64"}[plan["architecture"]]
        bundled = checkout / "desktopApp/src/main/resources/bin" / (os_tag + "-" + arch_tag) / runtime.name
        bundled.parent.mkdir(parents=True)
        shutil.copyfile(runtime, bundled)
        bundled.chmod(0o755)
        with (directory / (stage["label"] + "-build.log")).open("xb") as log:
            for command in stage["preparation"]:
                prepared = run_command(command, cwd=checkout, stdout=log, stderr=subprocess.STDOUT, check=False)
                require(prepared.returncode == 0, "Native helper preparation failed; retain log and inputs")
            command = stage["command"]
            if plan["platform"] == "windows":
                # Windows CreateProcess does not resolve the executable against cwd.
                require(command[0] == "gradlew.bat", "Unexpected Windows fixture wrapper")
                command = [str(checkout / "gradlew.bat"), *command[1:]]
            if plan["platform"] == "macos":
                command = ["bash", "-e", "-c", 'source ./scripts/setup_macos_signing.sh; exec "$@"', "fixture-macos", *command]
            result = run_command(command, cwd=checkout, stdout=log, stderr=subprocess.STDOUT, check=False)
        require(result.returncode == 0, "Native build failed; retain log and inputs")
        verify_sources(checkout, snapshot["files"])
        root = checkout / "desktopApp/build/compose/binaries/main"
        image = root / "app" / ("vpn-control.app" if plan["platform"] == "macos" else "vpn-control")
        identity = image_identity(image, stage["version"])
        stage_output = product / stage["label"]
        stage_output.mkdir(mode=0o700)
        exported_image = stage_output / image.name
        shutil.copytree(image, exported_image, symlinks=True)
        assets = []
        for extension in PLATFORMS[plan["platform"]]["extension"]:
            candidates = list(root.glob("**/*." + extension))
            require(len(candidates) == 1, "Expected exactly one native " + extension + " package")
            source = candidates[0]
            target = stage_output / source.name
            shutil.copyfile(source, target)
            require(file_hash(target) == file_hash(source), "Package changed during fixture capture")
            target.chmod(0o400)
            assets.append(package_asset(target, plan["platform"], plan["architecture"], stage["version"]))
        if plan["platform"] == "linux":
            assets.append(arch_fixture_package(checkout, image, runtime, stage_output, stage["version"], plan["architecture"]))
        record = {**stage, **identity, "image": str(exported_image.relative_to(directory)), "assets": assets,
                  "sourceFingerprint": snapshot["sourceFingerprint"]}
        # Linux's public fixture driver reads its extra data-only marker. Keep
        # signed macOS bundles and other platform images byte-for-byte intact.
        marker = (exported_image if plan["platform"] == "linux" else stage_output) / "TEST-ONLY-INSTALL-FIXTURE.json"
        write_json(marker, {"testOnly": True, "productionTrustChanged": False,
                   "sameSourceBuild": True, "version": stage["version"], **identity,
                   "sourceFingerprint": snapshot["sourceFingerprint"]})
        built.append(record)
    require(built[0]["codeFingerprint"] == built[1]["codeFingerprint"], "Base and target executable content differ beyond version metadata")
    manifest = {"schemaVersion": 1, "buildNumber": built[1]["buildNumber"], "releaseTag": RELEASE,
                "releaseNotesUrl": "https://github.com/Karapsin/vpn_control/releases/tag/" + RELEASE,
                "assets": built[1]["assets"]}
    receipt = {"schemaVersion": 1, "testOnly": True, "productionTrustChanged": False,
               "sourceFingerprint": snapshot["sourceFingerprint"], "nativeOs": host_platform.platform(),
               "architecture": host_arch, "builds": built, "manifest": manifest}
    write_json(directory / "fixture-receipt.json", receipt)
    return receipt


def select_resource(method, target, host, manifest):
    if method != "GET" or host.lower() not in ("github.com", "github.com:443"):
        return None
    if target == MANIFEST_PATH:
        return "manifest"
    for asset in manifest["assets"]:
        if target == asset["downloadUrl"].removeprefix("https://github.com"):
            return asset["fileName"]
    return None


def load_resources(directory):
    receipt = json.loads((directory / "fixture-receipt.json").read_text())
    require(receipt["testOnly"] is True and receipt["productionTrustChanged"] is False, "Not a verified fixture")
    base, target = receipt["builds"]
    require(base["sourceFingerprint"] == target["sourceFingerprint"] == receipt["sourceFingerprint"] and
            base["codeFingerprint"] == target["codeFingerprint"], "Fixture source/code identity mismatch")
    manifest = receipt["manifest"]
    require(manifest["assets"] == target["assets"] and manifest["buildNumber"] == version_build(target["version"]),
            "Fixture manifest disagrees with captured target")
    resources = {}
    for asset in manifest["assets"]:
        file = directory / "packages/target" / asset["fileName"]
        require(file.parent == directory / "packages/target", "Package escaped the fixture directory")
        require(package_asset(file, asset["platform"], asset["architecture"], asset["displayVersion"]) == asset,
                "Captured fixture package changed")
        require(not file.stat().st_mode & 0o222, "Fixture package must remain read-only")
        resources[asset["fileName"]] = file
    return manifest, resources


def serve(directory, certificate, private_key, ready_file, confirmed):
    require(confirmed, "Explicit owned-disposable-guest confirmation required")
    directory = directory.resolve(strict=True)
    manifest, resources = load_resources(directory)
    body = json.dumps(manifest, separators=(",", ":")).encode()
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(certificate, private_key)

    class Handler(socketserver.BaseRequestHandler):
        def header(self):
            data = bytearray()
            while not data.endswith(b"\r\n\r\n"):
                value = self.request.recv(1)
                if not value:
                    raise EOFError
                data.extend(value)
                require(len(data) <= 16384, "Oversized fixture request header")
            lines = data.decode("ascii").split("\r\n")
            method, target, protocol = lines[0].split(" ")
            require(protocol == "HTTP/1.1", "Unsupported fixture HTTP version")
            hosts = [line.split(":", 1)[1].strip() for line in lines[1:] if line.lower().startswith("host:")]
            require(len(hosts) == 1, "Expected one Host header")
            return method, target, hosts[0]

        def handle(self):
            self.request.settimeout(30)
            try:
                method, target, host = self.header()
                if method != "CONNECT" or target.lower() != "github.com:443" or host.lower() != "github.com:443":
                    self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                    return
                self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                self.request = tls.wrap_socket(self.request, server_side=True)
                resource = select_resource(*self.header(), manifest)
                if resource is None:
                    self.request.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    return
                if resource == "manifest":
                    length = len(body)
                    self.request.sendall(("HTTP/1.1 200 OK\r\nContent-Length: " + str(length) +
                                          "\r\nConnection: close\r\n\r\n").encode() + body)
                else:
                    # Recheck immutable inputs before each request, then stream from the
                    # same open file. Production length/hash verification stays active.
                    asset = next(value for value in manifest["assets"] if value["fileName"] == resource)
                    path = resources[resource]
                    require(file_hash(path) == asset["sha256"], "Frozen package changed")
                    with path.open("rb") as source:
                        length = os.fstat(source.fileno()).st_size
                        require(length == asset["sizeBytes"], "Frozen package length changed")
                        self.request.sendall(("HTTP/1.1 200 OK\r\nContent-Length: " + str(length) +
                                              "\r\nConnection: close\r\n\r\n").encode())
                        for chunk in iter(lambda: source.read(65536), b""):
                            self.request.sendall(chunk)
                print(json.dumps({"served": resource, "bytes": length}), flush=True)
            except (OSError, EOFError, ValueError):
                print('{"request":"closed-or-rejected"}', flush=True)

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = False

    with Server(("127.0.0.1", 0), Handler) as server:
        write_json(ready_file, {"port": server.server_address[1], "sourceFingerprint":
                              json.loads((directory / "fixture-receipt.json").read_text())["sourceFingerprint"],
                              "manifest": manifest})
        server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--repository", type=Path, required=True)
    prepare_parser.add_argument("--output", type=Path, required=True)
    prepare_parser.add_argument("--base-version", required=True)
    prepare_parser.add_argument("--target-version", required=True)
    prepare_parser.add_argument("--runtime", type=Path, required=True)
    prepare_parser.add_argument("--platform", choices=PLATFORMS, required=True)
    prepare_parser.add_argument("--architecture", choices=("x86_64", "arm64"), required=True)
    build_parser = commands.add_parser("build")
    build_parser.add_argument("--directory", type=Path, required=True)
    build_parser.add_argument("--confirm-owned-disposable-guest", action="store_true")
    serve_parser = commands.add_parser("serve")
    serve_parser.add_argument("--directory", type=Path, required=True)
    serve_parser.add_argument("--certificate", type=Path, required=True)
    serve_parser.add_argument("--private-key", type=Path, required=True)
    serve_parser.add_argument("--ready-file", type=Path, required=True)
    serve_parser.add_argument("--confirm-owned-disposable-guest", action="store_true")
    args = parser.parse_args()
    if args.action == "prepare":
        result = prepare(args.repository, args.output, args.base_version, args.target_version,
                         args.runtime, args.platform, args.architecture)
    elif args.action == "build":
        result = native_build(args.directory, args.confirm_owned_disposable_guest)
    else:
        serve(args.directory, args.certificate, args.private_key, args.ready_file, args.confirm_owned_disposable_guest)
        return
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
