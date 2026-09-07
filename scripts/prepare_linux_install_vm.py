#!/usr/bin/env python3
"""Prepare, but NEVER boot, one new disposable x86_64 Linux installer VM.

Image provenance: https://cloud-images.ubuntu.com/noble/20260826/SHA256SUMS
https://fedoraproject.org/cloud/download/
https://geo.mirror.pkgbuild.com/images/v20260901.583572/
Pinned digests were checked over official HTTPS, not a GPG signature ceremony.
NoCloud: https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html
QEMU: https://www.qemu.org/docs/master/system/invocation.html
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import uuid

BASE = "https://cloud-images.ubuntu.com/noble/20260826/"
IMAGE = "noble-server-cloudimg-amd64.img"
SHA256 = "d0fe84bb5f80853425fa6be28e2c106f30104c3cfe8611933f2e65c9b63f0e30"


def image_spec(distribution):
    if distribution == "ubuntu":
        return {"base": BASE, "image": IMAGE, "sha256": SHA256}
    if distribution == "fedora":
        return {"base": "https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/",
                "image": "Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2",
                "sha256": "28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f"}
    if distribution == "arch":
        return {"base": "https://geo.mirror.pkgbuild.com/images/v20260901.583572/",
                "image": "Arch-Linux-x86_64-cloudimg-20260901.583572.qcow2",
                "sha256": "e3e688f97a71b265ce202905a504253f60f3680cf57d011a45411c43bedfa930"}
    raise ValueError("Use a supported pinned installer guest distribution")


def guest_configuration(distribution, client_public, host_public, host_private):
    image_spec(distribution)
    packages = {
        "ubuntu": ["openssh-server", "sudo", "polkitd", "pkexec", "openjdk-17-jdk", "python3",
                   "curl", "ca-certificates", "git", "unzip", "zip", "libcap2-bin", "libx11-6",
                   "libxext6", "libxi6", "libxrender1", "libxtst6", "libgtk-3-0t64", "libgl1",
                   "libfontconfig1", "fonts-dejavu-core", "fakeroot", "rpm", "binutils", "xz-utils"],
        "fedora": ["openssh-server", "sudo", "polkit", "python3", "openssl", "curl", "ca-certificates",
                   "java-headless", "libX11", "libXext", "libXi", "libXrender", "libXtst", "mesa-libGL",
                   "fontconfig", "dejavu-sans-fonts"],
        "arch": ["openssh", "sudo", "polkit", "python", "openssl", "curl", "ca-certificates",
                 "jre-openjdk-headless", "libx11", "libxext", "libxi", "libxrender", "libxtst",
                 "libglvnd", "fontconfig", "ttf-dejavu"],
    }[distribution]
    return {
        "hostname": "vpn-install-x86", "manage_etc_hosts": True, "ssh_pwauth": False,
        "disable_root": True, "ssh_deletekeys": True,
        "ssh_keys": {"ed25519_private": host_private, "ed25519_public": host_public},
        "users": [{"name": "vpnfixture", "groups": ["sudo" if distribution == "ubuntu" else "wheel"],
                   "shell": "/bin/bash", "lock_passwd": True, "sudo": ["ALL=(ALL) NOPASSWD:ALL"],
                   "ssh_authorized_keys": [client_public]}],
        # Arch's rolling guest must be synchronized as one initial bootstrap;
        # this never changes the production installer's package transaction.
        "package_update": True, "package_upgrade": distribution == "arch", "packages": packages,
        "runcmd": [["systemctl", "enable", "--now", "ssh" if distribution == "ubuntu" else "sshd"],
                   ["systemctl", "enable", "--now", "polkit"]],
    }


def installed_linux_uefi():
    pairs = (("/usr/share/edk2/x64/OVMF_CODE.4m.fd", "/usr/share/edk2/x64/OVMF_VARS.4m.fd"),
             ("/usr/share/OVMF/OVMF_CODE_4M.fd", "/usr/share/OVMF/OVMF_VARS_4M.fd"))
    for code, variables in pairs:
        if Path(code).is_file() and Path(variables).is_file():
            return Path(code), Path(variables)
    raise RuntimeError("Missing existing x86 UEFI firmware; no host setup is performed")


def qemu_command(directory, qemu, firmware, port, accelerator="tcg"):
    if not 1024 <= port <= 65535:
        raise ValueError("Unprivileged explicit SSH port required")
    # Paths embedded in QEMU key=value arguments must not inject an extra option.
    if any(character in str(directory) + str(firmware) for character in ",\n\r"):
        raise ValueError("QEMU task/firmware paths cannot contain commas or newlines")
    if accelerator not in ("tcg", "kvm"):
        raise ValueError("Only explicit TCG or KVM acceleration is supported")
    boot = [] if firmware is None else [
        "-drive", f"if=pflash,format=raw,readonly=on,file={firmware}",
        "-drive", f"if=pflash,format=raw,file={directory / 'uefi-vars.fd'}"]
    return [str(qemu), "-name", "vpn-control-install-x86-task", "-machine", "q35",
            "-accel", "kvm" if accelerator == "kvm" else "tcg,thread=multi",
            "-cpu", "host" if accelerator == "kvm" else "max", "-smp", "4", "-m", "6144", *boot,
            "-drive", f"file={directory / 'task.qcow2'},if=virtio,format=qcow2",
            "-drive", f"file={directory / 'seed.iso'},media=cdrom,readonly=on",
            "-netdev", f"user,id=network,hostfwd=tcp:127.0.0.1:{port}-:22",
            "-device", "virtio-net-pci,netdev=network", "-display", "none", "-monitor", "none",
            "-serial", f"file:{directory / 'serial.log'}",
            "-qmp", f"unix:{directory / 'qmp.sock'},server=on,wait=off",
            "-pidfile", str(directory / "qemu.pid")]


def seed_command(tool, directory, linux):
    seed = directory / "seed"
    if linux:
        return [str(tool), "-as", "mkisofs", "-output", str(directory / "seed.iso"),
                "-volid", "CIDATA", "-rational-rock", "-joliet", str(seed)]
    return [str(tool), "makehybrid", "-iso", "-joliet", "-default-volume-name", "CIDATA",
            "-o", str(directory / "seed.iso"), str(seed)]


def capture_base_image(directory, curl, source=None, distribution="ubuntu"):
    spec = image_spec(distribution)
    image = directory / spec["image"]
    if source is None:
        subprocess.run([str(curl), "--fail", "--location", "--proto", "=https", "--proto-redir", "=https",
                        "--retry", "2", "--connect-timeout", "30", "--max-time", "1800", "--output", str(image),
                        spec["base"] + spec["image"]], check=True)
    else:
        source = Path(source)
        if not source.is_file() or source.is_symlink():
            raise ValueError("Existing image must be a regular captured cloud image, never a task disk or symlink")
        with source.open("rb") as input_file, image.open("xb") as output_file:
            shutil.copyfileobj(input_file, output_file, 1024 * 1024)
    digest = hashlib.sha256()
    with image.open("rb") as input_file:
        for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != spec["sha256"]:
        raise RuntimeError("Official cloud image checksum mismatch; NEVER boot this image")
    image.chmod(0o400)
    return image, digest.hexdigest()


def prepare(directory, port, image_source=None, distribution="ubuntu"):
    spec = image_spec(distribution)
    system = os.uname()
    linux = system.sysname == "Linux"
    if system.sysname not in ("Darwin", "Linux"):
        raise RuntimeError("Only existing macOS/QEMU or Linux/KVM prerequisites are supported")
    if linux and (system.machine not in ("x86_64", "amd64") or not os.access("/dev/kvm", os.R_OK | os.W_OK)):
        raise RuntimeError("Linux host must already provide x86_64 and readable/writable /dev/kvm; no host setup is performed")
    directory = directory.absolute()
    if directory.exists() or directory.is_symlink() or not directory.parent.is_dir():
        raise ValueError("Provide a NEW task directory under an existing parent; never reuse a disk")
    seed_tool = "xorriso" if linux else "hdiutil"
    binaries = {name: shutil.which(name) for name in ("qemu-system-x86_64", "qemu-img", seed_tool, "ssh-keygen", "curl")}
    if not all(binaries.values()):
        raise RuntimeError("Missing existing prerequisite: " + str(binaries))
    firmware = template = None
    if linux and distribution != "ubuntu":
        firmware, template = installed_linux_uefi()
    elif not linux:
        share = Path(binaries["qemu-system-x86_64"]).resolve().parent.parent / "share/qemu"
        firmware, template = share / "edk2-x86_64-code.fd", share / "edk2-i386-vars.fd"
        if not firmware.is_file() or not template.is_file():
            raise RuntimeError("Missing installed QEMU x86 UEFI firmware")
    # Noble amd64 supports the default BIOS boot shown by the official cloud-init QEMU guide.
    command = qemu_command(directory, binaries["qemu-system-x86_64"], firmware, port, "kvm" if linux else "tcg")
    directory.mkdir(mode=0o700)
    os.umask(0o077)

    def execute(*arguments):
        subprocess.run(arguments, check=True)

    # No existing cache/media is overwritten; a failed download remains in this marked task directory.
    (directory / "TASK-OWNED.json").write_text(json.dumps({"purpose": "disposable-public-linux-install",
        "distribution": distribution, "image": spec["base"] + spec["image"],
        "sha256": spec["sha256"], "sshPort": port}, indent=2))
    image, digest = capture_base_image(directory, binaries["curl"], image_source, distribution)
    execute(binaries["qemu-img"], "create", "-f", "qcow2", "-F", "qcow2", "-b", str(image),
            str(directory / "task.qcow2"), "40G")
    if template is not None:
        shutil.copyfile(template, directory / "uefi-vars.fd")
    for name in ("client-key", "host-key"):
        execute(binaries["ssh-keygen"], "-q", "-t", "ed25519", "-N", "", "-C", "vpn-install-disposable",
                "-f", str(directory / name))
    client_public = (directory / "client-key.pub").read_text().strip()
    host_public = (directory / "host-key.pub").read_text().strip()
    host_private = (directory / "host-key").read_text()
    seed = directory / "seed"
    seed.mkdir(mode=0o700)
    # JSON is valid YAML. Host private key is task-only seed data, never printed or sent as argv.
    configuration = guest_configuration(distribution, client_public, host_public, host_private)
    (seed / "user-data").write_text("#cloud-config\n" + json.dumps(configuration, indent=2))
    (seed / "meta-data").write_text(json.dumps({"instance-id": "vpn-install-" + str(uuid.uuid4()),
                                               "local-hostname": "vpn-install-x86"}))
    execute(*seed_command(binaries[seed_tool], directory, linux))
    (directory / "known-hosts").write_text(f"[127.0.0.1]:{port} {host_public}\n")
    ssh = ["ssh", "-p", str(port), "-i", str(directory / "client-key"), "-o", "IdentitiesOnly=yes",
           "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={directory / 'known-hosts'}",
           "vpnfixture@127.0.0.1"]
    receipt = {"distribution": distribution, "image": spec["base"] + spec["image"],
               "verifiedSha256": digest, "qemu": command, "ssh": ssh}
    (directory / "launch.json").write_text(json.dumps(receipt, indent=2))
    print("Prepared ONLY; root must separately start and retain this foreground QEMU process:")
    print(shlex.join(command))
    print("Readiness: " + shlex.join(ssh + ["sudo -n cloud-init status --wait"]))
    print("Set guest-only polkit password interactively: " + shlex.join(ssh[:-1] + ["-tt", ssh[-1], "sudo passwd vpnfixture"]))
    print("Orderly shutdown (after no pending installer): " + shlex.join(ssh + ["sudo shutdown -h now"]))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--ssh-port", type=int, default=2307)
    parser.add_argument("--distribution", choices=("ubuntu", "fedora", "arch"), default="ubuntu")
    parser.add_argument("--verified-image-source", type=Path,
                        help="Copy an existing pinned clean cloud image after rechecking its exact official digest")
    args = parser.parse_args()
    prepare(args.directory, args.ssh_port, args.verified_image_source, args.distribution)
