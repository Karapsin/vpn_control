# Developer Release Checklist

This document owns developer release packaging. User-facing install instructions stay in `README.md` and should point to GitHub Actions artifacts, not ignored local `dist/` paths.

## Prerequisites

All platforms:

- JDK 17 is available on `PATH`.
- The repository can run the Gradle wrapper.
- Generated artifacts under `build/`, `dist/`, and `.runtime/` are ignored and should not be committed.
- `sing-box` runtime downloads are allowed when packaging scripts prepare bundled runtime files.

Android:

- Android SDK and build tools are installed.
- `local.properties` points to the Android SDK when needed.
- Release APKs are currently signed with the debug signing config in `app/build.gradle.kts`; treat them as direct-install/test artifacts, not Play Store artifacts.

Linux desktop:

- Package build must run on Linux.
- `jpackage` requirements for `.deb`/`.rpm` are available through the JDK and host packaging tools.
- VPN mode after install needs `/dev/net/tun` and `CAP_NET_ADMIN` on the installed `sing-box`.

Windows desktop from a Windows host:

- PowerShell is available.
- JDK 17 is available.
- WiX is downloaded by the Compose packaging task when needed.
- Package regression scripts validate MSI/EXE payloads and extracted launcher smoke behavior.

Windows desktop from Linux VM:

- libvirt VM `vpn-control-win11` exists, or pass `--vm-name`.
- QEMU guest agent is installed and running inside the VM.
- The host can reach the VM file bridge address, usually `virbr0` or `192.168.122.1`.
- `VPN_CONTROL_SUDO_PASSWORD` can be set for non-interactive VM control if sudo is required.

macOS:

- DMG packaging must run on macOS.
- Unsigned DMG builds work without Apple secrets.
- Signing and notarization require the secrets described in `docs/macos-release.md`.
- Full desktop VPN mode is not implemented yet; package smoke should use proxy-only assumptions.

## One-Command Release Check

Run the full local release pass from the repository root:

```bash
./scripts/release_checklist.sh
```

The script first runs `scripts/check_release_hygiene.sh` to fail fast if generated release/runtime artifacts are tracked by Git. It then runs standalone regression tests, builds Android, Linux, macOS when on macOS, and Windows through the local VM, then prints candidate artifacts and SHA-256 checksums.

Useful skip flags:

| Flag | Effect |
| --- | --- |
| `--skip-tests` | Skip the standalone Gradle regression pass. |
| `--skip-android` | Skip `:app:assembleRelease`. |
| `--skip-linux` | Skip Linux desktop packaging. |
| `--skip-macos` | Skip macOS desktop packaging. |
| `--skip-windows-vm` | Skip Windows EXE/MSI packaging in the local VM. |

Windows VM packaging uses `scripts/package_windows_desktop_vm.sh`. If sudo is required non-interactively, set `VPN_CONTROL_SUDO_PASSWORD` in the environment.

## Expected Local Outputs

Android:

```text
app/build/outputs/apk/release/*.apk
```

Linux:

```text
desktopApp/build/compose/binaries/main/**/*.deb
desktopApp/build/compose/binaries/main/**/*.rpm
```

Windows from a Windows host:

```text
dist/windows/*.exe
dist/windows/*.msi
dist/windows/SHA256SUMS.txt
```

Windows from the local VM:

```text
dist/windows-vm/*.exe
dist/windows-vm/*.msi
dist/windows-vm/SHA256SUMS.txt
```

macOS from a Mac:

```text
dist/macos/*.dmg
dist/macos/SHA256SUMS.txt
```

Compose also writes platform package intermediates under:

```text
desktopApp/build/compose/binaries/main/
```

## Platform Notes

- Android release APKs are currently signed with the debug signing config in `app/build.gradle.kts`. Treat these APKs as direct-install/test artifacts, not Play Store release artifacts.
- Windows VPN mode requires Administrator privileges. Proxy-only mode does not.
- Linux VPN mode requires `/dev/net/tun` and `CAP_NET_ADMIN` on the installed `sing-box` binary.
- macOS DMG packaging exists, but full desktop VPN mode still needs a privileged helper.

## Release Validation

Run localization validation for all catalogs before packaging if UI/status text changed:

```bash
./scripts/check_localization.py
```

Run release hygiene directly before packaging if a previous build or VM package run created local artifacts:

```bash
./scripts/check_release_hygiene.sh
```

Run targeted package scripts when only one platform changed:

```bash
./scripts/package_linux_desktop.sh
./scripts/package_windows_desktop_vm.sh
./scripts/package_macos_desktop.sh
```

Each platform package script has skip flags for tests or extracted package smoke checks. Linux, macOS, Windows-host, and Windows-VM package scripts all run release hygiene before building. Use skip flags only when the omitted check is unrelated to the change and record that decision in the handoff.

## Common Failure Modes

- `Filename too long` on Windows checkout usually means generated `build/` outputs were committed. Remove generated artifacts from Git instead of changing source names.
- `Generated release/runtime artifacts are tracked by Git` means `build/`, `dist/`, `.runtime/`, or desktop bundled runtime outputs were accidentally added to the index. Remove them from Git before packaging.
- `Windows app image was not produced` usually means the packaging script expects an output layout that changed. Inspect `desktopApp/build/compose/binaries/main/`.
- `MSI payload is missing bundled runtime` usually means the package validation script and current Compose runtime layout disagree.
- `Timed out waiting for QEMU guest agent` means the Windows VM is off, locked too early, or the guest agent service is not running.
- macOS signing failures usually mean one of the Developer ID or notarization secrets is missing or malformed.
- Linux VPN package installs can build successfully but still fail at runtime if TUN or `CAP_NET_ADMIN` is missing on the installed machine.

## Repository Hygiene

- Do not commit generated artifacts from `build/`, `dist/`, `.runtime/`, or downloaded `sing-box` binaries.
- Do not add default subscriptions, default routing rules, or demo data.
- Do not document ignored local `dist/` paths in user install docs. Local paths belong in developer docs only.
- Do not kill a currently running VPN/runtime during validation unless the user explicitly approves the interruption.
