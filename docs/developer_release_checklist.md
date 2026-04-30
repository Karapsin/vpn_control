# Developer Release Checklist

This document is for maintainers building release artifacts from the repository. User-facing install instructions stay in `README.md` and should point to GitHub Actions artifacts, not ignored local `dist/` paths.

## One-Command Release Check

Run the full local release pass from the repository root:

```bash
./scripts/release_checklist.sh
```

The script runs standalone regression tests, builds Android, Linux, macOS when on macOS, and Windows through the local VM, then prints candidate artifacts and SHA-256 checksums.

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

Run targeted package scripts when only one platform changed:

```bash
./scripts/package_linux_desktop.sh
./scripts/package_windows_desktop_vm.sh
./scripts/package_macos_desktop.sh
```

Each platform package script has skip flags for tests or extracted package smoke checks. Use skip flags only when the omitted check is unrelated to the change and record that decision in the handoff.

## Repository Hygiene

- Do not commit generated artifacts from `build/`, `dist/`, `.runtime/`, or downloaded `sing-box` binaries.
- Do not add default subscriptions, default routing rules, or demo data.
- Do not document ignored local `dist/` paths in user install docs. Local paths belong in developer docs only.
- Do not kill a currently running VPN/runtime during validation unless the user explicitly approves the interruption.
