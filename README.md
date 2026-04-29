# VPN Control Installation

VPN Control is available from this repository as:

| Platform | Artifact | Main install path |
| --- | --- | --- |
| Android | APK | `app/build/outputs/apk/release/app-release.apk` |
| Linux desktop | Arch install, DEB, RPM, app image | `scripts/arch_install.sh` or `desktopApp/build/compose/binaries/main/` |
| Windows desktop | EXE, MSI | `dist/windows/` or `dist/windows-vm/` |
| macOS desktop | DMG, experimental | `dist/macos/` |

The Android app uses the Android VPN service. The desktop app uses bundled `sing-box`; VPN mode is implemented for Linux and Windows. macOS packaging exists, but macOS VPN mode still needs a privileged-helper implementation, so macOS is currently useful mainly for desktop packaging/proxy-mode validation.

## Repository Layout

Important files and directories:

| Path | Purpose |
| --- | --- |
| `app/` | Android application. |
| `desktopApp/` | Compose Desktop application for Linux, Windows, and macOS. |
| `shared/` | Shared model, storage, core logic, and UI code. |
| `scripts/arch_install.sh` | Build and install the Linux desktop app on Arch-style systems. |
| `scripts/package_linux_desktop.sh` | Build Linux `.deb` and `.rpm` packages. |
| `scripts/package_windows_desktop.ps1` | Build Windows `.exe` and `.msi` installers on Windows. |
| `scripts/package_windows_desktop_vm.sh` | Build Windows installers from Linux using the local Windows VM. |
| `scripts/package_macos_desktop.sh` | Build the macOS `.dmg`. |
| `.github/workflows/android-release.yml` | GitHub Actions release APK build. |
| `.github/workflows/linux-desktop.yml` | GitHub Actions Linux DEB/RPM build. |
| `.github/workflows/windows-desktop.yml` | GitHub Actions Windows EXE/MSI build. |
| `.github/workflows/macos-desktop.yml` | GitHub Actions macOS DMG build. |

## Get Build Artifacts From GitHub Actions

After pushing to `main`, GitHub Actions builds platform artifacts. In the GitHub UI, open `Actions`, choose the workflow, open a successful run, and download its artifact.

With GitHub CLI:

```bash
gh run list --workflow "Android Release APK" --branch main
gh run download <run-id> -n vpn-control-android-release-apk -D dist/android

gh run list --workflow "Linux Desktop Package" --branch main
gh run download <run-id> -n vpn-control-linux-packages -D dist/linux

gh run list --workflow "Windows Desktop Package" --branch main
gh run download <run-id> -n vpn-control-windows-installers -D dist/windows
```

The downloaded files are the same artifacts described below.

## Android

Requirements:

| Requirement | Notes |
| --- | --- |
| Android 10 or newer | `minSdk` is 29. |
| ARM64 device for release APK | Release builds are `arm64-v8a` only. |
| Android SDK platform tools | Needed only for `adb install`. |
| JDK 17 | Needed only when building locally. |

Build the release APK:

```bash
./gradlew :app:assembleRelease
```

The APK is written to:

```text
app/build/outputs/apk/release/app-release.apk
```

Install it on a connected Android device:

```bash
adb install -r app/build/outputs/apk/release/app-release.apk
```

For emulator/debug work, build the debug APK:

```bash
./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Debug APK output:

```text
app/build/outputs/apk/debug/app-debug.apk
```

Notes:

- The release build currently uses the debug signing config, so it is installable locally without Play Store signing setup.
- The release APK is optimized for real ARM64 phones. Use debug builds for x86_64 emulator testing.

## Linux Desktop

Requirements:

| Requirement | Notes |
| --- | --- |
| JDK 17 | Required for local builds. |
| `curl`, `tar`, `bash` | Used by the packaging scripts. |
| TUN support | VPN mode needs `/dev/net/tun`; load with `sudo modprobe tun` if missing. |
| Network privilege for `sing-box` | VPN mode needs `CAP_NET_ADMIN`; the Arch installer handles this automatically. |

### Arch Linux Local Install

The easiest local Linux install path on this repo is:

```bash
./scripts/arch_install.sh
```

The script:

- installs Arch dependencies with `pacman` when available;
- downloads and bundles the Linux `sing-box` runtime;
- builds the desktop app image;
- installs the app to `/opt/vpn-control`;
- installs the launcher at `/usr/local/bin/vpn-control`;
- installs the desktop entry and icon;
- loads the TUN module;
- grants `cap_net_admin,cap_net_raw` to the installed `sing-box` binary.

Launch after install:

```bash
vpn-control
```

Useful options:

```bash
./scripts/arch_install.sh --skip-deps
./scripts/arch_install.sh --skip-build
./scripts/arch_install.sh --allow-running-update
```

Default install paths:

```text
/opt/vpn-control
/usr/local/bin/vpn-control
/usr/share/applications/vpn-control.desktop
/usr/share/icons/hicolor/256x256/apps/vpn-control.png
```

### Linux DEB/RPM Packages

Build packages:

```bash
./scripts/package_linux_desktop.sh
```

The script compiles the app, runs desktop tests, builds Linux packages, and runs package smoke checks.

Outputs:

```text
desktopApp/build/compose/binaries/main/deb/*.deb
desktopApp/build/compose/binaries/main/rpm/*.rpm
```

Install on Debian/Ubuntu:

```bash
sudo apt install ./desktopApp/build/compose/binaries/main/deb/*.deb
```

Install on Fedora/RHEL-style systems:

```bash
sudo dnf install ./desktopApp/build/compose/binaries/main/rpm/*.rpm
```

If VPN mode reports missing privileges after a package install, either use the Arch installer path or provide a privileged `sing-box` executable and point the app to it:

```bash
sudo modprobe tun
sudo install -Dm755 desktopApp/src/main/resources/bin/linux-amd64/sing-box /opt/vpn-control/bin/sing-box
sudo setcap cap_net_admin,cap_net_raw+ep /opt/vpn-control/bin/sing-box
VPN_CONTROL_SING_BOX=/opt/vpn-control/bin/sing-box vpn-control
```

## Windows Desktop

Requirements:

| Requirement | Notes |
| --- | --- |
| Windows 10/11 x64 | Current desktop target is Windows AMD64. |
| JDK 17 | Needed only when building locally. |
| PowerShell | Used by packaging scripts. |
| Administrator launch | Required for desktop VPN mode. Proxy-only mode does not need it. |

### Install Existing EXE/MSI

Use one of these installers:

```text
dist/windows/vpn-control-<version>.exe
dist/windows/vpn-control-<version>.msi
dist/windows-vm/vpn-control-<version>.exe
dist/windows-vm/vpn-control-<version>.msi
```

Install by double-clicking the `.exe` or `.msi`.

For VPN mode, launch VPN Control as Administrator and accept the UAC prompt. The app can run without Administrator rights in Proxy-only mode, but Windows VPN mode needs Administrator privileges so `sing-box` can create the Wintun backend.

### Build On Windows

From a Windows PowerShell prompt at the repo root:

```powershell
.\scripts\package_windows_desktop.ps1
```

The script:

- checks Java;
- downloads and bundles `sing-box.exe`;
- compiles the desktop app;
- runs desktop unit tests;
- builds EXE/MSI installers;
- runs package regression tests;
- runs installed-package smoke tests;
- copies final installers to `dist\windows\`.

Outputs:

```text
dist\windows\vpn-control-<version>.exe
dist\windows\vpn-control-<version>.msi
dist\windows\SHA256SUMS.txt
```

Useful options:

```powershell
.\scripts\package_windows_desktop.ps1 -SkipTests
.\scripts\package_windows_desktop.ps1 -SkipPackageRegressionTests
.\scripts\package_windows_desktop.ps1 -SkipInstalledPackageRegressionTests
.\scripts\package_windows_desktop.ps1 -DistDir dist\windows-local
```

### Build Windows Installers From Linux VM

This repo also supports building Windows installers from Linux using the local libvirt VM.

Default VM name:

```text
vpn-control-win11
```

Run:

```bash
./scripts/package_windows_desktop_vm.sh
```

The script starts the VM if needed, waits for the QEMU guest agent, sends the current working tree snapshot to Windows, builds inside the VM, and copies the installers back to:

```text
dist/windows-vm/
```

Useful options:

```bash
./scripts/package_windows_desktop_vm.sh --vm-name vpn-control-win11
./scripts/package_windows_desktop_vm.sh --output-dir dist/windows-vm
./scripts/package_windows_desktop_vm.sh --skip-tests
./scripts/package_windows_desktop_vm.sh --skip-package-regression-tests
./scripts/package_windows_desktop_vm.sh --skip-installed-package-regression-tests
```

## macOS Desktop

macOS packaging is present, but desktop VPN mode is not complete on macOS yet.

Build the DMG on macOS:

```bash
./scripts/package_macos_desktop.sh
```

Outputs:

```text
dist/macos/*.dmg
dist/macos/SHA256SUMS.txt
```

Unsigned local DMGs are useful for development. Signed/notarized builds require the macOS signing and notarization environment variables used by `.github/workflows/macos-desktop.yml`.

## Smoke Tests

Common local checks:

```bash
./gradlew :app:assembleRelease
./gradlew :desktopApp:test
./scripts/package_linux_desktop.sh
```

Windows package checks are run by:

```powershell
.\scripts\package_windows_desktop.ps1
```

The desktop app also supports an internal smoke-test mode used by package tests:

```bash
desktopApp/build/compose/binaries/main/app/vpn-control/bin/vpn-control --smoke-test --smoke-test-state-dir /tmp/vpn-control-smoke
```

## Runtime Data And Logs

Desktop runtime data is stored under:

```text
~/.vpn-control-desktop/
```

Useful files during troubleshooting:

```text
~/.vpn-control-desktop/workspace.json
~/.vpn-control-desktop/runtime/runtime-sing-box.log
~/.vpn-control-desktop/runtime/runtime-sing-box-vpn.json
~/.vpn-control-desktop/runtime/runtime-sing-box-proxy_only.json
```

Android diagnostics can be exported from inside the app.
