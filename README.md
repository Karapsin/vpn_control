# VPN Control Install Files

This page lists which file to use for installing VPN Control on each platform.

## Windows

Use one of these installer files:

```text
dist/windows/vpn-control-<version>.exe
dist/windows/vpn-control-<version>.msi
```

Alternative Windows installer location:

```text
dist/windows-vm/vpn-control-<version>.exe
dist/windows-vm/vpn-control-<version>.msi
```

Recommended file:

```text
vpn-control-<version>.exe
```

Install by double-clicking the installer. For VPN mode on Windows, launch VPN Control as Administrator.

## Android

Use the release APK:

```text
app/build/outputs/apk/release/app-release.apk
```

For emulator or test installs, use:

```text
app/build/outputs/apk/debug/app-debug.apk
```

Install with:

```bash
adb install -r app/build/outputs/apk/release/app-release.apk
```

## Linux

For Arch Linux on this machine, use the installer script:

```text
scripts/arch_install.sh
```

Run it with:

```bash
./scripts/arch_install.sh
```

For package-based installation, use one of these files:

```text
desktopApp/build/compose/binaries/main/deb/*.deb
desktopApp/build/compose/binaries/main/rpm/*.rpm
```

Install DEB:

```bash
sudo apt install ./desktopApp/build/compose/binaries/main/deb/*.deb
```

Install RPM:

```bash
sudo dnf install ./desktopApp/build/compose/binaries/main/rpm/*.rpm
```

After installation, launch:

```bash
vpn-control
```

## macOS

Use the DMG file:

```text
dist/macos/*.dmg
```

Install by opening the DMG and dragging VPN Control to Applications.

Note: macOS packaging exists, but full desktop VPN mode is not implemented yet.
