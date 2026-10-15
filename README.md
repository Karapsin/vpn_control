# VPN Control Install Files

**Version:** `2.2.12`

Download install files from the [GitHub Actions package workflows](https://github.com/Karapsin/vpn_control/actions). Open the workflow for your platform, choose a successful run, and download its package from `Artifacts`.

In an installed app, open the settings menu and choose `Update` to download and install the compatible published update.

[User documentation](docs/README.md) includes optional features such as [SSH Routing](docs/ssh-routing.md) and the [Linux headless service](docs/linux-headless-service.md).

Artifacts can include `SHA256SUMS.txt` checksum files where the packaging workflow produces them.

| Platform | GitHub Location | File To Use |
| --- | --- | --- |
| Windows | [Windows Desktop Package](https://github.com/Karapsin/vpn_control/actions/workflows/windows-desktop.yml) | `.msi` or `.exe` |
| Android | [Android Release APK](https://github.com/Karapsin/vpn_control/actions/workflows/android-release.yml) | `.apk` |
| Linux | [Linux Desktop Package](https://github.com/Karapsin/vpn_control/actions/workflows/linux-desktop.yml) | `.deb`, `.rpm`, or the Arch update bundle |
| macOS | [macOS Desktop Package](https://github.com/Karapsin/vpn_control/actions/workflows/macos-desktop.yml) | `.dmg` |

## Windows

Use:

```text
vpn-control-windows-x86_64-v<version>.exe
```

Install by double-clicking it. For VPN mode on Windows, launch VPN Control as Administrator.

## Android

Use:

```text
vpn-control-android-arm64-v<version>.apk
```

Install on a connected phone with:

```bash
adb install -r vpn-control-android-arm64-v<version>.apk
```

Release APKs use the project's stable signing key so later versions can update in place and retain Android app data.

## Linux

Use one package:

```text
*.deb
*.rpm
```

Install DEB:

```bash
sudo apt install ./*.deb
```

Install RPM:

```bash
sudo dnf install ./*.rpm
```

After installation, launch:

```bash
vpn-control
```

For Arch Linux, the repo also includes this local installer script:

```text
scripts/arch_install.sh
```

Installed Arch copies can use the in-app updater, which downloads the release update bundle and preserves `~/.vpn-control-desktop`.

## macOS

Use:

```text
*.dmg
```

Install by opening the DMG and dragging VPN Control to Applications.

Note: macOS packaging exists, but full desktop VPN mode is not implemented yet.
