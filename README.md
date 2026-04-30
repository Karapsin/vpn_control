# VPN Control Install Files

Install files are available on the GitHub repository page under `Actions` artifacts.

Artifacts can include `SHA256SUMS.txt` checksum files where the packaging workflow produces them.

| Platform | GitHub Location | File To Use |
| --- | --- | --- |
| Windows | `Actions` -> `Windows Desktop Package` -> latest successful run -> `vpn-control-windows-installers` | `vpn-control-<version>.exe` |
| Android | `Actions` -> `Android Release APK` -> latest successful run -> `vpn-control-android-release-apk` | `app-release.apk` |
| Linux | `Actions` -> `Linux Desktop Package` -> latest successful run -> `vpn-control-linux-packages` | `.deb` or `.rpm` |
| macOS | `Actions` -> `macOS Desktop Package` -> latest successful run -> `vpn-control-macos-package` | `.dmg` |

## Windows

Open:

```text
Actions -> Windows Desktop Package -> latest successful run -> Artifacts
```

Download:

```text
vpn-control-windows-installers
```

Use:

```text
vpn-control-<version>.exe
```

Install by double-clicking it. For VPN mode on Windows, launch VPN Control as Administrator.

## Android

Open:

```text
Actions -> Android Release APK -> latest successful run -> Artifacts
```

Download:

```text
vpn-control-android-release-apk
```

Use:

```text
app-release.apk
```

Install on a connected phone with:

```bash
adb install -r app-release.apk
```

Note: the current release APK is signed with the Android debug signing config, so treat it as a direct-install artifact rather than a Play Store release artifact.

## Linux

Open:

```text
Actions -> Linux Desktop Package -> latest successful run -> Artifacts
```

Download:

```text
vpn-control-linux-packages
```

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

## macOS

Open:

```text
Actions -> macOS Desktop Package -> latest successful run -> Artifacts
```

Download:

```text
vpn-control-macos-package
```

Use:

```text
*.dmg
```

Install by opening the DMG and dragging VPN Control to Applications.

Note: macOS packaging exists, but full desktop VPN mode is not implemented yet.
