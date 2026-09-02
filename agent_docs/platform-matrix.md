# Platform Matrix

This matrix summarizes platform behavior so patches do not accidentally apply Android, Linux, Windows, or macOS assumptions globally.

| Platform | UI Target | VPN Mode | Proxy-Only Mode | Privileges | Package Output | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Android | Native Android app with shared Compose UI | Supported through Android VPN APIs | Supported where app/runtime flow exposes it | User grants VPN permission | `app-release.apk` | Release APK is currently debug-signed and intended as direct-install artifact. |
| Linux desktop | Compose Desktop | Supported through bundled `sing-box` TUN config | Supported | `/dev/net/tun` and `CAP_NET_ADMIN` on installed `sing-box` | `.deb`, `.rpm`, Arch local install script | `scripts/arch_install.sh` handles local Arch setup. |
| Windows desktop | Compose Desktop | Supported through bundled `sing-box` and Wintun path | Supported | Administrator required for VPN mode | `.exe`, `.msi` | Autostart/elevation behavior must be checked carefully. |
| macOS desktop | Compose Desktop | Not fully implemented | Supported | Full VPN mode still needs a privileged helper | `.dmg` | Package exists; use proxy-only for smoke testing. |

All packaged platforms expose an in-app `Update` action backed by the latest GitHub Release. Checking, downloading, and checksum verification do not stop an active connection. Installation uses the platform confirmation/elevation flow and may briefly disconnect; desktop relaunch preserves the existing reconnect/off intent. Linux selects DEB, RPM, or the Arch update bundle from the detected installation family.

## Shared Behavior That Should Stay Aligned

- Subscription parsing and profile selection should stay in shared logic when possible.
- `All` subscription/group behavior should be consistent across Android and desktop.
- `Find Best` should evaluate candidates independently of current VPN state.
- Default subscriptions and default routing rules must not be reintroduced.
- Empty app assignment rules with `ignoreRules = false` should route all apps through VPN.
- Automatic DNS and custom DoH/DoT behavior, validation, and legacy raw-DNS migration should stay aligned across Android and desktop.
- SSH Routing settings, fail-closed behavior, and VPN-aware subscription downloads should stay aligned. The SSH relay installer supports Linux `amd64` and `arm64`; the client feature uses the bundled runtime on every packaged platform.

## Platform-Specific Behavior

Android:

- Uses Android VPN APIs, not desktop TUN process privileges.
- App assignment rules are meaningful because Android can route by package.
- Diagnostics are exported from inside the app.

Linux desktop:

- VPN mode depends on a usable TUN device and installed runtime capabilities.
- Tray behavior depends on the desktop environment or window manager exposing a tray/status-notifier host. VPN Control auto-detects native AppIndicator/StatusNotifier/GtkStatusIcon support on Linux and falls back to AWT/XEmbed where possible, but environments with no tray host may not show an icon. The desktop window must remain accessible until a tray icon is confirmed available. i3/polybar-style XEmbed sessions use the AWT tray first because native GTK tray menus can be invisible there; set `VPN_CONTROL_LINUX_TRAY_BACKEND=native` or `awt` to force a backend while debugging.
- Local install behavior is covered by `scripts/arch_install.sh` and package scripts.

Windows desktop:

- VPN mode depends on Administrator privileges.
- Windows packaging and installed-app smoke tests can run inside the local VM through QEMU guest agent.
- Keep proxy-only usable without elevation.

macOS desktop:

- DMG packaging and proxy-only mode are the current supported desktop path.
- Do not imply full VPN mode is available until a privileged helper exists.
