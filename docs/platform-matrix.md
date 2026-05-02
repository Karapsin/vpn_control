# Platform Matrix

This matrix summarizes platform behavior so patches do not accidentally apply Android, Linux, Windows, or macOS assumptions globally.

| Platform | UI Target | VPN Mode | Proxy-Only Mode | Privileges | Package Output | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Android | Native Android app with shared Compose UI | Supported through Android VPN APIs | Supported where app/runtime flow exposes it | User grants VPN permission | `app-release.apk` | Release APK is currently debug-signed and intended as direct-install artifact. |
| Linux desktop | Compose Desktop | Supported through bundled `sing-box` TUN config | Supported | `/dev/net/tun` and `CAP_NET_ADMIN` on installed `sing-box` | `.deb`, `.rpm`, Arch local install script | `scripts/arch_install.sh` handles local Arch setup. |
| Windows desktop | Compose Desktop | Supported through bundled `sing-box` and Wintun path | Supported | Administrator required for VPN mode | `.exe`, `.msi` | Autostart/elevation behavior must be checked carefully. |
| macOS desktop | Compose Desktop | Not fully implemented | Supported | Full VPN mode still needs a privileged helper | `.dmg` | Package exists; use proxy-only for smoke testing. |

## Shared Behavior That Should Stay Aligned

- Subscription parsing and profile selection should stay in shared logic when possible.
- `All` subscription/group behavior should be consistent across Android and desktop.
- `Find Best` should evaluate candidates independently of current VPN state.
- Default subscriptions and default routing rules must not be reintroduced.
- Empty app assignment rules with `ignoreRules = false` should route all apps through VPN.

## Platform-Specific Behavior

Android:

- Uses Android VPN APIs, not desktop TUN process privileges.
- App assignment rules are meaningful because Android can route by package.
- Diagnostics are exported from inside the app.

Linux desktop:

- VPN mode depends on a usable TUN device and installed runtime capabilities.
- Tray behavior depends on the desktop environment or window manager.
- Local install behavior is covered by `scripts/arch_install.sh` and package scripts.

Windows desktop:

- VPN mode depends on Administrator privileges.
- Windows packaging and installed-app smoke tests can run inside the local VM through QEMU guest agent.
- Keep proxy-only usable without elevation.

macOS desktop:

- DMG packaging and proxy-only mode are the current supported desktop path.
- Do not imply full VPN mode is available until a privileged helper exists.
