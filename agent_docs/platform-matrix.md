# Platform Owner Matrix

Authoritative capabilities and limitations are `PLATFORM-001` through `PLATFORM-007` in `contracts.md`. This file routes platform work to implementation owners and validation procedures without redefining those contracts.

| Platform | Contract IDs | Primary Owners | Package/Smoke Procedure |
| --- | --- | --- | --- |
| Android | `PLATFORM-001`, `PLATFORM-005`, `PLATFORM-007` | `app/`, shared UI/core | `smoke-android.md`; `./gradlew :app:assembleRelease` |
| Linux desktop | `PLATFORM-002`, `PLATFORM-006`, `PLATFORM-007` | desktop runtime/tray, Linux package scripts | `desktop-smoke-testing.md`; `./scripts/package_linux_desktop.sh` |
| Windows desktop | `PLATFORM-003`, `PLATFORM-007` | desktop runtime/elevation, Windows package scripts | `desktop-smoke-testing.md`; `./scripts/package_windows_desktop_vm.sh` |
| macOS desktop | `PLATFORM-004`, `PLATFORM-007` | desktop proxy runtime, macOS package script | `macos-release.md`; `./scripts/package_macos_desktop.sh` |

## Change Routing

- Cross-platform selection, refresh, DNS, SSH Routing, or update decisions start in shared core and use `state-ownership.md`.
- Android VPN permission, app-package routing, or diagnostics changes stay in `app/` and use Android unit/instrumented coverage.
- Linux TUN/capability, tray backend, or installed-layout changes use desktop tests plus package and target-desktop smoke.
- Windows elevation, Wintun, UAC, autostart, or installer changes use desktop tests plus the Windows VM package/smoke path.
- macOS package, signing, notarization, Gatekeeper, or proxy-only changes use the Mac package path and `macos-release.md`.
- A capability change updates the applicable contract ID in `contracts.md`, its focused procedure, tests, and visual scenes together.
