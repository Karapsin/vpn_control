# AGENTS.md

Guidance for coding agents working in this repository.

## Project Overview

VPN Control is a Kotlin project with:

- Android app in `app/`.
- Compose Desktop app in `desktopApp/`.
- Shared model, storage, core logic, and UI in `shared/`.
- Packaging and helper scripts in `scripts/`.
- Release workflows in `.github/workflows/`.

The app is built around `sing-box`. Android uses Android VPN APIs and bundled native runtime. Desktop uses bundled `sing-box` and supports VPN mode on Linux and Windows.

## Repository Map

| Path | Purpose |
| --- | --- |
| `app/` | Android application and Android VPN service. |
| `desktopApp/` | Compose Desktop app for Linux, Windows, macOS. |
| `shared/model/` | Shared data models. |
| `shared/core/` | Shared parsing, selection, refresh, and config logic. |
| `shared/storage-api/` | Shared storage interfaces. |
| `shared/ui/` | Shared Compose UI. |
| `scripts/` | Packaging, runtime preparation, VM, and smoke-test scripts. |
| `.github/workflows/` | Android, Linux, Windows, and macOS package workflows. |

## Important Rules

- Do not commit generated artifacts from `build/`, `dist/`, `.runtime/`, or downloaded `sing-box` binaries.
- Do not kill a currently running VPN/runtime unless the user explicitly approves it. Stopping VPN can interrupt the active connection to the coding session.
- If runtime testing needs VPN interruption, first identify the current selected/running location and explain the risk.
- Do not restore old default subscriptions, default rules, or demo data.
- Preserve unrelated local changes. The worktree may be dirty.
- Prefer small, targeted fixes with regression tests for behavior changes.

## Common Commands

Android release APK:

```bash
./gradlew :app:assembleRelease
```

Android debug APK:

```bash
./gradlew :app:assembleDebug
```

Desktop tests:

```bash
./gradlew :desktopApp:test
```

Shared model Android compile check:

```bash
./gradlew :shared:model:compileDebugKotlinAndroid
```

Shared core desktop test:

```bash
./gradlew :shared:core:desktopTest
```

Linux desktop package:

```bash
./scripts/package_linux_desktop.sh
```

Arch local install:

```bash
./scripts/arch_install.sh
```

Windows package from Windows:

```powershell
.\scripts\package_windows_desktop.ps1
```

Windows package from Linux VM:

```bash
./scripts/package_windows_desktop_vm.sh
```

macOS package:

```bash
./scripts/package_macos_desktop.sh
```

## Platform Notes

Windows:

- VPN mode needs Administrator privileges.
- Proxy-only mode can run without Administrator privileges.
- Windows installers are produced as `.exe` and `.msi`.
- Windows VM packaging uses `vpn-control-win11` and QEMU guest agent.

Android:

- Release APK is ARM64-focused.
- Debug APK can be used for emulator/test installs.
- Android VPN behavior should stay aligned with shared core selection and refresh logic.

Linux:

- VPN mode needs `/dev/net/tun`.
- VPN mode needs `CAP_NET_ADMIN` for the `sing-box` binary.
- `scripts/arch_install.sh` handles local Arch install, TUN loading, desktop entry, icon, and capabilities.

macOS:

- DMG packaging exists.
- Full desktop VPN mode is not implemented yet because a privileged helper is still needed.

## Runtime And Logs

Desktop state and logs:

```text
~/.vpn-control-desktop/
~/.vpn-control-desktop/workspace.json
~/.vpn-control-desktop/runtime/runtime-sing-box.log
~/.vpn-control-desktop/runtime/runtime-sing-box-vpn.json
~/.vpn-control-desktop/runtime/runtime-sing-box-proxy_only.json
```

Android diagnostics are exported from inside the app.

## Testing Expectations

- UI-only Android changes: run at least Android compile or APK build when practical.
- Shared parsing/selection/refresh changes: run relevant shared tests plus one platform compile.
- Desktop runtime changes: run `:desktopApp:test`.
- Linux packaging changes: run `scripts/package_linux_desktop.sh` when practical.
- Windows packaging/runtime changes: run `scripts/package_windows_desktop_vm.sh` when practical.
- If tests cannot be run, state exactly which tests were skipped and why.

## Localization Rules

- Keep user-facing translations in JSON catalogs, not in Kotlin source.
- UI labels live in `shared/ui/src/commonMain/resources/i18n/<lang>.json`.
- Status/log/freeform message translations live in `shared/ui/src/commonMain/resources/i18n-status/<lang>.json`.
- `AppStrings.kt` should only choose keys, parse known message shapes, substitute placeholders, and generate English source messages for status catalogs.
- Do not add `when (AppLanguage...)` branches with translated UI/status text in Kotlin. Add a JSON key, dynamic status template, exact status entry, or replacement entry instead.
- For dynamic status strings, add placeholder templates under the `dynamic` section and keep placeholder names identical across all status catalogs.
- For freeform or legacy runtime messages, prefer `legacyExact` for complete messages and `legacyReplacements` for stable prefixes/fragments.
- Preserve technical commands, file paths, URLs, capability names, and protocol identifiers when translating. Example: keep `/dev/net/tun`, `sudo modprobe tun`, `CAP_NET_ADMIN`, `netsh.exe`, and `sing-box` recognizable.
- Add every new language to `shared/model/src/commonMain/resources/languages.json`, then add matching files in both `i18n/` and `i18n-status/`.
- Language choices in the UI should remain sorted alphabetically by visible display name, with `System` pinned first.
- Run `./scripts/check_localization.py --language <code>` for changed languages and `./gradlew :shared:ui:desktopTest` after localization changes.
- Add or update regression tests in `shared/ui/src/commonTest/kotlin/com/kardinal/vpncontrol/shared/ui/AppStringsCoverageTest.kt` when fixing untranslated screenshots or new status patterns.

## Behavior Requirements To Preserve

- No default subscriptions should be added automatically.
- No default routing rules should be added automatically.
- Desktop default mode should remain VPN mode unless intentionally changed.
- Desktop app should be single-instance aware.
- Closing the desktop window should hide to tray instead of killing the app.
- When app autostarts after boot, it should start in tray.
- If VPN was on before shutdown/reboot, desktop should reconnect using the remembered location.
- If VPN was off before shutdown/reboot, desktop should start without connecting.
- Scheduled subscription refresh should not leave VPN stopped. A short controlled restart is acceptable only when required by config changes.
- Desktop best-location checks should use direct probes so results are not biased by whether VPN is currently on.
- Android best-location and refresh behavior should remain consistent with shared core logic.

## User-Facing Install Docs

README is intentionally short and user-facing. It should point users to GitHub `Actions` artifacts, not ignored local `dist/` paths.

Use local generated paths such as `dist/windows/` or `dist/windows-vm/` only when documenting developer packaging workflows, not simple user installation.
