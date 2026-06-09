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
- After changes are done and validated, push completed commits to `origin main`, then complete the post-push CI verification loop before reporting success.
- If large work intentionally spans multiple dirty buckets, document the intent in `docs/work-in-progress.md`.
- Start low-context repository navigation from `docs/README.md`.
- Use `docs/state-ownership.md` before adding cross-platform actions or moving platform side effects.
- Use `docs/native-runtime-artifacts.md` before touching native runtime binaries or runtime preparation scripts.

## Post-Push CI Verification

After every push to `origin main`:

1. Capture the exact pushed commit with `git rev-parse HEAD`.
2. Query GitHub Actions runs for that exact `headSha`; do not rely on branch-latest status alone.
3. Wait until these expected workflows for that SHA complete:
   - Fast Checks
   - Android Release APK
   - Linux Desktop Package
   - Windows Desktop Package
   - macOS Desktop Package
4. If any expected workflow fails, inspect the failure logs, fix the cause, rerun the relevant local checks, commit the fix, push again, and repeat this verification loop for the new `headSha`.
5. Do not report the push as complete while any expected workflow for the pushed SHA is pending, missing, or failed.

## First-Read Docs

Use `docs/README.md` as the task router. It maps common tasks to the two or three focused docs, owner files, and minimum checks.

Focused docs are the subsystem detail layer:

- Low-context workflow and dirty worktree policy: `docs/development.md`.
- Path-based validation and validation tiers: `docs/test-matrix.md`.
- State/action ownership: `docs/state-ownership.md`.
- Runtime safety: `docs/runtime-troubleshooting.md`.
- Desktop lifecycle invariants: `docs/desktop-lifecycle.md`.
- Protocol and `sing-box` config contract: `docs/sing-box-contract.md`.
- Localization architecture and status catalogs: `docs/localization.md`.
- Release packaging and artifact policy: `docs/developer-release-checklist.md`, `docs/native-runtime-artifacts.md`.

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

Canonical platform capabilities, privilege requirements, packaging outputs, and known limitations live in `docs/platform-matrix.md`.

Use platform-specific smoke docs for manual checks:

- Android: `docs/smoke-android.md`.
- Linux/Windows desktop: `docs/desktop-smoke-testing.md`.
- macOS release packaging: `docs/macos-release.md`.

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

Detailed runtime safety and troubleshooting:

- `docs/runtime-troubleshooting.md`
- `docs/desktop-runtime-troubleshooting.md`

Use the redacted runtime snippets in `docs/runtime-troubleshooting.md` before sharing logs or config details.

## Testing Expectations

Use `docs/test-matrix.md` for path-based test selection and validation tiers. If checks cannot be run, state exactly which checks were skipped and why.

Documentation-only changes should run `git diff --check` and `./scripts/check_docs_hygiene.sh`.

## Localization Rules

- Keep user-facing translations in JSON catalogs, not Kotlin source.
- Do not add translated `when (AppLanguage...)` branches in Kotlin.
- Preserve placeholders and technical terms exactly.
- For broad translation changes, use one language owner per catalog file.
- Run the localization checks named in `docs/test-matrix.md`.

Detailed catalog structure, typed status rules, dynamic/legacy status handling, and test-update guidance live in `docs/localization.md`.

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

See `docs/architecture.md`, `docs/state-ownership.md`, `docs/desktop-lifecycle.md`, `docs/platform-matrix.md`, and `docs/sing-box-contract.md` before changing cross-platform runtime behavior.

## User-Facing Install Docs

README is intentionally short and user-facing. It should point users to GitHub `Actions` artifacts, not ignored local `dist/` paths.

Use local generated paths such as `dist/windows/` or `dist/windows-vm/` only when documenting developer packaging workflows, not simple user installation.

Developer release packaging details belong in `docs/developer-release-checklist.md`.
