# Desktop Lifecycle Development

Authoritative lifecycle behavior is `DESKTOP-001` through `DESKTOP-008` in `contracts.md`. This document maps those contracts to owners and coverage.

| Contract | Primary Owner Areas | Main Coverage |
| --- | --- | --- |
| `DESKTOP-001` | `DesktopSingleInstanceLock`, activation server/events | `DesktopSingleInstanceLockTest`, `DesktopActivationEventsTest` |
| `DESKTOP-002` | `Main.kt`, `DesktopTrayController`, tray availability state | `DesktopTrayWindowStateTest`, `DesktopSmokeTestTest`, visual tray scenes |
| `DESKTOP-003` | `DesktopAutostartManager`, startup arguments, tray state | `DesktopAutostartManagerTest`, `DesktopTrayWindowStateTest`, reboot smoke |
| `DESKTOP-004` | workspace mapper/store, app service startup | `DesktopAppServiceTest`, workspace mapper tests, reboot smoke |
| `DESKTOP-005` | auto-refresh scheduler and subscription refresh service | `DesktopAutoRefreshSchedulerTest`, `DesktopAppServiceTest` |
| `DESKTOP-006` | direct-probe routing/runtime, Find Best service | `DesktopDirectProbeRoutingTest`, `DesktopFindBestServiceTest`, shared benchmark tests |
| `DESKTOP-007` | Windows elevation and connection actions | `DesktopWindowsElevationTest`, Windows VM smoke and visual scenes |
| `DESKTOP-008` | headless controller and CLI | `DesktopHeadlessControllerTest`, CLI tests |

## Patch Procedure

- For window/tray changes, exercise close, show, first tray availability, autostart, both Linux tray backends, and the corresponding visual scenes.
- For startup/shutdown or workspace changes, exercise reconnect intent and off-state persistence without touching a live runtime on the development host.
- For autostart changes, cover Linux XDG entries, the managed i3 block, legacy systemd cleanup, Windows startup command generation, and real reboot smoke when available.
- For validation/probe changes, keep the direct-route contract tests adjacent to the implementation.
- For refresh/runtime changes, add the fastest deterministic regression that proves the runtime cannot be stranded.
- Run `./gradlew :desktopApp:test`; use `desktop-smoke-testing.md` for target-window-manager, UAC, reboot, and install paths.
