# Desktop Lifecycle Invariants

Desktop lifecycle behavior is easy to break because it crosses UI, tray, persistence, runtime, and platform startup code. Preserve these invariants when patching `desktopApp/`.

## Required Behavior

| Invariant | Expected Behavior | Main Coverage |
| --- | --- | --- |
| Single instance | Launching VPN Control again should activate/show the existing instance, not create a second independent app instance. | `DesktopSingleInstanceLockTest`, `DesktopActivationEventsTest` |
| Close hides to tray | Closing the window should hide it to tray instead of terminating the app only after the tray is confirmed available. | `DesktopTrayWindowStateTest`, `DesktopSmokeTestTest`, manual tray smoke |
| Autostart starts in tray | Boot/autostart launches with `--autostart` and starts hidden only after the tray is confirmed available; otherwise the window stays visible. | `DesktopAutostartManagerTest`, `DesktopTrayWindowStateTest`, `DesktopSmokeTestTest` |
| Reconnect after reboot | If VPN/proxy was on before shutdown, app startup should reconnect using the remembered selection. | `DesktopAppServiceTest`, manual reboot smoke |
| Off stays off | If VPN/proxy was off before shutdown, app startup should not connect automatically. | `DesktopAppServiceTest` |
| Scheduled refresh keeps runtime usable | Auto-refresh must not leave VPN/proxy stopped. A short controlled restart is acceptable only when config changes require it. | `DesktopAutoRefreshSchedulerTest`, `DesktopAppServiceTest` |
| Find Best is direct | Desktop best-location probes should be direct so current VPN state does not bias results. | `DesktopDirectProbeRoutingTest`, `BenchmarkSearchLogicTest` |
| Windows elevation is scoped | VPN mode can require Administrator, but proxy-only should remain usable without elevation. | `DesktopWindowsElevationTest`, manual Windows smoke |

## Patch Guidance

- If `Main.kt` window/tray flow changes, re-check close, show, and autostart paths.
- If `DesktopAppService.kt` startup/shutdown flow changes, re-check reconnect intent and off-stays-off behavior.
- If `DesktopAutostartManager.kt` changes, test Linux XDG desktop entries, the managed i3 fallback block, legacy systemd cleanup, and Windows startup command generation.
- If validation/probe code changes, confirm direct probe routing still bypasses the active VPN/proxy.
- If runtime manager code changes, inspect whether scheduled refresh can strand the app in stopped or stale-config state.

On Linux, the canonical user autostart entry is the XDG `vpn-control.desktop` file. Bare i3 sessions do not run XDG autostart entries by default, so VPN Control also maintains a marked app-specific block in the user's i3 config when start-on-boot is enabled from an i3 session. The i3 block must use i3-compatible shell-wrapper syntax; do not reuse the XDG `Exec=` quoted-path form there.

## Manual Smoke Points

Automated tests do not fully cover desktop environment behavior. Run `docs/desktop-smoke-testing.md` when changing:

- tray menu behavior
- actual window-manager integration
- Windows UAC/elevation
- reboot/autostart
- package installation paths
