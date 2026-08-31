# State Ownership

This document defines where state mutations should live. Use it before adding new UI actions or runtime behavior.

## Shared Core Owns Pure Cross-Platform State

Shared core owns state transitions that do not directly touch Android, desktop, files, processes, or OS permissions:

- `shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/MainController.kt`
- `shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/MainUiState.kt`
- `shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/MainCommandLogic.kt`
- `shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/data/BenchmarkSearchLogic.kt`
- `shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/data/SelectionWorkflowService.kt`
- `shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/data/RepositoryWorkflowService.kt`
- `shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/SubscriptionSourceLogic.kt`
- `shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/SelectionMappingLogic.kt`

Add or update shared tests when touching these files:

```text
shared/core/src/commonTest/kotlin/com/kardinal/vpncontrol/MainControllerTest.kt
shared/core/src/commonTest/kotlin/com/kardinal/vpncontrol/MainUiStateProjectorTest.kt
shared/core/src/commonTest/kotlin/com/kardinal/vpncontrol/data/
```

## Android Owns Android IO And VPN Side Effects

Android owns platform operations that need Android APIs, permissions, WorkManager, app catalogs, or the Android VPN service:

- `app/src/main/java/com/kardinal/vpncontrol/MainViewModel.kt`
- `app/src/main/java/com/kardinal/vpncontrol/AndroidProfileActionsService.kt`
- `app/src/main/java/com/kardinal/vpncontrol/AndroidConnectionActionsService.kt`
- `app/src/main/java/com/kardinal/vpncontrol/AndroidConnectionLifecycleService.kt`
- `app/src/main/java/com/kardinal/vpncontrol/AndroidFindBestActionsService.kt`
- `app/src/main/java/com/kardinal/vpncontrol/AndroidLocationActionsService.kt`
- `app/src/main/java/com/kardinal/vpncontrol/AndroidRoutingActionsService.kt`
- `app/src/main/java/com/kardinal/vpncontrol/AndroidSubscriptionRefreshActionsService.kt`
- `app/src/main/java/com/kardinal/vpncontrol/AndroidSettingsActionsService.kt`
- `app/src/main/java/com/kardinal/vpncontrol/AndroidDiagnosticsActionsService.kt`
- `app/src/main/java/com/kardinal/vpncontrol/AndroidInstalledAppsActionsService.kt`
- `app/src/main/java/com/kardinal/vpncontrol/AndroidUpdateActionsService.kt`
- `app/src/main/java/com/kardinal/vpncontrol/AndroidControllerEffectHandler.kt`
- `app/src/main/java/com/kardinal/vpncontrol/data/ProfileStorage.kt`
- `app/src/main/java/com/kardinal/vpncontrol/data/InstalledAppsCatalog.kt`
- `app/src/main/java/com/kardinal/vpncontrol/data/SubscriptionRefreshWorker.kt`
- `app/src/main/java/com/kardinal/vpncontrol/vpn/AndroidVpnService.kt`

Android should call shared controller/logic for pure state decisions and then execute the returned platform side effects. Keep profile/import action orchestration in `AndroidProfileActionsService`, connection UI commands in `AndroidConnectionActionsService`, start/stop selection lifecycle in `AndroidConnectionLifecycleService`, Find Best command orchestration in `AndroidFindBestActionsService`, location mutation/selection orchestration in `AndroidLocationActionsService`, routing draft/import/save orchestration in `AndroidRoutingActionsService`, manual subscription refresh orchestration in `AndroidSubscriptionRefreshActionsService`, settings persistence in `AndroidSettingsActionsService`, diagnostics export orchestration in `AndroidDiagnosticsActionsService`, installed-app catalog/effect orchestration in `AndroidInstalledAppsActionsService`, GitHub update/APK installer orchestration in `AndroidUpdateActionsService`, and persistence effect execution in `AndroidControllerEffectHandler` instead of growing `MainViewModel`.

## Desktop Owns Desktop IO And Runtime Side Effects

Desktop owns file persistence, tray/single-instance lifecycle, autostart, process management, and Linux/Windows VPN runtime setup:

- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopAppService.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopAppServiceFactory.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopStateStore.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopWorkspaceStateMapper.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopConnectionActionsService.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopConnectionLifecycleService.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopConnectionNameLogic.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopDiagnosticsExportLogic.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopDiagnosticsService.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopFindBestService.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopLocationBenchmarkService.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopLocationService.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopProxyRuntimeManager.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopProxyValidationRuntime.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopRoutingRulesService.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopRuntimeStatusService.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopSettingsService.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopUpdateService.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopSubscriptionSourceValidation.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopSubscriptionManagementService.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopSubscriptionRefreshService.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopSubscriptionService.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopTrayController.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopAutostartManager.kt`

Desktop currently bypasses some `MainController` actions while its service owns persistence/runtime orchestration. Keep responsibilities grouped this way instead of growing `DesktopAppService`:

- Construction and workspace: dependency assembly in `DesktopAppServiceFactory`, workspace restore/sync/persist mapping in `DesktopWorkspaceStateMapper`, persistence in `DesktopStateStore`.
- Connection/runtime: connection command glue in `DesktopConnectionActionsService`, start/stop lifecycle in `DesktopConnectionLifecycleService`, runtime process control in `DesktopProxyRuntimeManager`, validation probes in `DesktopProxyValidationRuntime`, status-detail assembly in `DesktopRuntimeStatusService`, and active-name decisions in `DesktopConnectionNameLogic`.
- Subscriptions/locations: subscription source labels and parsing in `DesktopSubscriptionService`, source validation in `DesktopSubscriptionSourceValidation`, add/delete/rename/activation in `DesktopSubscriptionManagementService`, refresh orchestration in `DesktopSubscriptionRefreshService`, location selection/mutation in `DesktopLocationService`, per-location benchmarks in `DesktopLocationBenchmarkService`, and broad Find Best selection in `DesktopFindBestService`.
- Settings/rules/diagnostics/lifecycle: settings and autostart orchestration in `DesktopSettingsService`, routing save/import behavior in `DesktopRoutingRulesService`, diagnostics collection/export in `DesktopDiagnosticsService` and `DesktopDiagnosticsExportLogic`, tray behavior in `DesktopTrayController`, and OS autostart entry management in `DesktopAutostartManager`.
- Updates: manifest/download verification and platform installer authorization in `DesktopUpdateService`; package replacement stays in the external helper so it can wait for a clean app exit.

New cross-platform behavior should still be implemented in shared core first when it can be expressed without desktop IO.

## Home SSH Route Ownership

- Shared model/core owns the persisted non-secret settings, validation, subscription route truth table, sing-box SSH/home-egress builders, and fail-closed custom-config transformation.
- Android owns private-key storage in the app sandbox, temporary bootstrap runtime processes for inactive-session subscription downloads, and management-proxy persistence for the running VPN service.
- Desktop owns private-key file permissions/ACLs, temporary bootstrap processes, management-proxy lifecycle, and the dedicated direct-probe executable.
- The private key is never serialized into `PersistedState`, DataStore, `workspace.json`, generated documentation, or exported diagnostics.
- Saving runtime-affecting settings never stops a live connection automatically. Platform settings services set the pending state, and the explicit restart action owns reconnection.

## Patch Rules

- Put pure validation, draft mutation, selection decisions, and status-message keys in shared core.
- Put Android permission checks, VPN service calls, WorkManager scheduling, and installed-app loading in Android.
- Put desktop process control, filesystem paths, tray behavior, autostart, and privilege checks in desktop.
- If the same decision is needed on Android and desktop, extract it to shared core before patching both platforms.
- If a platform must diverge, document the divergence in `docs/platform-matrix.md` or `docs/desktop-lifecycle.md`.
