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
- `app/src/main/java/com/kardinal/vpncontrol/AndroidLocationActionsService.kt`
- `app/src/main/java/com/kardinal/vpncontrol/AndroidRoutingActionsService.kt`
- `app/src/main/java/com/kardinal/vpncontrol/AndroidControllerEffectHandler.kt`
- `app/src/main/java/com/kardinal/vpncontrol/data/ProfileStorage.kt`
- `app/src/main/java/com/kardinal/vpncontrol/data/InstalledAppsCatalog.kt`
- `app/src/main/java/com/kardinal/vpncontrol/data/SubscriptionRefreshWorker.kt`
- `app/src/main/java/com/kardinal/vpncontrol/vpn/AndroidVpnService.kt`

Android should call shared controller/logic for pure state decisions and then execute the returned platform side effects. Keep profile/import action orchestration in `AndroidProfileActionsService`, location mutation/selection orchestration in `AndroidLocationActionsService`, routing draft/import/save orchestration in `AndroidRoutingActionsService`, and persistence effect execution in `AndroidControllerEffectHandler` instead of growing `MainViewModel`.

## Desktop Owns Desktop IO And Runtime Side Effects

Desktop owns file persistence, tray/single-instance lifecycle, autostart, process management, and Linux/Windows VPN runtime setup:

- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopAppService.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopStateStore.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopProxyRuntimeManager.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopProxyValidationRuntime.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopSubscriptionManagementService.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopFindBestService.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopTrayController.kt`
- `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopAutostartManager.kt`

Desktop currently bypasses some `MainController` actions while its service owns persistence/runtime orchestration. New cross-platform behavior should still be implemented in shared core first when it can be expressed without desktop IO.

## Patch Rules

- Put pure validation, draft mutation, selection decisions, and status-message keys in shared core.
- Put Android permission checks, VPN service calls, WorkManager scheduling, and installed-app loading in Android.
- Put desktop process control, filesystem paths, tray behavior, autostart, and privilege checks in desktop.
- If the same decision is needed on Android and desktop, extract it to shared core before patching both platforms.
- If a platform must diverge, document the divergence in `docs/platform-matrix.md` or `docs/desktop-lifecycle.md`.
