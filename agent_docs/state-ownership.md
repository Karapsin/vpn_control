# State Ownership

Authoritative ownership boundaries are `STATE-001` through `STATE-005` in `contracts.md`. This document maps those boundaries to current owner files and patch procedures.

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

`AndroidApplicationOwner`, lazily held by `VpnControlApplication`, constructs the
shared repository/storage/runtime-service graph and update service/state.
`AndroidCommandJobs` owns accepted job lifetimes and tracked-operation admission.
MainViewModel factories and refresh workers reuse this owner instead of building
independent graphs. ViewModels retain local controllers/drafts and observe owner
busy/update state. Full frontend-independent action state and typed ControlSession
admission are still being migrated; do not mistake this lifetime extraction for
complete Android CLI ownership.

Android configuration observation is owned by `data/AndroidConfigurationStore.kt`.
A permanent DataStore `data` collector can retain its initial Preferences snapshot
in the suspended collector even after newer values are published. For large routing
documents, that extra retained String can prevent the next edit on a 48 MiB heap.
The configuration flow uses one-shot subscriptions for distinct snapshots, releasing
the upstream collector before publishing each value. Keep observation of writes from
other storage facades and replay across subscription gaps; a private cache alone
cannot replace that observation. `AndroidConfigurationStoreTest` checks collector
release, equal snapshots, subscription-gap writes and source failures in routine
Android unit tests. Per `TEST-001`, retain the native consecutive add/remove and
independent cold-read scenario: a successful first import does not cover this lifetime.

## Android Generated Routing Assets

`AndroidRuntimeConfigBuilder` streams generated direct domains through
`AndroidDirectDomainRuleSetStore` into private content-addressed sing-box source
rule sets. The main runtime JSON references the local asset; user routing storage,
transfer version and CUSTOM rule-set meaning remain unchanged. This avoids retaining
another full domain JSON string in the 48 MiB ART heap. It does not promise constant
memory parsing or unlimited native runtime resources.

Publication uses the application JNI helper's atomic no-replace rename, because
API29 app policy denied hard-link creation. Existing or raced targets are never
overwritten; unsupported native operations remain failures with no copy fallback.
Same-file aliases return an existing-target result, and malformed path characters
are rejected before filesystem mutation. A successful publication consumes only
the temporary source. Full digest and private-mode checks still precede leasing.

The builder holds a lease until `AndroidPreparedConnections` captures one. Dispatch
holds an independent lease; expiry, rejection and cancellation release only their
own references. `AndroidVpnService` reacquires and hashes the exact generated asset
before validation or stopping an existing runtime, including cold service starts.
After native startup the observer owns the active lease. Recovery points retain
another reference so actual A survives candidate B and rollback; every caller must
close its recovery point. Failed native cleanup retains resources under UNKNOWN.

Pruning runs only with an unchanged authoritative STOPPED observation. It protects
leased assets and references in both committed and current runtime JSON. Inspection
failure skips deletion. A preparation may retain its asset until the existing
five-minute expiry/capacity pruning; while running or uncertain, unleased disk assets
may remain until a later safe cleanup. Do not claim the reference cap bounds total
on-disk cache size.

Routine tests cover real 48 MiB persisted routing plus full generated-asset digest,
immutable snapshot capture versus mutable inputs, file publication/identity,
CUSTOM tag collisions, empty normalized rules, preparation handoff, and A/B/recovery
lease lifetimes. `AndroidFindBestControl` reports failed planning/probes/verification and exhausted
searches through an owner callback. `AndroidFailureTrace` records bounded class/frame
and cause identity only, never exception messages, suppressed text or configuration.
Diagnostic failures must not replace the authoritative operation/recovery result.
These traces are in the private diagnostics log included by `diagnostics export`;
`logs` reads the connection/status journal and does not contain that log. Reports
include `direct_domain_suffixes_count`, never the complete domain list. Full routing
content belongs to explicit routing inspection/export, not diagnostic summaries.
Native acceptance still requires the nondebuggable APK to validate
and run those source rule sets through its bundled libbox. Host JVM success alone
cannot prove Android filesystem or native routing behavior.

External service START admission promotes a neutral foreground notification
synchronously before dispatching configuration reads, validation, or runtime work.
That notification must not read storage or wait for the command mutex. STOP and
retained foreground-service commands retain their existing dispatch paths. A
promotion failure completes the exact command with failure and may stop only a
fresh service whose runtime observation is authoritatively STOPPED. This ordering
is covered by `AndroidVpnServiceForegroundDeadlineTest`; the Android OS deadline
and packaged large-routing startup still require emulator verification.

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

## SSH Routing Ownership

Apply `STATE-001` through `STATE-005`, `PRODUCT-006`, and `CONFIG-003` through `CONFIG-005`. Current implementation owners are shared SSH settings/config builders, Android sandbox credential/bootstrap services, and desktop credential/bootstrap/management-proxy/direct-probe services.

## Patch Rules

- Put pure validation, draft mutation, selection decisions, and status-message keys in shared core.
- Put Android permission checks, VPN service calls, WorkManager scheduling, and installed-app loading in Android.
- Put desktop process control, filesystem paths, tray behavior, autostart, and privilege checks in desktop.
- If the same decision is needed on Android and desktop, extract it to shared core before patching both platforms.
- If a platform must diverge, document the divergence in `agent_docs/platform-matrix.md` or `agent_docs/desktop-lifecycle.md`.
