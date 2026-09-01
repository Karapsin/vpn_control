# Architecture Overview

This document gives a low-context map of the main data flow and owner files.

## Main Flow

```text
subscription/import input
  -> parser/resolver
  -> stored profiles and subscriptions
  -> shared UI state
  -> selection / Find Best / refresh logic
  -> sing-box config factory
  -> Android VPN service or desktop runtime manager
  -> diagnostics and connection log
```

## Owner Files By Stage

| Stage | Android | Desktop | Shared |
| --- | --- | --- | --- |
| Manual import/export UI | `app/src/main/java/com/kardinal/vpncontrol/ui/VpnControlApp.kt` | shared UI plus `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopTextTransfer.kt` | `shared/ui/` |
| Subscription fetch/resolve | `app/src/main/java/com/kardinal/vpncontrol/data/RemoteSourceResolver.kt` | `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopSubscriptionDownloadClient.kt` | `shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/data/` |
| Profile parsing | Android uses the shared parser from app workflows | Desktop uses the shared parser from service workflows | `ProxyParser.kt` facade, `SubscriptionPayloadParser.kt`, `ProxyLinkParser.kt`, `ProxyLinkEncoder.kt`, `JsonSubscriptionParser.kt`, `ClashSubscriptionParser.kt`, `ProxyParserEngine.kt` facade implementation, `VlessParser.kt` compatibility shim |
| Persisted state | `app/src/main/java/com/kardinal/vpncontrol/data/ProfileStorage.kt` | `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopStateStore.kt`, `DesktopWorkspaceStateMapper.kt` | `shared/storage-api/`, `shared/model/` |
| Main state/actions | `app/src/main/java/com/kardinal/vpncontrol/MainViewModel.kt`, focused `Android*ActionsService` classes including `AndroidInstalledAppsActionsService.kt`, `AndroidControllerEffectHandler.kt` plus shared controller | `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopAppServiceFactory.kt`, `DesktopAppService.kt`, and focused desktop services such as `DesktopLocationService.kt`, `DesktopRoutingRulesService.kt`, `DesktopRuntimeStatusService.kt`, and `DesktopSettingsService.kt` | `shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/MainController.kt`, `MainUiState.kt`, `MainUiStateProjector` |
| Find Best / benchmark selection | `AndroidFindBestActionsService.kt`, `app/src/main/java/com/kardinal/vpncontrol/data/BenchmarkOrchestrator.kt` | `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopFindBestService.kt`, `DesktopLocationBenchmarkService.kt`, `DesktopProxyValidationRuntime.kt` | `shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/data/BenchmarkSearchLogic.kt`, `SelectionMappingLogic.kt` |
| Subscription management and refresh results | `AndroidProfileActionsService.kt`, `AndroidSubscriptionRefreshActionsService.kt`, `app/src/main/java/com/kardinal/vpncontrol/data/SubscriptionRefreshWorker.kt` | `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopSubscriptionManagementService.kt`, `DesktopSubscriptionRefreshService.kt`, `DesktopSubscriptionService.kt` | `SubscriptionSourceLogic`, `AutoRefreshLogic`, `SubscriptionRefreshResultLogic`, `SelectionMappingLogic` |
| Config generation | `app/src/main/java/com/kardinal/vpncontrol/data/SingBoxConfigFactory.kt` | `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopProxyConfigFactory.kt` | shared outbound builder in `shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/data/SingBoxOutboundBuilder.kt`, shared route/DNS builder in `shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/data/SingBoxRouteDnsBuilder.kt`, model/rules in `shared/model/` |
| Runtime lifecycle | `AndroidConnectionActionsService.kt`, `AndroidConnectionLifecycleService.kt`, `app/src/main/java/com/kardinal/vpncontrol/vpn/AndroidVpnService.kt` | `DesktopConnectionActionsService.kt`, `DesktopConnectionLifecycleService.kt`, `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopProxyRuntimeManager.kt` | shared state models |
| Scheduled refresh | `app/src/main/java/com/kardinal/vpncontrol/data/SubscriptionRefreshWorker.kt` | `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopAutoRefreshScheduler.kt` | `AutoRefreshLogic`, shared refresh/selection logic |
| Diagnostics | `AndroidDiagnosticsActionsService.kt`, `app/src/main/java/com/kardinal/vpncontrol/data/DiagnosticsExporter.kt` | `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopDiagnosticsService.kt`, `DesktopDiagnosticsExporter.kt` | shared formatters and state models |

Desktop construction is intentionally separate from desktop behavior. `DesktopAppServiceFactory` owns the default dependency graph and test graph assembly. `DesktopAppService` should stay a runtime facade/state coordinator; put focused behavior in services or pure helpers such as `DesktopConnectionActionsService`, `DesktopConnectionLifecycleService`, `DesktopConnectionNameLogic`, and `DesktopSubscriptionSourceValidation`.

## Cross-Cutting Contracts

- Platform capability differences are in `agent_docs/platform-matrix.md`.
- `sing-box` config and routing expectations are in `agent_docs/sing-box-contract.md`.
- Runtime safety and logs are in `agent_docs/runtime-troubleshooting.md`.
- Desktop lifecycle invariants are in `agent_docs/desktop-lifecycle.md`.
- Localization architecture is in `agent_docs/localization.md`.
- State ownership boundaries are in `agent_docs/state-ownership.md`.
- Native runtime artifact policy is in `agent_docs/native-runtime-artifacts.md`.

## When Changing X, Touch Y Too

| Change | Also inspect/update |
| --- | --- |
| Subscription payload or direct-link parsing | `ProxyParser`, `SubscriptionPayloadParser`, `ProxyLinkParser`, `ProxyLinkEncoder`, `JsonSubscriptionParser`, `ClashSubscriptionParser`, `ProxyParserEngine`, `VlessParser` compatibility shim, parser tests, import/export behavior, `agent_docs/sing-box-contract.md`, Android and desktop smoke docs. |
| `ProxyProtocol` or `ProxyProfile` fields | shared model, parser encoder/decoder, `SingBoxOutboundBuilder`, Android and desktop config factories, diagnostics/export paths. |
| sing-box outbound/TLS/transport shape | `SingBoxOutboundBuilder`, `SingBoxOutboundBuilderTest`, Android instrumented config tests, desktop config tests. |
| sing-box DNS, route rules, domain bypass, or rule-set shape | `SingBoxRouteDnsBuilder`, `SingBoxRouteDnsBuilderTest`, Android parity/instrumented config tests, desktop config/parity tests. |
| Android VPN command lifecycle or app assignment routing | `AndroidConnectionActionsService`, `AndroidConnectionLifecycleService`, `AndroidRoutingActionsService`, Android storage/runtime classes, `SingBoxConfigFactory`, Android instrumentation tests, Android smoke docs. |
| Desktop runtime, tray, autostart, or reconnect behavior | `DesktopAppService`, `DesktopStateStore`, runtime managers, desktop tests, `agent_docs/desktop-lifecycle.md`, `agent_docs/desktop-runtime-troubleshooting.md`. |
| Desktop service construction or test graph wiring | `DesktopAppServiceFactory`, desktop service tests, `agent_docs/state-ownership.md`. |
| Desktop workspace restore, sync, or persisted-state mapping | `DesktopWorkspaceStateMapper`, `DesktopStateStore`, desktop mapper tests, `agent_docs/state-ownership.md`. |
| Shared UI state/action behavior | `MainController`, `MainUiStateProjector`, shared core tests, Android `MainViewModel`, desktop service integration. |
| Subscription source activation, add/delete, rename, or source labels | `SubscriptionSourceLogic`, `AndroidProfileActionsService`, desktop subscription management service, shared core tests, platform service tests. |
| Subscription refresh state/result behavior | `AutoRefreshLogic`, `SubscriptionRefreshResultLogic`, Android manual/background refresh paths, `DesktopSubscriptionRefreshService`, shared core tests. |
| Selected location matching, remapping, stored-key normalization, or per-location benchmark updates | `SelectionMappingLogic`, `AndroidLocationActionsService`, desktop location/subscription/benchmark services, shared core tests, platform service tests. |
| User-visible status or log text | Model status domain facades such as `ConnectionStatusMessages`, `SubscriptionStatusMessages`, `BenchmarkStatusMessages`, `LocationStatusMessages`, `RoutingStatusMessages`, `DiagnosticsStatusMessages`, `RuntimeStatusMessages`, `SettingsStatusMessages`; codec facade `StatusMessages`; `StatusMessageTypes.kt`, `StatusMessageCodec.kt`, `StatusMessageKeySelectors.kt`; UI renderer `StatusMessageRenderer.kt`; `i18n-status/*.json`; status renderer/coverage tests; `scripts/status_catalog_tool.py`; `agent_docs/localization.md`. |
| Native runtime binaries or packaging scripts | `agent_docs/native-runtime-artifacts.md`, release checklist, platform packaging scripts, checksum/update notes. |
