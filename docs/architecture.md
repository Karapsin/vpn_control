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
| Profile parsing | Android uses the shared parser from app workflows | Desktop uses the shared parser from service workflows | `ProxyParser.kt` facade, `ProxyLinkParser.kt`, `ProxyLinkEncoder.kt`, `ProxyParserEngine.kt` subscription implementation, `VlessParser.kt` compatibility shim |
| Persisted state | `app/src/main/java/com/kardinal/vpncontrol/data/ProfileStorage.kt` | `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopStateStore.kt` | `shared/storage-api/`, `shared/model/` |
| Main state/actions | `app/src/main/java/com/kardinal/vpncontrol/MainViewModel.kt` plus shared controller | `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopAppService.kt` | `shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/MainController.kt`, `MainUiState.kt`, `MainUiStateProjector` |
| Find Best / benchmark selection | `app/src/main/java/com/kardinal/vpncontrol/data/BenchmarkOrchestrator.kt` | `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopProxyValidationRuntime.kt` | `shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/data/BenchmarkSearchLogic.kt` |
| Config generation | `app/src/main/java/com/kardinal/vpncontrol/data/SingBoxConfigFactory.kt` | `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopProxyConfigFactory.kt` | shared outbound builder in `shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/data/SingBoxOutboundBuilder.kt`, shared route/DNS builder in `shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/data/SingBoxRouteDnsBuilder.kt`, model/rules in `shared/model/` |
| Runtime lifecycle | `app/src/main/java/com/kardinal/vpncontrol/vpn/AndroidVpnService.kt` | `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopProxyRuntimeManager.kt` | shared state models |
| Scheduled refresh | `app/src/main/java/com/kardinal/vpncontrol/data/SubscriptionRefreshWorker.kt` | `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopAutoRefreshScheduler.kt` | shared refresh/selection logic |
| Diagnostics | `app/src/main/java/com/kardinal/vpncontrol/data/DiagnosticsExporter.kt` | `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopAppService.kt` | shared formatters and state models |

## Cross-Cutting Contracts

- Platform capability differences are in `docs/platform-matrix.md`.
- `sing-box` config and routing expectations are in `docs/sing-box-contract.md`.
- Runtime safety and logs are in `docs/runtime-troubleshooting.md`.
- Desktop lifecycle invariants are in `docs/desktop-lifecycle.md`.
- Localization architecture is in `docs/localization.md`.
- State ownership boundaries are in `docs/state-ownership.md`.
- Native runtime artifact policy is in `docs/native-runtime-artifacts.md`.

## When Changing X, Touch Y Too

| Change | Also inspect/update |
| --- | --- |
| Subscription payload or direct-link parsing | `ProxyParser`, `ProxyLinkParser`, `ProxyLinkEncoder`, `ProxyParserEngine`, `VlessParser` compatibility shim, parser tests, import/export behavior, `docs/sing-box-contract.md`, Android and desktop smoke docs. |
| `ProxyProtocol` or `ProxyProfile` fields | shared model, parser encoder/decoder, `SingBoxOutboundBuilder`, Android and desktop config factories, diagnostics/export paths. |
| sing-box outbound/TLS/transport shape | `SingBoxOutboundBuilder`, `SingBoxOutboundBuilderTest`, Android instrumented config tests, desktop config tests. |
| sing-box DNS, route rules, domain bypass, or rule-set shape | `SingBoxRouteDnsBuilder`, `SingBoxRouteDnsBuilderTest`, Android parity/instrumented config tests, desktop config/parity tests. |
| Android VPN or app assignment routing | `MainViewModel`, Android storage/runtime classes, `SingBoxConfigFactory`, Android instrumentation tests, Android smoke docs. |
| Desktop runtime, tray, autostart, or reconnect behavior | `DesktopAppService`, `DesktopStateStore`, runtime managers, desktop tests, `docs/desktop-lifecycle.md`, `docs/desktop-runtime-troubleshooting.md`. |
| Shared UI state/action behavior | `MainController`, `MainUiStateProjector`, shared core tests, Android `MainViewModel`, desktop service integration. |
| User-visible status or log text | `StatusMessages`, `i18n-status/*.json`, `AppStringsCoverageTest`, `docs/localization.md`. |
| Native runtime binaries or packaging scripts | `docs/native-runtime-artifacts.md`, release checklist, platform packaging scripts, checksum/update notes. |
