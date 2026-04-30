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
| Profile parsing | `app/src/main/java/com/kardinal/vpncontrol/data/ProxyParser.kt` | desktop uses shared/model-compatible parsed profiles | `shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/data/` |
| Persisted state | `app/src/main/java/com/kardinal/vpncontrol/data/ProfileStorage.kt` | `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopStateStore.kt` | `shared/storage-api/`, `shared/model/` |
| Main state/actions | `app/src/main/java/com/kardinal/vpncontrol/ui/VpnControlApp.kt` | `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopAppService.kt` | `shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/` |
| Find Best / benchmark selection | `app/src/main/java/com/kardinal/vpncontrol/data/BenchmarkOrchestrator.kt` | `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopProxyValidationRuntime.kt` | `shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/data/BenchmarkSearchLogic.kt` |
| Config generation | `app/src/main/java/com/kardinal/vpncontrol/data/SingBoxConfigFactory.kt` | `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopProxyConfigFactory.kt` | model and rules in `shared/model/` |
| Runtime lifecycle | `app/src/main/java/com/kardinal/vpncontrol/vpn/AndroidVpnService.kt` | `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopProxyRuntimeManager.kt` | shared state models |
| Scheduled refresh | `app/src/main/java/com/kardinal/vpncontrol/data/SubscriptionRefreshWorker.kt` | `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopAutoRefreshScheduler.kt` | shared refresh/selection logic |
| Diagnostics | `app/src/main/java/com/kardinal/vpncontrol/data/DiagnosticsExporter.kt` | `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopAppService.kt` | shared formatters and state models |

## Cross-Cutting Contracts

- Platform capability differences are in `docs/platform-matrix.md`.
- `sing-box` config and routing expectations are in `docs/sing-box-contract.md`.
- Runtime safety and logs are in `docs/runtime-troubleshooting.md`.
- Desktop lifecycle invariants are in `docs/desktop-lifecycle.md`.
- Localization architecture is in `docs/localization.md`.
