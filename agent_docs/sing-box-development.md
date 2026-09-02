# sing-box Development

Authoritative networking behavior is in `contracts.md`, especially `CONFIG-001` through `CONFIG-011`, `PRODUCT-003`, `PRODUCT-004`, and the applicable platform contracts. This document only maps owners, tests, and the protocol-change procedure.

## Owner Files

| Boundary | Owner |
| --- | --- |
| Structured outbound, TLS, transport | `shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/data/SingBoxOutboundBuilder.kt` |
| Shared DNS, routes, direct CIDRs, domain bypass, rule sets | `shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/data/SingBoxRouteDnsBuilder.kt` |
| Secure endpoint parsing | shared core secure-DNS parser and tests |
| Android inbounds, app assignments, VPN wrappers | `app/src/main/java/com/kardinal/vpncontrol/data/SingBoxConfigFactory.kt` |
| Desktop inbounds, direct probes, mode wrappers | `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopProxyConfigFactory.kt` |
| Subscription/direct-link parsing | parser facade and implementations listed in `architecture.md` |

## Primary Contract Tests

```text
shared/core/src/commonTest/kotlin/com/kardinal/vpncontrol/data/SingBoxOutboundBuilderTest.kt
shared/core/src/commonTest/kotlin/com/kardinal/vpncontrol/data/SingBoxRouteDnsBuilderTest.kt
shared/core/src/commonTest/kotlin/com/kardinal/vpncontrol/data/SecureDnsEndpointParserTest.kt
shared/core/src/commonTest/kotlin/com/kardinal/vpncontrol/data/JsonSubscriptionParsingTest.kt
app/src/test/java/com/kardinal/vpncontrol/data/SingBoxConfigFactoryParityTest.kt
app/src/androidTest/java/com/kardinal/vpncontrol/data/SingBoxConfigFactoryInstrumentedTest.kt
desktopApp/src/test/kotlin/com/kardinal/vpncontrol/desktop/DesktopProxyConfigFactoryTest.kt
desktopApp/src/test/kotlin/com/kardinal/vpncontrol/desktop/DesktopProxyConfigParityTest.kt
desktopApp/src/test/kotlin/com/kardinal/vpncontrol/desktop/DesktopDirectProbeRoutingTest.kt
desktopApp/src/test/kotlin/com/kardinal/vpncontrol/desktop/DesktopFindBestServiceTest.kt
```

## Adding Or Changing A Protocol

1. Update `ProxyProtocol` and `ProxyProfile` only when new structured data is required; add a migration before changing serialized names.
2. Update parser/encoder coverage and preserve all prior payload shapes and export round trips.
3. Put common outbound/TLS/transport behavior in `SingBoxOutboundBuilder`; put common DNS/route/rule-set behavior in `SingBoxRouteDnsBuilder`.
4. Keep Android-only inbounds and app assignments in `SingBoxConfigFactory`; keep desktop inbounds, direct probes, and mode wrappers in `DesktopProxyConfigFactory`.
5. Update shared tests, Android parity/instrumented tests, and desktop config/parity tests for every changed JSON boundary.
6. Confirm subscription refresh and Find Best include the protocol where benchmarkable and preserve direct-probe isolation.
7. Exercise direct link, clipboard, QR, file, export, and diagnostic presentation paths.
8. Update the Android and desktop smoke procedures when fixture or live-endpoint coverage changes.
9. Run the path-based checks in `test-matrix.md`; run live smoke only when its external prerequisites are available.
