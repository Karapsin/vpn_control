# sing-box Contract

This project generates and runs `sing-box` configs on Android and desktop. The contract below is the expected behavior that patches should preserve.

## Supported Profile Types

The app models these proxy protocols:

- `VLESS`
- `Trojan`
- `Shadowsocks`
- `VMess`
- `SOCKS`
- `CUSTOM`

Non-custom profiles are generated from structured model fields. Custom profiles are treated as direct runtime JSON and must not be forced through structured outbound generation.

## Android Config Shape

Android config generation lives in:

```text
app/src/main/java/com/kardinal/vpncontrol/data/SingBoxConfigFactory.kt
```

Non-custom outbound/TLS/transport JSON is built in shared core:

```text
shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/data/SingBoxOutboundBuilder.kt
```

Primary coverage:

```text
app/src/test/java/com/kardinal/vpncontrol/data/SingBoxConfigFactoryParityTest.kt
app/src/androidTest/java/com/kardinal/vpncontrol/data/SingBoxConfigFactoryInstrumentedTest.kt
```

Android VPN mode uses Android VPN APIs and the bundled Android runtime. App assignment routing is Android-specific and meaningful there.

## Desktop Config Shape

Desktop config generation lives in:

```text
desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopProxyConfigFactory.kt
```

Desktop uses the same shared outbound builder as Android for non-custom profiles. Platform factories still own inbounds, route rules, DNS, direct probe routing, and runtime-specific wrappers.

Primary coverage:

```text
shared/core/src/commonTest/kotlin/com/kardinal/vpncontrol/data/SingBoxOutboundBuilderTest.kt
desktopApp/src/test/kotlin/com/kardinal/vpncontrol/desktop/DesktopProxyConfigFactoryTest.kt
desktopApp/src/test/kotlin/com/kardinal/vpncontrol/desktop/DesktopProxyConfigParityTest.kt
desktopApp/src/test/kotlin/com/kardinal/vpncontrol/desktop/DesktopProxyRuntimeManagerTest.kt
```

Desktop supports:

- proxy-only mode
- VPN mode on Linux and Windows
- direct probe routing for validation/best-location checks

macOS currently supports packaging and proxy-only smoke testing, but not full VPN mode.

## Routing Rules

Rules must preserve these expectations:

- No default subscriptions.
- No default routing rules.
- If `ignoreRules` is on, all app traffic uses VPN where VPN mode is available.
- If `ignoreRules` is off and the app assignment set is empty, all apps use VPN.
- Direct/national domain suffix rules bypass VPN/proxy where configured.
- Desktop does not expose Android app assignments because desktop app-level routing needs different OS-specific control.

## Find Best And Benchmarks

Best-location selection should not be biased by the current VPN/proxy state.

Android and desktop should both evaluate subscription candidates using shared selection logic where possible. Desktop validation must keep direct probe routing so active VPN state does not change probe results.

Relevant tests:

```text
desktopApp/src/test/kotlin/com/kardinal/vpncontrol/desktop/DesktopDirectProbeRoutingTest.kt
desktopApp/src/test/kotlin/com/kardinal/vpncontrol/desktop/BenchmarkSearchLogicTest.kt
shared/core/src/commonTest/kotlin/com/kardinal/vpncontrol/data/JsonSubscriptionParsingTest.kt
```

## Parser And Subscription Inputs

Parser behavior should be additive. Supporting a new subscription shape must not break previous payload states.

Relevant tests:

```text
app/src/androidTest/java/com/kardinal/vpncontrol/data/ProxyParserInstrumentedTest.kt
shared/core/src/commonTest/kotlin/com/kardinal/vpncontrol/data/JsonSubscriptionParsingTest.kt
```

## Adding Or Changing A Protocol

Use this checklist for protocol work:

1. Model

   - Add or update `ProxyProtocol` and `ProxyProfile` fields in `shared/model/` only if the protocol needs new structured data.
   - Preserve existing enum names and serialized state unless a migration is added.

2. Parser and encoder

   - Update Android parser coverage in `ProxyParserInstrumentedTest`.
   - Keep parsing additive: new formats must not break old base64, line-based, JSON, or direct-link subscriptions.
   - Update export/round-trip behavior when a protocol can be exported.

3. Android config

   - Update `SingBoxOutboundBuilder.kt` for shared outbound/TLS/transport behavior.
   - Update `SingBoxConfigFactory.kt` for Android inbounds, DNS, route rules, or VPN-only behavior.
   - Add assertions in `SingBoxOutboundBuilderTest`.
   - Add or update parity assertions in `SingBoxConfigFactoryParityTest`.
   - Add assertions in `SingBoxConfigFactoryInstrumentedTest`.
   - Check VPN routing behavior if the protocol interacts with app assignments or domain bypass rules.

4. Desktop config

   - Update `SingBoxOutboundBuilder.kt` for shared outbound/TLS/transport behavior.
   - Update `DesktopProxyConfigFactory.kt` for desktop inbounds, DNS, route rules, direct probes, or VPN-only behavior.
   - Add assertions in `SingBoxOutboundBuilderTest`.
   - Add assertions in `DesktopProxyConfigFactoryTest`.
   - Add or update parity assertions in `DesktopProxyConfigParityTest`.
   - Check proxy-only and VPN mode where the platform supports them.

5. Subscription and Find Best

   - Add subscription parser tests in shared core when the provider shape changes.
   - Confirm `Find Best` includes the protocol when benchmarkable.
   - Confirm desktop direct probes still avoid current VPN/proxy bias.

6. Import/export UI and diagnostics

   - Confirm direct link, clipboard, QR, and file import/export paths still preserve the payload.
   - Update diagnostics if the protocol needs new fields to debug failures.

7. Smoke docs

   - Update `docs/smoke-android.md` and `docs/desktop-smoke-testing.md` with fixture requirements and manual checks.

8. Validation

   - Run the path-based checks in `docs/test-matrix.md`.
   - Run manual smoke only when live endpoints or local fixtures are available.
