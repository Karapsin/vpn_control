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

Non-custom profiles are generated from structured model fields. Custom profiles remain full runtime JSON and are not passed through structured profile generation. VPN Control may apply narrowly scoped runtime transformations for the localhost management proxy, isolated desktop probes, and the optional SSH Routing. Home-route transformation is fail-closed: unknown outbound/DNS types, unsupported top-level network features, invalid detour graphs, and reserved-tag collisions reject the config.

## SSH Routing

When enabled, generated runtime configs form this outbound chain:

```text
application traffic -> selected proxy -> home SOCKS relay -> pinned SSH outbound -> public network
```

The SOCKS relay is reached as `127.0.0.1` from the remote side of the SSH connection. UDP uses sing-box UDP-over-TCP v2 for the SSH leg. The SSH host uses the dedicated bootstrap resolver; this establishment traffic is the intentional direct exception.

Routing-rule `DIRECT` actions, direct domain suffixes, and remote rule-set downloads use the home egress while the feature is enabled. Each active runtime also exposes a loopback-only mixed management inbound so subscription downloads can use the already-selected session even though the VPN Control app process itself is excluded from Android VPN routing and desktop direct-probe exemptions no longer include the app process.

Desktop direct probes run from the dedicated `vpn-control-probe-sing-box` executable and use a reserved direct outbound. That exception is added to both generated and accepted custom configs, so the currently active VPN does not affect Find Best. Custom profiles remain excluded as Find Best candidates.

## Android Config Shape

Android config generation lives in:

```text
app/src/main/java/com/kardinal/vpncontrol/data/SingBoxConfigFactory.kt
```

Non-custom outbound/TLS/transport JSON is built in shared core:

```text
shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/data/SingBoxOutboundBuilder.kt
```

Common DNS, route rules, direct CIDRs, domain bypass rules, rule-set definitions, and remote rule-set cache wiring are built in shared core:

```text
shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/data/SingBoxRouteDnsBuilder.kt
```

Primary coverage:

```text
shared/core/src/commonTest/kotlin/com/kardinal/vpncontrol/data/SingBoxRouteDnsBuilderTest.kt
app/src/test/java/com/kardinal/vpncontrol/data/SingBoxConfigFactoryParityTest.kt
app/src/androidTest/java/com/kardinal/vpncontrol/data/SingBoxConfigFactoryInstrumentedTest.kt
```

Android VPN mode uses Android VPN APIs and the bundled Android runtime. App assignment routing is Android-specific and meaningful there.
Unit tests should cover both empty app-assignment behavior and `include_package` behavior when Android app assignments are present.

## Desktop Config Shape

Desktop config generation lives in:

```text
desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopProxyConfigFactory.kt
```

Desktop uses the same shared outbound builder as Android for non-custom profiles. It also uses the shared route/DNS builder for common DNS, direct CIDR, domain bypass, and rule-set behavior. Platform factories still own inbounds, direct probe routing, app-assignment behavior where applicable, and runtime-specific wrappers.
Desktop VPN config must only inject direct probe process rules in VPN mode, before DNS hijack rules.

## Secure DNS

Desktop and Android share these DNS modes and generated-config behavior:

- `AUTOMATIC` uses the built-in `https://1.1.1.1/dns-query` DNS-over-HTTPS endpoint.
- `CUSTOM_DOH` accepts an `https://` endpoint. A missing path is normalized to `/dns-query`.
- `CUSTOM_DOT` accepts a `tls://` endpoint and uses port `853` unless an explicit port is supplied.
- The secure resolver is tagged `secure-dns`, is selected as the final resolver, uses IPv4 answers, and is sent through the `proxy` outbound.
- A separate `bootstrap-dns` UDP resolver at `1.1.1.1:53` is routed directly. It resolves only hostnames needed to establish the proxy or encrypted-DNS connection; ordinary application DNS does not use it.
- The bootstrap address, not the custom secure-DNS server address, is included in direct CIDR routing.
- Plain UDP/TCP custom DNS endpoints are not accepted. Legacy enabled raw-IP DNS settings migrate to automatic secure DNS and retain the old address only long enough to show a migration notice.

Endpoint validation rejects credentials, query strings, fragments, invalid ports, a DoH scheme other than `https://`, and a DoT scheme other than `tls://`. DoT endpoints cannot contain a path.

Primary coverage:

```text
shared/core/src/commonTest/kotlin/com/kardinal/vpncontrol/data/SingBoxOutboundBuilderTest.kt
shared/core/src/commonTest/kotlin/com/kardinal/vpncontrol/data/SingBoxRouteDnsBuilderTest.kt
shared/core/src/commonTest/kotlin/com/kardinal/vpncontrol/data/SecureDnsEndpointParserTest.kt
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
- Direct domain suffix rules bypass VPN/proxy where configured.
- Desktop does not expose Android app assignments because desktop app-level routing needs different OS-specific control.

## Find Best And Benchmarks

Best-location selection should not be biased by the current VPN/proxy state.

Android and desktop should both evaluate subscription candidates using shared selection logic where possible. Desktop validation must keep direct probe routing so active VPN state does not change probe results.

Relevant tests:

```text
shared/core/src/commonTest/kotlin/com/kardinal/vpncontrol/SelectionMappingLogicTest.kt
desktopApp/src/test/kotlin/com/kardinal/vpncontrol/desktop/DesktopDirectProbeRoutingTest.kt
desktopApp/src/test/kotlin/com/kardinal/vpncontrol/desktop/DesktopFindBestServiceTest.kt
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
   - Update `SingBoxRouteDnsBuilder.kt` for shared DNS, route rules, domain bypass, or rule-set behavior.
   - Update `SingBoxConfigFactory.kt` for Android inbounds, app assignments, or VPN-only behavior.
   - Add assertions in `SingBoxOutboundBuilderTest`.
   - Add assertions in `SingBoxRouteDnsBuilderTest` when route/DNS behavior changes.
   - Add or update parity assertions in `SingBoxConfigFactoryParityTest`.
   - Add assertions in `SingBoxConfigFactoryInstrumentedTest`.
   - Check VPN routing behavior if the protocol interacts with app assignments or domain bypass rules.

4. Desktop config

   - Update `SingBoxOutboundBuilder.kt` for shared outbound/TLS/transport behavior.
   - Update `SingBoxRouteDnsBuilder.kt` for shared DNS, route rules, domain bypass, or rule-set behavior.
   - Update `DesktopProxyConfigFactory.kt` for desktop inbounds, direct probes, or VPN-only behavior.
   - Add assertions in `SingBoxOutboundBuilderTest`.
   - Add assertions in `SingBoxRouteDnsBuilderTest` when route/DNS behavior changes.
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

   - Update `agent_docs/smoke-android.md` and `agent_docs/desktop-smoke-testing.md` with fixture requirements and manual checks.

8. Validation

   - Run the path-based checks in `agent_docs/test-matrix.md`.
   - Run manual smoke only when live endpoints or local fixtures are available.
