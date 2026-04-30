# Android Smoke Testing

This document owns Android device/emulator smoke testing. Desktop smoke testing lives in `docs/desktop-smoke-testing.md`.

Use one known-good endpoint for each supported non-VLESS protocol:

- `Trojan`
- `Shadowsocks`
- `VMess`
- `SOCKS`

## Preconditions

- Install the current app build.
- Record the build date and APK path used for the run.
- Record whether the run is on a real device or emulator.
- Make sure the test endpoint is valid and currently reachable.
- Grant Android VPN permission before VPN-mode checks.
- If the test uses subscription import, verify the source actually returns the expected protocol links.

## Instrumentation Commands

Run all Android instrumentation tests on a connected device or emulator:

```bash
./gradlew :app:connectedDebugAndroidTest
```

Prerequisites:

- A device or emulator is visible in `adb devices`.
- The debug build can be installed on that device.
- VPN permission prompts may still require manual interaction for tests that exercise real VPN flows.

Run parser coverage:

```bash
./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=com.kardinal.vpncontrol.data.ProxyParserInstrumentedTest
```

Run Android config factory coverage:

```bash
./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=com.kardinal.vpncontrol.data.SingBoxConfigFactoryInstrumentedTest
```

Run local protocol smoke tests. These require local fixture servers reachable from the emulator as `10.0.2.2`:

```bash
./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=com.kardinal.vpncontrol.data.LocalProtocolSmokeInstrumentedTest
```

Trojan local smoke is skipped unless explicitly enabled:

```bash
./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=com.kardinal.vpncontrol.data.LocalProtocolSmokeInstrumentedTest \
  -Pandroid.testInstrumentationRunnerArguments.vpncontrol.trojan.smoke=1
```

Local fixture ports expected by `LocalProtocolSmokeInstrumentedTest`:

| Protocol | Emulator Host | Port |
| --- | --- | --- |
| SOCKS | `10.0.2.2` | `18081` |
| Shadowsocks | `10.0.2.2` | `18082` |
| VMess | `10.0.2.2` | `18083` |
| Trojan | `10.0.2.2` | `18084` |

## Manual Per-Protocol Flow

1. Import

   - Import the config from a direct link, clipboard, QR, or file.
   - Confirm the app accepts the payload without rewriting it into an invalid form.
   - Confirm the location appears in the `Locations` tab with the expected name and server.

2. Edit / round-trip

   - Open the imported location in the editor.
   - Verify the displayed config is readable and protocol-appropriate.
   - Save without changing the payload.
   - Export it and re-import it.
   - Confirm the round-trip preserves a working config.

3. Benchmark

   - Run `Check` on the location from the `Locations` tab.
   - Confirm the benchmark completes without parser or runtime-config errors.
   - Confirm the result is stored in the location detail line.

4. Manual selection

   - Select the location manually from `Locations`.
   - Confirm the selected location and selected profile/source labels update correctly.

5. Connect

   - Start the connection in VPN mode.
   - Confirm the app reaches started state and does not immediately roll back.

6. Real traffic

   - Open a real site through the connection.
   - Confirm ordinary browsing works.

7. Disconnect / reconnect

   - Stop the connection.
   - Start it again using the saved selection.
   - Confirm the selection persists and reconnect works.

## Subscription Variant

If the protocol is also exercised through a subscription:

1. Add a subscription containing at least one location of that protocol.
2. Refresh the subscription.
3. Confirm the location appears in the cached list.
4. Run `Find Best`.
5. Confirm the selected winner can actually connect.
6. If `All` is active, confirm the protocol participates in the merged search set.
7. Confirm the Profile tab shows the correct cached-location count for that subscription.

## Regression Checks

For every protocol above, watch for:

- parser accepts import but connect fails immediately
- benchmark works but connect fails
- manual connect works but `Find Best` excludes the protocol unexpectedly
- export/import changes the payload meaningfully
- background refresh drops cached locations for that protocol
- source labeling becomes wrong when `All` is active
