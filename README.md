# vpn_control_android

Android app scaffold that mirrors the `vpn_cli` workflow with four actions:

1. `Get Profile`
2. `Start/Stop VPN`
3. `Refresh`
4. `Set Custom DNS`

## What Is Implemented

- Kotlin + Jetpack Compose single-screen app.
- Subscription URL storage.
- VLESS link parsing from plaintext or base64 subscriptions.
- Profile refresh that ranks endpoints and selects a winner.
- `sing-box` JSON runtime config generation and on-device benchmarking running full HTTP checks.
- Android `VpnService` wrapper that starts a local `sing-box` process if a binary is present in app files.
- Optional custom DNS setting.

## Important Limitation

The original desktop CLI benchmarks profiles by actually running `xray` and `sing-box` as temporary proxies, then testing Google and ChatGPT through them.

This Android project exposes the same measurement knobs as `vpn_cli` but still requires you to supply a VPN engine binary:

- `Refresh` actually launches `sing-box` per profile, performs real Google/ChatGPT HTTP probes over the local HTTP proxy, and selects the winner.
- `Start VPN` runs the same `sing-box` binary with the generated tun config as an Android `VpnService`, so the tunnel is functional once the binary is provided.

Place your Android-compatible `sing-box` executable in the app's internal storage before triggering `Start VPN` (the service expects `files/bin/sing-box`). For testing inside Android Studio you can drop the binary under `app/src/main/assets` and copy it to `files/bin` from a `Worker`/`Startup` task at runtime; on a device you can `adb push` it directly to `/data/data/com.kardinal.vpncontrol/files/bin/sing-box`.

## Project Layout

- `app/src/main/java/com/kardinal/vpncontrol/MainActivity.kt`
- `app/src/main/java/com/kardinal/vpncontrol/MainViewModel.kt`
- `app/src/main/java/com/kardinal/vpncontrol/data/VlessParser.kt`
- `app/src/main/java/com/kardinal/vpncontrol/data/SingBoxConfigFactory.kt`
- `app/src/main/java/com/kardinal/vpncontrol/vpn/AndroidVpnService.kt`

## Open In Android Studio

Open the `vpn_control_android` directory as a Gradle project and let Android Studio download the Android SDK and Gradle wrapper artifacts.
