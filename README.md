# vpn_control_android

Android VPN controller built around `sing-box` / `libbox`, modeled after the desktop `vpn_cli` flow.

The app now has 3 tabs:

1. `Main`
2. `Locations`
3. `Routing Rules`

It supports both subscription-based operation and manual location management.

## Main Features

- Functional Android VPN tunnel using bundled native `sing-box` / `libbox`.
- `Profile Source` modes:
  - `Subscription`
  - `Current Locations`
- `Refresh` benchmarks available locations and selects the best one.
- `Locations` tab:
  - add a location from either a `vless://...` link or JSON
  - edit / delete locations
  - mark one location as the current selected location via `Use`
  - import / export locations as JSON
- `Routing Rules` tab:
  - `Proxy Apps`
  - `Direct Apps`
  - `National Domains`
  - `Direct Domains`
  - `Ignore Rules`
  - import / export routing rules as JSON
- Advanced settings menu on the main screen:
  - `Set Custom DNS`
  - `Subscription Refresh Policy`
- Diagnostics export from the main screen.

## Selection Behavior

- Tapping `Use` on the `Locations` tab sets that location as the current selected location.
- `Start VPN` uses the current selected location if one is already selected.
- `Refresh` benchmarks candidates and replaces the selected location with the new winner.
- In `Subscription` mode, refresh downloads the subscription and syncs the `Locations` tab from it.
- In `Current Locations` mode, refresh benchmarks only the saved locations already in the app.

## Subscription Refresh Policy

Available from the main screen overflow menu.

Supported options:

- `Off`
- `Every hour`
- `Custom interval`

Notes:

- The policy applies only when `Profile Source` is set to `Subscription`.
- Background refresh redownloads the subscription URL and updates the saved locations list.
- It does not automatically benchmark/select a new winner.
- It does not automatically restart the live VPN tunnel.

## Routing Rules Behavior

- `Proxy Apps`:
  - if this list is non-empty, only these apps use the VPN
- `Direct Apps`:
  - these apps bypass the VPN
- `National Domains` and `Direct Domains` have priority over app-based proxy routing
- `Ignore Rules` disables custom routing rules and sends normal app traffic through the VPN

## Location Input Formats

The app accepts locations in two formats:

- raw `vless://...` links
- JSON location objects

Locations are normalized and stored internally as structured JSON-compatible data.

## Diagnostics

`Export Diagnostics` produces a text bundle with:

- current persisted app state
- selected profile info
- saved locations
- generated runtime config
- internal diagnostics log

This is intended for troubleshooting without requiring `adb`.

## Packaging

Current packaging is optimized for modern real phones:

- `arm64-v8a` only
- bundled native `sing-box` under `app/src/main/jniLibs/arm64-v8a/libsing-box.so`
- release shrinking / minification enabled

Tradeoff:

- the release APK is much smaller
- x86 / x86_64 emulators and some older 32-bit devices are no longer supported

## Build Outputs

- debug APK:
  - `app/build/outputs/apk/debug/app-debug.apk`
  - currently about `203M`
- minimized release APK:
  - `app/build/outputs/apk/release/app-release.apk`
  - currently about `33M`

The release build is configured to use the debug signing config so it can be installed locally without extra signing setup.

## Key Files

- `app/src/main/java/com/kardinal/vpncontrol/MainActivity.kt`
- `app/src/main/java/com/kardinal/vpncontrol/MainViewModel.kt`
- `app/src/main/java/com/kardinal/vpncontrol/data/AppRepository.kt`
- `app/src/main/java/com/kardinal/vpncontrol/data/BenchmarkOrchestrator.kt`
- `app/src/main/java/com/kardinal/vpncontrol/data/ProfileStorage.kt`
- `app/src/main/java/com/kardinal/vpncontrol/data/SingBoxConfigFactory.kt`
- `app/src/main/java/com/kardinal/vpncontrol/data/SubscriptionRefreshScheduler.kt`
- `app/src/main/java/com/kardinal/vpncontrol/data/SubscriptionRefreshWorker.kt`
- `app/src/main/java/com/kardinal/vpncontrol/ui/VpnControlApp.kt`
- `app/src/main/java/com/kardinal/vpncontrol/vpn/AndroidVpnService.kt`

## Open In Android Studio

Open the `vpn_control_android` directory as a Gradle project.
