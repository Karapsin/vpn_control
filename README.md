# vpn_control_android

Android VPN controller built around `sing-box` / `libbox`, modeled after the desktop `vpn_cli` flow.

The app now has 4 tabs:

1. `Main`
2. `Profile`
3. `Locations`
4. `Rules`

It supports both subscription-based operation and manual location management.

## Main Features

- Functional Android VPN tunnel using bundled native `sing-box` / `libbox`.
- `Profile` tab:
  - choose `Subscription` or `Saved Locations`
  - paste a remote source
  - clear the current source
  - reuse, rename, or delete items from subscription history
- `Find the best location` benchmarks available locations and selects the best one.
- `Locations` tab:
  - add a location from either a `vless://...` link or JSON
  - edit / delete locations
  - mark one location as the current selected location via `Use`
  - rerun benchmarks for one location via the refresh icon
  - import / export locations as JSON
- `Rules` tab:
  - `Proxy Apps`
  - `Direct Apps`
  - `Country-code Domains`
  - `Bypass Domains`
  - `Ignore Rules`
  - import / export routing rules as JSON
- Advanced settings menu on the main screen:
  - `Custom DNS`
  - `Subscription Auto-Refresh`
  - `Validation Settings`
- Diagnostics export from the main screen.

## Selection Behavior

- Tapping `Use` on the `Locations` tab sets that location as the current selected location.
- `Start VPN` uses the current selected location if one is already selected.
- `Find the best location` benchmarks candidates and replaces the selected location with the new winner.
- In `Subscription` mode, refresh downloads the subscription and syncs the `Locations` tab from it.
- In `Saved Locations` mode, refresh benchmarks only the locations already stored in the app.

## Best-Location Logic

- Standard VLESS subscriptions:
  - all locations are prefiltered by TCP connect speed
  - candidates are tested from fastest to slowest
  - the first location where the secondary test site succeeds is selected
- On the `Locations` tab, the per-location refresh action uses the same benchmark path as the main search for the current source type.

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
- `Country-code Domains` and `Bypass Domains` have priority over app-based proxy routing
- `Ignore Rules` disables custom routing rules and sends normal app traffic through the VPN

## Location Input Formats

The app accepts locations in two formats:

- raw `vless://...` links
- JSON location objects

Locations are normalized and stored internally as structured JSON-compatible data.

Remote source support:

- supported: direct subscription URLs and `sing-box://import-remote-profile...` links that resolve to a VLESS list
- not supported: `vpn://...` imports, including Amnezia Premium keys

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

## Windows Desktop Packaging

Run this from Windows or from the Windows VM:

```powershell
.\scripts\package_windows_desktop.ps1
```

The script builds local `.exe` and `.msi` installers, runs desktop unit tests, runs Windows package regression checks, and copies final artifacts to:

```text
dist\windows\
```

Expected outputs:

- `dist\windows\vpn-control-<version>.exe`
- `dist\windows\vpn-control-<version>.msi`
- `dist\windows\SHA256SUMS.txt`

Useful options:

- `-SkipTests` skips Gradle unit tests.
- `-SkipPackageRegressionTests` skips installer payload validation.
- `-DistDir <path>` changes the local artifact output directory.

## Key Files

- `app/src/main/java/com/kardinal/vpncontrol/MainActivity.kt`
- `app/src/main/java/com/kardinal/vpncontrol/MainViewModel.kt`
- `app/src/main/java/com/kardinal/vpncontrol/data/AppRepository.kt`
- `app/src/main/java/com/kardinal/vpncontrol/data/BenchmarkOrchestrator.kt`
- `app/src/main/java/com/kardinal/vpncontrol/data/LocationConfigs.kt`
- `app/src/main/java/com/kardinal/vpncontrol/data/ProfileStorage.kt`
- `app/src/main/java/com/kardinal/vpncontrol/data/RemoteSourceResolver.kt`
- `app/src/main/java/com/kardinal/vpncontrol/data/SingBoxConfigFactory.kt`
- `app/src/main/java/com/kardinal/vpncontrol/data/SubscriptionRefreshScheduler.kt`
- `app/src/main/java/com/kardinal/vpncontrol/data/SubscriptionRefreshWorker.kt`
- `app/src/main/java/com/kardinal/vpncontrol/data/VpnManager.kt`
- `app/src/main/java/com/kardinal/vpncontrol/ui/VpnControlApp.kt`
- `app/src/main/java/com/kardinal/vpncontrol/vpn/AndroidVpnService.kt`

## Open In Android Studio

Open the `vpn_control_android` directory as a Gradle project.
