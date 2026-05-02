# Test Matrix

Use this matrix to choose the smallest useful validation set for a patch. Add more tests when the touched code crosses boundaries.

## CI Shortcut

The GitHub Actions workflow `.github/workflows/fast-checks.yml` runs the usual fast guardrail set for code changes:

```bash
./scripts/check_release_hygiene.sh
./scripts/check_localization.py
./gradlew :shared:core:desktopTest :shared:ui:desktopTest :desktopApp:test :app:testDebugUnitTest
```

## Quick Mapping

| Touched Area | Run |
| --- | --- |
| `shared/model/` | `./gradlew :shared:model:desktopTest` |
| `shared/core/` parsing, refresh, selection, shared config builders, config-independent logic | `./gradlew :shared:core:desktopTest` |
| `shared/ui/` Kotlin or localization catalogs | `./scripts/check_localization.py` and `./gradlew :shared:ui:desktopTest` |
| Android UI-only code | `./gradlew :app:compileDebugKotlin` |
| Android profile/import action orchestration | `./gradlew :app:testDebugUnitTest :app:compileDebugKotlin` |
| Android location mutation, selection, import/export, or location benchmark orchestration | `./gradlew :app:testDebugUnitTest :app:compileDebugKotlin` |
| Android routing draft/import/save orchestration | `./gradlew :shared:core:desktopTest :app:testDebugUnitTest :app:compileDebugKotlin` |
| Android manual subscription refresh orchestration | `./gradlew :app:testDebugUnitTest :app:compileDebugKotlin` |
| Android settings or diagnostics orchestration | `./gradlew :shared:core:desktopTest :app:testDebugUnitTest :app:compileDebugKotlin` |
| Android VPN/config/runtime code | `./gradlew :app:compileDebugKotlin` and `./gradlew :app:testDebugUnitTest`; add relevant `app/src/androidTest` tests when practical |
| Desktop service, tray, runtime, lifecycle, autostart, Windows elevation | `./gradlew :desktopApp:test` |
| Desktop workspace restore/sync/persist mapping | `./gradlew :desktopApp:test` |
| Desktop settings/dialog/autostart orchestration | `./gradlew :desktopApp:test` |
| Desktop connection command/resume/shutdown orchestration | `./gradlew :desktopApp:test` |
| Desktop subscription refresh orchestration | `./gradlew :desktopApp:test` |
| Desktop per-location benchmark orchestration | `./gradlew :desktopApp:test` |
| Desktop package metadata or bundled runtime extraction | Relevant package script and package smoke tests |
| Linux packaging | `./scripts/package_linux_desktop.sh` |
| Windows packaging | `./scripts/package_windows_desktop_vm.sh` when a VM is available, or `.\scripts\package_windows_desktop.ps1` on Windows |
| macOS packaging | `./scripts/package_macos_desktop.sh` on macOS |
| Documentation only | `git diff --check` |
| Release workflow/package guardrails | `./scripts/check_release_hygiene.sh` and `git diff --check` |

## Common Combined Checks

Localization patch:

```bash
./scripts/check_localization.py
./gradlew :shared:ui:desktopTest
./gradlew :app:compileDebugKotlin
```

Shared core behavior patch:

```bash
./gradlew :shared:core:desktopTest
./gradlew :app:compileDebugKotlin
```

Subscription refresh behavior patch:

```bash
./gradlew :shared:core:desktopTest
./gradlew :desktopApp:test
./gradlew :app:testDebugUnitTest
```

Subscription source add/delete/rename/activation patch:

```bash
./gradlew :shared:core:desktopTest
./gradlew :desktopApp:test
./gradlew :shared:ui:desktopTest
```

Selection/remap behavior patch:

```bash
./gradlew :shared:core:desktopTest
./gradlew :desktopApp:test
./gradlew :app:testDebugUnitTest
```

Desktop runtime patch:

```bash
./gradlew :desktopApp:test
```

Android VPN/config patch:

```bash
./gradlew :app:compileDebugKotlin
./gradlew :app:testDebugUnitTest
```

If the Android patch changes actual generated `sing-box` config shape, also run or update:

```bash
./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=com.kardinal.vpncontrol.data.SingBoxConfigFactoryInstrumentedTest
```

If the patch changes shared outbound/TLS/transport generation, also update or inspect:

```text
shared/core/src/commonTest/kotlin/com/kardinal/vpncontrol/data/SingBoxOutboundBuilderTest.kt
app/src/test/java/com/kardinal/vpncontrol/data/SingBoxConfigFactoryParityTest.kt
desktopApp/src/test/kotlin/com/kardinal/vpncontrol/desktop/DesktopProxyConfigFactoryTest.kt
desktopApp/src/test/kotlin/com/kardinal/vpncontrol/desktop/DesktopProxyConfigParityTest.kt
app/src/androidTest/java/com/kardinal/vpncontrol/data/SingBoxConfigFactoryInstrumentedTest.kt
```

If the patch changes shared DNS, route rules, domain bypass, direct CIDRs, or rule-set generation, also update or inspect:

```text
shared/core/src/commonTest/kotlin/com/kardinal/vpncontrol/data/SingBoxRouteDnsBuilderTest.kt
app/src/test/java/com/kardinal/vpncontrol/data/SingBoxConfigFactoryParityTest.kt
desktopApp/src/test/kotlin/com/kardinal/vpncontrol/desktop/DesktopProxyConfigFactoryTest.kt
desktopApp/src/test/kotlin/com/kardinal/vpncontrol/desktop/DesktopProxyConfigParityTest.kt
app/src/androidTest/java/com/kardinal/vpncontrol/data/SingBoxConfigFactoryInstrumentedTest.kt
```

Import/export UI patch:

```bash
./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=com.kardinal.vpncontrol.ui.ImportExportActionsInstrumentedTest
./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=com.kardinal.vpncontrol.ui.ImportExportErrorInstrumentedTest
./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=com.kardinal.vpncontrol.ui.ImportExportMenuVisibilityInstrumentedTest
```

Protocol parser patch:

```bash
./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=com.kardinal.vpncontrol.data.ProxyParserInstrumentedTest
./gradlew :shared:core:desktopTest
```

## Android Instrumentation

Run all Android instrumentation tests on a connected device or emulator:

```bash
./gradlew :app:connectedDebugAndroidTest
```

Prerequisites:

- A device or emulator is visible in `adb devices`.
- The debug build can be installed on that device.
- VPN permission prompts may still require manual interaction for tests that exercise real VPN flows.

Run local protocol smoke tests only when local fixture servers are available:

```bash
./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=com.kardinal.vpncontrol.data.LocalProtocolSmokeInstrumentedTest
```

See `docs/smoke-android.md` for fixture ports and the Trojan opt-in flag.

## Manual Or Risky Checks

Do not run checks that stop the currently active VPN unless the user approves the interruption.

Manual checks are still needed for:

- Real Android VPN permission and traffic behavior.
- Real desktop VPN mode on Linux and Windows.
- Windows UAC/elevation behavior.
- Tray integration on the target window manager.
- Autostart after real reboot.
- Live subscription/provider behavior.

When a manual check is skipped, state the reason and name the closest automated coverage that ran.
