# Test Matrix

Use this matrix to choose the smallest useful validation set for a patch. Add more tests when the touched code crosses boundaries.

## CI Shortcut

The GitHub Actions workflow `.github/workflows/fast-checks.yml` runs the usual fast guardrail set for code changes:

```bash
./scripts/check_release_hygiene.sh
./scripts/check_docs_hygiene.sh
python3 -m unittest discover -s agent_tools/tests
python3 scripts/check_ui_theme.py
python3 scripts/test_visual_regression.py
python3 scripts/test_visual_platform.py
python3 scripts/test_visual_review.py
python3 scripts/check_contract_docs.py
./scripts/check_localization.py
./scripts/status_catalog_tool.py check
./gradlew :shared:model:desktopTest :shared:core:desktopTest :shared:ui:desktopTest :desktopApp:test :app:testDebugUnitTest :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin
```

## Validation Tiers

Use the smallest tier that gives meaningful coverage for the touched boundary.

| Tier | When To Use | Checks |
| --- | --- | --- |
| Minimum local | Documentation-only changes, one-file pure logic changes, or early iteration before a larger check | `git diff --check` plus the mapped check set from Quick Mapping |
| Expanded boundary | A patch crosses shared/platform, status/localization, runtime/config, or packaging boundaries | Run every mapped command for the touched rows and adjacent owner tests named in Common Combined Checks |
| Full fast guardrails | Before pushing broad behavior, localization, runtime, agent lifecycle, or release workflow changes | `git diff --check`, release/docs hygiene, agent tool tests, theme/visual comparator checks, localization/status checks, and the Gradle command from CI Shortcut |
| Manual or risky | Real VPN interruption, emulator/device VPN permission, tray/window-manager behavior, Windows UAC, VM packaging, reboot/autostart | Run only when the touched area requires it; get approval before interrupting VPN and report the closest automated coverage |

If a mapped check cannot run because the environment lacks an Android SDK, emulator, VM, network access, or platform host, run the closest non-risky local check and report the missing prerequisite explicitly.

## Quick Mapping

| Touched Area | Run |
| --- | --- |
| `shared/model/` | `./gradlew :shared:model:desktopTest` |
| Shared control DTOs, protocol codec, registry or command grammar | `./gradlew :shared:model:desktopTest :shared:core:desktopTest`; add affected desktop/Android adapter tests when wiring dispatch |
| GUI/CLI controller lifecycle, authentication or launchers | Shared control and affected platform tests, then public-CLI tests from each affected native package in disposable environments; see `cli.md` |
| Shared typed status helpers or status models | `./scripts/status_catalog_tool.py check` and `./gradlew :shared:model:desktopTest :shared:ui:desktopTest` |
| Status domain facade call-site migration | `./scripts/status_catalog_tool.py check` and `./gradlew :shared:model:desktopTest :shared:core:desktopTest :shared:ui:desktopTest :desktopApp:test :app:testDebugUnitTest` |
| Structured status renderer, dynamic status parser, or benchmark status rendering | `./scripts/status_catalog_tool.py check` and `./gradlew :shared:ui:desktopTest` |
| Shared settings/location mutation status helpers | `./gradlew :shared:model:desktopTest :shared:core:desktopTest :shared:ui:desktopTest` |
| `shared/core/` parsing, refresh, selection, shared config builders, config-independent logic | `./gradlew :shared:core:desktopTest` |
| `shared/ui/` Kotlin or localization catalogs | `./scripts/check_localization.py` and `./gradlew :shared:ui:desktopTest` |
| Shared/platform UI theme | `python3 scripts/check_ui_theme.py`, `python3 scripts/test_visual_regression.py`, `./gradlew :shared:ui:desktopTest`, and affected platform compile/test |
| Visual manifest, comparator, capture, review, VM bootstrap, or baselines | `python3 scripts/check_ui_theme.py`, `python3 scripts/test_visual_regression.py`, `python3 scripts/test_visual_platform.py`, `python3 scripts/test_visual_review.py`, agent tool tests, docs/release hygiene; run matching agent capture/verify when the platform is in scope |
| Android UI-only code | `./gradlew :app:compileDebugKotlin` |
| Android profile/import action orchestration | `./gradlew :app:testDebugUnitTest :app:compileDebugKotlin` |
| Android connection command/lifecycle orchestration | `./gradlew :app:testDebugUnitTest :app:compileDebugKotlin` |
| Android Find Best command orchestration | `./gradlew :shared:core:desktopTest :app:testDebugUnitTest :app:compileDebugKotlin` |
| Android installed-app loading/effect orchestration | `./gradlew :app:testDebugUnitTest :app:compileDebugKotlin` |
| Android location mutation, selection, import/export, or location benchmark orchestration | `./gradlew :app:testDebugUnitTest :app:compileDebugKotlin` |
| Android routing draft/import/save orchestration | `./gradlew :shared:core:desktopTest :app:testDebugUnitTest :app:compileDebugKotlin` |
| Android manual subscription refresh orchestration | `./gradlew :app:testDebugUnitTest :app:compileDebugKotlin` |
| Android background subscription refresh status mapping | `./gradlew :shared:core:desktopTest :shared:ui:desktopTest :app:testDebugUnitTest :app:compileDebugKotlin` |
| Android settings or diagnostics orchestration | `./gradlew :shared:core:desktopTest :app:testDebugUnitTest :app:compileDebugKotlin` |
| Android VPN/config/runtime code | `./gradlew :app:compileDebugKotlin` and `./gradlew :app:testDebugUnitTest`; add relevant `app/src/androidTest` tests when practical |
| Disposable full-VPN integration harness | `python3 scripts/test_vpn_integration_fixture.py`, `./gradlew :desktopApp:test :app:compileDebugAndroidTestKotlin`, then dispatch `VPN Integration` with `profile=all` only on hosted disposable runners |
| Desktop service, tray, runtime, lifecycle, autostart, Windows elevation | `./gradlew :desktopApp:test` |
| Desktop service construction, dependency graph, or testing factory | `./gradlew :desktopApp:test` |
| Desktop workspace restore/sync/persist mapping | `./gradlew :desktopApp:test` |
| Desktop runtime status detail assembly | `./gradlew :desktopApp:test` |
| Desktop diagnostics/export status mapping | `./gradlew :desktopApp:test` |
| Desktop settings/dialog/autostart orchestration | `./gradlew :desktopApp:test` |
| Android or desktop self-update flow | `./gradlew :shared:core:desktopTest :shared:ui:desktopTest :desktopApp:test :app:testDebugUnitTest :app:compileDebugKotlin` |
| Arch update bundle | `./scripts/package_arch_desktop_update.sh` and `./scripts/test_arch_desktop_update.sh <bundle>` |
| Desktop connection command/resume/shutdown orchestration | `./gradlew :desktopApp:test` |
| Desktop active-connection naming, selected-location toggle, or subscription-source validation helpers | `./gradlew :desktopApp:test` |
| Desktop subscription refresh orchestration | `./gradlew :desktopApp:test` |
| Desktop per-location benchmark orchestration | `./gradlew :desktopApp:test` |
| Desktop package metadata or bundled runtime extraction | Relevant package script and package smoke tests |
| Linux packaging | `./scripts/package_linux_desktop.sh` |
| Windows packaging | `./scripts/package_windows_desktop_vm.sh` when a VM is available, or `.\scripts\package_windows_desktop.ps1` on Windows |
| macOS packaging | `./scripts/package_macos_desktop.sh` on macOS |
| Documentation only | `git diff --check` and `./scripts/check_docs_hygiene.sh` |
| `agent_tools/`, `.codex/config.toml`, or `.github/required-workflows.json` | `python3 -m unittest discover -s agent_tools/tests`, `./scripts/check_docs_hygiene.sh`, `./scripts/check_release_hygiene.sh`, and `git diff --check`; use the full pre-push tier when lifecycle or CI behavior changes |
| Release workflow/package guardrails | `./scripts/check_release_hygiene.sh`, `./scripts/check_docs_hygiene.sh`, agent tool tests, visual comparator tests, and `git diff --check` |

The `VPN Integration` workflow has two profiles. `core` runs fast deterministic contracts and is advisory on `dev`; `all` additionally runs full traffic on an Android emulator, Windows, Arch Linux, Ubuntu, and Linux Mint, including Linux update install/relaunch. Release readiness accepts only explicit exhaustive VPN success plus a complete exact-SHA agent visual receipt and matching commit status. Never run the full desktop probe on a machine carrying an active VPN connection; its environment opt-in is reserved for disposable runners. Visual capture uses only isolated agent-owned environments or eligible GitHub-hosted ephemeral fallbacks with synthetic fixtures.

When an integration job fails because of application behavior, add the smallest deterministic regression to the fast suite before changing the implementation. Infrastructure-only failures should gain a fixture, script, or workflow-contract test when reproducible.

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

Desktop service extraction patch:

```bash
./gradlew :desktopApp:test
```

Structured status/localization patch:

```bash
./scripts/status_catalog_tool.py check
./scripts/check_localization.py
./gradlew :shared:model:desktopTest :shared:core:desktopTest :shared:ui:desktopTest
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

See `agent_docs/smoke-android.md` for fixture ports and the Trojan opt-in flag.

## Manual Or Risky Checks

Do not run checks that stop the currently active VPN unless the user approves the interruption.

Manual checks are still needed for:

- Real Android VPN permission and traffic behavior outside the hosted emulator.
- Real desktop VPN mode on the supported end-user Linux and Windows environments.
- Windows UAC/elevation behavior.
- Tray integration on the target window manager.
- Autostart after real reboot.
- Live subscription/provider behavior.

When a manual check is skipped, state the reason and name the closest automated coverage that ran.
