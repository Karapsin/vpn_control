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
| Full fast guardrails | Before pushing broad behavior, localization, runtime, agent lifecycle, or release workflow changes | `git diff --check`, release/docs hygiene, agent tool tests, theme/visual comparator checks, localization/status checks, the Gradle command from CI Shortcut, then `python3 scripts/test_desktop_sdk_independence.py` |
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
| Android application JNI/string storage | `./gradlew :app:testDebugUnitTest` builds the real host JNI library and runs constrained-heap/allocator regressions; install pinned SDK tools from `native-runtime-artifacts.md`, then verify API29/API35 packaged behavior |
| Android VPN/config/runtime code | `./gradlew :app:compileDebugKotlin` and `./gradlew :app:testDebugUnitTest`; add relevant `app/src/androidTest` tests when practical |
| Disposable full-VPN integration harness | `python3 scripts/test_vpn_integration_fixture.py`, `./gradlew :desktopApp:test :app:compileDebugAndroidTestKotlin`, then dispatch `VPN Integration` with `profile=all` only on hosted disposable runners |
| Root/module Gradle configuration and Android SDK lookup | `python3 scripts/test_desktop_sdk_independence.py` configures the real desktop task graph with an unavailable SDK; also run affected Android compilation/tests. Included after build setup in Fast Checks and pre-push. |
| Windows installer Gradle graph | `python3 scripts/test_windows_packaging_graph.py` verifies task discovery with configuration on demand and prepared-image dependencies in a minimal real Gradle fixture. Included after build setup in Fast Checks and pre-push. |
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

`TEST-001` in `contracts.md` applies to every distinct failure type found in VM, emulator, native/package, manual, visual, and integration testing. Add the quick reproducer to the relevant routine suite above before fixing the implementation. Kotlin regressions belong in the ordinary shared/desktop/Android unit-test tasks; constrained-heap regressions must run without a device or privileged runtime. New standalone script regressions must be wired into routine hygiene/pre-push and applicable CI, not left as optional commands. Record failing/passing evidence and the suite mapping alongside the native finding. Keep native verification for OS behavior that a host regression cannot faithfully reproduce; a skipped native test is not early regression coverage. Reproducible infrastructure failures require fixture, script, or workflow-contract regressions too.

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

The desktop SDK-independence check configures a real Gradle graph. Run it after
JDK/Gradle setup and the ordinary build tier (managed prepush and Fast Checks),
not in dependency-free release hygiene. Its copied project deliberately omits
local SDK settings while reusing the prepared Gradle dependency cache.

The Windows admission diagnostic behavior suite compiles and executes Java17
stubs, so `scripts/test_windows_install_admission_diagnostic.py` runs after JDK
setup in Fast Checks and Windows packaging, and in managed prepush. It is not
part of dependency-free hygiene. Native Windows reruns must also exercise Unicode
arguments/classpaths and exact packaged JARs; host stub results do not establish
Windows ACL or launcher admission behavior. The public package smoke retains its
original failure even if the additional diagnostic fails.

`scripts/test_fixture_environment.py` belongs in routine release hygiene alongside
the desktop update-fixture and Linux VM preparation suites. These checks cover
effective JDK selection, canonical QEMU arguments, and read-only source extraction;
they do not replace package installation and receipt recovery in disposable guests.

`scripts/test_jpackage_launcher_harness.py` runs in release hygiene on every host.
The actual Linux-only `scripts/test_jpackage_launcher.py --jdk "$JAVA_HOME"` runs
after JDK setup and before the Linux package build. It builds a minimal native
launcher with no application inputs and requires exact stdout, empty stderr and
exit zero. This catches the observed Arch JDK child abort even when its parent
exits zero; the same-patch Temurin comparison passed. Retain installed-package
checks as well: a clean minimal launcher does not establish application behavior.

`scripts/test_arch_public_update.py` exercises real bundle and JAR contents in
routine hygiene. The native public installer driver accepts `--arch-source-fixture`
with `--require-same-source-recovery` for bundle-installed Arch bases. Use the
supported `/opt/vpn-control/bin/vpn-control` installation path: the driver rejects
alternate paths before owner startup or authorization, matching the privileged
Arch adapter. `test_linux_public_install_harness.py` exercises both early rejection
and continued full verification for the supported path in routine hygiene. It verifies
the installed tree against the immutable base archive before owner startup;
DEB/RPM scenarios still require package-manager ownership. Keep harness source
hashes distinct from the immutable package fingerprint when testing older packages.

The opt-in `scripts/test_macos_install_enospc.py` runs in the macOS package job
using its assigned temporary fixture directory. It injects ENOSPC after a partial
write through the production worker's receipt and package-capture paths, requires
the original PREPARING receipt to survive, and verifies real admission rejects a
second attempt with BUSY. A no-fault control exercises successful publication.
These are component persistence tests; they do not replace a full machine install
or resolve an existing uncertain job. Routine hygiene launches them with explicit
skips outside an assigned macOS fixture.

For Windows admission changes, the native coverage inventory includes both
`DesktopWindowsInstallAdmissionTest` and `DesktopWindowsInstallAdmissionNativeTest`,
as well as the native source/process/worker tests. Before a parity checkpoint,
run the complete `:desktopApp:test` suite in the assigned Windows VM from the
actual checkpoint source, record all skips, and retain its XML results. A focused
selection is useful during iteration but did miss an unchanged fixture that
supplied nonexistent launcher files after physical admission began pinning them.
The fixture must represent real files; do not weaken missing-file rejection to
make an obsolete test setup pass.

Native Android domain readback uses `android_routing_evidence.routing_domain_evidence`
from `scripts/android_routing_evidence.py`. Mutation results use `data.direct-domains`;
inspection results use `data.routing.rules.direct_domain_suffixes`. The routine
four-test harness covers both shapes, explicit empty data, malformed/ambiguous
results, and duplicate-domain order. Never default an absent field to an empty
list when making a persistence claim. Controller epoch replacement may reset the
reported revision to zero; compare actual committed payload and owner identity.

## Cancellation And Native Fixture Regressions

`DesktopUpdateCancellationTest` is part of ordinary `:desktopApp:test` and the
applicable package/integration CI selections. Besides real stalled HTTP, its
`cancelledManifestBodyIOExceptionRemainsCancellation` regression forces socket-close
IOException after caller cancellation without network timing; TEST-001 evidence is
in the current WIP ledger. Keep ordinary HTTP failure reporting covered as well.

Release hygiene executes `test_macos_aqua_authorization_correlation.py` directly:
actual process parsing, unmatched/ambiguous prompt rejection, successful public
receipt envelopes and unknown installed state. The observer never sends credentials
or treats a click/process observation as authoritative authorization.

`test_windows_native_helpers.py` also exercises verified app-image staging and
inspection, including byte/policy mismatch rejection. Passing these data-only tests
does not certify the NativeAOT role execution, packaged wiring or MSI replacement.
