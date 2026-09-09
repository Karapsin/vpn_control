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
./gradlew :shared:model:desktopTest :shared:core:desktopTest :shared:ui:desktopTest :desktopApp:test :app:testDebugUnitTest :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin :app:verifyDebugAndroidTestSignatures
python3 scripts/test_android_instrumentation_signatures.py
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
| Android instrumentation tests or runner/signature wiring | `./gradlew :app:verifyDebugAndroidTestSignatures` compiles tests and checks actual JUnit bytecode before packaging or connected execution. `python3 scripts/test_android_instrumentation_signatures.py` exercises compiler dependencies and invalid/valid signatures without an emulator. Both run in Fast Checks and pre-push; keep the exact native scenario. |
| Disposable full-VPN integration harness | `python3 scripts/test_vpn_integration_fixture.py`, `./gradlew :desktopApp:test :app:compileDebugAndroidTestKotlin`, then dispatch `VPN Integration` with `profile=all` only on hosted disposable runners |
| Root/module Gradle configuration and Android SDK lookup | `python3 scripts/test_desktop_sdk_independence.py` configures the real desktop task graph with an unavailable SDK; also run affected Android compilation/tests. Included after build setup in Fast Checks and pre-push. |
| Windows installer Gradle graph | `python3 scripts/test_windows_packaging_graph.py` verifies task discovery, prepared-image dependencies, native-helper producer failure, bundled-runtime input invalidation and verified staging before EXE/MSI in a minimal real Gradle fixture. Included after build setup in Fast Checks and pre-push. |
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

`DesktopCliStreamPipeTest` runs in ordinary desktop tests. It closes real child
stdout/stderr readers while log history remains empty, and also verifies healthy
pipes and regular files keep following. Keep the native ADB/package scenarios;
a throwing printer mock cannot reproduce closure during a suppressed empty poll.

`DesktopSearchCancellationCliTest` exercises public Find Best/benchmark cancellation
through the real operation owner and service cleanup, including delayed actual-runtime
recovery, failed recovery, unknown outcomes and preservation of pending selection.
`DesktopFrontendInstanceTest` exercises automatic public-QUIT-to-frontend closure
through authenticated endpoints; normal-quit gate/receiver/sender tests reject
mismatched identities, retain response-loss retries and distinguish unknown from
confirmed process exit. These run in ordinary desktop tests; keep the installed
package and live-traffic scenarios as separate native acceptance.

`test_macos_packaging_jdk_preflight.py` runs in release hygiene. It checks actual
JVM property parsing, selected-launcher arguments, known Homebrew packaging
rejection, Java major and native architecture. `test_desktop_update_fixture.py`
verifies rejection precedes build-directory creation and native build execution.
Compose's own packaging vendor check remains enabled; passing this focused
preflight is not blanket approval of other JDK distributions.

`scripts/test_windows_broker_fixture_observer.py` runs in release hygiene. Its
portable tests exercise the actual read-only ready/exit consumers: auxiliary
console children cannot replace the captured runtime PID/generation/hash, and a
retained process handle's generation and exit signal are checked before an image
query that can fail after exit. Unavailable observations remain unknown. Two
additional Windows-native cases inspect the current process and an inert child;
these must execute on Windows and are explicit skips on other hosts.
The self-image smoke compares filesystem identity so a Python executable hardlink
alias does not fail on path spelling. Two portable cases use real files to accept
the same inode and reject identical bytes in a different file. This changes only
the smoke assertion; captured broker admission continues to require its exact path.

Desktop update fixture setup uses `require_selected_location` before ON and
`require_active_runtime` before an installer scenario; add does not select.
`fixture_proxy_arguments` derives JVM proxy properties from the captured server
ready manifest. The existing `test_desktop_update_fixture.py` routine selection
covers missing/wrong stable selection, disconnected runtime and dynamic proxy
port derivation so these setup mistakes fail before another native attempt.

`scripts/test_native_fixture_signal.py` runs in routine hygiene. Its partial-write
and staged-path collision regressions ensure native readers see complete fixed
acknowledgments and failed exclusive creation never deletes another file. Signals
publish through an exclusive atomic hard link; publication uncertainty retains
staging, and cleanup failure does not erase known publication. Keep the real
Windows callback RED/GREEN and the scoped TUN scenario: portable tests do not
establish privileged runtime readiness.

Desktop SSH runtime regressions exercise A start, committed key B import, failed
candidate start and recovery reading A's captured private key. They also assert
candidate cleanup after validation failure and preserve the committed credential.
The focused selection includes DesktopProxyRuntimeManagerTest,
DesktopHomeSshPersistenceTest, DesktopGuardedSshKeyTest, DesktopSshCliTest and
DesktopFrontendSshKeyImportTest; native JVM launch uses frozen inputs and explicit
preflight. DesktopRuntimeRestoreCredentialTest and DesktopRuntimeRestoreLeaseTest
exercise successful intermediate B, post-start persistence failure, retained A key
bytes and closing a restore handle while it waits behind another transition.
DesktopRuntimeMutationTransactionTest, DesktopSubscriptionRefreshServiceTest and
DesktopFindBestServiceTest check terminal release and unresolved-outcome retention.
DesktopOperationProgressTest and DesktopOperationRetainedInputsTest exercise the
actual operation owner across unknown/native-confirmed completion, ended uncertain
actions, returned uncertain codes, cleanup failure and explicit terminal retry.
Unknown results must retain their exact inputs without replay; cleanup failure must
not erase known committed success. Keep these in the routine desktop test tier.
These run in the routine desktop test tier. Native Find Best/SSH traffic recovery
remains a separate acceptance requirement; inert child adapters do not prove it.

Android SingBoxConfigFactoryParityTest includes the causal API29 TCP stack guard.
Keep the nondebuggable APK comparison with a separate-UID raw TCP probe and native
TUN/outbound correlation on API29/API35; the fast emitted-config assertion catches
stack regressions but does not replace real traffic or background lifecycle checks.

DesktopWindowsOutputNativeTest runs by default in the Windows desktop test tier
using the repository-pinned modern .NET SDK, direct dotnet execution and the actual
broker/config/original-user/publication sources. Its17 native cases cover retained
file-handle rewinds, complete large-input copies, console and file log destinations,
mixed CACHE/OUTPUT descriptors, duplicate destinations, late writes and publication
conflicts. Foreign platforms explicitly skip this Windows-only test. Missing SDK
on Windows is a failed prerequisite. Preserve the actual runtime log-semantics and
packaged privileged-helper scenarios alongside this inert native regression.

`scripts/test_native_jvm_tests.py` exercises the reusable JVM launch gate before
JUnit dispatch. A failed native image/path probe or missing success marker cannot
launch the suite; test failures and literal argv survive successful admission.
With Java tools available, it compiles `NativeJvmPreflight.java` for Java17 and
checks the actual interpreter identity, readable dependency, missing dependency
and wrong-image rejection. Set `JAVA_HOME` to the selected real JDK; an unusable
configured toolchain fails rather than silently substituting another JDK.
Native bundles include the compiled probe and use `run_native_jvm_tests` under
their intended user after verifying all artifact hashes. Keep the selected Java
and dependency bundle immutable across the separate probe and JUnit launches;
this fixture gate does not secure a concurrently replaced interpreter. The probe changes no
permissions and cannot establish runtime/VPN or installed-package acceptance.
For an owned JRE-only guest, `VPN_CONTROL_NATIVE_JVM_PROBE_CLASSES` may point to
the hash-verified frozen probe directory to run the three actual Java checks;
record compilation on the build host separately from execution in the guest.

`scripts/test_android_ssh_fixture.py` checks the actual fixture log consumer:
fresh log/receipt claims before spawn, startup marker and same-read authentication,
replacement/truncation/missing log rejection, retained child identity on unknown
startup and post-spawn receipt-write failure, and live-handle authentication observation. These portable fake-process
tests run in routine hygiene. Actual `sshd -E` and owner-only mode verification
belong to the owned POSIX fixture; Windows execution does not certify POSIX modes
or ACLs. The setup-only CLI receipt is correlation data, never kill authority or
proof of later authentication. Keep the real A/B traffic scenario and current
log observer alive together; historical log bytes cannot certify a new attempt.

`scripts/test_native_python_tests.py` runs in release hygiene. Its real child-process
regression catches Windows path backslashes being interpreted as Python escapes
before a VM is needed. The reusable `native_python_request` builder supplies paths
through argv, changes only the child PATH, preserves test failure exits/evidence,
and rejects empty suites. Native fixture drivers use it with a verified interpreter
and tool directories in their owned guest; it does not provision tools or establish
their provenance. Keep the native Windows launch as a separate acceptance check.

`scripts/test_android_no_update_tls_preflight.py` also runs in release hygiene.
It exercises the actual disposable-fixture driver: exact APK/OFF baseline,
Android legacy CA filename, staging-only relabeling, failed setup rollback,
changed-zygote cleanup retention, and nonzero cleanup failures with evidence.
These tests do not establish Android trust or installation behavior; retain the
nondebuggable API29/API35 native scenarios. Relabel only newly created, validated
staging entries to the captured certificate-store context; never change system
certificate files, SELinux policy/enforcement, or host trust.

`scripts/test_macos_fixture_owner_launch.py` runs in release hygiene. The actual
launcher checks the active console identity and GUI bootstrap session before an
ordinary-user owner is launched through `launchctl asuser`; failed preflight must
not start an owner. Remote macOS paths use POSIX semantics on every host. Retain
the native headless `INTERACTION_REQUIRED` scenario separately from Aqua prompt
and delayed-cancellation acceptance.

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
python3 scripts/run_android_instrumented_tests.py --serial emulator-5592 \
  --class com.kardinal.vpncontrol.data.SingBoxConfigFactoryInstrumentedTest
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
python3 scripts/run_android_instrumented_tests.py --serial emulator-5592 \
  --class com.kardinal.vpncontrol.ui.ImportExportActionsInstrumentedTest
python3 scripts/run_android_instrumented_tests.py --serial emulator-5592 \
  --class com.kardinal.vpncontrol.ui.ImportExportErrorInstrumentedTest
python3 scripts/run_android_instrumented_tests.py --serial emulator-5592 \
  --class com.kardinal.vpncontrol.ui.ImportExportMenuVisibilityInstrumentedTest
```

Protocol parser patch:

```bash
python3 scripts/run_android_instrumented_tests.py --serial emulator-5592 \
  --class com.kardinal.vpncontrol.data.ProxyParserInstrumentedTest
./gradlew :shared:core:desktopTest
```

## Android Instrumentation

Run Android instrumentation only on the explicitly assigned device or emulator:

```bash
python3 scripts/run_android_instrumented_tests.py --serial emulator-5592
```

Prerequisites:

- Reidentify the owned device in `adb devices`; replace the example serial above.
- The debug build can be installed on that device.
- VPN permission prompts may still require manual interaction for tests that exercise real VPN flows.

The launcher uses AGP's early `ANDROID_SERIAL` device-provider filter. Do not use
Gradle's `--serial` option with AGP 8.7.3: its later filter mutates an immutable
device list and fails before instrumentation starts. The release-hygiene regression
`test_android_instrumented_launcher.py` verifies one-device selection, invalid
serial rejection and failure/cancellation propagation without retry. A successful
launcher can still report a failing instrumented test; retain that native result.

Run local protocol smoke tests only when local fixture servers are available:

```bash
python3 scripts/run_android_instrumented_tests.py --serial emulator-5592 \
  --class com.kardinal.vpncontrol.data.LocalProtocolSmokeInstrumentedTest
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
or treats a click/process observation as authoritative authorization. A subprocess
regression removes `os.getuid` before launching the real parser/correlation suite,
reproducing Windows' missing Unix API on every host without skipping these tests.

`macos_fixture_frontend.py` closes one reidentified fixture frontend by PID using
SSH and its guest Aqua session. The release-hygiene test checks exact argument
separation, positive identities, the close button and explicit unknown outcome on
transport timeout. The helper never selects a frontmost app, retries a timeout or
kills a frontend. Before use, confirm the assigned disposable guest and a visible
window; a windowless close-to-tray process is not a failed-close reproduction.

`test_windows_native_helpers.py` also exercises verified app-image staging and
inspection of both fixed helpers, including missing-broker and byte/policy mismatch
rejection. It also covers missing/malformed runtime authority, changed generated
source, and changed/duplicate packaged runtime resources. Passing these data-only tests
does not certify the NativeAOT role execution, packaged wiring or MSI replacement.
The Windows package workflow builds both pinned NativeAOT projects before the app
image. Extracted and installed MSI checks verify both manifest/PE records, execute
the installer helper's nonmutating `validate-only` probe and require the broker to
reject missing arguments and a mismatched compiled runtime digest before admission.
The producer hashes the prepared bundled AMD64 runtime into generated build output;
the broker project fails without that authority, and Gradle tracks the runtime as
an input. Native installer/UAC/recovery scenarios remain separate acceptance requirements.

`test_android_fixture_preflight.py` runs in release hygiene. It reproduces the
fixture inspection that cleared an uncaptured selection and requires a final,
authoritatively stopped, explicitly unselected state before switching source scope.
The helper returns the observed controller/revision for the actual mutation guard;
it does not authorize replay after owner replacement or restore a lost selection.

`DesktopWindowsBrokerEntrypointTest` runs three native compiler fixtures for missing,
mismatched and matching compiled runtime authority without launching a runtime.
`DesktopWindowsMutableBrokerNativeTest` includes metadata, configuration and commit
ordering checks in ordinary Windows tests. Its two inert-child pipe cases require
`VPN_CONTROL_TEST_SCOPED_BROKER_MUTABLE=1` only in the assigned disposable VM. They
cover post-exit cache publication, repeated admission and a9MiB configuration,
retaining protected journals when cleanup is unproven. Record exact Java wrapper
execution as well as native source tests; neither enables the production broker.

The early Windows package checks run `test_windows_native_helper_builder.ps1` with
Windows PowerShell, matching the Gradle producer's shell. Private inert executables
exercise the actual producer with explicit paths and duplicate applications in
both PATH orders. This catches application discovery joining several executable
paths into one invalid command before the expensive native build starts.

Android disposable HTTPS fixture transport regressions run through
`test_android_fixture_transport.py` in release hygiene. They model adbd restart
loss of reverse mappings and preserve unrelated route/proxy ownership through
setup, cleanup failure and retry. Native callers must additionally reidentify the
owned AVD and check mappings before any setup-time adbd restart. Public product
commands always run with verified UID2000.

`test_android_fixture_trust.py` uses the development host's OpenSSL executable to
verify legacy Android CA subject-hash naming with an ephemeral certificate and
checks the namespace command separator without mounting anything. The fixture
helper never installs host trust. Windows byte-bound native policy/loader inputs
have explicit LF Git attributes; `test_windows_native_helpers.py` exercises a real
`core.autocrlf=true` checkout and verifies exact bytes, in addition to producer and
Kotlin fixture agreement.

`DesktopMacAuthorizationLifetimeTest` and `DesktopMacUpdateServiceTest` cover late exact rejection, receipt-authority conflicts,
retryable cleanup and owner-only maintenance. These are ordinary desktop tests;
retain packaged late-denial verification separately, including active traffic.
