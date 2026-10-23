# Test Matrix

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

### Desktop GUI CLI test selection

Desktop GUI CLI test selection starts with this mapping and [Common Combined Checks](#common-combined-checks).
Use applicable CLI, state and desktop lifecycle contracts for native acceptance limits.

### Path mapping

| Touched Area | Run |
| --- | --- |
| Native fixture manifests, staging and rollback drivers | Run the corresponding `scripts/test_native_fixture_manifest.py`, `scripts/test_native_fixture_archive.py`, `scripts/test_native_fixture_payload.py`, `scripts/test_macos_rollback_fixture.py`, `scripts/test_macos_fixture_processes.py` and `scripts/test_windows_prompt_observation.py` suites (also in release hygiene). Keep native package acceptance separate from fixture-unit results. |
| Native fixture completion receipts | `scripts/test_native_fixture_run.py` executes real POSIX children, nonzero exits and competing receipt claims in routine hygiene; Windows explicitly skips this POSIX-only runner. |
| QGA fixture observations | `scripts/test_native_fixture_qga.py` uses actual Unix sockets to cover stalled collectors, stale-response synchronization, bounded/fragmented replies, and read-only file operations. Windows skips this Unix transport suite. Keep guest-exec mutations outside this reader and never replay an installer after observation timeout. |
| Windows native output receipts | `scripts/test_windows_native_fixture.py` runs real PowerShell children and checks empty/nonempty output plus direct exit codes; Windows behavioral cases explicitly skip where PowerShell is unavailable. |
| Android nondebuggable x86 fixture | `scripts/test_android_native_fixture_build_type.py` guards release inheritance, ABI replacement and production hook sources in release hygiene. Also build `:app:assembleNativeFixture` and independently inspect APK ABI, debuggable flag, signer and version before native use. |
| Scheduled-refresh native traffic observer | `python3 scripts/test_desktop_scheduled_refresh_fixture.py` (also included in release hygiene); retain the installed-package scheduled refresh with overlapping traffic evidence. A terminal refresh failure is recorded separately from traffic continuity. |
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
| QMP fixture input admission | `python3 scripts/test_capture_visual_windows_qemu.py` verifies capability negotiation before keys, interleaved events, and error propagation using a bounded fake server; release hygiene runs it. Native account authentication remains separate. |
| Private QEMU fixture assets | `python3 scripts/test_native_fixture_qemu_assets.py` verifies that missing VGA ROMs, changed bytes and escaping symlinks are rejected before VM startup; release hygiene runs it. Native device realization and memory restore remain separate checks. |
| Android SDK/AVD admission | `python3 scripts/test_android_avd_sdk_preflight.py` checks wrong-root symlink rejection for creation, launch-only admission without avdmanager, real wrapper root selection, private AVD environment and exact image metadata. Release hygiene runs it; the executable shell-wrapper scenario explicitly skips on Windows. |
| GitHub workflow parser | `python3 scripts/check_workflow_syntax.py` runs checksum-pinned actionlint over all workflows; `python3 scripts/test_check_workflow_syntax.py` reproduces invalid runner-context placement with the real parser and verifies executable-cache integrity. Both run in release hygiene without an optional installed-tool skip. |
| Windows batch-logon fixture admission | `python scripts/test_windows_task_admission.py` executes the PowerShell helper with injected denied/successful native outcomes and token cleanup. Mandatory in Windows Desktop Package; requires PowerShell and fails if absent. Real account admission and MSI execution remain separate disposable-guest gates. |
| Windows same-source MSI fixtures | `python3 scripts/test_windows_update_fixture_workflow.py` checks the manual dev-only fixture workflow, canonical target version, pinned build setup and restricted artifact/provenance upload. Release hygiene runs it. Hosted pair creation and native installation remain separate gates. |
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
| `agent_tools/`, `.codex/config.toml`, `.mcp.json`, `.claude/settings.json`, or `.github/required-workflows.json` | `python3 agent_tools/affected_agent_tests.py --run`, `./scripts/check_docs_hygiene.sh`, `./scripts/check_release_hygiene.sh`, and `git diff --check`; the complete managed pre-push tier selects affected agent consumers when lifecycle or CI behavior changes |
| Release workflow/package guardrails | `./scripts/check_release_hygiene.sh`, `./scripts/check_docs_hygiene.sh`, agent tool tests, visual comparator tests, and `git diff --check` |

The `VPN Integration` workflow has two profiles. `core` runs fast deterministic contracts and is advisory on `dev`; `all` additionally runs full traffic on an Android emulator, Windows, Arch Linux, Ubuntu, and Linux Mint, including Linux update install/relaunch. Release readiness accepts only explicit exhaustive VPN success plus a complete exact-SHA agent visual receipt and matching commit status. Never run the full desktop probe on a machine carrying an active VPN connection; its environment opt-in is reserved for disposable runners. Visual capture uses only isolated agent-owned environments or eligible GitHub-hosted ephemeral fallbacks with synthetic fixtures.

`TEST-001` in `contracts.md` applies to every distinct failure type found in VM, emulator, native/package, manual, visual, and integration testing. Preserve original failure evidence and relevant unfixed source/file beforeimages before editing. Workers may first implement and test reversible quick fixes within explicit file and environment ownership without coordinator micro-approval; scope, runtime-interruption authorization, unknown-outcome non-replay, and source/artifact provenance gates remain binding. Once the flow works, report the finite encountered failure types, known or unresolved causes, and proposed regression coverage. Then implement each required causal reproducer, run the same test on an isolated owned copy of preserved unfixed source for actual RED and on the fix for GREEN, and wire it into the relevant routine suite above before integration, push, or completion; proposed coverage alone does not satisfy TEST-001. Preserve and rerun the original native scenario against the fixed artifact without reverting shared or live native state for RED. Kotlin regressions belong in the ordinary shared/desktop/Android unit-test tasks; constrained-heap regressions must run without a device or privileged runtime. New standalone script regressions must be wired into routine hygiene/pre-push and applicable CI, not left as optional commands. Record failing/passing evidence and the suite mapping alongside the native finding. Keep native verification for OS behavior that a host regression cannot faithfully reproduce; a skipped native test is not early regression coverage. Reproducible infrastructure failures require fixture, script, or workflow-contract regressions too.

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

## Focused Check References

Use the touched-path row above first, then the relevant focused note. The notes
retain complete causal records, routine-suite enrollment, platform skips, command
arguments and native acceptance limitations. Recorded passing counts do not
establish current acceptance. [AGENTS.md](../AGENTS.md) governs workflow and
[contracts.md](contracts.md) remains the product-invariant authority.

| Boundary | Focused reference |
| --- | --- |
| Agent runner, affected selector, SSH/DIRECT custody, Android observers, engineering context, GUI/native orchestration | [Agent custody regressions](testing/agent-custody-regressions.md) |
| Desktop/Android owner behavior, frontend and visual capture, platform admission, update/runtime package regressions | [Product and package regressions](testing/product-package-regressions.md) |
| Complete fast CI command set | [CI Shortcut](testing/ci-shortcut.md#ci-shortcut) |
| Android instrumentation, manual/risky checks, installed-package and platform prerequisites | [Native acceptance gates](testing/native-acceptance.md) |
| Native fixture preparation, cancellation, portable/OS-only coverage and MCP workflow regressions | [Native regressions](testing/native-regressions.md) |
| Source custody and historical text | [Migration manifest](testing/migration-manifest.md), [historical source snapshot](archive/parity/2026-10-14/test-matrix-original.md) |

## Previous Section Routes

These fragment redirects retain the original section identities; follow the
linked focused note for the complete requirements and source-bound results.

<a id="runner-self-input-ssh-fixture-custody-and-android-owner-admission"></a>[Runner self-input, SSH fixture custody and Android owner admission](testing/agent-custody-regressions.md#runner-self-input-ssh-fixture-custody-and-android-owner-admission)

<a id="original-actor-identity-and-isolated-package-markers"></a>[Original actor identity and isolated package markers](testing/agent-custody-regressions.md#original-actor-identity-and-isolated-package-markers)

<a id="retained-android-os-and-result-observations"></a>[Retained Android OS and result observations](testing/agent-custody-regressions.md#retained-android-os-and-result-observations)

<a id="refresh-status-and-deterministic-complete-visual-capture"></a>[Refresh-status and deterministic complete visual capture](testing/product-package-regressions.md#refresh-status-and-deterministic-complete-visual-capture)

<a id="launcher-collector-test-fixture-isolation"></a>[Launcher collector test fixture isolation](testing/agent-custody-regressions.md#launcher-collector-test-fixture-isolation)

<a id="frozen-engineering-source-and-first-observation-collection"></a>[Frozen engineering source and first-observation collection](testing/agent-custody-regressions.md#frozen-engineering-source-and-first-observation-collection)

<a id="agent-test-selection-and-measured-execution"></a>[Agent test selection and measured execution](testing/agent-custody-regressions.md#agent-test-selection-and-measured-execution)

<a id="ci-shortcut"></a>[CI Shortcut](testing/ci-shortcut.md#ci-shortcut)

<a id="early-prepush-ssh-dependency-gate"></a>[Early prepush SSH dependency gate](testing/agent-custody-regressions.md#early-prepush-ssh-dependency-gate)

<a id="selected-arch-descendant-routing"></a>[Selected Arch descendant routing](testing/agent-custody-regressions.md#selected-arch-descendant-routing)

<a id="linux-gui-lifecycle-source-custody-and-cleanup"></a>[Linux GUI lifecycle source custody and cleanup](testing/agent-custody-regressions.md#linux-gui-lifecycle-source-custody-and-cleanup)

<a id="mcp-responsiveness-and-linux-download-recovery"></a>[MCP responsiveness and Linux download recovery](testing/agent-custody-regressions.md#mcp-responsiveness-and-linux-download-recovery)

<a id="mac-artifact-selection-and-linux-fixture-admission"></a>[Mac artifact selection and Linux fixture admission](testing/agent-custody-regressions.md#mac-artifact-selection-and-linux-fixture-admission)

<a id="windows-compressed-task-and-inert-preflight"></a>[Windows compressed task and inert preflight](testing/agent-custody-regressions.md#windows-compressed-task-and-inert-preflight)

<a id="android-owner-drafts-and-collector-deadline"></a>[Android owner drafts and collector deadline](testing/agent-custody-regressions.md#android-owner-drafts-and-collector-deadline)

<a id="local-openssh-option-parser-controls"></a>[Local OpenSSH option parser controls](testing/agent-custody-regressions.md#local-openssh-option-parser-controls)

<a id="held-source-mode-handoff-controls"></a>[Held-source mode handoff controls](testing/agent-custody-regressions.md#held-source-mode-handoff-controls)

<a id="local-fixture-isolation-under-full-discovery"></a>[Local fixture isolation under full discovery](testing/agent-custody-regressions.md#local-fixture-isolation-under-full-discovery)

<a id="completed-direct-connection-history-controls"></a>[Completed DIRECT connection history controls](testing/agent-custody-regressions.md#completed-direct-connection-history-controls)

<a id="original-channel-and-readonly-collection-controls"></a>[Original channel and readonly collection controls](testing/agent-custody-regressions.md#original-channel-and-readonly-collection-controls)

<a id="current-ssh-close-dependency-controls"></a>[Current SSH close dependency controls](testing/agent-custody-regressions.md#current-ssh-close-dependency-controls)

<a id="macos-acl-fixture-command-lifecycle"></a>[macOS ACL fixture command lifecycle](testing/product-package-regressions.md#macos-acl-fixture-command-lifecycle)

<a id="desktop-input-acquisition-failure-parity"></a>[Desktop input acquisition failure parity](testing/product-package-regressions.md#desktop-input-acquisition-failure-parity)

<a id="windows-update-admission-and-denied-input-controls"></a>[Windows update admission and denied input controls](testing/product-package-regressions.md#windows-update-admission-and-denied-input-controls)

<a id="native-orchestration-regressions"></a>[Native orchestration regressions](testing/agent-custody-regressions.md#native-orchestration-regressions)

<a id="android-instrumentation"></a>[Android Instrumentation](testing/native-acceptance.md#android-instrumentation)

<a id="manual-or-risky-checks"></a>[Manual Or Risky Checks](testing/native-acceptance.md#manual-or-risky-checks)

<a id="cancellation-and-native-fixture-regressions"></a>[Cancellation And Native Fixture Regressions](testing/native-regressions.md#cancellation-and-native-fixture-regressions)

<a id="compose-frontend-process-exit"></a>[Compose frontend process exit](testing/native-regressions.md#compose-frontend-process-exit)

<a id="isolated-native-update-package-builds"></a>[Isolated native update package builds](testing/native-regressions.md#isolated-native-update-package-builds)

<a id="https-fixture-address-family-admission"></a>[HTTPS fixture address-family admission](testing/native-regressions.md#https-fixture-address-family-admission)

<a id="owned-macos-vm-resource-monitor"></a>[Owned macOS VM resource monitor](testing/native-regressions.md#owned-macos-vm-resource-monitor)

<a id="scoped-native-fixture-preparation"></a>[Scoped native fixture preparation](testing/native-regressions.md#scoped-native-fixture-preparation)

<a id="native-mcp-workflow-regressions"></a>[Native MCP workflow regressions](testing/native-regressions.md#native-mcp-workflow-regressions)

<a id="retained-direct-wrapper-transition-controls"></a>[Retained DIRECT wrapper transition controls](testing/agent-custody-regressions.md#retained-direct-wrapper-transition-controls)

<a id="direct-local-refusal-reason-controls"></a>[DIRECT local refusal reason controls](testing/agent-custody-regressions.md#direct-local-refusal-reason-controls)

<a id="original-android-host-status-capture-and-linux-holder-parsing"></a>[Original Android host-status capture and Linux holder parsing](testing/agent-custody-regressions.md#original-android-host-status-capture-and-linux-holder-parsing)

<a id="api35-current-cli-process-epoch"></a>[API35 current CLI process epoch](testing/agent-custody-regressions.md#api35-current-cli-process-epoch)

<a id="protected-rich-linux-resource-consumer"></a>[Protected rich Linux resource consumer](testing/agent-custody-regressions.md#protected-rich-linux-resource-consumer)
