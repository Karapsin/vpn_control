# Product and package regression notes

This focused note preserves test-selection instructions and source-bound regression
records from `agent_docs/test-matrix.md` at `3944739d3f33` (2026-10-14).
Passing counts, timings, checkpoint words such as “current”, and native observations
are historical claims for that source and scope, not fresh acceptance or permission
to replay operations. Commands remain mapped check references; apply current
[contracts](../contracts.md), [validation tiers](../test-matrix.md#validation-tiers)
and the [active ledger](../work-in-progress.md) before use. Preserve every stated
skip, uncertainty, causal RED/GREEN requirement and separate native gate below.

## Refresh-status and deterministic complete visual capture

After changing the desktop subscription status consumer or its neutral catalog
label, run `:desktopApp:test --tests com.kardinal.vpncontrol.desktop.DesktopProfileRefreshStatusTest`,
`:shared:ui:desktopTest` and `python3 scripts/check_localization.py`. Eight actual
owner/frontend row tests cover legacy/private/unavailable, empty and typed results.
Normal desktop/prepush/Fast Checks discover the class without special enrollment.

The two `VisualCaptureTest` stress pointer regressions must seed the exact hover
color and demand complete frame equality after the real capture helper. Run
`narrowStressCaptureClearsInheritedPointerHover` and
`largeFontStressCaptureClearsInheritedPointerHover` through ordinary desktop tests.
Native Windows recapture remains a separate acceptance gate.

`python3 scripts/test_visual_regression.py` retains16 comparator controls, including
actual PNG differences and manifest admission for prohibited masks. Existing
release hygiene/prepush/Fast Checks execute it. VISUAL-004 requires complete image
comparison and deterministic capture, including OS-owned surfaces; tests do not
authorize mask exceptions, threshold changes or native acceptance promotion.

Use this matrix to choose the smallest useful validation set for a patch. Add more tests when the touched code crosses boundaries.

## macOS ACL fixture command lifecycle

`DesktopMacBootSessionRecoveryTest` preserves the real everyone-write grant,
0600 mode and product boot-token rejection. Its owned command helper retains the
10-second execution deadline and treats timeout/nonzero exit as failures, while
killing/waiting/reaping and closing streams before token cleanup. The timed-out
inert-child regression requests that same10-second deadline and substitutes only
its own100ms wait; authentic prior decisions fail the orphan assertion. The full
candidate class passes14 tests without skips on macOS. These controls join normal
`:desktopApp:test` and Fast Checks; other hosts retain explicit Darwin skips.
Historical chmod stall cause remains UNKNOWN, and complete native macOS installer
acceptance remains separate.

## Desktop input acquisition failure parity

`DesktopInputResultTest` runs through ordinary `:desktopApp:test` discovery and
Fast Checks. It covers allocation failure before location/routing owner admission,
SSH input failure without constructing an action, silent picker cancellation,
unchanged successful input/controller/revision, and the actual CLI request builder.
Run it with `DesktopTextTransferTest`, `DesktopCliJsonTest`,
`DesktopFrontendSshKeyImportTest`, `DesktopLocationCliEndToEndTest`,
`DesktopRoutingCliEndToEndTest` and
`DesktopLargeControlTransportTest.cliRoutingImportAndGuiSnapshotKeepLargeCommittedResults`.
Controlled allocation exceptions exercise the original callback decisions; they
do not prove real heap exhaustion, native picker/clipboard behavior or dialog
rendering. Preserve those native GUI acceptance gates.

## Windows update admission and denied input controls

Ordinary `:desktopApp:test` discovers `DesktopWindowsDeniedInputCleanupTest`,
including real journal capacity, native-error authority, same-owner service
maintenance, exact object/byte disposal, close-debt retry and actual preparation
admission. Its explicit syscall model does not replace native UAC/NTFS cleanup.
`DesktopWindowsInstallAdmissionTest` covers the locked reservation-byte fallback;
`DesktopWindowsInstallAdmissionNativeTest` checks actual Win32 ranges on an inert
owned file. The native test skips explicitly outside Windows. Preserve complete
installed update, ready acknowledgement, original-user return, denial, cold-owner
recovery and equivalent MCP scenarios as separate acceptance gates.

`DesktopWindowsCoordinatorAdapterTest` includes three return-lease controls:
terminal gate release before exact-child reconciliation, five uncertain
publication/result/pending-clear cases retaining gates and witnesses, and
independent cleanup preserving the first failure. The fixture compiles complete
production adapter/role classes and uses real semaphores and retained files for
external facilities. Ordinary desktop tests discover these Windows-only cases;
they skip explicitly on other hosts. Local C# fixture success does not prove
Win32 range unlocking, MSI execution or packaged automatic app return.
`test_windows_msi_public_scenario` also checks that a bound successful protected
receipt retains the separate target/return/cleanup verification requirements,
without promoting unbound receipts or authorizing replay.

`test_windows_cp117_historical_package_source` binds the inert historical factory
to its original public-module source, including exact bytes, pair guards, source
drift refusal and reference restoration. Current public MCP bindings remain
unchanged. Run it with the six CP117 historical factory consumer modules after
changing their current dependencies; source generation is not native admission.

`test_managed_checks_source_freshness` covers stale/missing check-runner source
before inspection/lease/dry-run, unchanged content after touch, changes between
commands and final-command drift blocking receipt publication. It runs in normal
agent-tool discovery, managed prepush and Fast Checks. Pair it with
`test_mcp_server`, `test_managed_check_lease`, `test_check_output_retention` and
`test_mcp_check_failure_output` for check-runner changes. It does not prove atomic
publication or native filesystem authority.

The named-profile `test_windows_guest_input` has33 controls in ordinary agent
discovery, including seven actual configuration tests/121 decisions. Its valid
large-frame case exercises dispatch, emitted main, retained collector and a real
local QMP socket, asserting all five required frames and three actual broker
packets with exact final Alt+Y. Stdout is finite at18,874,386 bytes; optional
observations consume that same budget and may exhaust it to UNKNOWN. Win32/proc/
QGA verdicts remain modeled, and current-source native MCP acceptance stays open.
Its real retained-FD latch covers collector/foreground rehash serialization;
separate byte-mutation and named-replacement cases preserve UNKNOWN/non-replay.
All three methods run through existing discovery and Fast Checks enrollment.

## Product regression and artifact boundaries

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
Its Linux missing-`objcopy` regression also rejects an absent `binutils`
prerequisite before creating immutable stage outputs or invoking Gradle. This
covers the Fedora native `jlink` failure; keep the package build replay as native
evidence alongside the routine script test.
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

For a native JUnit 4 selection, export `VPN_CONTROL_NATIVE_TEST_CLASSPATH` from the
verified frozen host test bundle (including its test classes and JUnit dependency),
then run `"$JAVA_HOME/bin/java" -cp "$VPN_CONTROL_NATIVE_TEST_CLASSPATH"
com.kardinal.vpncontrol.desktop.NativeExecutionJUnitGate <fully.qualified.TestClass>`.
The test-only gate emits JSON counts plus `NATIVE_JUNIT_EXECUTION_GATE_OK` only when
at least one test ran and there were zero ignored tests, assumption failures, and
failures; any other result has a nonzero exit and cannot certify native execution.

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
It also covers an acknowledged staging push followed by a lost mount response:
retain the possibly mounted source until authoritative unmount reconciliation.
These tests do not establish Android trust or installation behavior; retain the
nondebuggable API29/API35 native scenarios. Relabel only newly created, validated
staging entries to the captured certificate-store context; never change system
certificate files, SELinux policy/enforcement, or host trust.

`scripts/test_android_installer_lifecycle.py` runs in release hygiene. Exercise
the real argument-to-action path so both `--continue-file` and
`--handoff-ready-file` reach the installer callback. Successful replacement runs
must durably capture the original controller/operation/receipt/session before OS
approval, then reconcile that exact receipt through the replacement owner without
querying its old in-memory operation. Cover two TTY prompts, distinct private file
callbacks, foreign pre-approval owners, typed session IDs, bounded unknown outcomes,
artifact identity and cleanup. This tests fixture coordination, not OS confirmation
or installer recovery; retain the API29/API35 native cases.

`scripts/test_android_subscription_refresh_lifecycle.py` runs in release hygiene.
It checks the public add/refresh/wait/delete sequence, owner binding, an initially
empty subscription cache, explicit fetch evidence, original source restoration,
and retention after an uncertain mutation. These fixture regressions do not prove
device network trust, runtime recovery, or scheduled refresh; retain native cases.

`scripts/test_macos_rollback_fixture.py` also covers explicit receipt authority:
machine receipts must use the protected /Library root, user-local receipts use the
specified owner home, and failures never fall back across authorities. Candidate
flag changes require the retained exact identity. The ordinary owner predicate
uses the shared process-role parser so sudo/launchctl wrappers do not become extra
owners. Keep Windows-path/mocked Unix-identity vectors in this portable fixture
suite and native protected machine rollback as a separate gate.

`scripts/test_macos_fixture_owner_launch.py` runs in release hygiene. The actual
launcher checks the active console identity and GUI bootstrap session before an
ordinary-user owner is launched through `launchctl asuser`; failed preflight must
not start an owner. Remote macOS paths use POSIX semantics on every host. Retain
the native headless `INTERACTION_REQUIRED` scenario separately from Aqua prompt
and delayed-cancellation acceptance.

`scripts/test_linux_vpn_fixture_guard.py` runs in release hygiene. The native
Linux fixture inspects the exact extracted runtime binary with `findmnt` and
`getcap`: a capability xattr does not confer privileges on a `nosuid` mount.
Reject unavailable/malformed mount evidence, `nosuid`, `noexec`, capabilities for
a different path, and missing effective/permitted capabilities before VPN start.
A local HTTP regression verifies explicit DNS resolution while preserving the
synthetic Host header; use the same probe builder for the native TUN fixture.
These checks establish fixture prerequisites, not real TUN or traffic acceptance.

