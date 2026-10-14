# Native fixture and platform regression notes

This focused note preserves test-selection instructions and source-bound regression
records from `agent_docs/test-matrix.md` at `3944739d3f33` (2026-10-14).
Passing counts, timings, checkpoint words such as “current”, and native observations
are historical claims for that source and scope, not fresh acceptance or permission
to replay operations. Commands remain mapped check references; apply current
[contracts](../contracts.md), [validation tiers](../test-matrix.md#validation-tiers)
and the [active ledger](../work-in-progress.md) before use. Preserve every stated
skip, uncertainty, causal RED/GREEN requirement and separate native gate below.

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

On Windows, `DesktopWindowsCoordinatorNativeAdmissionTest` and
`DesktopWindowsOriginalUserLaunchTest` always compile their actual C# fixtures with
the repository-pinned `.NET` SDK in `native/windows/global.json` under the selected
JDK test run. The original-user fixture enables the NativeAOT analyzer with warnings
as errors, catching unsupported marshaling APIs before full package publication.
Before its interactive opt-in gate, the original-user fixture also runs the actual
self-image pin from a private current-user apphost directory. It verifies exact
image identity, permits the bound user and rejects an unrelated principal. This
requires no desktop shell, UAC, installer role or system-directory mutation.
Its clean restore uses only the official NuGet feed for the pinned SDK's analyzer
package; an unavailable dependency is a failed prerequisite, not a skipped pass.
The coordinator's ProgramData ACL/process-authority probe additionally
requires `VPN_CONTROL_NATIVE_COORDINATOR_ADMISSION=1` in an owned disposable admin
VM. The original interactive-token proof additionally requires
`VPN_CONTROL_NATIVE_ORIGINAL_USER_LAUNCH=1` in an owned interactive VM (or JVM property
`vpn.control.native.interactiveOriginalUser=true` when invoking JUnit directly). Both
opt-ins skip by default; neither proves the distinct administrator case, which
remains a manual required check.

`test_android_fixture_preflight.py` runs in release hygiene. It reproduces the
fixture inspection that cleared an uncaptured selection and requires a final,
authoritatively stopped, explicitly unselected state before switching source scope.
The helper returns the observed controller/revision for the actual mutation guard;
it does not authorize replay after owner replacement or restore a lost selection.

`scripts/test_android_update_fixture.py` imports
`AndroidUpdateFixtureCertificateSanTest`, so its existing release-hygiene entry also
runs the Android update-fixture certificate-SAN regressions: a CN-only leaf is
rejected before evidence creation, while a DNS-SAN leaf serves the hostname-verifying
client.

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

### Compose frontend process exit

`DesktopComposeApplicationExitTest` runs the production frontend application
boundary in a child JVM and verifies that the enclosing cleanup executes. It
creates no window, product workspace, controller, or VPN runtime. The actual
Compose application still reads screen configuration, so Linux hosts without
`DISPLAY` require `xvfb` and `xauth`; the test uses `xvfb-run -a` and does not skip
when the prerequisite is missing. Fast Checks installs both packages. This quick
regression belongs to ordinary desktop tests and prepush; retain the packaged
normal-close/immediate-show traffic scenario as separate native evidence.

### Isolated native update package builds

The desktop fixture builder's `build --confirm-owned-native-host-build` permits
build-only package capture on an authorized native build host. It preserves the
same clean source snapshot, runtime identity, native architecture, package hash
and base/target executable-content checks as the guest build path. The original
`--confirm-owned-disposable-guest` build option remains supported. Host build
confirmation is not accepted by serving, recovery, offload authorization or
finalization commands; it does not authorize host installation or test CA trust.
Use `--discard-completed-builds` only through the builder, which verifies retained
artifacts before discarding each generated stage. The option is covered by the
routine desktop update fixture test suite.

### HTTPS fixture address-family admission

Routine `test_https_subscription_relay_fixture.py` covers an IPv6-first resolver
with a real IPv4 TLS client and SOCKS forwarding through the same fixture.
`test_vpn_integration_fixture.py` preserves IPv6-only fallback and rejects any
non-loopback resolution. Use the installed JVM for native resolver diagnostics;
a system JVM alone does not establish the packaged runtime behavior.

### Owned macOS VM resource monitor

Run `python3 scripts/test_macos_vm_resource_monitor.py` (included in release
hygiene). POSIX cases use synthetic processes to verify separate child sessions,
continued work after observer-group termination, pressure-stop receipts and
unknown-outcome preservation. Windows skips the POSIX process cases explicitly
and still runs portable admission checks. Launch the real monitor in a retained
foreground execution session; do not background it with `nohup ... &`. Keep the
exact session handle and private evidence directory. A missing monitor receipt
is an unknown outcome, not permission to boot another copy or replay installation.

### Scoped native fixture preparation

Routine release hygiene runs `test_windows_fixture_stage_acl.py` and
`test_guest_build_connect_proxy.py`. The former rejects incomplete/truncated QGA
captures and missing recipient rights, and guards generated typed-SID ACL setup.
Native PowerShell parsing, actual file inheritance and unchanged package hashes
remain required. The latter covers peer/destination admission, HTTP CONNECT
framing, opaque byte forwarding, partial writes, half-close and strict buffer
bounds, plus certificate-verified repository preflight failure. A passing fake
transport does not certify the guest network or a successful package build.

`test_linux_public_install_fixture.py` simulates Linux metadata explicitly when
the host is Windows; its Windows-stat regression must still reject foreign owners.
Do not interpret host Windows permission bits as Linux target directory modes.

The Linux public-install harness also replays polkit's multiple-account selector.
Only an explicitly authorized exact account may produce a numbered response;
selection never admits password input. The native driver must retain the original
PTY master and wait for the subsequent password/echo-disable gate.

`test_guest_fixture_input.py` runs in routine release hygiene. It exercises the
actual generated verify-and-exec argv against empty, stale and missing guest
helpers, proving the probe sentinel is not launched after a dropped transfer.
The verifier itself is an argument, not another unverified transferred file.
The completion-runner suite also compares malformed generated Python without
and with `native_fixture_run.sh`, retaining failure receipts without invoking ADB.

The Android fixture preflight selection checks every global proxy component,
including PAC and exclusions. Its lifecycle regression must reject a stale
component even when `http_proxy=null`, before any fixture mutation. Keep the
full disabled baseline in the native receipt and verify effective network state
after cleanup; settings storage alone does not prove cached routing has changed.

The desktop update fixture suite rejects missing Git, source archives and Git
subdirectories before creating output. The Android fixture preflight suite admits
retained terminal history while rejecting active/unknown/foreign-owner records;
a terminal restart-required flag does not itself indicate active work.

### Native MCP workflow regressions

`test_android_qualified_cli_observation` exercises the full observer with owned
inert children, real output retention and declared source/profile/HEAD seams.
Its30 controls include late output after observation timeout, post-retention
source/profile/HEAD drift, actual registered FastMCP request/JSON serialization
and a fresh isolated CLI process forwarding an owned identity JSON. Selected
routing rejects access to current private configuration in these inert controls;
default routing remains covered. POSIX custody controls skip on unsupported
coordinators. Full API35 status/operations must still be retested natively through
MCP against the qualified image. These checks do not qualify API29, installers,
actions, uncertain leases or final-source Android acceptance.

`test_native_owner_gui_preparation_admission` runs eight portable controls in
ordinary agent-tool discovery. It executes the actual transfer-root observer
against modeled Linux metadata and the real registry selection against inert
registered locations. Missing or unsafe roots stop before the GUI probe; exactly
correlated preparation locations resolve identical receipt bytes without changing
registry defaults. Remote guest ownership, display admission and full GUI/traffic
cleanup still require direct native proof and matching MCP retesting.

`DesktopNativeVisualCaptureTest.windowsForeignSystemPropertiesDialogRejectsFrameBeforeAndAfterCapture`
uses the real capture guard with injected inert dismissal for modeled Windows
titles, including when the provider is hosted on Linux or macOS. It runs in
ordinary desktop tests and hosted native capture. Real Windows dismissal remains
separate and is used only at the actual Windows capture boundary. The portable
control does not prove secure OS surface capture.

Run `python3 -m unittest discover -s agent_tools/tests -t .` for private SSH profile
validation, strict host-key routing, actual fake-SSH timeout/quoting behavior,
canonical staged-input isolation, resource planning, and public MCP/CLI dispatch.
This suite is already included in managed prepush. These checks do not substitute
for a live authenticated probe, measured host admission, or native product tests.

Native acceptance helper changes also run `scripts/test_linux_fixture_runtime_config.py`,
`scripts/test_release_hygiene_runner.py`,
`scripts/test_guest_build_connect_proxy.py` and `scripts/test_windows_prompt_observation.py`.
All are wired into release hygiene. Independent hygiene failures are aggregated;
cancellation still stops the runner. Unit results never replace installed-package evidence.

Optional macOS immutable-update pair workflow changes run
`scripts/test_macos_update_fixture_workflow.py`,
`scripts/test_record_macos_fixture_signing.py`, and
`scripts/test_setup_macos_signing.py` through release hygiene. The signing helper's
real Bash/shebang fixture checks are POSIX-only; macOS/Linux run them, while
Windows reports explicit skips. Workflow dispatch produces test artifacts only
and does not replace guest installation/recovery acceptance.

