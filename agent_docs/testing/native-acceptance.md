# Native acceptance and manual check gates

This focused note preserves test-selection instructions and source-bound regression
records from `agent_docs/test-matrix.md` at `3944739d3f33` (2026-10-14).
Passing counts, timings, checkpoint words such as “current”, and native observations
are historical claims for that source and scope, not fresh acceptance or permission
to replay operations. Commands remain mapped check references; apply current
[contracts](../contracts.md), [validation tiers](../test-matrix.md#validation-tiers)
and the [active ledger](../work-in-progress.md) before use. Preserve every stated
skip, uncertainty, causal RED/GREEN requirement and separate native gate below.

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

`scripts/test_packaged_cli_harness.py` also executes the preserved Windows
persistent-ready parser and task-root causal fixtures with owned inert children.
Release hygiene, managed prepush, Fast Checks and Windows packaging discover
these controls. Native PowerShell is required on Windows; elsewhere the controls
explicitly skip when `pwsh` is unavailable. Local PowerShell7 execution does not
replace Windows5.1 or native installer acceptance. The portable exact-path
artifact-equivalence controls belong to ordinary agent-tool test discovery.

`DesktopAppUpdatePersistenceTest` uses the actual constructed AppService update
callback, real loopback check/download and workspace store. Its causal assertion
detects durable workspace replacements from transient update state, while checking
verified package bytes, progress, READY state, configuration and revision. Ordinary
desktop tests, managed prepush and Fast Checks discover it without an OS skip.
Native GUI polling, heartbeat timing and installer return still need platform
acceptance against the fixed installed baseline and target packages.

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
Use `linux_public_install_fixture.py setup` for target-user fixture directories;
existing foreign-owned ancestors fail admission without chmod/chown. Its `keytool`
subcommand explicitly forwards the public CA store environment through sudo and
runs as the target user. `test_linux_public_install_fixture.py` covers these setup
boundaries in routine hygiene; it does not replace native authorization/install tests.

`agent_tools.tests.test_linux_public_install_negative` discovers three quick
cases from `scripts/test_linux_public_install_negative.py` in the ordinary
agent-tool/prepush suite. Actual public-install harness and HTTP responder run
with owned temporary files and harmless child processes. A corrupt wire stops
before install and retains the original raw terminal; an honest control reaches
the harness recovery assertions. Both perform explicit test cleanup. A fresh
Python child verifies import search-path restoration and real harness identity.
CLI checksum/install/status, package ownership and OS/TTY boundaries are
simulated. These tests do not establish product checksum handling, settings
preservation or native authorization/install acceptance. POSIX flow cases skip
honestly on Windows; the import isolation case is portable.

The opt-in `scripts/test_macos_install_enospc.py` runs in the macOS package job
using its assigned temporary fixture directory. It injects ENOSPC after a partial
write through the production worker's receipt and package-capture paths, requires
the original PREPARING receipt to survive, and verifies real admission rejects a
second attempt with BUSY. A no-fault control exercises successful publication.
Its copyfile EIO probe calls the same staging helper as the coordinator and proves
the injector ran once. It verifies base identity, failed receipt bytes/metadata,
admission release and native input cleanup. An isolated mutation ignoring the
production copy failure must fail this test; a duplicated fixture predicate is
not causal coverage. The partial staging tree remains explicit retained evidence.
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
six-test harness covers both shapes, explicit empty data, malformed/ambiguous
results, and duplicate-domain order. Never default an absent field to an empty
list when making a persistence claim. Controller epoch replacement may reset the
reported revision to zero; compare actual committed payload and owner identity.
For full transfer-document comparison use `routing_documents_equal`: it ignores
only generated `exported_at`, preserves every rule and unknown field, and rejects
incomplete documents. Do not compare export timestamps as persisted settings.
The same routine script covers changed rules, versions and additional fields.

