# Work In Progress

## Active Objective And Safety

Finish the full GUI/CLI parity handoff across Android, Linux, Windows and macOS,
including current packaged native evidence, visual review, reviewed commits pushed
to `origin/dev`, and all required CI for the exact pushed SHA. The goal is active
and incomplete. No release, main merge, tag, publisher or runtime upgrade is authorized.
Product authority: [contracts.md](contracts.md), especially CLI-001..008,
STATE-001..005, DESKTOP-001..008; command specification: [cli.md](cli.md).

VPN, installation and elevation are authorized only in positively identified
agent-owned disposable VMs/emulators. Preserve the host VPN, personal workspaces,
unrelated VMs, emulator 5580 and locally excluded `agent_docs/.Rhistory`.
A timeout never authorizes restarting or killing an installer/runtime.

## Current Repository And Scope

Startup on 2026-09-07 fetched origin successfully. Ten reviewed checkpoints
have been pushed to `origin/dev`; latest SHA is
`fa76a4c1d209a33c2e489ec423c834366f84aa10`. Canonical version is **2.1.4**
with four Unreleased bullets at that checkpoint. Managed prepush passed (1614
selected, 1557 executed, 57 platform skips, no failures). Its focused actual
Windows run passed22/22 with no skips. Exact-SHA Fast Checks, Android and macOS
passed, including the new native macOS persistence check; Windows failed in a
previously unselected native fixture, before packaged launcher checks. Linux was
still running at this observation. The failed test supplied nonexistent launcher
paths, now correctly rejected by physical pinning. Causal CI evidence:
`/tmp/vpn-fa76-windows-ci-failed.log`, run34157391679. The corrected fixture
asserts missing-file rejection, then supplies real inert files and checks unchanged
bytes/mtime plus no extra entries. The next push requires the full actual-source
Windows desktop suite, not the earlier focused22 selection. Full parity remains
incomplete and the previous packaged-launcher failure is not yet cleared by CI.

Earlier checkpoint `28c42598dd063357ea598ba06e3c0bf49ea53659` had a different
Windows startup failure. Its managed prepush passed. Exact-SHA Fast Checks, Android Release APK, Linux
Desktop Package and macOS Desktop Package passed; advisory VPN Integration also
passed. Windows Desktop Package built EXE/MSI but extracted-console `--help`
exited 2 with empty stdout and `UNAVAILABLE` on stderr (run 34151739039).
The exact packaged diagnostic identifies the runner's D: root owner as
NETWORK SERVICE, rejected by installer ancestry validation during ordinary
startup. The causal quick regression now fails with `Untrusted installer owner`
at the same validation point; an existing-protected-gate case passes. Evidence:
`/tmp/vpn-windows-runner-owner-causal-red.log` and
`/tmp/vpn-parity-28c-windows-ci-admission.json`. No installer trust expansion is
approved. This remains an unresolved delivery gate pending a reviewed separation
of ordinary startup and privileged installation checks.
The ordinary-startup slice now retains physical executable/ancestor pins before
the first gate and defers installer trust checks until a protected gate exists.
Its four causal regressions failed before the change; admission14 and process4
tests then passed with no skips (`/tmp/vpn-windows-ordinary-admission-green.log`).
Native x64 sharing/alias experiments verified the required gate transition,
including case, 8.3 and alternate drive aliases. Coordinator fencing is now integrated: actual file identities match aliases,
readiness probes cover both launchers, and the exclusive gate spans replacement.
The actual Windows JUnit run passed admission14/process4/captured-worker2 and
coordinator alias behavior; its native mutation test caught a Java-to-PowerShell
quote transport bug. That test now captures its C# bytes as Base64, with a frozen
native rerun passed22/22 before checkpoint approval. Its archive is
`/tmp/vpn-windows-finish.WhKUbn/windows-admission-scope-v3-native-evidence.zip`,
SHA `295143fa3df8f680d763b6930273c2e9dfc9849af1df683fffc4efcb5d7ed50d`.
An actual elevated inventory probe subsequently found a separate installer blocker:
Registry and Memory Compression return native process-image error31 and keep the
readiness check BUSY despite no application copy. Evidence:
`/tmp/vpn-windows-finish.WhKUbn/coordinator-inventory-v1-result.json`.
A correction must prove kernel/minimal process identity; names, PIDs and error31
are not an exclusion policy. Actual MSI replacement remains unverified.

The Arch distro JDK's minimal native launcher emits a child abort despite its
parent exiting zero. An isolated launcher built with the same-patch Temurin JDK
passes. The quick regression and Linux pre-package probe are now wired into
routine checks; fresh 28c Temurin base/target packages pass direct bundle
replacement and static public launch checks. The subsequent public update and
next-owner receipt recovery also passed, as recorded below.
The new root-owned Arch verifier compares the complete installed tree to its
hash-verified base archive, including launcher/runtime/JAR bytes, and checks the
source-pair identity. Ten real-file regressions pass locally. The public driver
accepts `--arch-source-fixture` only with same-source recovery; DEB/RPM paths
retain package-manager ownership checks. The harness is separate from package inputs.
The complete harness subsequently passed natively (Arch verifier10, launcher6,
public harness12), and the actual frozen base2.1.3 tree was accepted. The first
public update reached authorization but returned terminal CANCELLED without a
handoff: the pinned Arch polkit package uses a socket helper, whose unit was
inactive after cloud-init installation. Package integrity was clean and helper
mode0755 was intentional. A causal provisioning regression failed before adding
explicit socket activation; all11 VM preparation tests then passed. Logs:
`/tmp/vpn-arch-polkit-socket-red.log` and `-green.log`. The assigned guest socket
is now active without chmod or package changes. Original operation
`ccaf10ba-4136-4a88-96c2-b94214d5f253` and evidence
`/tmp/vpn-public-install-evidence-uazhxmg9` are preserved. This remains failure
evidence, not successful replacement. The fixture TLS server is PID11640,
port33925, under `fixture-28c-temurin/tls-public-sq4ow432` in guest2317;
revalidate before reuse. Root currently owns guest execution.
After confirming the first operation was terminal, a deliberate new request
completed actual public Arch replacement from 2.1.3 to 2.1.4. Job
`d812ab86-d318-4828-bc59-00a58e346dad` has protected sequence4 SUCCEEDED/OK;
operation `ee59b917-ac7d-4a49-8205-46e47536a39c` recovered under new owner
`d5750a69-d6cc-4321-a2ca-9a9d9f1893af` with original request/controller identity.
Public update status reports installed=true and cleanupCode=OK; runtime remains
OFF. Evidence: `/tmp/vpn-arch28c-public-recovery-evidence.json`, source fingerprint
`6c96efd29fcd6b124bad05d6169e4e68c96f8bac03fa4beb4681d02136909494`.
This is installed-package same-source update/recovery evidence, not traffic or
rollback coverage. Guest-only TLS inputs and the private test credential remain
owned by root pending exact fixture cleanup; no host trust was modified.
The resulting authorization-error audit also found pkexec127 misreported as user
cancellation. The quick regression failed with expected UNAVAILABLE / actual
CANCELLED before the mapping fix; 126 still means cancellation. Logs:
`/tmp/vpn-linux-authorization-exit-red.log` and `-green.log`. The focused union
selected28 tests, executed25, skipped3 native-platform cases and had no failures.
Native Windows checks remain necessary for its skipped cases.
Current provisioning tests also passed11/11 on Arch Linux7.2.2 x86_64/Python3.14.7
(`/tmp/vpn-arch-provisioning-native-current.log`). macOS15.7.7 ARM64/Python3.9.6
executed provisioning11, Arch verifier10 and launcher harness6, with zero skips
or failures (`/tmp/vpn-mac-current-python-native.log`). Each record contains
actual source hashes and a dedicated guest scratch directory. Latest aggregate
hygiene passed (`/tmp/vpn-parity-checkpoint10-hygiene-latest.log`); this is focused
validation and does not replace the final managed prepush receipt.

Eight old macOS fixture DMGs were archived with per-file hash verification and
then removed only after confirming none were open. Guest free space rose from
337 MB to 1.46 GB. Archive SHA256:
`d1bb4907a697b8c1a9bb333793eceaacc25b8b466487e86768534fd4562d884c`;
cleanup receipt: `/tmp/vpn-mac-old-dmg-cleanup-receipt.json`. The uncertain
machine install job `2c8b216a-f967-4aaf-bd5c-07d0c163cc64` still has its protected
PREPARING receipt and inputs preserved; it was not replayed.
Current-source macOS gate/component tests passed 7/7 with no skips in the assigned
guest, including actual launchd owner exit and watcher survival. Source hashes:
`/tmp/vpn-mac-current-gate-source.json`; output:
`/tmp/vpn-mac-current-gate-run.log`. This is component evidence, not proof of
machine-wide package replacement or recovery.
The new ENOSPC component regression also passed3/3 in that guest: actual production
write calls fail after8 bytes during receipt publication or package capture;
PREPARING survives and real gate admission rejects another attempt with BUSY.
The no-fault control publishes SUCCEEDED. Evidence:
`/tmp/vpn-mac-enospc-native-current.json` (worker SHA
`39424e76eecb0cfa3188e22ff2dbf003ff2f8883e9df226d0cadba62c2e37e4d`).
This characterizes existing correct failure behavior; no product fix or fake
RED claim is involved. It now runs in the native macOS CI job and routine hygiene.

Native launch coverage now includes the complete quick tier on macOS Python 3.11,
Ubuntu Python 3.12.3, and Windows x64 Python 3.12.10. Windows selected 184 tests,
executed 159, and explicitly skipped 25 foreign-platform cases; all 26 Python
commands and the Git Bash aggregate passed. These results do not certify the
artifact/device-dependent launchers still awaiting their native fixtures.
The Python stat-callback recursion regression was verified RED before the fix,
then GREEN under the affected interpreter versions before checkpoint seven.

Broad native Linux Gradle testing exposed six desktop failures: five private
fixture-directory permission errors under umask 0002 and a distinct stalled HTTP
body cancellation failure. Test-only 0700 fixture corrections passed the focused
native selection; cancellation and PTY-observer regressions/fixes passed focused native checks
and are frozen for broader validation.
Android API29 native GUI add succeeded on the frozen 04f base15 APK, but the next
remove returned resource exhaustion and unknown outcome; unchanged full readback
was preserved and the mutation was not replayed. A separate API29 emulator is
being used for causal ART/Compose instrumentation. A short-domain 56,002-item
scratch GUI owner-save test passed, but it was not pressure-equivalent to the
original 11.8 MB long-domain input. Exact-input owner-save acceptance remains
required; the short-input and host-only probes did not reproduce the failure.

Long-domain scratch runs exhausted ART at persisted decoding and then document
parsing. A subsequent fixture audit found an artificial second `ProfileStorage`
facade/cache retaining another roughly 11.7MiB projection alongside the GUI owner.
Those scratch OOMs are therefore confounded and do not establish production causes.
The original 5582 production failure remains authoritative and unresolved. The
fixture must seed separately, cold restart, avoid a test-owned storage cache, and
rerun the unfixed source before evaluating primitive-table or local-admission
prototypes. All prototypes remain scratch-only. Required acceptance still includes
complete add/remove persistence, export and independent cold readback at the same
48MiB growth limit; the short-input GREEN is not a substitute.

All inherited dirty product buckets were preserved and included in checkpoint
c44ebc5472502942dbea06c4fe0917e671ea97b2, followed by two CI repair commits.
The user approved removing machine-specific Codex configuration from Git.
Local `.codex/config.toml` is preserved and ignored; tracked portable template
`agent_tools/codex-config.toml.in` and `configure_codex.py` derive its paths.
The generated MCP handshake and all30 agent-tool tests passed. Locally excluded
`agent_docs/.Rhistory` remains preserved. Full native parity is unfinished.

Historical contradictory summaries and detailed native evidence are preserved in
[parity-native-history.md](parity-native-history.md) and
[parity-history.md](parity-history.md). Their process IDs and source versions must
be revalidated before reuse.

## Ownership And Build Coordination

One writer per file. Root owns shared declarations, lifecycle tools, host Gradle,
version metadata, documentation ledger, scope, commits, push and exact-SHA CI.
Workers request ownership before editing common integration files and do not stage,
commit, push, bump versions or spawn further agents.

| Task ID | Agent | Owned files/subsystem | Shared files reserved | Dependencies | Artifact/environment | Current check | Next handoff |
| --- | --- | --- | --- | --- | --- | --- | --- |
| B/shared | root | CLI/common integration, desktop Find Best, macOS, build/CI/docs | Shared declarations, version/delivery | Current-source platform reruns | Host Gradle serialized; macOS guest192.168.64.3 | FindBest14 + operation/CLI7 GREEN | Finish native cancellation/recovery and final parity audit |
| C/D/G-Android | android_terra (Terra medium) | Android actions/install/storage/JNI/tests and owned scratch instrumentation | App Gradle/CI remain root | Frozen04f APK15/16; diagnostic17 retained | Preserve AVD5582 native failure; separate5584 API29;5580 protected | 48MiB rendered remove commits in scratch2.2.1 but returned-state allocation OOM persists | ART reproducer, API35 lifecycle, visuals |
| F/E-Windows | windows (Astra) | Windows broker/native helper/policy/tests, MSI and launcher diagnosis | Factory/Main/autostart/common update remain root | NativeAOT validate-only proof; privileged production roles pending | Real x64 guest2314; ARM2299 historical only | Python3.12 native quick tier GREEN; packaged static admission diagnosis active | Native launch inventory, fixed privileged roles, VPN/MSI production binding |
| E-Linux | linux_terra (Terra medium) | Read-only Linux/Mac review; native Arch execution transferred to root | Common update behavior/build remain root | Checkpoint2408 plus reviewed fixture overlay; prior failures preserved | Ubuntu2318; Fedora2316 read-only pending evidence review; Arch2317 | Cancellation and private fixture fixes committed; Arch-only fixture checks GREEN | Arch public update/recovery passed; remaining traffic and rollback |
| E-Mac/H | root | macOS worker/cleanup, GUI/localization/visuals | Shared UI/scenes/catalogs remain root | Frozen coordinator-fix base15/target16 DMGs hash-verified | macOS15.7.7 ARM64 guest192.168.64.3 | Public user-local replacement and exact next-owner recovery GREEN | Handoff/recovery, machine authorization, current visual/package acceptance |

Only one host Gradle invocation at a time. No source edits during artifact freeze.
Native artifacts are immutable and require source fingerprints and byte hashes.

## Implemented And Locally Tested

Native Linux follow-up fixes were validated and pushed in checkpoint eight. Manifest
fetching uses an asynchronous request with explicit response-body ownership so
cancellation remains prompt during headers/body stalls, and a completed body is
closed even if cancellation wins before the get handoff. Cleanup cancels the
request even when body close fails. Original native stalled-body RED and the
pre-lease ownership RED are retained; the latter is
`/tmp/vpn-linux312-lease-preownership-red.log` (SHA256
`37160cec7bb7369e0178d8980b7645a68a8c790bb05751a6d1afa5ee32c2ccc0`).
Final native focused cancellation tests passed on Ubuntu/JDK17. Private fixture
directories use explicit POSIX permissions only where supported; the two changed
Windows fixture classes passed 25 native tests with no skips as an ordinary user.
The complete native Windows desktop/model/core/UI selection then passed 1,121
executed tests, with 55 explicit native/foreign-platform skips out of 1,176 selected.
The coordinator verified all 267 XML suites in the evidence archive
`/tmp/vpn-windows-finish.WhKUbn/native-checkpoint8-full-suite-evidence.zip`
(SHA256 `fb2dfcd09c4a97dbf54cc38a3d84215c0864991637ea417c33cde1c5afaa38a4`).
This component-suite evidence does not resolve the packaged CI admission failure.
The routine PTY
observer tests cover buffered final output, EIO and a live-process timeout; the
actual native PTY driver imports the tested helper and never restarts an installer
on observation loss. Checkpoint eight also has a successful managed prepush receipt;
the current follow-up edits require a new receipt before another push.

The current diagnostic follow-up collects bounded native admission evidence from
the exact packaged Windows JARs when static launcher checks fail, while preserving
the original failure. Its public harness tests were verified 2 RED then 15 GREEN
(`/tmp/vpn-parity-admission-wiring-red.log` and corresponding `-green.log`).
The JVM diagnostic tests run after JDK setup in Fast Checks, Windows packaging and
managed prepush. The final native Windows diagnostic/fixture union passed 59
selected tests: 56 executed, three explicit POSIX skips, no failures. The
coordinator matched all ten script hashes in
`/tmp/vpn-windows-finish.WhKUbn/windows-diagnostic-quick-v5-decoded-result.json`
to the working tree. The diagnostic also reads the real 57-JAR package and
preserves the SYSTEM-account trust rejection. No admission trust-policy
relaxation has been accepted; the actual CI launcher cause remains unresolved.

Arch fixture failures exposed Java26 selection, an invalid QEMU serial argument,
read-only archive extraction, and unsupported DEB tasks on Arch. Fixture checks
now validate the effective `JAVA_HOME`, use the tested canonical QEMU command,
preserve file/directory modes during deferred extraction, and emit only the Arch
bundle for an explicit Arch plan. The reviewed fixture union passed 29 tests and
the VM preparation suite passed 10; `test_fixture_environment.py` is in routine
hygiene. Native package results and their remaining failures are recorded below.

The new Arch-only pair then built successfully in guest2317 from checkpoint2408
plus the reviewed fixture overlay (source fingerprint
`84a7f78eb285495af76902e045f6f809794e8786776661815787d6ffee017e94`).
The installed base reports version2.1.3, but direct launcher help/version/status
also emit `pure virtual method called` on stderr; public static smoke therefore
remains failed. This anomaly is under native JVM/library investigation. Native
Python3.14.7 passed the 3 environment and 10 VM preparation tests; the 21-test
desktop fixture suite initially encountered missing `git`. After the package
transaction completed, all 21 fixture tests passed natively too. A minimal
HelloMain JAR packaged with the same Arch JDK17.0.20.1 reproduces the child abort;
the captured core shows `Logger::log` called by the jpackage library's `dcon`
destructor. This excludes product JARs as the cause. A same-version CI-toolchain
comparison is pending; no runtime upgrade or application workaround is accepted.

Latest native macOS coordinator-fix fixture: source fingerprint
`9ad1fef6a9af37819c5b2243cbd8148757fb1b646c8e8efb3607d81c415b7112`,
base15/target16 actual ARM64 DMGs with common code fingerprint
`029ba03e0530f3c90a4ca0bc3306680bb11e464e9351ef5ca9b987f40640f2cc`.
Public check/download/install succeeded from the DMG-installed user-local base.
Job `edb0b54b-35f9-4d69-b819-d6cf356d2a69`, operation
`ebd22a18-b3da-4fca-94e7-e02bb3a4d9ab` received native SUCCEEDED/OK sequence4.
Replacement owner `6480fb01-5a19-4386-8498-2ac4778637d1` recovered the exact
original operation/controller/request. Public update status reports installed=true
and cleanupCode=OK; runtime remains off. Target image/version2.1.16 verified.
Evidence: `vpn-parity-macos-coordinator-fix-c0820y0h/local-evidence/native-success.json`
under the host temporary root, copied from the owned macOS guest.
Machine-owned authorization denial then passed with native Cancel, public exit130
and exact operation `8b2f68c2-bbe9-42ae-91bd-fc36d11bd4b8`; the base15 image and
off runtime were preserved. The base was a root-owned APFS clone of the verified
DMG-exported image, not an independent DMG installation.
An explicit authorized retry encountered guest ENOSPC. Its client eventually
returned exit2, OUTCOME_UNKNOWN/final=false with original operation
`c141681b-3ae7-4386-8219-f82b12b5b10a` and job
`2c8b216a-f967-4aaf-bd5c-07d0c163cc64`. The protected receipt was last observed at
sequence0 PREPARING; installed remains unknown. No installer replay or forced
termination was performed. Exact failure evidence is retained in the same fixture's
`machine-evidence` directory. Successful machine replacement, GUI return and live
traffic remain unverified. Older uncertain 201b evidence remains preserved too.

A scratch native preflight initially expected `ready_to_install`, but the public
phase is `ready`; it aborted before invoking installation. The shared fixture
`require_install_ready` helper now replaces that inline assumption. Its routine
`test_desktop_update_fixture.py` regression failed on the old literal and passed
after correction (17 tests); the native harness imported the same tested helper.
Host RED/GREEN logs: `/tmp/vpn-mac-ready-phase-{red,green}.log`.
The installed target also passed `test_packaged_cli.py` through its real public
launcher; `packaged-cli.log` records the disconnected smoke success. The DMG
wrapper also passed natively with unchanged test scripts and a disposable
version16 metadata projection, leaving canonical source metadata unchanged.


Historical opening focused baseline completed 2026-09-07 (Gradle session 63042, 46 seconds); later source-specific evidence below supersedes it:

- Shared core `*Control*Test`: 100 tests, zero failures/errors/skips.
- Desktop CLI/Android adapter/large transport/install/Linux/Windows broker selection:
  173 tests, zero failures/errors, 12 platform skips (Linux Arch/admission/pipe/
  terminal/installer and Windows native broker/config tests).
- Android Find Best, SSH draft, connection, GUI location, settings actions, refresh,
  install/update and reader selection: 92 tests, zero failures/errors/skips.
- `:app:compileDebugKotlin` and `:app:compileDebugAndroidTestKotlin` passed.

Baseline changed-input fingerprint:
`81a8ae7a9a09cc2ede6c1e0bcacc46bfb837ee1b01a1564900e460894772071e`.
Manifest and copied XML/JSON selections are in temporary evidence directory
`vpn-parity-resume-20260907.7h0oy59t` under the host temporary root.
This is focused component evidence, not complete parity or package certification.
Subsequent focused changes and evidence:

- Shared invocation builder, registry-derived help, typed human/JSON dispatch,
  stderr failure/progress rendering, Android status/stats watch and log follow.
- Shared cursor journal with platform synchronization and Android post-durability
  publication. Desktop/Android stream union: 29 desktop and 38 Android tests passed.
- Android Find Best committed-result reconciliation, credential error redaction,
  PackageInstaller correlation/cancellation/recovery and strict version-label checks.
  Current action/installer selection: 92 passed; metadata mismatch regression red
  then four passed. Android/UI compilation and localized installer presentation passed.
- Android 56,000-domain memory test passed with cold reopen in a second 48 MiB JVM;
  together with serializer and credential version checks: 12 passed, no skips.
- Linux postinst race preserves an existing directory mode; headless install return
  launches `serve`. Immutable desktop fixture builder and routine hygiene wiring added.
- Windows scoped preparation interface and bounded configuration transfers compile;
  six prepared-process tests pass. Native component evidence is ARM64/x64 emulation.
- CLI public tests now use the authoritative controller. Lost subscription-refresh
  outcomes and benchmark timings are fixed and retained; public desktop selection
  133 passed, three platform skips. Startup failures now obey stderr rules.
- Desktop rejected-restart regression passed: actual A, runtime identity, telemetry,
  pending B and reconnect intent survive refusal; public cancellation is terminal130.
  Production Windows manager integration remains outstanding.
- Existing transient owners now adopt explicit `serve` without changing their epoch;
  real process regression passed. Recovered desktop installation status now projects
  protected receipt state, including unknown outcomes and bounded correlated history.
  Common focused selection44 passed with two host platform skips; history10 passed.
- Public Android Find Best consent launch was missing from the desktop ADB adapter.
  Delayed-consent synchronous/async regression reproduced it; all21 adapter tests now
  pass. The refreshed packaged CLI is included in immutable macOS sourcef77d below.
- Windows capture failure classification and exact TrustedInstaller ancestor/witness
  handling passed the host selection:73 selected,12 native platform skips, no failures.
  Ordinary private spool policy and installer authority policy remain distinct.

The source-matched Android release pair is in temporary directory
`vpn-parity-android-bundle-20260907-llef0sbe`, with source fingerprint
`417035001cd623dec7d2c4d2e6a18d3c5d3d5a4700dbf53ee20b59246ff9e52d`.
Base 2.1.3/16460 SHA-256 `aa642ad6ddadc4dd9f9fea4dc53d694bad1948ea8a03e86ae30cefee70ce5fd9`;
target 2.1.4/16480 `9395f7ad0c0473faf8e982d2130e06efbbdf63ca06052d79042f9766eb88af50`.
Both are nondebuggable and signer-matched. Version overrides are fixture-only;
canonical version metadata is unchanged. Android benchmark negative-measurement
reporting was fixed in v2. Native API35 independent confirmation resume exposed a
stale task; manifest regression red then two green, protected interaction now gets
an independent document task. Current v3 pair is `vpn-parity-android-bundle-v3-x53dr1w7`,
source `6b3d4ed8f4012fd5ae9291bb4e086692b6fd9f97760b170376a1dd8ae00d5b8d`;
base SHA `bb7e188bd3a724b9fc604975c11ebe5eafaf663bd3ae513f0a75b1784e3da818`,
target SHA `c748bcb10ab79d0f52d7726612e7c0e07a432aae18a18a7305bdb595ee46c656`.
Both prior pending dialogs were authoritatively cancelled before replacement.
API29/API35 current CLI rejects wrong signer/package/damaged/display-version APKs;
unrelated caller provider access was rejected on both APIs, including with DUMP.

Current v4 source `1ee0b7074b68b664f26f77f72789bd0ab4658f3451e421b52ef0bbd876598e44`
is in `vpn-parity-android-bundle-v4-ef7ph_ah`. Compatible nondebuggable base2.1.4
SHA `738ff44880ab9c5fbf25b5bf56377ab8522e7ac4ce6001bb91bae2b8ac477cde`
and target2.1.5 SHA `dac4dd7edc4d680bf880a214560d936082817f41f2a4572719bdd98844521080`
passed independent explicit confirmation recovery after cold STAGED and handed-off
process loss on both APIs. Exact receipts: API29 `a6128739-9a41-47e4-b638-93b5e776f4bd`,
session446531918; API35 `24240b33-ede3-4e5b-b154-f69fc05d70f5`, session189819957.
Both installed2.1.5 with authoritative installed=true and terminal retry NOT_FOUND.
The v4 same-session confirmation repair had31 focused tests and compilation pass.

The large-routing second-write failure now has a passing full consecutive-edit
48-MiB host regression using standard JNI construction and disk-backed history.
The integrated37-test Android selection passes, including corruption, mutable
capture, failed cleanup ownership, serializer and resource boundaries. Fresh
API29/API35 APK10/11 verification remains open; historical first-import/cold-read
evidence alone never certified consecutive edits.

Android scratch 2.2.4 minified/nondebuggable seed acceptance and independent cold
readback both contain56000 identical domains. Root inspected the complete JSON
and corrected a false failure claim caused by reading the mutation field from an
inspection envelope. Evidence `/tmp/5584-gesture-seed-root-verified.json`, newline
SHA `8e1700935e0f02a2d2a25d854d29296462ac7ce15166b06a7d10dad6e9bfdd2a`.
The reusable evidence helper has four routine tests; the field-only fallback
reproduced zero instead of three before correction (`/tmp/vpn-routing-evidence-red.log`),
then the new reader passed (`/tmp/vpn-routing-evidence-green.log`). This was a
harness defect, not evidence of failed DataStore persistence. Android product
candidates remain scratch-only pending external GUI add/remove/cold proof.

## Implemented But Awaiting Current Native Evidence

- Authenticated owner/frontend lifetime, guarded drafts, operation retention and
  document transfers exist; current packages need detach/crash/live-traffic proof.
- Android large routing/persistence/export and Find Best/SSH paths exist; historical
  API29 success does not cover current source, API35 or remaining failure lifecycle.
- Android PackageInstaller independent confirmation/process-loss recovery is proven
  for v4 on both APIs; remaining native actions, cancellation/retention and visual
  scenarios still require their own evidence.
- Desktop Linux/Windows/macOS installer adapters exist. Published Linux 2.0.18
  installation after manual dependency repair is not fresh same-source recovery.
- Windows broker native compilation/policy evidence exists; production runtime
  remains gated pending preparation/authorization/configuration and native tests.

## Remaining Implementation

- B: finish capability correspondence and verify
  common streams through fake ADB and current nondebuggable APKs/public packages.
- C: audit Find Best commit uncertainty/cancellation and SSH credential rollback,
  GUI callback identity, actual-A/pending-B refresh and service ownership.
- D: review remaining Android installer cancellation, retention and visual scenarios
  against the completed v4 independent recovery evidence.
- E: current-source fresh Linux dependency/recovery; RPM/Arch; MSI original-user
  execution and successful replacement; actual-architecture macOS worker/package.
- F: broker prepare/authorize/commit, identity/storage/resource/CUSTOM/large-config
  support, production binding, scoped elevation and ordinary autostart.
- G: current cold-process large-document/persistence/resource/transfer/export gates.
- H: reachable GUI parity, catalogs, changed visual scenes/baselines and routine
  deterministic script/package-workflow checks.

## Revalidated Environments And Live Work

No host runtime was started or stopped. Host Gradle invocations remain serialized.
API29 emulator5582 is `vpn-control-cli-task-api29`, ARM64, installed2.1.3/16460
at discovery and 48 MiB growth limit. Worker booted task5590
`vpn-control-cli-task-api35`, ARM64, previously2.1.2/16440, 192 MiB growth limit.
Both had no active app service and no proxy setting at discovery;5580 untouched.
Android owns task-only HTTPS/caller-probe setup and its exact trust/network cleanup.

Windows QEMU20532 uses the repository-owned Windows disk, QGA/QMP sockets,
VNC127.0.0.1:5 and SSH2299. Guest Windows11build26200 is ARM64; actual checksum-
verified x64 JVM/runtime are under test and evidence is labelled emulation.
Native broker prepared a suspended child and committed loopback traffic. Ordinary
user real UAC approval passed19 component tests/one privileged-pin skip; v4 real
denial preserved271 traffic samples. Native >8MiB configuration passed; one v4
stage-cleanup test-order assertion was corrected. No public production/TUN/native
x86 claim yet. Worker owns fixture processes/cleanup and is preparing a separate
x86 Windows guest under remote `/home/kardinal/vpn-control-windows-native-20260907`.
Native v6 component source `df8627d86e4f295936ca5273e7e87c5aba34269ad69d02b373c55f844acc4f56`
completed successfully on the ARM64 guest with x64 JVM. JUnitCore reported52
selected and no failures; an exact assumption count was not recorded, so this is
not52 executed tests. Denial/TUN opt-ins were absent. Native x86 QEMU765494/SSH2310
has reached guest-tools installation; its active installer must not be interrupted.

Linux remote key was unlocked via the user's supplied passphrase at an interactive
prompt. Reusable SSH master on jump host `/tmp/vpn-parity-ssh.IHuVWGp1/archlinux.sock`
restored access; worker owns cleanup. Historical task9540bc92/2307 was stopped and
preserved. Fresh task `/home/kardinal/vpn-control-install-vm-20260907-fresh`, forward2308,
is Ubuntu24.04.4 x86_64, `vpnfixture` uid1000, 4vCPU/6GiB. Guest-only JDK17.0.20
and Gradle8.10.2/build tools were prepared there. Linux worker owns its identified
task guest/cache fixtures and cleanup; unrelated VMs remain untouched.
Frozen source `6ffb0d359983f624aa0366fd5efdba8c0ecb6c0ec028579edb9428cd02a89368`
built same-source DEB/RPM/Arch base2.1.3 and target2.1.4 in fresh guest2308. Separate
audited verifier fixed Compose unpadded-MD5 filename normalization and matched all
29,859 logical JAR entries except version metadata, without changing packages.
Public help/version/capabilities and missing-owner status passed without a display.
Native authorization denial exposed OUTCOME_UNKNOWN instead of CANCELLED: fixed
wrapper reserves pkexec126/127; deterministic red then green. Real
approval acquired only vpn-control+xdg-utils, proving dependency acquisition, then
postinst failed: packaged hook was JDK default, so resource wiring needs correction.
Guest2308 is half-configured; no global repair or package-manager termination occurred.
Current frozen source `467fed6330d83884960ada91f6c8b229dd702dca9e8b80346e601bda76fa3500`
contains the corrected explicit DEB packaging resource and public denial handling.
It built base2.1.3/target2.1.4 DEB/RPM/Arch with matching code identity. Guest2309
started without xdg-utils and passed real denial130 on two independent requests,
including a detached persistent owner; native Linux components19 passed without skips.
The subsequent approved install produced protected SUCCEEDED/OK seq4 and a new
serving owner. Its initial unmanaged base image left an unreferenced old JAR, so
the strict complete-image verifier intentionally rejected that fixture. Preserve it
as fresh dependency/installed-target evidence; it does not prove a clean managed
base-to-target image replacement. Guest2311 now passed clean package-managed DEB replacement and exact next-owner
recovery (job a2c46e90-6dc3-4e66-9081-57ad22048ef5, protected seq4 SUCCEEDED).
Its local evidence bundle SHA256 is
13c9be384f0d29568c2df09326bdfc28089d73ce68a9fe5cf90f92477ad88d22.
Fedora44 x86_64 guest2312 is running for RPM verification; Arch2313 is prepared.
The retained SSH master is shared with the Windows worker and must remain available.

macOS source6ff image was built with checksum-verified private Temurin17.0.20.1,
actual ARM64 worker/runtime, and immutable app image under `vpn-parity-macos-image-6ffb-x8h75l1o`.
The source6ff DMG-installed public CLI passed headless/static/operation/stream/large
document smoke in the guest. That is installed-package evidence without live proxy
traffic, GUI detach or successful update recovery. The first local update reached
protected WAITING_FOR_EXIT, job `3eb4b84f-c9b2-4ced-b292-d33f93e6dd9f`, but Darwin
reservation locking incorrectly blocked pending status/cancel admission. The
worker eventually exited and its receipt remains nonterminal; preserve this
uncertain job and staged package, do not replay or clear it to claim success.
The exact native gate regression reproduced errno35; a separate protected reservation
inode now allows pending readers while excluding another worker/replacement, and
the regression passes in the owned macOS guest. Package CI now runs this regression.
Current immutable source `f77d3a82861ca91f2b767c3d8d35508ea5ea9ee00e7a10f4a1d468ca7ca99b46`
is in `vpn-parity-macos-current-20260907-ra456l4q`; its new app-image/DMG build includes
the lock fix, current recovered status/serve behavior and ADB Find Best consent.
The sourcef77d DMG-installed user-local update passed protected SUCCEEDED seq4
and same-source next-owner receipt recovery, job
`bd4aa216-c0ff-439a-8aa4-1b4f881238cb`. Automatic headless return failed because
the native watcher always launched GUI mode. A native regression reproduced this;
the helper now passes `serve` when no GUI frontend was captured. Three native
helper tests pass; fresh packaged relaunch proof is still required. Terminal input
cleanup after next-owner recovery remains under review.

The latest desktop operation selection passed 29 tests selected, 7 native skips,
0 failures, including four uncertain-outcome tests and an authenticated public CLI
identity/wait/reconciliation scenario. Android large-replacement attempt4 passed
14 of 15 tests; the same 48-MiB default-G1 third cold process still fails during
final persisted-string allocation. That failure remains open; SerialGC diagnostic
and actual API29 ART evidence are separate gates.

Fresh immutable source `a7dc103d2da6080c242ccf688beec7e387045a971a344cdbca68c88df55a3307`
includes the native headless-return fix. Base2.1.4 DMG SHA256
`a029c8f3fc592b228d77b14ae52781cafe24dd77026b5b41d903bd3c7ddf5677`
and target2.1.5 `2429e1169043bf6f6c0c9500a1e11a42c191062c1194c8a8a5cf3bc460006c63`
have matching code fingerprint
`680387fb8396a450895ba582939cd01bfe5fe6f0d6e38d79fb009251a1289dbe`.
Host compilation/package output is under `vpn-parity-macos-relaunch-20260907-f_0n2dzz`;
Public native verification passed on the guest's new `parity-a7dc103d` application path,
`local-a7dc103d-workspace` and `local-a7dc103d-evidence`, preserving older jobs.
Job `12920920-7579-4e8a-a6cd-be19896dbc9a` reached protected seq4 SUCCEEDED;
new owner `55411491-1ed3-4f4c-8e52-e72904721600` returned automatically and
remained serving disconnected for45 seconds before recovery inspection. Local
`native-evidence` retains calls, receipt, process IDs and summary. Machine installation,
GUI return, proxy traffic and terminal input cleanup remain open.
The same source built diagnostic nondebuggable Android2.1.5/2.1.6 packages
with the verified existing signer; actual ART48-MiB testing is next. Default-G1
failure remains explicitly unclosed.

Manager transition regressions reproduced four failures in the real manager's
injected native path (12 selected), and the recovered-runtime lifecycle regression
reproduced stale runtime identity (9 selected, one failure). Windows owns manager
fixes; root owns lifecycle identity/timestamp integration. The first union is now
green: manager12, lifecycle9, scoped-process6, broker14 selected/7 native skips,
0 failures. Additional cancellation/uncertainty tests and production binding remain.
The Android resource-boundary selection is also green:5 executed,0 skips/failures.

Root owns macOS guest execution. Reused Tart guest192.168.64.3/macOS15.7.7 ARM64
was already running and must remain running. Its exact task root is
`/tmp/vpn-parity-macos-native-20260907.O45e6J`. TLS fixture trust is process-only;
its private server/trust resources require cleanup after test-owned users finish.

## Final Delivery Gates

Every handoff requirement remains part of completion. Required matrix: installed
Linux x86_64 DEB/RPM/Arch; native Windows x86_64 plus correctly labelled ARM64
emulation; macOS installed DMG; Android API29/API35 nondebuggable ADB. Cover public
launchers, modes/traffic, operations/cancellation, OS interactions, installation
receipts/recovery, exports, one owner and GUI detach/crash/scheduled continuity.
Capture/review changed GUI and installer scenes and update intentional baselines.

After final content: workflow_status/scope review, version_bump, managed prepush,
explicit reviewed staging/commit/push, then Fast Checks, Android Release APK,
Linux Desktop Package, Windows Desktop Package and macOS Desktop Package all
successful for the exact pushed SHA. Revalidate package evidence against delivered
source. Advisory VPN Integration does not replace native parity evidence.

Current additional native evidence: Windows native x86 v8 SYSTEM component run
selected53/executed52/skipped1 denial opt-out,0 failures, including real TUN HTTP.
Fedora2312 RPM denial/failure/recovery/success evidence is preserved locally at
`/tmp/vpn-linux-2312-evidence-467fed6330d8.tar.gz`, SHA256
`03f64692e44eb81acefb5e850896ed9ee5cb2d86061eaa09235da6e2d764c67a`.
The old RPM removed the new desktop menu entry; six deterministic RPM tests now
pass after posttrans registration/final-removal guards, with fresh native proof pending.
Fedora is shut down cleanly; Arch2313 is bootstrapping in its assigned environment.
Mac machine-owned base4 now exists at `/Applications/vpn-control.app` only in the
owned guest, uid0; its public `--version` succeeds. Machine update authorization
is not yet tested. Source-a7dc Android API29 actual ART48-MiB large replacement
and full56k readback passed; the rest of that native chain remains in progress.

Owner terminal-input maintenance now has deterministic RED→GREEN coverage, separate
from read-only installation history. Previous-owner authoritative terminal inputs
are released once per receipt; failed cleanup remains independently visible as
`cleanupCode`, retains known installation outcome/evidence, and may retry cleanup.
Cleanup/history/install selection14 plus Android SerialGC memory/resource selection16
passed with no skips/failures. Native cleanup and GUI cleanup feedback still require
verification. Windows manager cancellation/unknown-child selection34 passed with
2 native capture skips; confirmed aborts now finish the real ledger as RUNTIME_FAILED,
while unresolved outcomes retain their operation identity and remain pending.
Default-G1 Android48-MiB RED evidence remains preserved; explicit SerialGC48-MiB
three-cold-process regression and actual API29 ART48-MiB replacement/readback/cold
reopen/export/exact retry/no-op chains are separately green.

Android GUI large-document gate remains distinct from CLI: native sourcea7dc
MainActivity crashed allocating a27,525,128-byte joined editor string after56k
import. Shared GUI projection regression reproduced the eager read. List-backed
drafts now avoid that text copy; indexed add/remove and asynchronously sorted indices
preserve edits, while large domain lists compose only visible rows. Shared core226
and UI37 tests passed, plus Android routing actions7 after its legacy-text assertion
was updated. Native GUI proof and guarded/spooled Android picker import remain open.
Android Find Best foreground token lifecycle regression reproduced early token
release; its app fix passed connection13/interactions4/FindBest10 and both compiles.
New source-matched APK6/7 is being prepared for native confirmation.
Windows ownership broker v9 uses a retained original-owner native job before UAC;
local broker16/scoped7/capture10/manager15 selection passed with10 native skips.
Its immutable component source9590fef4 awaits native verification. Production and
mutable cache/output remain gated. Linux new RPM mode normalization and Arch setup
normalization require fresh snapshot/native packages; historical success records
retain their exact earlier source/setup classifications.
Mac source1794bb57 cleanup base5/target6 packages built with matching code fingerprint
51da53f60a0b8a0f0a57d9821dbeaf99fb3e795e82ae5c603aad4a107ed187e6,
but native cleanup is not yet verified. Machine a7dc attempt operationefa40b45
has not reached an observable OS prompt; preserve its watcher13186/job07b5da81
and originalowner13030. An independent inert /usr/bin/true AppleScript authorization
probe returned OS error-60007; no grant/denial success is claimed.

Latest verified checkpoint (supersedes the pending statements immediately above):
Mac source1794bb57 user-local installed DMG5→6 public update completed with protected
receipt60a74a21-bd62-4f4b-a699-5eacf53f93e9 sequence4 SUCCEEDED/OK. Automatic headless
owner889ce592-5f53-489e-9eb9-e9929d9ea939 stayed alive disconnected for45 seconds;
same-source installed image matched, public recovered status retained original
request/operation/controller identities and installed=true. Cleanup independently
reported cleanupCode=OK; the exact private input directory is absent and receipt
evidence remains. Local native-evidence is under the macos-cleanup fixture pointed
to by /tmp/vpn-parity-macos-cleanup-path.txt. This is user-local/runtime-off evidence,
not machine authorization, GUI return or traffic evidence. Machine owner13030 and
watcher13186 were reidentified alive; their unknown attempt is preserved. SDK
Authorization.h identifies -60007 as errAuthorizationInteractionNotAllowed; the
AppleScript generic password wording does not establish an incorrect password.

Android sourceeb6379 API29 opens and scrolls the56k-domain GUI without the previous
joined-string crash. Its Current Rules count still used legacy text: new shared UI
regression reproduced this, then list-size projection fixed it without reading list
elements (including an explicitly empty list overriding stale text). Shared UI39
passed without skips. Native remove/save returned owner metadata unavailable and is
under Android-owner investigation; large GUI editing/import is not certified.
Malformed SSH body rejection regression independently failed as expected before
Android-owner implementation; exact evidence is preserved under
/tmp/vpn-parity-android-malformed-ssh-red-evidence.
Windows prepared-close ownership regression also reproduced the failure before its
fix. Full scoped-process8/manager15/broker16 selection now passes with8 explicit
native broker skips, alongside the UI39 checks. XML and logs are retained under
/tmp/vpn-parity-count-broker-close-green-evidence and matching log prefix.
Linux sourceeb6379 packages built under restrictive umask and real old3→fixed4 RPM
migration passed installed identity, ordinary launcher and desktop registration
checks; public4→5 remains with the exclusive Fedora worker.

Mac authorization isolation now has native evidence: the identical inert
`/usr/bin/true` administrator AppleScript launched as a temporary Aqua LaunchAgent
displayed the real OS password prompt. The screenshot was opened and reviewed;
Escape returned -128 (user cancelled), exit1. The exact terminal LaunchAgent was
removed, evidence retained at /tmp/vpn-parity-macos-gui-auth-evidence. This proves
the SSH -60007 failure is a session interaction boundary, not guest authentication.
It does not certify installer denial/recovery: the current adapter discards script
output and only waits for protected receipts, so pre-worker authorization failures
still need correlated typed handling. Original uncertain machine job is untouched.
Android SSH envelope/parser/storage selection18 passed with no skips after its
malformed-body RED; native bundled-parser proof requires the next source-matched APK.

Mac authorization handling now preserves CANCELLED, PERMISSION_DENIED and
INTERACTION_REQUIRED separately in bounded NOT_STARTED correlation dispositions;
legacy markers remain cancellation. Missing/inaccessible protected state is never
overridden merely by process exit. Only exact job-bound output from the completed
authorization child proves rejection; the watcher must exit and protected absence
is checked before publishing the disposition. Recovery projects failed versus
cancelled consistently and installed=false only for this proven no-start case.
Correlation and reply regressions failed before fixes; integrated selection34
(Mac reply3/launch2/installer2, correlation13, Linux correlation10, recovered status4)
passed without skips/failures. Evidence /tmp/vpn-parity-mac-auth-integrated-green-evidence.
The exact production AppleScript was exercised in the owned macOS guest with an
inert worker: SSH returned correlated -60007; a visually reviewed Aqua OS prompt
cancelled with correlated -128, both script exit0. Probe LaunchAgent was removed;
/tmp/vpn-parity-macos-auth-reply-native-evidence retains exact bytes and screenshot.
This is script/component evidence; new installed-package public-path validation
is still required, and the earlier unknown machine job remains untouched.

Current frozen macOS source304c24fc682c7408281dab1b67e3bcd631bf9126f6a489ecfd6b2a485ffb3f58
DMG6/7 built with code fingerprint918bf02041d92e4c17551aec4125467bbc60af9e6546f67c23d2893d5bdce265.
Base SHA de9968ae6f82c794a77c4e169644c3e263af25ff904078d487cbe2bbdd5f563d;
target SHA89bbc9b8341db32d081566476c87ebc5a721c9f98624b6fb826ba6ad36495594.
Machine-owned installed base at /Applications/parity-304c24fc/vpn-control.app in the
owned guest passed public SSH authorization rejection and next-owner recovery:
operation1b4961b6-4664-45f2-a59d-29437ef8ccbc/job72606627-7304-491e-bac4-88c5f8fda885,
INTERACTION_REQUIRED/exit1/final, failed phase and installed=false with original
identities retained. Evidence under native-ssh-evidence in the fixture pointed to by
/tmp/vpn-parity-macos-auth-path.txt. Runtime remained off. Aqua public cancellation
harness is running as temporary jobcom.kardinal.vpncontrol.parity-public-auth-304c24fc;
fixture TLS14686/port53689 has process-only JVM trust. Earlier unknown owners remain.
Android guarded routing selection20 and debug/instrumentation compilation passed.
The retained-GUI serializer regression first failed during fixture construction,
so that result is not accepted as serializer RED; corrected construction is being
checked before production changes. Native API29 add OOM remains independently proven
at protobuf toByteArray, with previously committed55999 domains preserved.

Mac source304c24fc public Aqua denial now also passed: real OS prompt screenshot
opened/reviewed, Escape cancellation yielded operation88c434eb-f67c-48ed-8540-98fdfab53a42
job3661380a-1368-4315-9830-d38f92c29fd6 CANCELLED/130/final, then exact next-owner
recovery with installed=false. Native-cancel-evidence retained beside native-ssh-evidence.
The exact terminal LaunchAgent was removed. TLS14686 is intentionally retained for
the next machine grant scenario; no active runtime was started. New authorization
codes still need catalog-backed GUI detail text (current update detail renderer only
localizes cancellation/unknown), and proven-no-start private input cleanup remains
a separate open gate. These do not invalidate the recorded CLI/native denial evidence.
Corrected Android48MiB heap regression now reaches retained-snapshots-ready at
36,617,704 bytes and reproduces OOM specifically in protobuf toByteArray/writeTo78;
targeted RED evidence retained at /tmp/vpn-parity-android-serializer-retained-targeted-red-evidence.
Android owner is implementing the compatible bounded writer; production/native proof
is still pending. Windows actual x86 v9 denial preserved506 traffic samples with no
failures, following ordinary-user repeated grant success; production remains gated.

Installer authorization GUI detail now maps INTERACTION_REQUIRED and PERMISSION_DENIED
to separate typed UI keys in all66 JSON catalogs. A regression first reproduced raw
wire-code rendering; full shared UI checks passed, followed by focused3 presentation
tests requiring translated, distinct outcomes in every language. Localization checker
passed with existing unchanged-English status warnings; these new keys have no
English fallback. Evidence /tmp/vpn-parity-install-auth-ui-green-evidence and matching
UI/localization logs. Native source304c24fc predates these text-only changes; new
visual captures remain required. Machine grant/replacement/rollback and GUI attach
to an owner launched in a noninteractive session still need public-path verification.

Owner cleanup now has a separately optional proven-no-start release callback;
cleanup acknowledgments bind to both the receipt and disposition code, so they cannot
decorate a later unknown outcome. Only CANCELLED/PERMISSION_DENIED/INTERACTION_REQUIRED
without a protected receipt qualify; inconsistent flags with an active receipt or
unknown code never authorize removal. Two regressions failed before fixes; cleanup5,
correlation13 and recovered status4 passed (22 executed, no skips/failures), evidence
/tmp/vpn-parity-no-start-cleanup-final-evidence. Platform release callbacks/native
private-input disposal are not yet wired, so this does not close the cleanup gate.
The disposable macOS guest administrator credential was queried asynchronously to
continue the real machine grant test; this does not block other platform work.


Current continuation evidence (2026-09-07):
- Root owns DesktopGuiVisibilityControl and its tests; Linux now owns the new
  synchronous operation client/tests and coordinated public-client dispatch.
  Android app inputs are frozen after export10 passed; Windows owns manager
  resource warning integration. No worker stages, commits or pushes.
- Source304 installed macOS proxy traffic passed4552/4552 probes through public
  hide/show, OS window close and exact frontend crash, unchanged owner/runtime.
  Initial public show failed from the SSH owner; diagnostic LaunchServices attach
  enabled these traffic checks, so automatic public launch is not certified.
  Archive /tmp/vpn-parity-macos-proxy-304c24fc-evidence.tar.gz,
  SHA91a0f71b9edc54653ddfe5c3457d11c17360364850ef3c4332471c6aec1e0d3f.
  Explicit off/quit and exact fixture cleanup completed. Packaged macOS frontend
  launch now uses LaunchServices; its regression failed before the fix and the
  GUI selection12 passed. Fresh-package verification remains required.
- Android serializer now streams compatible protobuf rather than allocating the
  full byte array; focused retained-heap and compatibility evidence is green.
  Latest Android union49 passed with no skips and both debug/instrumentation
  compiles. Fresh picker completion after process loss reproduced an orphaned
  empty document, then export selection10 passed after exact-URI cleanup and
  duplicate-callback preservation. Evidence directories:
  /tmp/vpn-parity-resource-red-android-freeze-evidence/android and
  /tmp/vpn-parity-export-green-gui-close-red-evidence/android.
  Both task AVDs are off and awaiting immutable base7/target8 APKs; native ART,
  SSH identity/parser and GUI transfer checks still require those packages.
- Windows manager resource regressions now execute: both fail as intended,
  demonstrating lost committed warnings and incorrect confirmed-stop reporting.
  An initial unsupported enum reference prevented compilation and is corrected;
  no shared wire code was added. Evidence /tmp/vpn-parity-resource-export-red-evidence.
- Linux installed eb6379 package passed GUI tray hide/show, detach/crash traffic,
  real benchmark measurements, disconnected-client completion, five-minute
  scheduled refresh (1724/1724 probes), and real TUN GUI lifecycle (31/31 probes).
  Permission preflight retained active proxy A before guest-only caps were granted.
  Explicit off restored routes; exact fixture processes/trust files/caps removed,
  guest2311 shut down. Archives /tmp/vpn-linux-gui-proxy-evidence-eb6379d3658f.tar.gz
  SHA52fd4db97f4d099942fe6fb698fce88b7b0dccaf9f4a37bb3bb6bb1c59c21fe8 and
  /tmp/vpn-linux-https-traffic-evidence-eb6379d3658f.tar.gz
  SHAcba692d68f674f85fccf10df925c8991cef48641b2e9915eda84525e2ae3831e.
  Remaining defects: synchronous transport timeout loses accepted operation ID;
  scheduled refresh lacks operation-list visibility; Home lacks pending/active cue.
  Closed GUI endpoint falsely reported INCOMPATIBLE_PROTOCOL; deterministic RED
  now proves this and mapping to UNAVAILABLE is implemented, green check pending.
  No automatic replay against replacement frontend was introduced.
- Final source review, native/visual closure, version bump, managed prepush,
  commits/push and exact-SHA required CI remain outstanding. No full parity claim.


Immutable sourcea2f17517c611c0e450f6236bbfde58f184fcdce14e5674315b39509d6710f9d3
fixture pointer /tmp/vpn-parity-export-runtime-freeze-path.txt now contains macOS
DMG7/8 and nondebuggable AndroidAPK7/8. Mac code009f1f0dc14e5b283735d4972cbf31194c0ee1c57fea8d883d2efeaee69e1093;
DMGbase SHAad2d8ffd74434018b1ddf5c67d77c70c3e43fb0ea51d8ce7eddaab0252176cd7,
target SHA65faea9f609db36c67bce611dbc1712fdbb48cf5362842b84f13ec048b0de9d6.
APKbase SHAe54e7aa69d42666918cc9b1746a70960da0bd08f092bb57542fa130bc78b35b8,
target SHAe17a885a6c331c07c07c95fbafdc1afe436903cc241b7768d12995cee3a9ae3d;
both39456966 bytes and canonical signer verified, codes16540/16560. Android worker
is installing base7 in the two off task AVDs for current native regressions.
Manager2 and GUI13 passed without skips before this snapshot's packages were used.

Fresh installed a2f17517 macOS base7 public gui show from SSH owner reached the
Aqua frontend but timed out during cold initialization. A new explicit request
succeeded, then public hide/show/status/quit all returned0. Screenshot opened and
reviewed. Runtime never started; owner quit, exact lingering frontend terminated
with SIGTERM after command/owner/workspace validation. Archive
/tmp/vpn-parity-macos-gui-a2f17517-evidence.tar.gz captures this bounded evidence;
first-call cold launch is still a failure, not a full native pass. Deterministic
cold-readiness regression failed at the old two-second limit. Production now uses
15-second bounded UI readiness plus an outer transport margin; green check and a
new frozen package remain required. Sourcea2f17517 cannot certify that later fix.
Linux CLI identity and observation-mode regressions both failed before fixes;
worker is implementing authenticated acceptance/status polling without mutation
replay. RED /tmp/vpn-parity-cli-identity-gui-cold-red-evidence. All final delivery
gates remain active and no version bump, commit or push has been performed.


Shared Home status now accepts authoritative ConnectionConfigurationPresentation:
active display name (or explicit unavailable identity) while running, plus saved
changes requiring restart. Pending selection is never used as the active-name
fallback. Desktop uses the same authenticated frame's runtime/location identities;
Android adapter wiring is reserved to Android owner. All66 catalogs have three
translated UI keys, localization checker passed, shared UI44 passed without skips.
Initial missing-details projection reproduced two failures before implementation.
Evidence /tmp/vpn-parity-active-pending-ui-red-evidence and
/tmp/vpn-parity-cli-identity-active-ui-green-evidence/ui. Native captures remain open.
Latest bounded cold frontend readiness fix passed GUI14 without skips; sourcea2f175
predates it. /tmp/vpn-parity-gui-cold-green-evidence records this focused proof.

Synchronous desktop acceptance/status client first passed27 selected CLI checks;
review then found authoritative terminal UNAVAILABLE was converted to a protocol
failure. Added regression reproduced it; Linux owner is correcting this before
acceptance. Never use that initial green union as proof for terminal-code fidelity.

Android current-package native correction: cold readback proves56000 domains,
including gui-added.example.test. Earlier eb6379 add therefore committed before
its subsequent allocation crash; the prior statement that55999 remained is
contradicted. Preserve the known56000 baseline. API29 current a2f175 GUI removal
then committed revision1, but immediate full read while the GUI remained open
returned OUTCOME_UNKNOWN. Android owner is gathering crash/heap evidence; root
reserves shared draft/Compose retention investigation. No rollback/reimport was
performed on the basis of that response failure. API35 malformed SSH envelope
rejected INVALID_ARGUMENT without revision change; valid real fixture key accepted
before runtime start. Further native SSH/runtime identity checks remain underway.


API29 failure investigation refined: the owner3477552e-db53-4d5e-999a-07570df8e7aa
remains alive with statusOK/revision1; GUI import operation7efe6b35-4ffa-4dfd-897f-9e6cc3906028
is terminalOK. No new fatal crash. Heap36,572KiB and immediate read OUTCOME_UNKNOWN
correlate with a separate eager ROUTING_SHOW path in ControlConfigurationInspection,
which materialized every domain Text beside the retained GUI. Reader regression
reproduced retained Text objects before fix; Android now supplies the immutable
AndroidPersistedDomainSuffixes.controlValues adapter, while shared default reads
still snapshot ordinary inputs. /tmp/vpn-parity-routing-inspection-red-evidence.
Two independent retention regressions also reproduced: StateFlow retained an
obsolete indexed draft when equal canonical data was applied, and Compose list
keys compared equal after backing replacement. Committed draft generation now
forces the UI-only state replacement; referential cache keys and sort-result
holders release equal old backings. No persisted configuration format or control
revision changed. RED evidence /tmp/vpn-parity-canonical-draft-red-evidence and
/tmp/vpn-parity-domain-compose-key-red-evidence. Integrated checks running; native
proof needs a new immutable APK and is not supplied by the older a2f175 artifact.


Integrated continuation checks now GREEN: core13 (RoutingGuiProjection4,
MainUiStateProjector4, ControlConfigurationInspection5), UI45, desktop42 across
SynchronousOperationClient11/LinuxInstallClient6/Unified4/OperationProgress4/
OperationCli3/ControlSession3/ControlInstallSession8/CliProcess3, all without skips
or failures. /tmp/vpn-parity-routing-cli-integrated-green-evidence. Android reader18
plus debug and instrumentation Kotlin compiles also passed without skips/failures,
/tmp/vpn-parity-routing-reader-green-evidence. Actual ART read-with-GUI after these
latest fixes still needs new APKs. Android worker is preparing a retained-reader
48MiB component regression and Android active/pending projection wiring.

Ownership transfer: Linux worker returned synchronous client/tests, public dispatch
and fingerprint stanza to root after GREEN42. It now owns Windows MSI installer/
coordinator/original-user admission/receipt implementations and tests/fixtures,
excluding VPN broker/userfiles/runtime manager, shared JNA (ask first), common
installation DTOs/dispatch, Main/factory and version metadata. Windows worker
retains broker/resources and must confirm its current native x86 union terminal
before transferring that environment to MSI; no overlapping operators authorized.
Desktop Find Best cancellation remains an explicit open implementation gate:
capabilities currently omit cancellation, recovery may capture pending selection,
and persistence results are discarded by an existing Unit callback. Benchmark
native cancellation cleanup also needs review; no support flag was enabled alone.
Root must integrate new resource publication warnings into lifecycle/public results,
including clearing active UI identity after a confirmed native stop with a resource
publication failure. Manager-only green tests do not certify that integration.


Connection presentation now preserves nullable runtime/restart knowledge for Android:
unknown is not projected as off or no-pending. Active identity unavailable and restart
requirement unknown are distinct localized facts (fourkeys in all66 catalogs).
Focused presentation5 and localization checks passed; Android adapter pending.
Docs hygiene initially found an unindexed historical parity-native-history.md;
added its history-only routing entry, then docs hygiene passed. Windows native x86
v12 component45 selected/44 executed/1 deliberate denial skip/0fail is terminal;
Windows owner transferred exclusive x86 operator to MSI worker after a fresh
no-runtime/no-msiexec/no-TUN inventory. Broker resource work moves to its separate
ARM guest; native x86 evidence remains separately classified. MSI workspace-return
regression is being checked before fixing the private request/worker relaunch.


Latest focused gates GREEN: Android16 (retained public reader48MiB/full56000 entries1,
connection presentation4, control status3, location presentation4, observer4) plus
both compiles. Evidence /tmp/vpn-parity-android-reader-memory-presentation-green-evidence.
This is a SerialGC JVM proxy; actual ART verification remains required. Lifecycle
now clears active identity after confirmed native stop with resource publication
failure while preserving original failure and off/reconnect intent; regression
first failed, then lifecycle10/actions5 passed. Captured originally disconnected
runtime restore also reproduced a failure and now restores off without treating
unknown running identity as off; lifecycle12/actions5 passed afterward. Evidence
/tmp/vpn-parity-runtime-off-restore-green-evidence. Resource warning presentation
and public recovery metadata integration remain open, separate from these facts.
MSI originating-workspace return fix passed19 tests with2 native-only skips; source
and native worker return behavior still require x86 execution. Android/Mac/Windows
base8/target9 snapshot is being frozen with all source owners paused.


Fresh source101268569c0866cfd646b8ea938bd0a96959b4ec536abf9f57609e5513cddd92
native macOS base8 passed first public GUI show from SSH owner in2.71s, then
hide/show/status. Actual proxy A stayed active after selecting pendingB; screenshot
opened/reviewed shows both names and restart notice. Continuous252/252 probes
passed through hide/show, OS close and exact frontend crash/reopen, ownere94d30b8-94fd-468b-99b9-1c064fcac3b8
runtime78a751a9-5742-4637-87f0-38bf40f7dd9b unchanged. Explicit off/quit, SOCKS and
exact frontend cleanup completed; fresh process inventory empty for this fixture.
Archive /tmp/vpn-parity-macos-gui-10126856-evidence.tar.gz SHAa77164add7419d78d1dfba9fceb0710d709fe97e6cc689f523061a90a00e8007.
Supplementary static help/version/capabilities and missing-ownerstatus created no
workspace. Valid settings set mode vpn returned authoritative UNSUPPORTED and
preserved off/proxy-only; initial malformed settings mode invocation is retained
as harness error, not a product failure. Static evidence archive
/tmp/vpn-parity-macos-static-10126856-evidence.tar.gz SHAc0404cdc6a7b44248af0f5bfce8a2219081e6f32e6cf1a84a6d09bdfb188569b.
Machine authorization grant/replacement/rollback, same-source update return and
remaining cleanup gates stay open. Old unknown machine journals/owners and TLS
fixture are unchanged; current proxy fixture alone is fully stopped.

Android Reader now obtains one owner status snapshot for non-runtime read envelope
warnings: settings reads no longer falsely claim unavailable runtime identity when
the owner knows it, while explicit unknown status/telemetry keeps its warnings.
Native discrepancy reproduced in a20reader regression beforefix; reader20 plus
retained-reader-memory1 and both compiles passed afterward, evidence
/tmp/vpn-parity-android-reader-observation-green-evidence. This change postdates
101268 packages. SSH stale draft save is correctly rejected but native dialog hid
failure feedback; three deterministic regressions failed, Android worker is fixing
sanitized ephemeral feedback. MainUiState field ownership returned to root.
Windows broker/user-files/return hostunion23 selected/10executed/13nativeskips/0fail,
/tmp/vpn-parity-windows-resource-return-union-evidence. Native x86 MSI return component
now passed after correcting test-only PowerShell literal indentation. Windows native
fixture wrapper-path launch failed before product execution; corrected orchestration
helper is separately hashed against unchanged101268 source, with failed build kept.


Windows runtime workspace scope is now lazily bound by DesktopAppService before
DesktopControllerOwner session construction. The owner regression first failed
without binding, then passed; scope creation is deferred until runtime resource
admission. Strict canonical records are never repaired/overwritten, and repeated
admission verifies original path, parent/file identity, bytes and digest. Focused
host union56 selected/41 executed/15 native-only skips/0failure, archived at
/tmp/vpn-parity-windows-scope-binding-green-evidence. This is controller/component
evidence, not production-enabled Windows VPN. Native resource leases and durable
job correlation remain Windows/root integration work.

Find Best now propagates benchmark/final persistence failures instead of discarding
Result through a Unit callback. Failed initial benchmark persistence stops before
verification/runtime mutation. Admitted search clears busy/refresh flags on probe
cancellation and propagates candidate-verifier cancellation. Deterministic RED
evidence: /tmp/vpn-parity-find-best-persistence-cancel-red-evidence (persistence);
/tmp/vpn-parity-find-best-cancel-flags-red-evidence (busy flags). The first cancellation
test also exposed coroutine exception stack-recovery copying, so identity assertion
was corrected to type/message and the absent-cleanup regression independently rerun.
Final FindBest7/BenchmarkCli2/Lifecycle12 all21 GREEN, zero skips/failures,
/tmp/vpn-parity-find-best-persistence-cancel-green-evidence. This does not yet certify
Find Best runtime transition cancellation, actual-A recovery, or known/unknown commit
handling; cancellable capability remains unchanged until those are complete.

Current ownership handoff:

| Task | Agent | Owned subsystem | Dependency / next handoff |
| --- | --- | --- | --- |
| Windows durable runtime correlations | root | DesktopWindowsWorkspaceResourceJournalRegistry (new), scope provider binding, tests | Windows owner supplies immutable registry API and authoritative reconciliation |
| Windows native resources | windows | Broker, runtime resource declarations, mutable leases/journals | Root durable registry, then production integration |
| Android retained import OOM | android | RoutingRulesCharacterImport.kt and focused shared parser/memory tests, app heap tests | Exclusive shared parser ownership granted; request host check before native freeze |
| Windows MSI native replacement | linux | Existing installer ownership, exclusive native x86 guest | Built source101268 base8/target9; public replacement/recovery next |

Android source101268 first real48MiB GUI add and full read passed; subsequent remove
failed without changing committed data. Worker traced ART OOM to existingDomains
toTypedArray materializing persisted strings in RoutingRulesCharacterImport with
retained GUI/operation snapshots. This parser-specific follow-up is assigned above;
earlier eager-reader fix remains independently proved and no completed operation
should be reclassified because this later mutation failed.

Windows ordinary-workspace resource registry now binds scope.journals lazily.
Immutable private job records contain exact original controller/scope proof and
opaque resource identities, retain up to8 unresolved jobs without eviction, and
never initiate helper work. Lost publication replies recover by exact job identity;
conflicts/corruption and failed cleanup retain evidence. Registry6/scope3/owner2
passed on host. Native conditional removal holds READ_DATA+DELETE with READ sharing
only through ACL/content verification; a new opt-in Windows test remains pending.
No native-registry or production-enabled VPN claim follows from host coverage.

Android parser retained-string lookup fix passed shared7 and Android10 tests plus
both Kotlin compiles, alongside desktop11: all28 selected/executed, zero skips or
failures, /tmp/vpn-parity-resource-registry-android-import-evidence. Before-fix
/tmp/vpn-parity-android-retained-import-red-evidence proves both eager old-list reads
and actual constrained-heap OOM in preparation after fixture readiness. Native
full-size consecutive GUI editing remains mandatory. New immutable source snapshot
950ccc0fe4e1d3b344b9515a34314b701ac0bc77d895b6a7a0a5f731684ffb12
is building Android diagnostic9/10; pointer /tmp/vpn-parity-retained-import-freeze-path.txt.
This snapshot includes Reader warning and SSH feedback fixes omitted from101268.
Registry native test/digest guard added afterward are not certified by this snapshot.

User-required fast native-failure regression policy is now canonical TEST-001 in
contracts.md, referenced by AGENTS.md, development.md and test-matrix.md. Applies
to every distinct VM/emulator/native/package/manual/visual/integration failure
type, requires pre-fix failing and post-fix passing behavior plus routine suite
wiring, and records OS-only limitations. Source assertions or skipped native tests
alone are not reproducers. Docs hygiene/diff whitespace passed after this change.

Windows registry nativev15 is GREEN on ARM64 Windows SYSTEM with x64 JVM emulation:
15selected/15executed/0skip/0failure,15.555s; exact native conditional record deletion
and cold-owner recovery executed. /tmp/vpn-windows-finish.WhKUbn/native-arm-v15-resources-result.json.
Not ordinary-user or installed-package evidence. Root latest host registry/scope/owner
13selected/12executed/1native skip GREEN; /tmp/vpn-parity-resource-registry-native-ready-evidence.

Find Best failure recovery now captures actual runtime before subscription refresh
and invokes that restoration instead of starting the staged selected location.
Regression failed with old fallback; /tmp/vpn-parity-find-best-actual-runtime-red-evidence.
Cancelled candidate authorization now terminates the search after captured recovery
instead of prompting for subsequent candidates; RED at
/tmp/vpn-parity-find-best-authorization-cancel-red-evidence. Final FindBest9/Actions5/
BenchmarkCli2/Lifecycle12/Manager transient-cleanup1 all29 GREEN, zero skips/failures,
/tmp/vpn-parity-find-best-recovery-cancel-green-evidence. Remaining Find Best gates:
coroutine cancellation during native mutation, pending-selection preservation after
failed candidate staging, recovery on all early/exception exits, and committed/unknown
result semantics. Cancellation capability remains unadvertised until fully verified.

Source950 Android9/10 APKs built/verified same signer and nondebuggable. Base9 hash
fd45dc27307dd77f3cc5ea4be7cbdcb3fa553ee9dd8d61c72e5b351f3e0df1ef; target10 hash
9d822b51a70d6598e4d3af5f129ef3fe7ff657459b19d7cd147afa01854f0989.
First API29 full GUI edit/read56001 passed, but second edit still fails under48MiB
without changing committed data; exact new allocation diagnosis pending. The passing
small-replacement heap regression proves old-pool materialization fixed, not full
consecutive-edit memory acceptance. API35 stream cancellation/epoch termination and
Reader warning correction passed on950. Android owns optional MainUiState
routingDraftFailure stanza plus app Rules controls-slot feedback/tests; shared
RoutingRulesScreen remains root-owned unless explicitly transferred.

Find Best unknown-result boundary reproduced overwriting benchmark state after an
OUTCOME_UNKNOWN start response, and CLI mapper downgraded unknown to runtime failure.
Both fixed: mark owner operation pending, preserve code/exit2, no further candidate
or restoration/write; competing GUI actions remain busy until reconciliation.
Busy guard independently RED at /tmp/vpn-parity-find-best-unknown-busy-red-evidence.
Final FindBest10/BenchmarkCli3/OperationProgress4 GREEN17/0skip/0failure,
/tmp/vpn-parity-find-best-uncertainty-green-evidence. Earlier combined RED attempt
failed compilation because of test nullable-list inference; its stale XML directory
is explicitly named compile-failed-stale-xml-not-evidence and is not validation.
Actual behavior RED: /tmp/vpn-parity-runtime-uncertainty-red-evidence; CLI RED:
/tmp/vpn-parity-runtime-uncertainty-code-red-evidence. Native pending-result recovery
and all early/exception/cancellation paths still require completion; no capability
was enabled on this evidence alone.

Resource registry schema2 adds required original native PID/creation FILETIME/SID,
exactly roundtrips that identity on owner replacement, and rejects changed PID,
PID reuse or foreign SID for the same scope/job/resources. Registry8 selected/7exec/
1native skip plus MSI Prepared10/Captured2/ReceiptNative1skip/ReceiptScript1skip
GREEN in /tmp/vpn-parity-msi-native-owner-union-evidence. Native publication journal
v3 has corresponding owner tuple; Windows worker owns an exclusive admission gate
that combines exact original-owner exit with durable closure to exclude delayed
helper creation. Stage absence alone remains insufficient. Registry v1 records fail
closed; only disposable component fixtures used that unshipped format.

Full Android consecutive-edit regression now reproduces the second write without
an emulator: first full56000 import commits, second starts near37.7MiB then OOM in
AndroidStringListCodec.asciiString -> encodeOwned -> AndroidPreparedRouting.consume
inside DataStore editProjected. /tmp/vpn-parity-runtime-uncertainty-android-chain-evidence
(Android1RED; desktop30 executed/1native skip GREEN separately). Heap/source evidence
/var/folders/vq/zns5cfbd6zd64jw8hfgzzczr0000gq/T/android-routing-consecutive-memory-17980896387461839969.
Android worker is inspecting retained objects before choosing a fix; existing
Preferences format unchanged. Host diagnostic helper /tmp/android-routing-hprof.py.


### Coordinated receipt snapshot and memory boundary, 2026-09-07

| Task ID | Agent | Owned subsystem | Shared reservations | Dependency/artifact | Current check | Next handoff |
| --- | --- | --- | --- | --- | --- | --- |
| B/F integration | Root | Desktop connection/Find Best; build/CI/docs | App Gradle, shared integration, final delivery | Host build serialized | Candidate selection/recovery35 GREEN | JNI host build and integrated regression |
| C/G | Android | Android JNI C/CMake/Kotlin, retained result spools, Android tests | MainUiState routing failure stanza only | 48-MiB consecutive edit RED | Standard JNI and disk history implementation | Coherent host/native helper selection |
| F | Windows | Native broker/resources and focused tests | Production binding coordinated with root | ARM component guest2299 | Gate/native owner regressions | Complete mutable resources and production evidence |
| E Windows | Linux | MSI worker/token/receipt, fresh x86 guest | No common update changes without coordination | Frozen aee288a7 base9/target10 | Fresh guest bootstrap; old unknown owner preserved | Same-source replacement/recovery |

Find Best now defers candidate selection until successful runtime transition;
authorization denial preserves actual A and pending B. Failed final selection
persistence restores A and publishes the restored session timestamp. Causal RED
selections and final35 GREEN/0skip are retained under
/tmp/vpn-parity-candidate-selection-recovery-green-evidence (FindBest10, Actions5,
BenchmarkCli3, PendingConnectionCli2, Lifecycle15). This does not close remaining
Find Best cancellation and uncertain-result recovery gates.

The verified immutable Windows fixture is
/var/folders/vq/zns5cfbd6zd64jw8hfgzzczr0000gq/T/vpn-parity-msi-receipt-freeze-i2cxnpxr/windows-fixture,
source aee288a7602d579a444031eb10f0062c232e27ef0bea4e5107d5f018264455dc,
base2.1.9/target2.1.10, actual x64 runtime
ca74563c93440a2e9cb73eae6a04c109d3f5efce36a385f8261a654e362d2ea3.
All workers paused for verified copying, then resumed. This snapshot includes the
receipt rename/wait fixes and excludes subsequent linked-token/JNI/resource edits.
New installation attempts use the fresh owned guest2314; the old2310 unknown
installation owner/journal remain intact. Its separate build directory may build
immutable inputs without touching the installed owner.

Heap analysis isolates the second Android write peak to old Preferences backing,
new output byte array, and new String allocation, with an8-MiB UI proxy; old token
retention is no longer the cause. Android is implementing a standard-JNI String
constructor with bounded callback reads and explicit allocation failures, plus
private disk-backed historical results. Native temporary memory remains linear
in document size. Root owns pinned NDK/CMake and ordinary fast-test build wiring;
Android owns production C/CMake and host-only allocator tests. No libbox/sing-box
runtime upgrade is involved. Full consecutive edit/native APK acceptance remains
pending; the earlier small-replacement GREEN is not sufficient evidence.


Find Best cross-source identity regression now proves a duplicate profile in a
hidden source was selected instead of its observed visible-source record. Causal
RED: /tmp/vpn-parity-find-best-source-causal-red-evidence (expected visible URL,
actual hidden URL). The first attempted fixture omitted current locations and
failed precondition; it is not causal evidence. Winner lookup now binds observed
source URL/raw identity and winner flags select only that record, clearing other
selection flags. Final union /tmp/vpn-parity-source-native-owner-final-green-evidence:
FindBest11, NativeOwner3, Registry8/1native skip, Scope4, Reconciliation7;33 selected,
32 executed,1 native skip,0 failures. NativeOwner separately reproduced non-ASCII
SID digit acceptance before correction in /tmp/vpn-parity-native-owner-ascii-red-evidence.

Pinned SDK NDK28.2.13676358/CMake3.22.1 installation completed successfully. App
Gradle config parses with the new host JNI build tasks; actual C/test execution
and new APK verification remain pending the Android worker's coherent handoff.
Fast Checks and Android Release now explicitly install those pinned build tools.

Host JNI configure/build passed with AppleClang21 and strict warnings, log
/tmp/vpn-parity-native-string-host-build.log. Both production C and host allocator
hooks compiled into the generated host dylib. This is compilation evidence only;
Kotlin callback, constrained heap, failure-path execution and APK evidence remain
pending. Android C source hold released after successful build.

Android JNI boundary selection:11 selected,10 passed,1 NewString-allocation failure
test failed; both Android Kotlin compiles passed. Evidence
/tmp/vpn-parity-android-native-string-boundary-evidence. Android owns diagnosis.
Root FindBest refresh-cancel regression initially failed cancellation exception
identity due to coroutine stack recovery, not causal runtime restoration; changed
to message assertion, needs rerun before accepting RED. No restoration fix yet.


Find Best refresh/cancellation causal RED confirmed expected Actual A but observed
Refresh temporary runtime in
/tmp/vpn-parity-find-best-refresh-cancel-causal-red-evidence. Recovery now captures
before refresh, tracks possible mutation and known commit, and restores at most
once under NonCancellable on early failures or cancellation. Unknown outcomes keep
owner work pending/busy; committed runtime is never rolled back for later metadata
failure. Added restoration-failure/unknown and post-commit persistence guards.
Initial cancellation fixture compared exception object identity, which coroutine
stack recovery changes; that initial failure was not causal and was corrected.

Integrated /tmp/vpn-parity-recovery-android-jni-chain-evidence passed:
FindBest14, OperationProgress4, BenchmarkCli3, Broker19/9native skips,
UserFiles7native skips; AndroidNativeString8, StringListCodec3,
RoutingConsecutiveMemory1. Total59 selected,43 executed,16 native skips,0 failures;
both Android Kotlin compiles passed. Full consecutive48-MiB GUI-like edit/history
chain now passes in5.82 seconds. Fresh API29/API35 APK evidence and historical spool
failure/lifetime tests remain mandatory. Native allocation test initially exhausted
heap constructing its own pressure fixture before JNI; corrected fixture proves
all input bytes were read before NewString OOM and successful cleanup/later use.
This was a test-fixture correction, not an additional production memory fix.

MSI same-user elevated-owner linked token probe failed1346 because token was
identification-level impersonation. Root reviewed the documented retained-parent
process token inheritance route and authorized a bounded native probe with exact
same owner SID/session, non-elevated verified OS shell handle, and suspended-child
identity verification. No name enumeration or alternate-user fallback is allowed;
production integration still requires review and native evidence. Ordinary MSI
replacement remains the Linux worker's first priority.

Production ARM64 application JNI build passed via :app:externalNativeBuildRelease.
ELF AArch64 with0x4000 LOAD alignment and only production JNI export (no host test
hooks), unstripped32984 bytes SHA
f677a0bc1aad244170c1a2f800031736b73cf8ff0f1acc1c82556c7724e7a758.
C/CMake source hashes and component classification in
/tmp/vpn-parity-native-string-arm64-identity.json; build log
/tmp/vpn-parity-native-string-arm64-build.log. This is component build evidence,
not a packaged APK or live ART acceptance result.

Retained Android result lifecycle selection9 ran7 GREEN/2 RED before fixes:
changingCaptureInputCannotPublishAnUnverifiableHistoricalResult, failedPartialSpoolCleanupRemainsOwnedForShutdownRetry.
Evidence /tmp/vpn-parity-android-retained-results-red-evidence. Android owns fixes
for mutable capture rejection and failed partial-spool cleanup ownership/retry;
APK freeze waits for their coherent regression plus full48-MiB chain.


Android retained-result capture/partial-cleanup fixes now pass the broader37-test
selection, no skips/errors: history9, NativeString8, consecutive memory1, pipeline
memory1, codec3, Preferences serializer9/memory1, resource boundary5. Both Android
Kotlin compiles pass. /tmp/vpn-parity-history-green-admission-red-evidence/android.
The same --continue build intentionally ran Windows admission2 causal RED tests;
that independent failure does not invalidate the executed Android selection.
Windows owns the pre-UAC ancestor pin fix before the next coherent source freeze.

Debug JNI ARM64 and x86_64 builds passed. Both ELF architectures match their ABI,
LOAD alignment0x4000, only production JNI export; identities in
/tmp/vpn-parity-native-string-debug-identities.json. CMake generated app/.cxx was
not previously ignored. New fixture regression reproduced cache inclusion before
fix; source snapshot rejects .cxx, .gitignore excludes app/.cxx, and release hygiene
rejects tracked cache paths. scripts/test_desktop_update_fixture.py now16 GREEN;
this suite is already wired to routine hygiene/pre-push. No generated cache is
part of the upcoming immutable APK source.


Immutable source8dd8984f68118497f83fcf6fbf0418329df74db44576eb97b2b031476bfafa36
verified1315 inputs with all owners paused. Root
/var/folders/vq/zns5cfbd6zd64jw8hfgzzczr0000gq/T/vpn-parity-jni-history-freeze-t3g5u2d9;
pointer /tmp/vpn-parity-jni-history-freeze-path.txt. Read-only source plus private
build copy; generated .cxx excluded. WindowsAdmission2/Broker19 (9 native skips)
passed before capture; native C# ancestor fix and later close-ownership tests are
outside this snapshot. Source hold released after verification.

Both8dd nondebuggable APKs built with canonical signer
 a43b5330501b02f5558fa381c52e7f7dcdd9db362d6807d449d7bbb5e207c5a0:
base2.1.10/code16600 SHA78e685403285f7c8b588c4e287a6cced875b487e29c04dad61d07270460269aa;
target2.1.11/code16620 SHAe7fa443f7c51eb66401b80b95a8842a085b3a37d77cd6f333a2c8403e87f190d.
Each39501439 bytes. artifacts.json and APK badging/signer/JNI ELF inspection are
under android-diagnostic. JNI architecture/alignment/production-only exports pass.
Android owns current native verification preserving API29 committed56001 domains.
First f77d3 CLI→8dd APK reads are explicitly mixed-artifact; matching complete8dd
macOS CLI app-image build follows from the same private checkout and captured
unchanged ARM64 runtime e6c43070482bbe4d2282b5de704d4e9a510a78249d8ed67f9c9cf57e002a8651.


Complete same8dd macOS ARM64 CLI app-image built and169-entry manifest verified:
desktop-cli/vpn-control.app under the8dd root. Launcher
Contents/MacOS/vpn-control SHA403fd6eb885f799f137eb3dbe9067125810c0d2a104a785fa4928394da634ae7.
Generated files made read-only after checksum verification. Includes bundled JVM,
unchanged captured runtime, and native Mac worker freshly compiled from8dd source.
Classify app-image, not DMG-installed. Android worker received matching launcher
for subsequent current-source ADB gates. Initial scratch build invocation attempted
an unexecutable shell script directly; corrected to the existing bash invocation
before any Gradle build started. No product source/permission change was needed.

New Windows admission close-failure regressions run4 selected/2 GREEN/2 RED:
readyChildAndUnclosedAdmissionAreBothRetainedAfterCleanupFailure loses its known
child, and failedAdmissionRetainsUnclosedHandlesForExplicitRetry loses native pin
ownership. /tmp/vpn-parity-windows-admission-close-red-evidence. Windows owns fixes;
source hold released. Native C# ancestor5 GREEN is separate ARM component evidence,
not part of8dd nor proof of production scoped VPN activation.


## Current Native Findings And Regression Follow-up (2026-09-07, 12:55 UTC)

- Android source8dd APK10 reproduced the second full GUI save failure at48MiB.
  A real UID2000 heap dump identified the old approximately11.7MiB Preferences
  backing retained through an offscreen Compose summary card's MainUiState.
  The headless rendered DesktopRoutingSnapshotRetentionTest reproduced that
  precise obsolete backing retention before the fix. Bounded outer cards now
  use a scrolling Column and scalar summary presentation; domain/application
  rows remain virtualized. The rendered regression, all46 shared UI tests and
  both Android Kotlin compilation targets passed (Gradle31308). Evidence:
  `/tmp/vpn-parity-routing-snapshot-causal-red-evidence` and
  `/tmp/vpn-parity-routing-snapshot-resource-green-evidence`. Current ART full
  GUI rerun remains required; host rendering is not low-memory device proof.
- The same union passed Windows resource protocol3, configuration capture11
  (2 native skips), broker19 (9 native skips), user-file8 (8 native skips).
  Separately v17 Windows native storage/admission selected81/executed72/skipped9
  runtime/UAC/TUN scenarios, zero failures, on ARM64 with verified AMD64 JVM.
  Production scoped runtime remains disabled. No packaged runtime claim follows.
- Fresh native x86 MSI sourceaee failed before UAC because Defender blocked the
  dynamically compiled PowerShell worker. No protection exclusions or settings
  were changed. NativeAOT fixed-role packaged executables are the agreed
  replacement; Linux owns pinned projects/build preparer, Windows owns broker
  source, root owns Gradle/workflows. Elevated Framework loading was rejected
  because mutable adjacent configuration/CLR loading precedes managed Main.
  Native loader/import authority and complete current-package execution remain
  gates. Exact external pre-readiness worker exit now remains RUNTIME_FAILED
  in both public operation and proven-no-start correlation. Shared34-test
  selection passed; subsequent WindowsPreparedInstall12 selection passed.
- Current macOS immutable8dd DMGs use test-only versions2.1.10/2.1.11; logical
  code fingerprint is bbe5c84a554540607ce40ea5f86c582f2ff5ae3a0612f5e9772abab8138bf117.
  BaseSHA b8bc1958edd8abcc65ec2990e543aec8986b5e526d97d5502109ac232eaac8cf;
  targetSHA43a20451d0362f63a0259fbe8a61f5c0211717d41eb59e38daca4c30f68a33c9.
  Machine-owned base is guest-only `/Applications/parity-8dd8984/vpn-control.app`.
  Private fixture proxy/JKS is confined to its owner JVM; an initially incorrect
  trustStorePassword option failed before networking and was removed to match
  the existing fixture JKS configuration. Add a fast fixture regression for this
  harness error. Download observer timeout preserved operation7537b527-0f44-4b80-b308-c96f207ecbb8;
  waiting on the same operation later established successful full download.
- Mac temporary guest admin vpnparity8dd was created without changing any
  existing account password. Its credential remains guest-private and unprinted.
  Remove that exact account and private credential after authorization scenarios.
  Real OS grant for jobb2a33475-6c52-428d-ac58-e403c3b932cf arrived after the
  preparation deadline: original operationa9d8e160-7db9-4ac8-897d-31f1dd4d3e8b
  remained OUTCOME_UNKNOWN, then explicit public cancellation established
  CANCELLED/130, protected terminal receipt and installed=false. No installer
  was killed or uncertain mutation replayed. Only after terminal proof was a
  new installation requested: operationbfdcc39a-34a8-4be4-bf26-3b66a8e76c25,
  owner58a91157-8300-4628-99f5-030bb90b5e5c. Its outcome is pending observation.
  Evidence/task root: `/tmp/vpn-parity-macos-native-20260907.O45e6J` on guest
  192.168.64.3; current fixture proxy port49876 and exact transient LaunchAgent
  com.vpncontrol.parity.machine8dd8984. Old unrelated/unknown owners preserved.


### macOS Owner-Exit Watcher Regression (13:02 UTC)

The timely retry is identified by
job844718c1-91fe-4807-a035-79312660e52a, operationbfdcc39a-34a8-4be4-bf26-3b66a8e76c25.
It reached protected WAITING_FOR_EXIT and authenticated handoffReady=true;
owner21354 exited normally, then protected sequence3 became FAILED/CONFLICT.
Base2.1.10 remained installed. The return watcher disappeared at owner exit.
A real-worker component regression reproduced its inherited owner process group
before any installer or receipt was created (0.562s, causal RED). The worker now
sets its own process group before reporting readiness, retaining UID/eUID/session
and all original generation/receipt checks. The portable production primitive
also reproduced the inherited-group failure before the fix, then passed on the
host; all5 native gate/watcher/return tests passed in the macOS guest (0.293s).
This fast portable test is part of existing routine test_macos_install_gate.py
hygiene wiring. Host run executes1 and explicitly skips4 guest-only tests.
Native evidence is under the task root's watcher-group-red and watcher-group-green;
portable logs are /tmp/vpn-parity-watcher-group-portable-{red,green}.log.
Full source-matched installed replacement must still rerun with the fixed worker;
no current package contains this fix yet. Do not change fixture launchd cleanup
settings to conceal this product watcher lifetime failure.

Android routing feedback/control regression selection additionally reproduced5
failures before the fix: invisible failed autosave feedback, stale input feedback,
unknown-result retry identity, and distinguishing import from editor retry.
Evidence /tmp/vpn-parity-routing-feedback-causal-red-evidence (Gradle68150).
Android owns the bounded field/message/catalog and explicit Save retry fix.

Public macOS updates status started recovery owner3eba688e-b8d0-45c5-a49a-6d558a999f59
in the same machine workspace and recovered both exact original correlations.
The failed job reports CONFLICT/final=true/cleanupCode=OK/installed=null; cancelled
job reports CANCELLED/final=true/cleanupCode=OK/installed=false. Retained uncertainty
is not rewritten merely because external bundle inspection still sees base2.1.10.
Evidence machine-8dd8984-evidence/failed-next-owner-recovery.json. New transient
owner must be reidentified before further fixture changes; no new install requested.


## Snapshot64d Routing Feedback And Watcher Packages

Source64d43b7fdf17b94cb3d464f36bc31642688b8bb1f1d37234c6893747290a7c5d
freezes1327 inputs after all three workers confirmed source holds. Pointer:
/tmp/vpn-parity-routing-feedback-freeze-path.txt. Canonical version remains2.1.3;
immutable fixture versions are2.1.11/2.1.12. Source includes Android rendered
retention/typed feedback/explicit retry fixes, all66 status catalog additions,
macOS independent watcher process group, and intentionally unwired Windows
NativeAOT scaffolding. It is not a complete Windows implementation snapshot.

Android Gradle77133 passed20 feedback/control/actions tests,47 shared UI tests
and both app/instrumented Kotlin compilation targets. Current evidence:
/tmp/vpn-parity-routing-feedback-green-evidence. The APK pair built in session47715
(terminal0), retains canonical signer a43b5330501b02f5558fa381c52e7f7dcdd9db362d6807d449d7bbb5e207c5a0,
and is nondebuggable. Base2.1.11/code16620 SHA
c5ec9779219a0a8414573d2eabed867088fd2d82a4462d8a7b3688621ca2bf63;
target2.1.12/code16640 SHA
d130e8938afa377f3abc45877c085b5da3004676c0ddc05d2d770ccb6ecfff74.
JNI ARM64 alignment/export checks passed. ART verification remains pending.
Mac same-source DMG build session81582 failed before compilation because eager
Android SDK lookup configured the unrelated app module without ANDROID_HOME.
The immutable64d retry uses the installed SDK and a separate log (session26530);
inspect its handle before further host Gradle work. A real launchd component test also reproduces
watcher death with the old native worker (0.278s) and passes with the fixed worker
(0.286s), without altering launchd's process-group cleanup behavior.

User authorized Terra-medium for Android/routine Linux-packaging subagent work,
while retaining Astra for privileged Windows architecture and final review.
Worker ownership is transferring via explicit temporary handoffs; do not infer
that old/new workers may operate a guest simultaneously. NativeAOT provisioning
PID8056 in fresh Windows x86 guest continues; never restart it solely because
observation times out.

Model transition completed with explicit spawn settings gpt-5.6-terra/medium for
/root/android_terra and /root/linux_terra. Old /root/android and /root/linux
released all source/native ownership and finished; do not assign them writes.
Handoffs: /tmp/vpn-parity-android-terra-handoff.md and
/tmp/vpn-parity-linux-terra-handoff.md. Root and /root/windows retain inherited
Astra for privileged design/review. Existing native fixtures/toolchain were
preserved, and replacements must observe existing operation handles first.


## Desktop SDK Configuration Regression And Resumed Checkpoint

The no-SDK desktop task graph regression reproduced the package configuration
failure before the fix (/tmp/vpn-parity-desktop-sdk-red.log). Lazy CMake SDK
resolution alone still failed because the Android module was eagerly configured.
Gradle configuration on demand plus deferred native-task SDK lookup passed the
real graph regression (/tmp/vpn-parity-desktop-sdk-green.log); the final routine
script permits dependency downloads for fresh CI caches. Android focused tests
also compiled and passed with configuration on demand. The check is wired into
release hygiene and mapped in test-matrix.md. This is build evidence, not native
installation evidence.

API29 base64d cold GUI startup exposed a separate Preferences protobuf allocation
failure at 48MiB. The first 12MiB host pressure candidate passed, so it is not
causal RED evidence. Android owns further reproduction; storage-format changes
are not yet justified. Windows owns a newly identified rejected-witness close
failure regression, awaiting the serialized host test slot before a fix.

The next delivery milestone is a coherent validated checkpoint push, followed by
exact-SHA required CI; full parity remains unfinished. The local Codex config
contains machine-specific paths and approval overrides. The user authorized moving machine settings out of Git. The local file is now
ignored and generated from agent_tools/codex-config.toml.in; its explicit index
removal is part of the reviewed checkpoint, and the working local config remains
present. configure_codex.py derives paths and backs up changed local settings.


Source64d macOS base/target DMGs completed in session26530, terminal0. Base
SHA b9d8fc32aa5e93565536ba105be479da5ebf6b8b62c8ffbd2743e02bd5894864;
target SHA e16c0989588dc8df89cff9faf8c3521b4159cd5d1cf654effc1e98ba95aaa6d3.
Both match codeFingerprint522ca69cd52eb502a70e898bcd06716740c00537dc1faf42e5a168d5e7246cb5.
Transferred immutable DMGs/manifests to owned macOS guest task root
update-fixture-64d43; installation has not started.

Windows witness retention and accepted-candidate readiness OOM regressions
reproduced both defects before fix (resource-causal-red-evidence under /tmp).
The focused GREEN union ran53 tests,44 executed,9 native skips,zero failures;
evidence /tmp/vpn-parity-windows-resource-green-evidence. Native component
v19 source fingerprint f1419d878633fa32d58c5890702633a888562f4d941eb56627e606b56cb6e9ef
is being verified independently. No production broker enablement is claimed.

Android cold reopen now has causal host RED: stock protobuf readRawBytesSlowPath
allocates beyond the48MiB heap before routing mapping. Evidence
/tmp/vpn-parity-android-cold-read-red-evidence. Android owns compatible streaming
read implementation and corpus checks; old protobuf/newline persistence remains
required. This source slice is not frozen or ready for checkpoint yet.


Checkpoint tooling verification: generated ignored Codex config passed a real
MCP initialization/list-tools handshake (10 tools). The agent-tool suite ran28
without skips in .agent_venv; ordinary Python omitted the MCP handshake dependency.
Root dry-run prepush includes the full shared/desktop/Android task union.
Hygiene first encountered external AppleSharpener injection writing diagnostics
into a fixture process output. A rerun removes DYLD_INSERT_LIBRARIES only from
the verification subprocess environment; host/global settings remain untouched.
That rerun then exposed a real direct-script import failure in
test_android_update_fixture.py. Adding its repository-root import path made the
existing routine two-test command GREEN; failed log is
/tmp/vpn-parity-checkpoint-hygiene-clean-process.log.

WindowsNativeAOT fixed validate-only entrypoint compiles and executes in the fresh
x64 guest after causal IL3050 RED identified Marshal.SizeOf(Type). The generic
SizeOf<SecurityAttributes> correction preserves behavior. Emitted helper
SHA a1c5120d8dc58f5b807cc7b24db0b27638c05a9c52b7a81b96e330c95cd16405.
It has no installer role yet and is not wired into packages; emitted imports and
loaded modules remain unverified. Current native helper script suite runs6 tests.

The64d base DMG was installed in the owned guest at
/Users/admin/Applications/parity-64d43/vpn-control.app; its public launcher reports
2.1.11, exit0. Receipt under update-fixture-64d43/installed-base.json. No runtime
or installer replacement started. Initial scratch checksum invocation used a
Python3.11-only convenience unavailable on the guest; the resumed harness uses
the fixture's existing bounded file_hash implementation.


Checkpoint source hold: Android read compatibility and cold48MiB pipeline union
passed22 tests (16 serializer,5 suffix-list,1 pipeline),zero skips/failures.
Copied XML/log: /tmp/vpn-parity-android-reader-green-evidence. String decoding uses
bounded private UTF-16 spooling and the existing JNI constructor; supported
protobuf persistence remains unchanged. Segmented unique-domain ranges avoid
large-array growth/final-copy peaks and preserve logical list bounds. Native
API29/API35 reader acceptance is pending and is not certified by this host run.
All workers now hold source for coordinator prepush/checkpoint delivery.
Release hygiene passed with only documented platform-specific skips; metadata
and managed prepush must still follow this final content edit.


First managed prepush reached the broad desktop suite (868 selected,56 native
skips) and found5 obsolete test assertions, with source behavior intact: human
inspection is a labelled result and human failure output goes to stderr; routing
drafts retain structured lists instead of eager duplicate text. Updated tests
assert those contracts, exact JSON inspection data, and preserved revision guards.
Focused rerun66441 passed; evidence /tmp/vpn-parity-checkpoint-desktop-alignment-green.
Initial managed failure retained at /tmp/vpn-parity-checkpoint-prepush-red-evidence.
A new managed receipt remains required after these test edits.


Final checkpoint review: the full Android suite passed426 tests with no skips
and Android instrumented sources compiled. Independent Preferences-reader review
then added causal RED cases for overwide protobuf int32 tags/lengths and strict
UTF-8 map keys. Corrections preserve stock AndroidX semantics; final focused
serializer20 plus cold48MiB pipeline1 passed with zero skips/failures. Evidence:
/tmp/vpn-parity-android-proto-overwide-red-evidence,
/tmp/vpn-parity-android-proto-key-red-evidence, and
/tmp/vpn-parity-android-proto-review-green-evidence. These are host regressions;
new-reader API29/API35 packaged acceptance remains pending. Source is held for
final metadata, managed prepush and checkpoint delivery.


Checkpoint c44ebc5472502942dbea06c4fe0917e671ea97b2 was pushed to origin/dev
with version2.1.3 after managed prepush passed: model30/core228/UI47,
desktop868 (56 explicit native skips), Android430, instrumented compilation,
hygiene/localization/agent/visual tooling. Local Codex config remains present
and ignored; portable template/generator are tracked. Full parity is unfinished.
Exact-SHA CI exposed fixture/workflow setup defects: Windows POSIX-shell tests
were invoked from native Python; Linux early hygiene attempted a cold Gradle
download before setup; Fast/Android invoked sdkmanager absent from PATH.
Corrections keep portable tests active, move real SDK-free Gradle configuration
after the build tier, and resolve pinned native tools from configured SDK roots.
Fast regressions/evidence: /tmp/vpn-parity-hygiene-build-tier-{red,green}.log;
/tmp/vpn-parity-prepare-android-native-tools-causal-red.log and
/tmp/vpn-parity-prepare-android-native-tools-green.log. Windows test review also
corrects path separators, resolved drive roots, and POSIX-only mode assumptions.
These are CI portability fixes, not new native product acceptance. A new exact
SHA must pass every required workflow before checkpoint delivery is verified.

CI repair source held: focused postinst8/public7/DEB6/RPM8(one native skip)/
VM preparation10/native-helper6/desktop fixture16 all passed. Actual former
postinst process-launch failure is retained in /tmp/vpn-postinst-windows-legacy-red.txt;
the permanent regression calls the current runner and verifies early Windows
eligibility handling. Agent tool suite30 and fake SDK resolution5 also passed.


Follow-up aff10582e54bdcea17244fb2ef790828653b452c was pushed after prepush
passed. Android Release APK34134527902 succeeded. Fast Checks reached the
real optimized host JNI build and exposed a GCC13 signed-length range warning
as an error. The native chunk now retains an unsigned bounded size (at most
65536), casting only at JNI calls; compiler warnings remain errors. Existing
quick host JNI build/tests are the regression gate: CI RED in
/tmp/vpn-parity-aff-fast-ci-failed.log; local Clang JNI8 and cold48MiB pipeline1
GREEN in /tmp/vpn-parity-native-string-gcc-range-green-evidence. No new APK
from this corrected C source is yet certified. Integration workflow native
build prerequisites now use the same SDK resolver (wiring RED/GREEN logs in
/tmp/vpn-parity-integration-native-setup-{red,green}.log).


Windows package CI34134527882 exposed Mac-specific test paths that were not
absolute under the Windows filesystem provider. Test-only paths now use native
absolute roots with the same injected Darwin metadata; no tests are skipped
and no production admission behavior changed. Focused Mac/lifecycle/cancellation
union31 passed locally (/tmp/vpn-parity-windows-mac-fixtures-green-evidence).
Desktop test failures now print full exception details. One Windows cancellation
assertion needs native follow-up: historical v19 could not run it because of an
incompatible shared UI constructor, so current desktop/shared/tests were frozen
as v20 (component-manifest-v20.json, source fingerprint
a3e924018d0fe76209851431bcb8aaddcc2b2b59895a4fe5175f9d4ae066b881).
The older dependency failure is not product cancellation evidence. Guest2308
authentication is resolved, but no GCC is installed there; the GCC-specific
compiler result must come from CI, without provisioning or host runtime effects.


Windows v20 component run31 executed/0skips: both cancellation tests passed;
2 MacInstallRequest failures confirmed a strict POSIX-wire/default-provider
constraint. Those2 tests now retain original POSIX fixtures and skip explicitly
on Windows; all other portable Mac policy tests remain enabled. A separate
authenticated frontend null-registration failure under SYSTEM is under review
as a component environment/classpath boundary, not attributed to the CI
cancellation failure. Exact evidence:
/tmp/vpn-windows-finish.WhKUbn/arm-v20-mac-fixtures-update-cancellation-result.json.
Cancellation deadlines/behavior are unchanged; readiness assertion diagnostics
now distinguish a request that never reached the stalled HTTP fixture.


Current 3e Android test-only APK pair built successfully with source fingerprint
1ce2fb9ed8d53d51e2c916fe622e02e5a89962591878405e4b5417188abb7253:
base2.1.13 SHA669998183b6c1ebdcbfc3cb1e59d8e5a2368c95fa2515630111992866e43b1c8;
target2.1.14 SHA59dbf131e610a926cd5d37bf5dbdc72b26f544518f8a2c09af623e33e32ccfe3.
Manifest: temporary `vpn-parity-android-gccbound-freeze-dvhr4f4k/android-diagnostic/artifacts.json`.
Both are nondebuggable with the same compatible local fixture signer, not a claim
about the stable-release signer. Native installation/reader acceptance is pending.

Windows v20 SYSTEM endpoint probe diagnosed user-principal lookup failure for the
JVM-reported machine account, while private file publication succeeded. This is
separate from ordinary-user Windows CI, whose desktop tests now pass. Evidence:
/tmp/vpn-windows-finish.WhKUbn/arm-v20-endpoint-probe-result.json.


The Windows init-script failure is reproduced by a small real Gradle fixture
with configuration on demand, before changing task registration (causal RED:
/tmp/vpn-parity-windows-packaging-graph-red.log). Registering the desktop verifier before project evaluation instead of
projectsEvaluated makes it discoverable during task selection; task lookup and
output checks remain deferred until execution. The regression also covers image dependencies, deferred output
reads, and rejecting an image that bypasses the prepared application. It runs
after Gradle setup in Fast Checks and managed prepush, without packaging or SDKs.
Android failure logging now retains full subprocess assertion details; no memory
limit or fixture size is relaxed. The advisory heap-test cause remains unproven.

Final packaging graph selection: five cases passed in1.780seconds, including
late plugin registration (additional causal RED before the deferred lookup fix).
No SDK, packager, installer or runtime was executed. Agent-tool suite30 passed
without skips in the managed Python environment. Host Gradle/metadata/prepush
remain serialized before the next push.


## Current Checkpoint And Native Progress (201b)

Checkpoint201b2d44fb33f861b51f691a602f79e0e960588a passed managed prepush and
was pushed. Fast Checks, Android, Linux and macOS package workflows passed.
Windows now builds both EXE/MSI, then fails the extracted console launcher help
smoke; actual launcher output was missing from the assertion. The existing quick
harness now checks bounded diagnostics (causal RED then13 GREEN), preserving the
native assertion. Logs: /tmp/vpn-parity-packaged-cli-diagnostics-{red,green}.log.
No Windows launcher product fix is claimed until actual output is captured.

The advisory Android failure now identifies Arrays.copyOfRange in asciiString.
ProfileStorage.updateRoutingRules still used the non-spooled encoder for GUI saves.
An actual48MiB ProfileStorage regression reproduced it before the fix; the common
encodeList now uses a private spool while preserving immutable caller lists and
persisted newline syntax. Focused GUI/codec4 and the full Android unit suite plus both Android compilation checks passed.
The standalone memory probe now exercises the explicit-spool production path;
small/raw equivalence tests remain. SerialGC calibrates host input allocation;
it does not change the48MiB heap or replace required ART evidence. Causal record:
/tmp/vpn-parity-profile-storage-routing-memory-red.xml and matching green directory.

On API29/48MiB AVD5582, immutable3e nondebuggable base2.1.13 cold-opened the
retained56,002-domain dataset, then passed full public CLI readback, private
12,207,944-byte export, no-overwrite preservation, observed terminal no-op import,
and cold GUI reopen. Same logical digest was retained throughout. The fixture
CLI child must remove inherited DYLD_INSERT_LIBRARIES and include SDK adb in PATH;
AppleSharpener injection caused the earlier unavailable result. No global host
environment changed. Evidence: emulator-5582-cli-3e-base13-full-routing-summary.json,
export-summary and noop-final-summary under vpn-android-native-parity-sy7slbvg.
This source predates the new GUI-save spool fix; it does not certify that fix.

Mac201b fixture source fingerprint43ab188116812f9ee5dd5485125d2374d1b527f5da4af5f711a1b448ac32588f
built both DMGs inside the ARM64 guest. Base13 SHA d78bf723b3ac5c29968e1371797858a5335e87e6cc3ae52c098b26d6f1e144e3;
target14 SHA cd3cf292097562dd5b506e44fca633b869332460743895f4fe5c3ff62a0e0e5c.
The base is installed at /Users/admin/Applications/parity-201b/vpn-control.app;
owner71049f96-dac4-4de5-9355-c03f289fb2fb initially ran off in its private workspace.
Download c6ce4120-1fa9-4e1e-84b8-311db8a2f769 completed after its wait timeout.
First install job16d07beb-db54-4af1-89f6-1f8c24781762 failed PERSISTENCE_FAILED
before handoff with only133MiB disk free and an incomplete202MiB staged app.
Exact errno was not recorded. Removing only completed fixture build intermediates
freed1.8GB; the retry passed preparation, supporting disk pressure as the cause.
Failure stage, mount, receipt and package evidence remain preserved.

Retry job37065ac7-75bf-4718-ad01-7cbe31e741e1 reached handoffReady and owner exit0,
but its coordinator disappeared while the original-user watcher23204 survived.
Receipt remains WAITING_FOR_EXIT/sequence2: installation is unknown, never replayed.
The real coordinator inherited the launchd owner's process group. A quick native
regression observed actual coordinator identity before any storage effect: RED
PID23283/group23279. Giving the coordinator its own group preserves UID/session;
all7 native gate cases passed in0.423s. Evidence is under
/tmp/vpn-parity-mac-coordinator-group-{red,green}.log and the green manifest.
This test runs in the existing macOS package workflow. Full fixed-package
replacement/recovery is pending. Guest-only TLS23042/51000 remains assigned;
older owners and the uncertain retry are preserved.

Linux Ubuntu2315 authenticated the public install and produced SUCCEEDED/OK,
installing target2.1.4 and acquiring xdg-utils plus desktop-directory prerequisites.
The strict image check then rejected an obsolete unowned base JAR left by the
manually copied fixture. This is fresh-dependency/authorization evidence only,
not exact same-source recovery. A new package-managed base scenario uses2318;
Fedora2316 and Arch2317 remain separately assigned. The harness now rejects
unmanaged bases before attempting same-source recovery, trying each available
package manager. Causal RED used the old real harness, which attempted to execute
the inert unmanaged launcher; the fixed harness rejects before launch. Linux
harness10 and fixture16 tests passed; /tmp/vpn-linux-unmanaged-base-guard-red.log. Exact201b Linux artifacts
remain under /tmp/vpn-control-201b-ci-linux-34138680894.

Windows validate-only NativeAOT v4 emitted System32-only dependent-load flags,
matched the reviewed embedded asInvoker manifest and exact11-import policy,
and passed9 quick tests. Its full-lifetime x64 observer captured24 System32 DLL
loads and confirmed child exit; inert companion cases remain in progress.
Evidence lives under /tmp/vpn-windows-finish.WhKUbn. Privileged product roles,
production broker binding, and packaged native integration remain incomplete.

Checkpoint04f3f276fccd678dce56418340113a12df5d627f passed managed prepush and
was pushed (fifth checkpoint). Linux-hosted required workflows then rejected the
new unmanaged-base regression fixture because its root-ownership shim retained
public temporary-ancestor modes. Windows rejected the same fixture because
os.uname/getuid are absent. Production ancestry checks remain unchanged; the
test now separately proves public ancestry rejection and models private fixture
ancestry. Missing-POSIX-API coverage and actual Linux/Windows runs precede the
next push. Failed logs: /tmp/vpn-parity-04f-{fast,windows}-failed.log. Exact-SHA
CI is not green; the earlier packaged Windows help failure is still pending.

Immutable04f3 Android fixture15/16 is built from fingerprint
de00267264a863bcc61a2c1db01fcbca3d3758cb3e1bc7a860a8f12ae8af68bf.
Base SHA adaeafe3052239ddec5e23be6d17f277ea4e70ba4efa5f7aac04c30db156b2b5;
target SHA5474b0f3a8560ec8c0aa116ee1b052cb84c5af52132a41abbb76578833afe915.
Both are nondebuggable, compatibly signed local fixtures, with identical AArch64
16KiB-aligned JNI0752488e6a7c8485529ed8a80a7ddd473110b5544fe5c30eeca52c6494611b3d.
Manifest pointer: /tmp/vpn-parity-android-gui-spool-freeze-path.txt. API29 native
large GUI-save verification is assigned to the Android worker on5582 only.

Windows frozen validate-only v4 companion matrix passed six cases with24
System32 DLL loads per case and confirmed process-handle exit. Pre-fix v3
causally loaded the inert app-local bcrypt canary and failed, while plain v3
succeeded. Registry loader overrides were inspected only. No privileged role
is enabled by this evidence. Full record: /tmp/vpn-windows-finish.WhKUbn/loader-matrix-v2-result.json.

Fresh Ubuntu2318 same-source package-managed DEB replacement/recovery passed.
Public operation2cf68c72-cbb8-4e58-86a1-7bf1a2f3f0e1 produced protected job
b00fb2c5-5593-455f-a134-a8107e6209ad SUCCEEDED/OK; the new owner recovered
matching controller/request/job and target2.1.4. Guest evidence is
/tmp/vpn-public-install-evidence-chlwdo60 and fixture-201b/public-recovery-pty-result.json.
Replacement owner5769 remains alive/off; no runtime interrupted. This source201b
scenario is distinct from Ubuntu2315 fresh-dependency installation evidence.

The user expanded completion to native launch of every applicable test entrypoint,
with explicit platform skips and checkpoint pushes. Inventory at
/tmp/vpn-parity-native-test-launcher-inventory-8840.json enumerates32 script
launchers and routine references; a reference is not execution evidence. Linux
and Windows workers own native quick-suite and Gradle runs; the coordinator owns
Mac runs and the package/device-dependent coverage audit.

Checkpoint8840bcbfe6e7cbff7e544b3bec076dd6a2d5ee38 rolled development version2.1.4
and passed managed prepush, then was pushed. Native harness runs had passed on
Mac3.14, Arch Python and Windows3.13, but CI Python3.12 exposed a recursive
Path.resolve call inside the mocked Path.stat callback. No production logic
changed. The callback now compares a precomputed canonical path. A fast regression
explicitly makes resolve call stat, reproducing the bug even on newer Python.
Root verified new-test/old-callback RED on3.14 and full10 GREEN on3.11; native
Linux/Windows3.12 and full quick-tier runs are required before the next push.
Evidence: /tmp/vpn-harness-resolve-regression-red.log,
/tmp/vpn-parity-8840-macos-python311-red.log, and
/tmp/vpn-parity-8840-{fast,windows}-failed.log. The prior fixes did not establish
Python-version parity; do not classify8840 CI as successful.
