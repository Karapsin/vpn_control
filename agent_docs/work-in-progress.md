# Work In Progress

## Objective And Boundaries

Finish the complete GUI/CLI parity handoff on Android, Linux, Windows and macOS,
including native execution of applicable test launchers, current packaged behavior,
visual review, checkpoint pushes to `origin/dev` and all five required exact-SHA CI
workflows. This objective is active and incomplete. No release, main merge, tag,
publisher or native-runtime upgrade is authorized.

Product authority is [contracts.md](contracts.md), especially CLI-001..008,
STATE-001..005, DESKTOP-001..008 and TEST-001; commands are specified in [cli.md](cli.md).
For each distinct product, fixture or workflow failure, retain a causal quick
RED/GREEN regression in routine checks and rerun the native scenario. Compilation,
source-text assertions and skipped native tests do not replace causal/native evidence.

VPN, installation and elevation are limited to positively identified agent-owned
disposable VMs/emulators. Preserve the host VPN, personal workspaces, unrelated VMs,
AVDs5580/5582 and excluded `agent_docs/.Rhistory`. A timeout never authorizes a
runtime/installer restart, kill or mutation replay. Unknown installer jobs retain
inputs and correlation records until authoritative reconciliation.

## Repository And Current Validation

- Checkpoint32 is pushed as `f943578fe11d36f4db291353d90aa9451210c9f4`
  (version2.1.8, one Unreleased note). All15 corrected prepush checks passed;
  all five required exact-SHA workflows passed (managed session81128 terminal0;
  checkpoint32/commit-result.json). Final frozen JVM86 passed on host, macOS ARM64,
  and Limited-user Windows AMD64 under ARM64 emulation, no failures/skips/stderr.
  Manifest50005b9d666320cefea73a94bb59f527c89be3de15ffe4c09be6be371935fc81
  has563 source hashes matching this commit. Windows receipt is under
  checkpoint32/windows-pending-native/run-11a86897-d91e-42a4-b1a4-59cbb90c2698;
  exact test processes exited and its scheduled task was removed.
  The earlier JVM63 and estimated84 counts do not describe this final bundle.
  Evidence: checkpoint32/prepush-v2-result.json, final-bundle-commit-source-match.json,
  final-native-jvm-host.json and macos-final-jvm84/native-jvm84-receipt.json.
- Checkpoint30 is pushed and verified as `5a199886ecd4be31e67e0da02fca2269f0842505`
  (version2.1.7, eight Unreleased notes). All15 final prepush commands and all five
  required exact-SHA workflows passed; managed session84454 terminated0. Receipt:
  `checkpoint30/commit-result.json`. Final SSH fixture13 passed on host and limited
  Windows user with matching hashes; receipt-write failure retains the live child.
- Checkpoint31 is pushed and verified as `324f17ebde0d445aeca157ff2828abc3e0d49af7`
  (version2.1.7, nine Unreleased notes). All15 final prepush commands and all five
  required exact-SHA workflows passed; managed session83287 terminated0. Receipt:
  `checkpoint31/commit-result.json`. Per-candidate SSH credentials passed the same
  frozen JVM30 selection on host, macOS ARM64 and Windows AMD64 under ARM64 emulation;
  manifest c0bc07c6477e8789c42dcb20b915e77d5ab9f424d56d3f5f36859677587a4cd7.
  This proves internal failed-start recovery, not recovery after a successful B.
- Checkpoint32 is source-complete for managed prepush review. Desktop immutable
  restore leases preserve actual A across successful intermediate B, failed
  post-start persistence, cancellation and queued restore/close. The exact
  operation retains cleanup owners while native outcome is unknown; confirmation
  alone does not roll back or release inputs. Terminal cleanup retries preserve
  committed success. Explicit unknown outcomes and transport failures with retained
  native inputs remain nonterminal; completed upstream check failures stay terminal.
  Root reviewed and integrated Windows OUTPUT capture/publication, exact console
  semantics, mixed CACHE/OUTPUT destinations and modern .NET retained-handle rewind.
  Causal REDs preceded fixes; final focused desktop selection passed142 tests with
  12 explicit platform skips. Evidence: checkpoint32/final-focused-xml and the
  restore-credential, lifecycle-unknown, operation-owner, restore-close and
  returned-unknown RED/GREEN logs. Production scoped Windows binding remains off.
- Initial checkpoint32 prepush passed ten checks, then desktop testing found one
  failure among1012 tests (80 platform skips): a completed update-check transport
  failure incorrectly stayed pending without native inputs. The existing causal
  HeadlessSession regression was retained; pending classification now requires
  retained inputs or explicit uncertainty. Focused HeadlessSession/progress/input
  ownership GREEN is21 tests, no skips. Evidence: checkpoint32/prepush-failed-xml
  and completed-check-transport-green-xml. A fresh full prepush receipt is required.
- Current Windows source hashes match the final native draft. Root verified all469
  files in windows-output/evidence-manifest.json; actual Windows JUnit1/internal17
  passed on x64 .NET10 under ARM64 emulation. Pinned sing-box output semantics5/5
  passed with all children self-exiting on an occupied loopback listener. Actual
  packaged OUTPUT/cold recovery/native-x64-host proof remains open.
- Frozen normal-restore JVM63 passed on host and native macOS ARM64 with no skips
  or stderr, manifest c0e18e57992cf330a31d4c79f7cb700e1608088bdb7f367011a25c63a9845e44.
  This bundle predates pending-operation ownership integration; it is component
  evidence, not final source/package proof. Native overlay cleanup preserved the
  immutable checkpoint31 inputs and all live installer/relay fixtures.
- Android API29 separate-UID TCP pair isolated the stack failure: immutable system
  2.3.1 APK timed out at connect after12s; gvisor2.3.2 connected in4ms and received
  HTTP301 in27ms. Target TUN inbound/home-SOCKS outbound correlate with the helper.
  Both ON operations reconciled terminally; target remains running. The production
  change is only system→gvisor. Quick factory RED had12 tests/1 failure, followed
  by focused GREEN. API35 both stacks passed correlated TUN TCP/direct egress;
  helper UID10207, with no selected-SOCKS attribution. That is compatibility proof,
  not full proxy-chain acceptance. Owned5590 ends at signed nondebuggable2.3.2 OFF;
  subscription/null-selection/settings/routing56,000/SSH key baseline was restored,
  task candidate/reverse/forward/helper removed. Preserve5584 active runtime and
  saved proxy cleanup intent. Evidence: checkpoint30/android-tun-stack-pair and
  checkpoint32/android-api35-stack-run. API29 SSH/Find Best acceptance continues.
- Root reviewed Windows TUN3 component evidence: factory-generated config with
  three documented fixture edits, real UAC helper start, raw NO_PROXY TCP payload,
  exact owned-process cleanup and all six network baselines restored. This is
  AMD64-on-ARM64 component evidence, not production-factory/native-x64/MSI parity.
  Receipt/manifest/archive are under `checkpoint31/windows-tun3*`.
- Root reviewed macOS malformed-DMG pre-handoff failure: install operation
  e4a74cc9-2300-419a-b846-36f3ddd7b95e failed RUNTIME_FAILED; protected job
  ef46f996-f0c2-42aa-8216-4d9beed7beb0 FAILED with installed=null. Original runtime
  stayed live and passed the recorded TLS probe; base2.1.7 signature/launcher stayed
  unchanged. This does not prove post-replacement rollback. Fresh owner/server were
  publicly stopped; failure records remain under checkpoint30/macos-malformed.

### Checkpoint33 Exclusive Ownership

| Task ID | Agent | Owned files/subsystem | Shared files reserved | Dependencies | Artifact/environment | Current check | Next handoff |
| --- | --- | --- | --- | --- | --- | --- | --- |
| C33-integrate | Root | Integration, desktop benchmark data, docs | Build/version/delivery | Coherent worker slices | Host Gradle; owned API35/5590 | ADB continuation23/0; benchmark10/0 | Review, prepush, checkpoint delivery |
| C33-cleanup | Root; cleanup_review read-only | Broker lifecycle/storage, terminal and Stage probes | No factory/Main/autostart changes | Durable cleanup intent | Windows inert SYSTEM components, x64 on ARM64 | Terminal13/0 and Stage3/0 | Review; public cold recovery and acknowledgment remain |
| C33-installer | mac_fixture_terra | Fixed helper sessions and tests; ProcessPin close/constructor | Kotlin integration reserved | Exact owner admission | Exclusive Windows VM operator | Close, constructor and generation native GREEN | Hold source for checkpoint review |
| C33-android | android_terra | Android benchmark control, ProxyValidationRuntime and tests; fixture transport | No shared model/build/version edits | Production-path diagnostic RED2/2 | API29/5584 OFF, signed fixture2.3.3 | Diagnostic fix pending; native benchmark manual/error | Focused GREEN, then new frozen APK |
| C33-cli | cli_parity_audit | DesktopAndroidAdbClient and tests | Shared declarations reserved | Owner-pinned continuation | Fake ADB | GREEN23/0 | Source ready for checkpoint |
| C33-linux | linux_native | Public installer harness and tests | Build/update dispatch reserved | Guest connectivity | Gateway unavailable before authentication | Focused44/0 | Native package matrix remains |
| C33-macos | mac_native | Read-only guest/package evidence and next fixture plan | No shared source edits | Source-matched fixture pair | Owned Tart guest; existing jobs preserved | Static packaged launcher/signature checks | Unique USER_LOCAL installation scenario |

Windows cleanup now saves a binding/checksum-validated durable intent before deleting
private inputs. Retry validates that intent without rereading deleted inputs or
repeating ordinary publication; confirmation follows successful disposal and gate
closure. Root native RED compiled successfully and failed the two causal cases
(8 selected/2 failed). Native GREENv2 compiled the full broker/configuration sources
and passed10 cases with zero compiler warnings. Evidence is under
checkpoint33/windows-terminal-red and windows-terminal-green-v2. These are inert
SYSTEM component runs on x64 .NET under ARM64 Windows emulation, not TUN or packaged
cold-recovery evidence. The public cold reader and final acknowledgment remain open.
No root native process remains live (GREENv2 handle2860 terminal0); the Windows VM
operator slot transferred to mac_fixture_terra for original-user installer admission.

The manifest revision now passes native terminal12/0 and actual protected-stage3/0
under the disposable Windows SYSTEM component harness, both compilations with zero
warnings. Exact source hashes and output are in checkpoint33/windows-manifest-native;
QGA handle2096 is terminal0 and operator ownership returned to mac_fixture_terra.
This adds actual altered-input/unexpected-child/missing-input checks; no public
cold-recovery or runtime traffic claim follows from these cases. Android fixture2.3.3
APK built from a frozen source snapshot, is nondebuggable, and matches the previous
signer. SHA fcdc1c30842b443e951f508d35b488baa3ee7a0e858a1395796b317e8cdf5d3f;
source closure and artifact receipt are under checkpoint33/android-benchmark-status-pair.
Canonical version remains2.1.8. API29 replay is assigned to android_terra.

Checkpoint33 focused updates: Android benchmark terminal data now preserves primary
and secondary status alongside timings; desktop generation/decoding matches it.
Causal Android RED7/1 and desktop RED3/1 preceded fixes; integrated GREEN10/0 is in
checkpoint33/benchmark-status-green. The first integrated run caught an Android
captured-variable smart-cast compile error, fixed before the passing run. The frozen2.3.3 APK replay completed with a retained manual/error result and null timings; benchmark traffic acceptance remains open. Linux public-install harness now removes
only inherited DYLD_INSERT_LIBRARIES from the fixture child environment, preserving
the caller environment and session ownership test; its focused selection passed44
checks (15 public-harness,8 postinst,11 VM preparation,10 Arch). Gateway connectivity
still times out before authentication; no Linux guest/native scenario ran.

Current follow-up evidence: API35 public ADB status/stats watch each returned three
OK records pinned to one owner; logs follow with limit0 returned an empty initial
history and a valid cursor. All three stopped with130 on output closure. An OFF,
idle-install, empty-operation owner was explicitly force-stopped; its watcher
returned CONFLICT/1 for the replacement epoch without rebinding. The installed
nondebuggable2.3.2 test APK has445 Android/shared source paths matching checkpoint32;
this is a test-version fixture, not canonical-version installed-package evidence.
Frozen client manifest50005b9d666320cefea73a94bb59f527c89be3de15ffe4c09be6be371935fc81
and raw receipts are under checkpoint33/api35-streams. The first local export
correctly rejected the0777 projects ancestor; no user permissions were changed.
Private /private/tmp export succeeded with12208243 bytes. Existing export tests
passed9 executed/1 Windows skip; the new Windows terminal test compiled and skipped
on macOS. Independent cold-owner export passed: both exports contain12208243 bytes,
all56000 domain rules match exactly and transfer version remains7. Only exported_at
differs, so the raw file hashes appropriately differ. cold-export-receipt.json records
both hashes and epochs. Existing-destination publication returned PERSISTENCE_FAILED/1
and preserved the original bytes; no partial final files remain. Private exports are
retained under /private/tmp/vpn-api35-cold-gd5z4nv5. Final API35 status is OFF and all
root stream/export processes are terminal.

API29 correction: the initial empty SOCKS reply was caused by premature diagnostic
stdin closure, not proof of a broken reverse. The corrected held-input probe
returned0500; recreating that exact mapping was not a necessary repair. Candidate
preflights still failed: the configured external validation target returned403 or
timed out. A task-only HTTPS204 fixture is being prepared using the existing
disposable CA lifecycle; no silent URL rewriting or product TLS weakening is allowed.
The first HTTPS trial was cleaned up and left API29 OFF with its original URL/key,
UID2000 and exact task reverse mappings restored. Its accepted benchmark failed
NOT_FOUND in the same controller ledger because the caller supplied an owner-local
status configuration ID as a selector. The documented public selector is the rendered
row index/name. This is fixture misuse, not evidence of owner replacement or lost
operation registration. Stable diagnosis and envelopes are retained under
checkpoint33/android-api29-benchmark-outcome. A fresh trial must use a newly observed
rendered selector; no benchmark traffic or A/B recovery is claimed for the failed trial.

Latest checkpoint33 evidence supersedes the earlier in-flight notes above:

- Installer input admission now retains each acquired directory before attempting
  the next open. The ordinary-user native causal RED could not delete the ancestor
  after a missing job-child failure; current GREEN reported
  MISSING_INPUT_ANCESTOR_RELEASED with compile/probe exit0 and empty stderr.
  Evidence: windows-installer-owner-input-retention-red/green; GREEN task
  VpnInstallerClose32-9d695791-d23c-48c6-8713-eab434d99a1e. No MSI ran.
  The wrapper preserves files/output on timeout and only cleans after termination.
- Checkpoint33 content is frozen for managed prepush. Version2.1.8 now has two
  Unreleased notes; all30 dirty paths belong to this checkpoint. Full native parity
  and final delivered-package validation remain open even if this checkpoint passes.

- Current-source focused union passed36 executed tests with two explicit Windows
  platform skips on macOS: diagnostics3, Android benchmark7, desktop benchmark3,
  ADB continuation23. Both native wrappers compiled. XML and exit0 are archived in
  checkpoint33/focused-final (07:33:14–52Z). Script union41/0 and docs hygiene passed.
  This is focused validation only; final managed prepush and delivery remain open.

- Finalizer review found a second terminal ordering failure: a transient cleanup
  failure could be retried by broker finally after sending unconfirmed status.
  Causal native14/1 RED preceded terminal14/0 plus Stage3/0 GREEN; both builds had
  zero warnings. FinishAfterTransportClosed now preserves the already attempted
  terminal outcome, leaving explicit recovery possible. Evidence:
  windows-terminal-finalizer-red/green; QGA4664 terminal1 and7084 terminal0.
  Independent review accepted the guard; no cold-recovery/ACK completion is claimed.
- Android production diagnostics GREEN: ProxyValidationRuntime3/0 and benchmark
  control7/0 at07:28:51Z, archived in android-validation-stage-green. Readiness now
  snapshots once. SOCKS fixture validation explicitly disables NO_PROXY bypass;
  its command-contract RED preceded transport24/0 GREEN. Final combined checks
  cover the snapshot adjustment and both platform wrappers.
- A fresh Linux gateway probe again timed out before authentication (exit255).
  It did not reach archlinux or inspect/mutate any guest.

- Windows normal terminal output now follows input release and cleanup completion.
  Causal native RED13/1 preceded GREEN13/0 plus protected Stage3/0, both builds with
  zero warnings (windows-terminal-response-red/green). QGA handle1368 is terminal0;
  Windows operation returned to the installer worker. Cold public recovery and
  acknowledgment remain incomplete; production scoped runtime stays disabled.
- Android synchronous accepted mutations now continue through owner-pinned status
  reads after the provider timeout, without mutation replay. Causal RED23/2 and
  final GREEN23/0 are recorded in android-sync-timeout-red and
  android-sync-timeout-green-v2; two Windows-only wrapper tests explicitly skipped
  on the host. Timeout zero remains unlimited; owner loss preserves unknown outcome.
- API29 fixture2.3.3 benchmark a4e7e2c4-16bf-4ccf-8cae-145eff9f6d2d ended
  RUNTIME_FAILED with committed=true, primaryStatus=manual, secondaryStatus=error
  and null timings. Cleanup restored OFF, original validation URL, UID2000 and task
  reverse mappings; one original proof row remains. The HTTPS request ledger was
  not captured before cleanup, so this run cannot prove request nonarrival.
- Production-path Android diagnostics have an actual failing baseline: two tests
  at 2026-09-09T07:21:18Z fail because request timeout emits no safe stage and a dead
  child is labeled merely not ready. Evidence: android-validation-stage-red.
  Fixed-stage diagnostics must preserve cancellation and exclude target/exception
  text; the diagnostic source is newer than the2.3.3 APK.
- Quick fixture regressions rerun locally: Windows fixture2, Android transport24,
  Linux public harness15, all41 passed. Native installer owner close, constructor
  failure and generation probes also passed in the ordinary Windows user session;
  their source hashes and task receipts remain under checkpoint33/windows-installer-*.
  Fixed MSI sessions still return a typed failure: successful MSI integration is open.
- The macOS obsolete checkout was archived and verified before exact removal;
  archive SHA a008d857b7f28375d712d563d357be5e2b474c0727a521d1f6cad4ea13e8bf7.
  Canonical2.1.8 DMG signature and static public launcher checks passed in the guest.
  Mount detached, existing jobs preserved. This is static package evidence, not
  same-source installation/recovery proof; a distinct USER_LOCAL bundle has its
  own gate and does not require replaying old waiting jobs.

Earlier checkpoint delivery, native observations and superseded ownership tables
are preserved in [the historical checkpoint ledger](parity-checkpoint-history.md).

## Implemented And Locally Tested

### Shared Commands And Desktop Ownership

Typed registry/grammar/envelopes, revision/epoch guards, request deduplication,
retained operations, logical-document transport/private spools and export publication
are implemented. Desktop GUI/CLI use one authoritative controller with authenticated
frontend attachment, guarded drafts, visibility acknowledgments and owner scheduling.

Public Android streams are already dispatched before the downstream adapter's
nonempty-flag rejection. Shared cursor bookkeeping retains duplicates, limit0,
owner pinning, gaps and output-closure behavior; `DesktopAndroidStreamTest` covers
fake ADB/device/owner failures. Do not reopen the old claim that watch/follow is unwired.

Recent checkpoint fixes include cancelled manifest reads closing their IO lease,
ordinary/elevated Windows workspace startup, bounded safe CLI failure diagnostics,
Android configuration observer lifetime and safe macOS DMG smoke cleanup. The
existing script/JVM suites contain their causal regressions.

### Android Large Documents And Streams

Clean minified nondebuggable fixture2.2.14/code17080 APK SHA
`a6af10616e64dfa69cb17b6bd12c1d539da4c4f45653ca8e26a894e594c8ff84` uses signer
`a43b5330501b02f5558fa381c52e7f7dcdd9db362d6807d449d7bbb5e207c5a0`.
The permanent DataStore observer retained an obsolete large Preferences snapshot;
one-shot distinct subscriptions now release it without losing facade/gap writes.
Integrated configuration/serializer/reader/memory selection54 passed without skips.

API29 owned5584/48MiB passed same-process GUI56008→56009→56008 and independent
cold56008 readback, original digest
`0ef2ce70d306e71d44a899d52a56a375022cb194cc534fab005934fb83bdaaa7`.
Evidence `/tmp/5584-clean214-*.ndjson` and
`/tmp/vpn-android-resubscription-integrated-green.log`.

API35 owned5590 has192MiB heap growth, not48MiB. Same-process GUI add/remove,
full public cold readback and exact accepted cleanup wait passed. Operation
`cdab40f0-0259-43ae-af8f-43706c71f08d` reached terminal OK,56000 domains, digest
`5b7fcc5a4bff652c2165ff53836f01abc141df36df8705b9350f8ccfe64fe15c`.
After device loss and a data-preserving normal reboot, independent full readback
matched that count/digest. Status watch/log follow produced valid frames and client
Ctrl-C130; device-loss watch explicitly reported unknown owner outcome. A prior
116-second silent read was interrupted observation, not a demonstrated stall;
64KiB ADB frames were advancing and the complete read took about five minutes.
Evidence `/tmp/5590-cli-remove-fix235-wait.json`,
`/tmp/5590-after-device-loss-routing.json` and `/tmp/5590-reboot-cli-status.json`.

API35 SSH native import/replacement/invalid input and cold key-presence status were
exercised under `/tmp/5590-ssh-native.fVsoDj`. A further invalid import after a known task-generated credential preserved public
settings digest and key presence; private key identity is intentionally unavailable
through public readback. This does not certify
live SSH routing or active-connection preservation. No secrets belong in evidence.

### Current Coherent Follow-up Slice

The fixed Windows installer invocation/worker-ready codecs and role state machines
remain inert in production: Main still exposes validate-only and the old installer
launch path is unchanged. Review found four causal defects in the new role core:
valid commit racing owner exit, undefined receipt phase, and cancellation receipt
publication failure before/after replacement. All22 native component cases now pass;
receipt `/tmp/vpn-windows-finish.WhKUbn/fixed-installer-roles-v1/review-green-v1-native-evidence.json`.
This is Windows ARM64/x64-emulated C# execution with inert sessions, not native
installer integration. Host role/protocol selection13 selected,7 executed,6 explicit
Windows-only skips; the new role source is in the project and producer inventory.
The exact current five JUnit methods also executed natively (5/5, zero skips),
through x64 Temurin17/PowerShell5.1 on the ARM64 guest. Source/resource hashes match:
`/tmp/vpn-windows-finish.WhKUbn/fixed-installer-roles-v1/junit-wrapper-v1/summary.json`.

The following MSI adapter slice is implemented but not production-bound: fixed
read-only ProductName/UpgradeCode queries, retained handles/input on close failure,
silent per-user installation API and exact native result retention. Its19 behavioral
and2 real System32 database cases passed without installation or byte/mtime changes.
Evidence `/tmp/vpn-windows-finish.WhKUbn/fixed-installer-msi-v1-evidence.zip`.
Root reviewed the module and added its project/source inventory. Original-user
process/token/package/ancestor admission and actual install-user binding remain open.
Both exact current MSI JUnit methods also ran natively:2 executed, zero skips/failures,
using x64 Temurin17/PowerShell5.1 on the ARM64 guest. Archive
`/tmp/vpn-windows-finish.WhKUbn/fixed-installer-msi-junit-v1-evidence.zip`, SHA
`ea26b93f631b4a7ec922ae592282714782d05876c5e1a512855d358697b64e0e`.

Kotlin mutable-resource opcode5 now retains durable correlation before UAC and
decodes terminal resource evidence only after native exit. Opcode4 stays unchanged;
CACHE is an intermediate implementation and OUTPUT/cold recovery remain open.
Review caught the final-log bytes being read as the terminal envelope. The direct
decoder test reproduced that failure before correction; decoder/scoped-process/
reconciliation selection22 executed with no skips/failures. Its RED is retained in
the worker tool turn (no standalone RED receipt). The earlier broad selection39
selected/30 executed/9 platform skips is `/tmp/vpn-windows-resource-v5-focused.log`.
Native C# v5 now passes metadata7, commit/gate ordering6, configuration5 and two
real authenticated-pipe cases with an inert child: cache publication/repeated
admission and a9MiB configuration. Protected stages and gates remain retained;
cleanup=false is explicit. Main now binds its runtime digest to a constant generated
from the prepared bundled AMD64 runtime. Missing, mismatched and matching authority
passed6 native assertions; causal RED showed mismatched authority reaching only an
injected inert runner before the fix. No caller-selected digest authorizes another
runtime. Both suites ran on Windows ARM64/x64 emulation under SYSTEM, not ordinary
UAC or NativeAOT. Root verified all10 source hashes against the handoff. Archive
`/tmp/vpn-windows-finish.WhKUbn/broker-v5-authority-component-evidence.zip`, SHA
`5f487f0e433547942398901e708fb5b0963f0e91d73d7d7d9c3b9dba0d10a40e`.
Current host Windows selection196 selected/137 executed/59 platform-opt-in skips,
zero failures: `/tmp/vpn-checkpoint20-windows-focused.log`. All8 new exact JUnit
wrappers then ran natively through x64 Temurin17/PowerShell5.1, with no skips or
failures; runtime inventory stayed empty and protected stage/journal evidence was
retained. Archive `/tmp/vpn-windows-finish.WhKUbn/broker-v5-junit-v1-evidence.zip`, SHA
`aee2b502a06638c6e5c231fbc673bfa8cb300eab96895f63884297ef792d41b6`.
This remains ARM64 emulation with inert children. The production factory remains disabled.

The Windows helper tool now stages verified PE bytes/manifest into a prepared
`app/native/windows-amd64` directory and inspects the packaged result. Twelve fast
helper tests pass, including changed-byte/policy rejection. Root has now added
Windows-only Gradle producer wiring, pinned SDK CI setup, and helper validation/
nonmutating launch probes in extracted and installed MSI checks. Eight real Gradle
graph tests passed, including producer failure blocking packages and verified bytes
reaching both installer inputs: `/tmp/vpn-windows-native-package-graph.log`.
Current NativeAOT build/package execution passed in checkpoint19 Windows CI as
recorded above. The ARM guest lacks the pinned SDK/MSVC and native x64 guest access
is still unavailable; CI evidence does not enable or certify unfinished roles.
The next package slice adds the actual VpnBroker NativeAOT project and stages both
fixed executables under one verified manifest. A package missing its broker was
accepted by the old staging code: causal RED
`/tmp/vpn-native-broker-package-missing-red.log`. The verifier now requires both
reviewed helper names, hashes, PE/loader policies and copied bytes before atomic
publication. Verifier13 GREEN `/tmp/vpn-native-broker-package-green.log`; real
Gradle graph8 GREEN `/tmp/vpn-native-broker-package-graph.log`. Independent review
accepted this boundary. Synthetic PE/graph evidence does not certify actual AOT
compilation; the next exact-SHA Windows workflow must build and probe both files.
The producer now generates the compiled runtime authority from its exact prepared
runtime input. Generator/verifier15 pass; graph9 includes unchanged-input reuse
and runtime-change invalidation before both installers. Logs
`/tmp/vpn-native-broker-runtime-authority-green.log` and
`/tmp/vpn-native-broker-package-graph-final.log`.
The updated dual-helper producer's three inert executable-discovery cases also pass
on Windows PowerShell5.1, with all21 captured inputs matching current source.
Archive `/tmp/vpn-windows-finish.WhKUbn/dual-helper-builder-v1-evidence.zip`, SHA
`6d916e75339ae64a28d370c1d02d074559f79b0b928a4e26bf6e6f0922cca2ba`.

The macOS Aqua fixture observer is read-only: a single matching process/prompt is
only candidate correlation, never proof of authorization. Terminal authority uses
the successful public updates envelope and preserves unknown installed state.
Four direct tests passed on host and native macOS Python3.9; actual earlier fixture
false-positive and invalid-envelope RED logs are retained under
`/tmp/macos-aqua-correlation-prepare.ZSyEvK`. The test runs in release hygiene.
Its current five-test portable selection and Windows CI repair are recorded above.

The new single-device Android instrumentation launcher avoids AGP8.7.3's broken
`--serial` filtering by using its earlier `ANDROID_SERIAL` provider filter. Fast3
GREEN: `/tmp/vpn-android-instrumented-launcher-green.log`. Native launcher failure
and corrected launch are recorded in `/tmp/vpn-android-local-protocol-5592-launch-diagnostic.log`
and `/tmp/vpn-android-local-protocol-5592-benchmark-red.log`. The corrected launcher
ran exactly one test on owned5592. The safe greeting transcript identified two
empty preflight connections followed by native sessions offering only method2;
the old fixture incorrectly replied method0. RFC1929 fixture support now passes
7 quick tests, including unoffered methods, correct/wrong credentials and redacted
transcripts. Native auth/CONNECT passed before TLS reached the plaintext fixture:
`/tmp/vpn-android-local-protocol-5592-auth-boundary.log` and
`/tmp/vpn-terra-protocol-api35/fixture/greetings-auth-rfc2.ndjson`.

The authenticated bundled sing-box relay was restored after the host reboot.
Guest PID939 listens on loopback58181; host PID27277 forwards loopback18081 to it;
the guest reverse-dynamic SSH listener uses58183. Persistent tmux sessions are
`vpn-parity-macos-{restore,egress,relay,android-forward}-20260908`. A normal-trust
HTTPS request through the full Android-facing18081 path passed; no CA/root/host
VPN settings changed. Current evidence is retained under
`.runtime/parity-evidence/checkpoint20/macos/` in `android-facing-health.txt`,
`relay-stability.txt`, `tmux-processes.txt` and the corresponding listener receipts.
The Android native rerun reached manual/ok before an incorrect new assertion
required primary timing. Manual benchmarks intentionally keep primaryTotal=null;
testTotal is the measured proxy request. A host semantics regression now preserves
that contract; the native assertion was corrected without changing product code.
Log `/tmp/vpn-android-local-protocol-5592-trusted-https.log` retains this test defect.
The measured rerun passed exactly1 native test with no skips, test_ms844.282209 and
score1311.400334. Its source/APKs/XML/logs are recorded privately under
`/tmp/vpn-terra-protocol-api35/trusted-measurement/`. Resolved diagnostic child-replay
code was then removed. The final concise smoke passed exactly1 native test with
zero skips after correcting the JUnit signatures described below. Its debug APK
SHA `16f32483a8ad8ad4f32feed57d8571c383d2bb1363125b350eb7c0611905bb28`, test APK
SHA `941de8b06416f8f2a56d51ccb469bbc87ff10d5302f9a7557c4c6d5572a837da`, XML/log hashes
are archived in `/tmp/vpn-terra-protocol-api35/final-smoke-signature-guard`.
Test target routing has a passing quick config test that checks CIDR containment
and requires the final proxy route. This is debug instrumentation evidence; the
nondebuggable public GUI/ADB action scenarios remain separate.

The concise native smoke initially could not initialize its JUnit runner: three
expression-bodied tests returned Int, and a provider test returned Bundle.
`verifyDebugAndroidTestSignatures` reproduces all four using actual compiled
bytecode, before APK packaging or connected execution. Explicit Unit returns fix
the methods. Its isolated Gradle fixture compiles valid and invalid classes and
also catches a missing compile dependency, which had made the first verifier read
stale bytecode. Guard and fixture now pass; both are in Fast Checks and managed
prepush. Causal RED `/tmp/vpn-android-instrumentation-signatures-red.log`; native
rerun/archive above preserves the original OS scenario.

API35/5590 nondebuggable GUI Recheck reached final OK with test=ok, tcp52.6ms and
score846.62375, operation `c0333fad-af5b-4dae-9b96-0adc25ea643e`.
GUI Find Best reached final OK, operation `35ae6758-ef38-4526-8a77-90c874cbabcd`,
revision23. Explicit disconnect and guarded restoration reached final OK through
revision26: runtime OFF, no selected/active location, original source and validation
target restored. Locations match semantically after excluding regenerated exported_at;
digest `e9527d74df47fc3f8726699580572c78f7b99bfc17222cfb952303f021794909`.
Private manifest `/tmp/vpn-terra-api35-public-baseline/public5590-gui-evidence-manifest.json`
records exact APK/signer/source and operations. Production Android main/JNI/assets
and shared source closure matches the bcc fixture; only test build wiring and
canonical version metadata differ. This remains bcc2.2.15 fixture evidence, not
certification of a final delivered package or the remaining cancellation/SSH matrix.

### Desktop Installation Evidence

macOS r4 machine update from a source-matched23d base2.1.17 to target2.1.18 passed
real Aqua authorization, handoff, replacement, protected receipt and next-owner
recovery. Job `d5b9b029-36d1-495c-bdba-44d628e08a3d`, operation
`6c4c09cb-d78a-4452-b58c-1ad0a5388d3e`; protected sequence4 SUCCEEDED/OK.
New controller `45e4bcad-b270-4afb-aa60-6e613591f5bc` reports installed=true and
cleanupCode=OK; GUI show succeeds and runtime remains OFF. Target DMG SHA
`524f982e1cced9bf70a3278d33240373c82a9cdd46e11202bdf8ebbb9dd099a6`.
Root-verified redacted archive `/tmp/vpn-parity-macos-r4-evidence.hErTxE/r4-evidence.tar.gz`,
SHA `a65d83021f6d9d89088747852261d0cad920ca8ddf948b5dff925bbc95bc56f0`.
This is an earlier-source fixture and ad-hoc signing evidence, not final delivered
package/signing certification. Current full DMG smoke and18-test CLI harness passed.

The same installed r4 app preserved traffic and one controller/runtime through
seven GUI/CLI lifecycle gestures (40/40 probes each). A real Aqua close-button
action by exact frontend PID also passed40/40 with the runtime identity unchanged;
root-verified archive `/tmp/vpn-parity-macos-r4-os-close.afDvtb/r4-lifecycle-through-os-close.tar.gz`,
SHA `4087f58c2dcc71736838b7e714d791ca26852113f1018e07a78ea17174cb6b79`.
The first GUI-free scheduled-refresh fixture reported partial failure because
active refresh uses the running proxy route rather than the offline JVM fixture
proxy. A corrected isolated SOCKS/TLS fixture passed scheduled refresh with the
same active runtime and traffic10/10 before plus20/20 after. Root-verified archive
`/tmp/vpn-parity-macos-r4-active-route-refresh.tar.gz`, SHA
`f66579e3a6cba56dde4149d27c187ef7bce92d796b2003035e487dd3c99989ec`.
The intervening manual/active fixture-body mismatch has an executable local-route
RED/GREEN consistency check. The broader r4 environment and unknown jobs are preserved.

The reusable exact-PID Aqua helper passed4 quick tests and a fresh native window
close (AX1→0, exit0, owner remained OFF), final source SHA
`120a3e8bd399d314147d0bca052dc4b1b684a8f6d8ceb6d84e8a98ead9d8f54b`.
Archive `/tmp/vpn-parity-macos-r4-aqua-helper-final.tar.gz`, SHA
`77dd33314bf29e035bd4f92ffd9fd7a25b78b8c36aa4b1319fed9f6bfa773973`.
This is launcher/Aqua evidence, not installation authorization. Task owners were
publicly quit; close-to-tray frontends may remain without windows. Do not kill them
or replay a timed-out remote click based on observation alone.

Reuse the current exact-SHA CI evidence before repeating native launch checks:
macOS run34219519076 passed7 native worker gate and3 ENOSPC cases plus the newly
built2.1.6 DMG's disconnected public CLI smoke. Linux run34219519200 passed public
CLI smoke for extracted DEB/RPM payloads and an installed Arch bundle. Windows
run34219519026 passed NativeAOT production/staging/probes, the routine role wrappers,
extracted public CLI smoke and installed MSI smoke. Their logs are retained as
`/tmp/vpn-ci-<run-id>-readonly.log`. CLI smoke includes streams/Ctrl-C/QR and large
routing import/retained result/private export. These specific proofs do not replace
real update/UAC/Aqua/original-user recovery, GUI/traffic or final signing evidence.

Linux earlier same-source Ubuntu/Arch recovery and RPM scenarios have evidence;
see the historical ledger for manifests. Current7c Arch pair2.1.6/2.1.7 built with
actual JDK17; source fingerprint
`53b3c2beb2e056766ca8a523f47835691a3c8dcbbcdcd1c77c85582499e4acb7`.
Guest fixture `/home/vpnfixture/fixture-7c28fe6-5t1xfenn/fixture`, verified receipt
`/tmp/vpn-linux-fixture-7c28fe6-native-receipt.json`. The alternate-root attempt
correctly failed before handoff because the privileged adapter admits only
`/opt/vpn-control/bin/vpn-control`. Public harness now rejects that fixture setup
before owner startup/authorization: causal RED1/14, GREEN14, bundle verifier10 passed.
This fixture correction is not evidence of a supported-path product update failure.

Windows corrected immutable image passed ordinary/elevated public smoke and29
focused transfer/install/cancellation tests without skips. Archive
`/tmp/vpn-windows-finish.WhKUbn/current23d-corrected-v1-native-evidence.zip`, SHA
`10a0e9dd10b4bc793c32cc2ecf28e6c3cd763405b41465f12be09c4bba9cc914`.
Native x64 broker component evidence includes TUN traffic and UAC denial continuity;
it does not certify production broker binding or MSI replacement.

Checkpoint16 kernel-process classification retains native process handles and
matches PID/creation time around image/snapshot queries. Unknown processes fail
closed; no process-name/error-code/managed-HasExited exemption is authority.
Causal native RED rejected independently proven kernel classes3/4. Host backend13
passed; six Windows native fixture tests skipped on macOS. Exact native6+13 v4
job was launched before gateway loss; outcome remains unknown pending retrieval.
Scratch `/tmp/vpn-windows-finish.WhKUbn/kernel-inventory-v3` retains identities.

## Remaining Implementation And Native Acceptance

- Windows is the largest implementation gap: installer helper currently exposes
  only validate-only; runtime installer still launches captured PowerShell roles.
  Complete fixed native user/coordinator roles, original-user token handling,
  pinned helper launch and verified native packaging. Broker project/staging and
  Kotlin/native mutable-resource framing have component evidence; actual AOT/package
  checks remain. Finish OUTPUT/cold resource recovery and full configuration
  support, replace the PowerShell launch with retained fixed-helper admission, enable the
  production path, then remove whole-GUI elevation and HIGHEST autostart. Current
  `windowsScopedRuntimeEnabled=false` is not parity completion.
- Android: both-API installer lifecycle/cancellation/retention/confirmation recovery
  with current compatible packages; full SSH credential rollback/live routing;
  Find Best/cancellation/recovery, benchmarks, consent/foreground-service ownership,
  actual-A/pending-B connected/scheduled refresh, GUI callbacks and visuals.
- Linux: current supported-path Arch installation/recovery, remaining fresh DEB/RPM
  dependency/replacement/rollback cases, traffic and GUI/controller continuity.
- macOS: remaining local/machine authorization-denial/failure/rollback/cleanup cases,
  current-package signing/worker evidence, proxy traffic and GUI/controller continuity.
  The corrected Aqua observer and exact-PID helper have native evidence; keep using
  real receipt authority for subsequent authorization scenarios.
- Shared/public audit: capabilities/help/real handlers, equivalent human/JSON
  timeouts/errors/raw bytes, every required stream/owner-replacement case,
  document/persistence/resource/export races and GUI/CLI action equivalence.
- Visuals/localization: review changed scenes and Android installer states, update
  intended baselines/inventories, verify reachable controls and typed failures.
- Refresh the native-launcher inventory for current hashes. Earlier37/40 mapping
  is historical; changed scripts require their own native receipts and no-skip
  execution. Launcher execution alone never closes the full product matrix.

## Live Environments And Uncertain Outcomes

Revalidate current processes and public state before acting; these are last-observed
identities, never authorization to kill/restart anything.

- Remote gateway `ssh.karapsin.com:228` currently times out. Authorized route remains
  that gateway, then archlinux, then the assigned disposable guest. This is network
  access failure, not guest authentication failure or evidence of terminal jobs.
- Windows owned x64 guest2314: scheduled `vpn-parity-kernel-inventory-v4`, guest
  `C:\VpnParity\KernelInventory-v4-20260908`, setupQGA6884 terminal0; test outputs
  unretrieved. Do not duplicate/restart its run because observation timed out.
- Arch2317: earlier OFF owner12230 and alternate-root OFF owner17118 last observed.
  Alternate install job `f8de2e5a-3e62-496b-a821-8c12b4ed117b` has protected terminal
  FAILED/RUNTIME_FAILED, operation `6eed2827-740a-4003-999b-91dea7741c0c`.
  Loopback-only fixture TLS process17077/port39419 has process-only JVM trust.
  On restored access, revalidate old owner OFF/terminal, use its public quit, confirm
  exit, then install current base at the supported root. Preserve prior evidence.
- macOS owned Tart `vpn-control-visual-macos`, guest192.168.64.3. Latest read-only
  inventory observed r4 owner38207, frontend44198 and runtime44590; older r2/r3
  owners/runtimes remain present. About349MiB disk was free. Preserve the live relay
  and uncertain earlier jobs2c8…,79677cc5… and5d5a78c3…
  and their owners/watchers/input applications. Earlier authorization arrived after
  owner timeout; later cancellation is not proof of terminal recovery.
- Android owned5584/API29,5590/API35 and isolated5592/API35 protocol-test AVD.
  API29 has clean fixture2.2.14, API35/5590 has current source-pair base2.2.15;
  5592 has the debug instrumentation fixture and host loopback SOCKS server18081.
  protected5580/5582 untouched. Native scenarios use nondebuggable ADB without
  root or run-as. Frozen96f CLI manifestSHA
  `a14bdfa526c35cec734fe2b03ed4293d3eb9d2412db1d587cccaeba9042d54e6`.

## Checkpoint 23 Fixture Corrections And Component Evidence

Checkpoint23 was pushed as `749bdc38d658eec05e9e91c8644b3c67fa2a0693` after
all15 managed prepush commands passed. Windows package CI34264247437 failed
release hygiene: the macOS observer used host-specific path serialization, so its
literal POSIX fixture failed on Windows. A PureWindowsPath regression reproduced
this on the host before changing comparison to POSIX serialization. All7 observer
tests now pass locally; corrective native Windows execution and exact-SHA CI
remain delivery gates. Evidence is under local checkpoint23,
`windows-ci-failed.log` and `macos-path-portability-{red,green}.log`.


- The actual macOS `ps` output renders the installer worker path containing
  `Application Support` without shell quotes. The observer previously rejected
  that live coordinator. A literal unquoted process-tail regression failed before
  replacing shell parsing with an exact path plus terminal job/PID match; all six
  observer tests now pass. RED/GREEN logs are in local
  `.runtime/parity-evidence/checkpoint23/macos-ps-parser-{red,green}.log`.
  This corrects observation only; cancellation and public terminal recovery still
  require fresh native correlation and authoritative receipts.
- Android fixture transport regressions now run in release hygiene: all eleven
  pass, including adbd restart clearing reverse mappings, refusal to replace
  unrelated mappings, changed proxy ownership, and retryable ordered cleanup.
  The API29 manual route repair preceded the reusable regression; it was not a
  regression-first operational repair. Native callers must also check mappings
  before setup-time `adb root`, then verify UID2000 before public app commands.
- Actual Gradle execution passed the new Windows helper admission selection
  (13 tests) and existing Windows installation admission selection (14 tests),
  with no failures or skips. This is component evidence; production broker
  binding, scoped UAC and actual packaged-owner/native traffic gates remain open.

## Final Delivery Gates

Require current installed-package evidence on Linux x86_64 DEB/RPM/Arch, Windows
native x86_64, macOS actual architecture and Android API29/API35. Label Windows
ARM64 emulation/component/mixed-artifact evidence accurately. On every desktop,
prove one owner and traffic continuity through attach/hide/show/close/crash,
CLI disconnect and GUI-free scheduled refresh. Verify static commands cause no
startup, missing-owner status is unavailable, transient query-owner behavior,
serve lifetime, explicit OFF intent and later GUI reconnect initialization.

For each native run record source fingerprint, package/helper hashes, OS/architecture/
JVM/API, public launcher, fixture/workspace, safe output/exits, exact operation/job,
terminal outcome and cleanup. Match final package evidence to delivered source.

After final content, review workflow_status/scope, version_bump for non-documentation
changes, managed prepush, explicit reviewed commit/push and all five required
workflows for the exact SHA. Fix CI defects with causal regressions and repeat.
Advisory VPN Integration and passing component tests cannot replace native/visual gates.

## Preserved History

The previous contradictory checkpoint ledger is preserved verbatim in
[parity-checkpoint-history.md](parity-checkpoint-history.md). Earlier evidence is in
[parity-native-history.md](parity-native-history.md) and [parity-history.md](parity-history.md).
Those are historical retrieval aids, not current completion or process authority.
