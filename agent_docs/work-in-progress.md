# Work In Progress

## Objective And Boundaries

Finish the full GUI/CLI parity plan on Android, Linux, Windows and macOS,
including matching public behavior, persistence, runtime effects, progress,
cancellation, packaged native acceptance, visual review, reviewed dev pushes and
all five required workflows for the exact delivered SHA. The goal is incomplete.
No release, main merge, tag, publisher, runtime upgrade or TUI implementation is
part of this task.

Product authority: [contracts.md](contracts.md), especially CLI-001..008,
STATE-001..005, DESKTOP-001..008 and TEST-001. Command authority: [cli.md](cli.md).
Failure/prevention index: [parity-failure-regressions.md](parity-failure-regressions.md).
Historical checkpoint descriptions remain in Git at
`fc82b28eab7b42dadbb9bdd04443e2c66e8b3dec:agent_docs/work-in-progress.md`.
The pre-consolidation working copy is preserved in ignored
`checkpoint51/work-in-progress-before-consolidation.md`. Evidence paths below are
relative to `.runtime/parity-evidence/` unless explicitly absolute.

Only positively identified owned VMs/emulators may run VPN, elevation, installation
or fixture trust operations. Preserve the host VPN, personal workspaces, unrelated
VMs and AVDs5580/5582/5584/5590/5592, and excluded `agent_docs/.Rhistory`.
A timeout is not cancellation, termination, or permission to replay. Retain unknown
job correlations and inputs. One operator per environment and one writer per file;
root owns host Gradle, shared integration, metadata, commits, push and exact-SHA CI.

## Current continuation — checkpoint118

Checkpoint8e0a6b3fbe41ace535abce610737bc64710df074 passed the complete
prepush tier and all five exact-SHA push workflows; managed watcher91497 exited0.
The same-source Windows fixture run35835908106 also passed. Root verified the
archive, base/target MSI hashes, main JARs and shared code fingerprint. Fresh
Windows CP117 is separate from preserved CP95; no new installer has run yet.

| Task | Owner | Exclusive scope / next handoff |
| --- | --- | --- |
| Delivery118 | root | QEMU preflight integration, docs, metadata, checks and delivery |
| Windows base118 | windows_base118 | New CP117 guest only; ordinary-account setup and verified package transfer |
| Android29 benchmarks | android29_public117 |5684 only; diagnose failed relay preflight before benchmark mutation |
| Android35 readback | android_readback117 |5682 only; dedicated gateway multiplexing after proven SSH disconnect |
| Linux recovery | linux_next117 | Fedora2326 private QEMU/ROM preparation; reviewed second-attempt candidate |
| QEMU asset guard | completed | Root owns new guard/tests and routine wiring |

API29 initial public status/stats/streams have70 independently verified evidence
hashes; the original self-including manifest is preserved alongside a corrected
self-excluding manifest. Its benchmark preflight did not reach the relay, so no
location was added. API35 readback capture attributes failure to SSH exit255 and
gateway connection closure; the same controller/revision remains available. No
import was replayed. Evidence and source identities remain in checkpoint117.

Linux restore first rejected changed host QEMU, then a private matching binary
failed before migration due to a missing VGA ROM. Original memory and paired
storage remain preserved; attempt-one intent/log/socket are not erased. The new
asset guard must precede a separate, reviewed retry. Mac remains stopped because
of host memory pressure. Full parity and final native/visual gates remain open.

## Prior continuation — checkpoint117

At11:09 Moscow the authoritative worker inventory was empty. The Android large
import has a successful terminal receipt; its following full-readback client is
absent and has no exit receipt, so readback remains unverified. Do not repeat the
import. Root is integrating SDK admission and the workflow parser gate before
prepush. Prior ownership rows below are historical, not active assignments.


77976806328da03f43a7952224ec272d69787a74 passed all five required exact-SHA
push workflows; managed watcher1593 exited0. The next checkpointadd840ad234c23f0588fc1dbc0a0a68c480ecd70
was pushed after complete local prepush passed, but Windows push35833398572
failed and manual fixture dispatch returnedHTTP422: runner.temp is unavailable
in job-level env. Watcher88997 exited1. This is not a verified delivery.
The workflow now initializes FIXTURE_ROOT through a PowerShell step/GITHUB_ENV;
a causal regression failed before repair. A fresh worker workflow_lint117 owns
only a pinned real actionlint runner and its tests; root will wire it into routine
checks before another full validation/push. No release/main operation occurred.

API35 packaged status/stats/capabilities and initial watch/follow records passed.
Root independently verified40 stream evidence hashes and same controller
0ab99cc7-32e5-47a2-8bda-c5e9416a56cd; local TERM143 stopped only each client.
First records took12–14 seconds; earlier3-second cutoff was insufficient evidence.
Full duplicates/rollover/owner-replacement stream scenarios remain open.
android35_document116 owns only emulator5682 large-document work. Baseline export
under the repository returned PERSISTENCE_FAILED before mutation; a private
trusted /private/tmp output path is the next discriminator, not a claimed fix.

API29 worker created only private SDK/AVD vpn-control-parity116-api29 on5684,
PID67529,2GiB/2CPU. Shared avdmanager symlink resolved to /opt/android-sdk and
could not see the selected SDK's image; copied real tools under the private SDK
fixed creation. No shared SDK edit. Target2.1.14 installed once into the fresh
nondebuggable guest; exact APK hash matches API35. Command observation timed out,
so the worker checked installed package state instead of retrying installation.
Private-SDK/AVD admission needs a quick causal regression before reuse.

| Task | Owner | Scope / next step |
| --- | --- | --- |
| Delivery117 | root | Workflow parser fix, routine integration, metadata, prepush and exact-SHA CI |
| Workflow lint117 | workflow_lint117 | New pinned checker and test only; real parser RED/GREEN |
| Android35 documents116 | android35_document116 | Exclusive5682, synthetic large routing after baseline, no VPN/installer |
| Android29 baseline116 | completed |5684 remains running; root owns next assignment, no replay |
| Linux resume116 | completed | Read-only2326 inventory; no resume authorized |

Linux2326 is separately memory-parked at
/home/kardinal/vpn-control-install-vm-cp83-fedora-20260920,6GiB/4CPU; do not
cold-boot a parked disk in place of the documented memory restore. CP99 package
inputs are historical. Its read-only identity/resources are checkpoint116/linux.
Mac boot remains deferred for local memory headroom. Unknown installation
correlations and Fedora2316 memory remain preserved.

## Prior continuation — checkpoint116

Checkpoint77976806328da03f43a7952224ec272d69787a74 was pushed after the
complete managed prepush tier passed. Its exact-SHA managed CI watcher is live
(session1593); all five workflows were in progress at10:29 Moscow September23.
Do not reuse the older9e57 CI receipt as evidence for779.

| Task | Owner | Exclusive scope | Evidence / next step |
| --- | --- | --- | --- |
| Delivery116 | root | Docs, metadata, host Gradle, commits, CI | checkpoint115/prepush-result.json; CI watcher1593 |
| Android baseline115 | native_evidence115 | Owned API35 serial5682 only; ignored evidence | qemu59345, UID2000, nondebuggable2.1.14; packaged CLI read-only commands next |
| Windows fixture116 | windows_artifacts115 | New manual-only workflow and its test | Build same-source base/target on disposable CI; no dispatch yet |
| Linux regression116 | linux_regression116 (done) | DesktopLinuxInstallWorkerTest.kt only | Root focused five tests pass; actual shell RPM failure branch |

Android baseline confirms boot of only the existing private AVD at2GiB/2CPU.
Direct content call status/capabilities returned empty output and are not valid
provider protocol evidence. Use the packaged adapter. The first launch omitted
ANDROID_AVD_HOME and failed; its raw error is retained, causal regression still
required. API29 image files exist but completion receipt is insufficient.

Mac VM remains stopped: root deferred its4GiB reservation with roughly11.5GiB
physical compressed memory and1.6GiB swap already in use. No unrelated process
was stopped. Arch had53GiB available before the Android allocation. Keep unknown
installer records and parked Fedora memory intact.

## Prior continuation — checkpoint115

On 2026-09-23 startup revalidated dev at9e57f01, equal to origin/dev, and
preserved ten dirty fixture/doc paths. The previous turn was a status estimate,
not implementation progress. No previous collaboration workers were live.
Fresh bounded workers own fixture review (fixture_review115), retained local
native evidence inspection and exclusive owned API35 discovery/admitted boot
(native_evidence115), and readiness helper/tests (readiness115, completed).
Root owns docs, integration, other environments and delivery. Android permission
is limited to existing vpn-control-parity113-api35, serial5682,2GiB/2CPU after
10GiB free-memory and unoccupied-port checks, then read-only baseline; no install,
clear, force-stop or mutation replay is authorized to that worker.

The old Arch SSH control socket refused connections. Root authenticated a new
session using the authorized key and created a distinct arch115 control socket;
no guest or installer was restarted. Tart reports the owned macOS boot-control53
VM stopped; its old IP times out. Historical process identifiers are not live
state. Reinspect retained operations after any capacity-admitted normal boot.

The dirty batch remains QGA bounded reads, fixture dependency inventory, macOS
public-status readiness, their causal regressions and routine documentation.
No current dirty batch pre-push receipt or delivery exists yet.

Current read-only native discovery establishes that Arch is reachable through
the new authenticated session, with54480MiB available and no qemu/emulator/SDK
manager process observed. This supersedes historical capacity estimates but does
not authorize replay of retained installer jobs. The Android CLI113 folder lacks
raw stdout/stderr/exit receipts, so its prior worker success summary is unverified.
Mac machine114 exports prove preparation/download only, not installation.

## Previous continuation — checkpoint114

Checkpoint9e57f01f31f66607627606468de773afae99f7fc (product2.1.14) was
committed and pushed after the complete managed pre-push tier passed. Its exact
CI watcher completed successfully: all five required workflows passed for that
exact SHA, as did advisory core VPN Integration. Its managed receipt is
checkpoint113/commit-result.json. Do not substitute the earlier40307db receipt.

The fresh macOS pair is /private/tmp/vpn-macos-parity113-pair, source fingerprint
23ada94d67f67ef024c889a29d125b7af99356f4f45a62f06edce32d8cb08cbd and same-code
fingerprint dee8037d0404750a1d7c96abef65250b9cd42eb827d8981c0885e27fa0b3724a.
Base2.1.13 DMG631be2d775ea4abf75c8f1d8d1e9fc3b8411540ebacad6ebf2256ce4ae654b46
and target2.1.14 DMGd90d2cd96d4d7a1cb424cf2dc1e9665372c60818cb8604b2d7add255e643eba7
passed independent hash and strict signature verification. CP113 submitted one
operation7a3ab594-00e5-4b4d-849d-bd5a35465190/job8ff62b6a-adbd-4d46-866e-eff279603bd8,
which reached protected SUCCEEDED/OK sequence4. The observer captured automatic
GUI17540 and internal owner17543 before any post-terminal public query. Its first
status read failed and discarded command output; a later read succeeded under
new epoch ed34bea8-7f35-4f65-b44a-2c4fd595e844, runtime OFF. An endpoint-readiness
race is an inference, not recovered stderr. Same-job final identity, visibility,
and recovery now passed: public updates status reports the exact origin request,
operation and job with installed:true and cleanupCode:OK. Root verified16 manifest
entries, including the target tree/version/signature, automatic process captures,
guarded GUI visibility acknowledgment and empty post-cleanup process captures.
Only the new owner and verified server were stopped. Evidence and limits are
checkpoint113/macos-return113/root-review.json. This closes current user-local
replacement/automatic-return/recovery, not machine rollback or interruption.

Windows native image admission is now root-reviewed: old managed component
rejected the image owner/ACL; the corrected component returned exit0 and its
success marker. Both ran as parity95/SID1002 with elevated:false. The apphost hash
is identical between .NET component variants; their managed DLL hashes differ.
This is not NativeAOT or MSI replacement evidence. Receipts/hashes are under
checkpoint113/windows-admission-root-review.json and windows-code-hashes.json.
The actual Windows empty-output receipt regression also passed (QGA child4752,
exit0), including its old-expression rejection and four direct child exit cases.

Android API35 now has an exclusively owned remote x86_64 AVD:
vpn-control-parity113-api35/emulator5682, PID1622752/start6569944,2GiB/2CPU,
private root /home/kardinal/.vpn-control-parity113. The frozen nondebuggable target
APK is installed; direct UID2000 provider status/capabilities passed with runtime
stopped. Those reads did not exercise the packaged desktop CLI. Evidence was
exported to checkpoint113/android-guest113. A fresh worker owns the default CLI
and stream/document tests. The same-source nondebuggable base2.1.13/code16660 APK
also built and passed ABI/signer/manifest inspection; its SHA256 is
75e46211534d6de219e53916483b7f35949d1d28a05da274ca0b3de5cc367bbe. The exact API29
Google APIs x86_64 system image download is separately running under PID1666739;
do not create or start another emulator until resource admission and ownership.

Remote relay refusal was caused by an expired read-only QGA collector that
remained alive after its local wrapper timed out. Root verified and stopped only
that collector; queued connections drained. The new bounded, synchronized
read-only QGA helper and causal tests are the next dirty batch. An independent
native read/open/close passed with exact receipt hash. Existing unknown installer
jobs, parked Fedora memory and old macOS owner881 remain preserved.

The latest native GUI-return diagnosis separates successful replacement from
failed return. With the jpackage marker absent, direct launch from SSH still
fails graphical-session admission; Launch Services starts the same installed
bundle and its authenticated controller in a separate workspace. The native
worker now uses Launch Services for GUI return and the captured launcher for
headless serve. Three portable C regressions pass, the actual ARM64 worker
compiles, and both assigned Darwin component tests pass on the final revision.
Fresh packaged replacement/return remains open; no component result certifies it.

Windows original-user image-admission RED and GREEN probes have both reached
terminal expected outcomes under the ordinary-user token. Root is reviewing
the exported native output and identities before accepting this component gate;
full MSI replacement and recovery remain open. Neither probe ran an MSI.

Fedora2316 was safely memory-saved and parked after QMP completion and exact
process/media checks, preserving the unknown CP79 installation and controller.
The 4,051,683,404-byte memory image is retained under memory-park112 in its owned
remote root. Available remote RAM is approximately12GiB: sufficient for the
planned Android allocation, below the14GiB Linux admission threshold. Do not
restore the saved guest or replay its pending install without a resource review.

Android remote preparation found only an API35 x86_64 image and no suitable
nondebuggable x86 build route. A bounded worker owns app/build.gradle.kts and
scripts/test_android_native_fixture_build_type.py to add an explicit test-only route,
preserving production release ABI and signer behavior. No Gradle or emulator
operation is assigned to that worker. API29 still needs its system image; existing
unknown/protected AVDs remain untouched.

The corrected nativeFixture build now passes (checkpoint112/
android-native-fixture-build2.log). Root independently verified the frozen target
APK as x86_64-only, nondebuggable, package com.kardinal.vpncontrol, version2.1.14/
code16680, with signer a43b5330501b02f5558fa381c52e7f7dcdd9db362d6807d449d7bbb5e207c5a0.
APK SHA256 is1af2a6c40afe47bca10d40344f9a33ab7f71b774f710a41c4fdf8780502d00ca;
tracked runtime bytes match the merged input, and the AGP-stripped output matches
the APK runtime entry. Evidence is checkpoint112/android-x86-target. This is
built-artifact evidence only. android_guest113 owns preparation of a new remote
API35 AVD with a10GiB free-memory gate and maximum2GiB/2CPU allocation; protected
and unknown AVDs remain excluded.

Checkpoint `027fcc6a2378a8dabb7f1030c1a47cc804498ecf` (product2.1.14)
was committed and pushed after the complete managed pre-push tier passed.
Windows CI35560957259 failed because the new real Unix-socket fixture test used
its Windows temporary path as an Arch QGA endpoint. The correction keeps payload,
hash and quoting checks portable and limits the real Unix transport roundtrip to
Unix hosts. Correction40307db4121bae3bd307126324615af8d55194ec is pushed after
the complete managed pre-push tier passed. All five required exact-SHA workflows
passed; managed watcher81052 completed successfully. Its receipt is
checkpoint109/commit-result.json. Advisory core VPN Integration also passed.
Prior282c937 passed all five required workflows.
The delivered batch includes Windows image admission/pin lifetime fixes, durable
macOS rollback observation, strict Android installer acceptance, private fixture
staging, prompt/serial/manifest regressions and their routine wiring.
Full parity remains incomplete.

| Task ID | Agent | Owned files/subsystem | Shared files reserved | Artifact / environment | Current check / next handoff |
| --- | --- | --- | --- | --- | --- |
| Delivery114 | root | Shared integration, metadata, evidence review | Host Gradle, commits and push | 9e57f01 all required CI passed | Review and deliver bounded-observer regression batch |
| Android CLI113 | android_cli113 | Ignored CLI transport evidence | No tracked edits or other AVDs | Exclusive owned remote emulator5682 | Default packaged CLI streams/documents; provider-only result already passed |
| Android image113 | passive observer1680016 | Existing SDK download1666739 | No AVD start | Remote exact API29 x86_64 image | Retain same download handle and terminal package metadata |
| Mac machine114 | mac_machine114 | New private machine rollback fixture | No existing app/job changes | Exclusive owned Tart VM | Prepare exact /Applications fixture; root review before one install |
| Mac readiness114 | mac_readiness114 | macos_fixture_processes.py and test | No VM or shared docs edits | Deterministic readiness fixture | Preserve attempted read output and wait for endpoint readiness |
| Windows build114 | windows_build114 | Read-only native build inventory | No installer/runtime commands | Exclusive CP95 QGA | Exact JDK/SDK/NativeAOT prerequisites and same-source MSI build plan |
| Linux gate114 | linux_gate114 | Read-only failure/recovery coverage audit | No VM/build/edit | Current tests and historical receipts | Distinguish pre-install rejection from transaction failure/recovery |
| Delivery111 | root | Shared integration, docs, metadata, delivery | Host Gradle and shared product files | Pushed40307db, all five CI passed | Next observer regression batch and native evidence review |
| Windows image103 | windows_image103 | Coordinator helper image admission, original-user image-pin lifetime and focused tests | No shared Kotlin edits or VM mutation | CP102 read-only evidence | Reviewed fix and RED/GREEN source bundle frozen; native execution pending |
| macOS native105 | mac_native105 | Private native preparation/evidence | No tracked source edits | Exclusive owned Tart guest | User-local rollback/recovery passed; root verified21 hashes; fixture cleaned |
| Windows native112 | windows_native112 | Read-only RED/GREEN evidence export | No product/MSI commands | CP95 guest; probes terminal | Both expected results reached; verify underlying receipts and hashes |
| macOS return108 | completed | Private GUI-return observer/evidence | No tracked edits | Owned Tart guest now available | Replacement succeeded; causal Launch Services comparison and two component tests passed; fresh package next |
| macOS observer111 | root | Process observer, completion runner and tests | Root owns hygiene/docs | Local synthetic fixtures only | Five role, seven runner and eleven rollback tests pass |
| Linux baseline110 | completed | Private native public-launcher evidence | No old-owner changes | Existing owned Fedora2316 | Baseline passed on historical2.1.12; own new controller quit publicly |
| Linux capacity112 | linux_capacity_plan112 | Read-only parking evidence export | No restore or VM mutation | Fedora2316 saved and parked | Preserve unknown CP79 memory/disk; root receipt review |
| macOS fix112 | root | Native relaunch environment primitive and regression | Host builds/docs/delivery | Native108 failure; portable native RED/GREEN | Actual worker compiles; fresh package return still required |
| Manifest104 | manifest_regression104 | Fixture manifest writer and tests | Root owns docs/hygiene | Private temporary fixtures | Manifest/path-safety review and focused checks pass |
| Certificate scope102 | certificate_scope102 | android_fixture_trust.py and its routine tests | Root owns docs/hygiene | Private temporary OpenSSL fixtures | Causal serial-path regression and helper integration |
| Android fixture113 | android_remote_plan113 | app/build.gradle.kts and fixture regression | No Gradle, hygiene, metadata or AVD changes | Remote API35 x86 route; local5596 stopped | Add explicit nondebuggable fixture; root builds after review |
| Windows receipt113 | windows_empty_output113 | windows_native_fixture.py and its tests | No VM, docs, metadata or other source edits | Local deterministic fixtures | Empty-output causal regression and reusable receipt reader |
| macOS package113 | mac_package_plan113 | Read-only package recipe | Root owns Gradle and package execution | Fresh immutable ARM64 pair planned | Exact version/runtime/signing inputs and fingerprint recipe |
| Linux pending | root | Resource allocation and acceptance scheduling | No old guest restore | Remote Arch; Fedora2326 parked | Current packages ready; remote capacity insufficient for another admitted guest |

Checkpoint111 read-only document audit found existing deterministic coverage for
transfer binding/expiry/integrity, failed spool persistence, retained results and
no-overwrite export publication. It found no new source defect. Remaining proof
is the current nondebuggable default Android document path on both APIs, Android
GUI picker/private export, and current installed desktop export paths. Existing
unit/process evidence does not replace these native gates.

CP95 reboot invalidated historical process identities: old PID2968 is now a
Windows service, and old controller6612 is absent. Unknown install records remain
preserved. A single S4U task registration failed with access denied before task
creation despite confirmed SYSTEM authority; no probe ran. One protected
LogonUserW check subsequently succeeded, closed its token and removed its exact
credential temp. The retained credential is valid; the UI password-entry failure
does not prove a stale password. Ordinary-user probe launch is being prepared for
review, without product/MSI commands or persistent policy changes.

Fedora2316 cp79 owner16278 (start ticks652956) remains a disconnected persistent
controller with no runtime child. Its job6bc79509-a517-40b4-89be-ae3f945a47e9 has
no protected receipt and remains unknown; do not replay or stop it. A distinct
workspace can exercise disconnected/public proxy-only behavior without touching
the pending installation. Package provenance must be recorded before attributing
that guest's evidence to current source.

Native108 attempt2 uses the exact tracked canonical bundle identity and process
observer. Its single accepted install operation7fbfc860-4192-4431-ba94-9590cc8f6e42
reached protected job17a28d33-8097-49cd-b25b-51cb167d9424 SUCCEEDED/OK sequence4.
This establishes replacement, not automatic GUI return: the observer had not
seen a returned owner/frontend and terminated after240 seconds with exit1. No
public command bootstrapped that return. Target version2.1.13, codesign and exact
canonical target digest passed read-only verification; installed inode957596 is
distinct from original939688. Preserve the receipt and distinguish successful
installation from failed automatic return. The native worker now clears the
inherited jpackage marker before exec, with a causal portable C regression and
successful root ARM64 compilation; current-package return must be rerun.

Checkpoint106 contained an owned Windows fixture staging failure before any guest
fixture execution. The staging script ran remotely through `python3 -`, interpreted
`__file__` as the remote working directory, and recursively buffered unrelated
remote files while holding QGA. Its exact identified Python process reached about
5GiB RSS. After PID/start-time/socket verification, only that client was terminated;
QGA accepts connections again. No installer, VM, runtime or guest test was stopped.
The bounded local-payload regression and corrected standalone receiver now pass;
do not reuse that old staging script. Native Windows RED/GREEN execution is
assigned to windows_probe107 and remains pending.

The checkpoint106 Android audit found that the installer lifecycle harness records
status/wait without asserting successful target installation. The corrected driver
requires explicit expected outcome, exact correlation, and target version/code/hash
for success; its17-test suite passes. Existing capture-only or cancelled runs cannot
certify installed-package acceptance. No emulator was started by this audit.

Checkpoint105 closes user-local macOS rollback and next-owner failure recovery
for the frozen3ba018f base2.1.12/target2.1.13 DMG pair. Root verified21 guest
evidence hashes and exact controller/request/operation/job correlation. The
worker published FAILED/PERSISTENCE_FAILED sequence4 after the deliberately
immutable candidate prevented replacement; the exact original base inode/tree
and signature were restored. A new controller recovered final failure with
cleanupCode:OK and installed:null. Observed runtime remained OFF. The driver
finished in7 seconds; its owner quit publicly and only its verified server was
stopped. Prior owner881/watcher12320 and their unknown jobs remain preserved.
Evidence: checkpoint105/macos/root-review.json. Machine rollback, interrupted
recovery, automatic GUI return and final-source attestation remain separate.

CP102 Windows read-only evidence confirms the worker-ready helper hash matches
its original-user-owned installed image. Coordinator image inspection still uses
machine-only ownership checks for that image; this is a causal hypothesis for the
post-bootstrap failure, pending regression and native execution proof. Protected
receipt ACLs must remain strict.

The fresh macOS rollback job3bf3b125-8411-42c8-8a1b-ee7ea0d8b232 reached
WAITING_FOR_EXIT with owner12216 live. A public quit returned BUSY; no owner was
killed. The temporary candidate immutable flag and fixture lock were removed.
The fixture omitted a post-readiness public status acknowledgement; raw receipt
reads cannot release DesktopOwnerExitGate. Same-job continuation through exact
public operation status is assigned, retaining the staged-candidate rollback
fault and original owner identity. No product exit defect is established.
Preserve older owner881. The exact public acknowledgement subsequently returned handoffReady:true and
the owner exited. The protected receipt remained WAITING_FOR_EXIT during the
observation window. An additional fixture lock was identified and released.
PID12320 is the watcher role; the actual coordinator is absent and no exact
launcher/gate lock holder remains. The receipt is stale/nonterminal; exit cause
is unproven. Only our staged-candidate immutable flag was removed after
identity/signature verification. No same-job replay or rollback success is claimed. Native public
rollback is not yet proven.

CP101 macOS now proves sampled traffic across a fresh scheduled operation on the
frozen3ba018f target DMG:252/252 successful probes, maximum observed gap1.2206s,
one fresh application HTTPS request, exact operation wait, same controller/runtime.
The operation ended RUNTIME_FAILED after Find Best target validation; successful
Find Best remains unproved. Root verified all301 manifest entries. Public off/quit
returned OK; only protected owner881 remains. Evidence:
checkpoint101/macos/cp101-collected and root-manifest-review.json.

CP100 Windows is authoritatively CANCELLED. Its credential sequence followed the
not-started marker and cannot prove approval. CP102 prepared helpers in advance,
rejected a changed screenshot without input, then admitted one guarded input
8.664seconds after fresh review. Public recovery now retains unknown job
b066a7a6-8016-492d-9e09-476d7288d027, operation
b5342e30-6290-4408-a68a-82b4fd00dccb, request
da4446e4-8b4b-419b-9a91-e107df048cf4, controller
8e027d3b-019e-448f-ba03-ede600624db9. Handoff is unacknowledged and installed
remains null. Do not replay, cancel, quit or stop this owner/VM without new
terminal evidence. Base version2.1.13 remains observed. Raw evidence:
checkpoint102/windows/recovery-result.json and prompt captures.

Read-only Android inventory identifies AVD5594 as API35 with VPN Control2.3.2
installed but no app process. A system Legacy VPN has unproven ownership;
preserve the emulator. Ordinary pending installer sessions remain uncertain.
Remote Arch checkpoint106 reports10442MiB available after staging-client
containment, just202MiB above the Android threshold. Recheck immediately before
any start; Linux remains3894MiB below its14336MiB threshold.
Multiple existing QEMUs are present; preserve them pending ownership/lifecycle
verification, rather than assuming CP95 is the sole running guest. API29 image is absent there;
existing API35 environments lack established ownership. Evidence:
checkpoint101/android-capacity and remote-android-admission.md.

The current-source macOS base2.1.12/target2.1.13 pair is built under
/private/tmp/vpn-macos-3ba018f-pair. Both package hashes and common code fingerprint
were independently verified. Source fingerprint:
2c94f668537f0d73e7858716dea54197f119be1fb3fd2ce0ad6ab29e5f415ab2.
Evidence: checkpoint98/macos-pair-receipt.json and macos-pair-root-verification.json.
This is package-build evidence, not native installation or traffic acceptance.

Current source audit confirms Android watch/follow dispatch precedes the legacy
adapter flag rejection. Shared streams pin owner identity, retain cursors/gaps and
per-read timeouts. DesktopCliOutputHealth checks idle output pipes each poll;
DesktopCliStreamPipeTest exercises real child-reader closure for JSON and human
output. Historical CP25 idle-follow failure is superseded by this implementation.
Current nondebuggable API29/API35 default-document transport stream execution is
still required; legacy-provider records do not close that gate.

Linux corrupt-package rejection already has deterministic coverage in
DesktopLinuxUpdateServiceTest.changedVerifiedPackageNeverReachesNativeAdapter
(the fixture selects RPM), with exact protected receipt correlation separately
covered by DesktopLinuxInstallCorrelationTest. Current native RPM preservation
and recovery remain open; no duplicate test or native success is inferred.

## Checkpoints95–98 evidence

The Windows same-source base2.1.13 and target2.1.14 MSIs built successfully and
were exported with verified hashes (checkpoint94/msi-export-result.json).
The fresh Windows standard user parity95 now has verified per-user Python3.13.15
AMD64 with a non-elevated token (checkpoint95/windows-fresh/python-verification-result.json).
The installer succeeded; a separate inline PowerShell/Python verification quoting
error was resolved using a script file without rerunning installation.
The source-to-bdaa57 delta contains Android tests/fixtures and documentation only;
this does not itself prove a native installation outcome. Earlier unknown Windows
and Linux jobs remain preserved and must not be replayed.

Android CP89 was restored using its exact compiled-parser identity, and CP94 B
was removed by stable ID (checkpoint94/android/restoration-summary.json).
CP96 cleanup leaves only CP89, runtime off, revision18. The small-frame fixture
uses the supported legacy public provider, not the default desktop CLI document
transport; its evidence must retain that distinction. The document wrapper's
roughly ten-second overhead came from eight separate guest `content` processes;
a persistent shell did not remove that cost.

macOS CP94 continuous GUI lifecycle passed32/32 traffic requests. CP95c passed
335/335 requests and scheduled refresh fired twice, but refresh TLS failed because
the fixed-response SOCKS fixture answered TLS with plaintext HTTP. This is a
fixture defect, not proof of a scheduler or product TLS defect. The new exact
loopback forwarding mode has causal EOF, cleanup and backpressure regressions;
CP96 then captured an application HTTPS GET and SUBSCRIPTION_REFRESHED after
AUTO_REFRESHING_SUBSCRIPTION, retaining the same controller and active runtime.
Its subsequent Find Best failed target validation and restored the previous
connection; this does not prove successful scheduled Find Best. The sampler has
seven early fixture-port failures among326 requests, so it is not an all-pass run.
The corrected interval from00:44:40Z has319/319 successful requests. Root verified
the corrected manifest; the original self-including manifest is preserved as invalid.
Audit confirms automatic refresh bypasses DesktopOperationRunner; its missing
operation identity/history is a product gap under CLI-003/005. The implementation now tracks scheduled refresh, retains committed source outcomes
after post-refresh failures, and preserves unknown outcomes for recovery. Seventy
focused tests pass with no skips. Native TLS success predates this change and does
not close the rebuilt operation-visibility scenario.

CP96 Android cleanup is confirmed by its original receipt listing all11 transfers.
A later discard correctly returned NOT_FOUND. One fresh UID2000 create/discard
probe returned the expected empty bundle and both commands exited0; no parser
fix is warranted (checkpoint96/android-cancel/21-cleanup-probe-*).

## Checkpoint94 evidence (historical)

Latest pushed checkpoint is `c880e05275184ed242b611684ab8eacf3a62d97b`
(product2.1.13). All five required exact-SHA workflows passed; receipt:
checkpoint93/commit-result.json. Full parity remains incomplete.

| Task ID | Agent | Owned files/subsystem | Shared files reserved | Dependencies / environment | Current check / next handoff |
| --- | --- | --- | --- | --- | --- |
| Windows package94 | root; windows_build63 retired | Ignored same-source Windows fixture/build scripts | Root owns integration and delivery | Root exclusively operates existing Windows AMD64 VM | Verified source archive bd218828 fingerprint; ordinary-user build wrapper4160 and Python1240 observed live; no MSI replacement yet |
| Android stall94 | root; android_fixture54 retired | Benchmark relay and Python tests | Root owns docs and delivery | No native operation by this worker | Causal RED captured; corrected relay six-test GREEN; native cancellation rerun remains |
| Android selector94 | android_dispatch59 | Location presentation/control tests and smoke-android guidance | Root owns product code and delivery | No AVD operations | Focused list/delete and stable-ID tests pass; numeric cleanup was fixture misuse |
| Android recovery94 | root; fixture_review92 read-only recovery | Ignored restoration evidence | Root alone authorizes emulator mutations | Owned5596 stopped; prior CP89 fixture mistakenly deleted, CP94 B remains | Recover exact original raw record/identity before restoration; native worker retired |
| macOS traffic94 | mac_resume73 | Ignored native evidence | Root owns integration | Exclusive Tart vpn-control-boot-control53 | Same controller/runtime and five traffic probes through attach/hide/show/close passed; continuous32/32 traffic checks and identified frontend termination passed; native visible-property query gap retained |
| Linux evidence94 | root; linux_rollback66 retired | Ignored recovered raw receipts | Root owns integration | No VM mutations | Nineteen raw files hash-verified; terminal failed receipt retained; full restored-tree proof still absent |

Windows archive SHA256
`1df24d3574e853939162aac6337b50872c057674bbf387e1c3a9d451936a0c58`
was verified after remote and guest transfer. The ordinary-user build preflight
passed Python/JDK/.NET probes; fresh base2.1.13/target2.1.14 use source fingerprint
`bd218828827b1662debe41f7a6e2026bc57fb9a272ea5cf1664cc0f8d5bff82e`.
No original unknown installation was replayed. QEMU memory parking has only been
reviewed, not executed; no additional VM or freed RAM is claimed.

Android Find Best committed through the tracked default-target relay, with four
actual chatgpt.com CONNECTs. The cancellation fixture ended prematurely and is
fixed under its own causal regression. Cleanup then misused stale numeric indices
after sorting; the prior task fixture must be restored before further native work.
See checkpoint94/android/receipt.md and parity-failure-regressions.md.

Checkpoint91 proves the original-user bootstrap with the same NativeAOT image
SHA256 `05510b3c22df1fdd6301dba4f7af9918dce82ff2cfa004ae3dfa3682e459e20a`
(case-insensitive hex): ordinary and same-user elevated runs return0 with exact
non-elevated child identity and bounded pre-admission cleanup. See
checkpoint91/windows/ordinary-result.json and elevated-progress2.json. This
protected ProgramData test image does not prove the actual per-user installation
path, a different approving administrator, or MSI replacement. Checkpoint92's
read-only image-acl.json confirms the real helper is original-user-owned under
AppData; its old native self-pin used machine-only trust. The same old image then fails from an isolated original-user-owned AppData directory
with exit91 / Installer mutation rights rejected (checkpoint92/windows/peruser-result.json).
This reproduces the self-pin incompatibility without an installer role; the
production fix and routine causal regression are recorded below. The original unknown
job is preserved.

Checkpoint93 adds a routine noninteractive apphost/private-user-directory test
before the interactive Windows test gate. Its actual NativeAOT fixture first fails
with the same mutation-rights rejection (red-result.json, image93f8aba9). The fix
threads only the captured original interactive token SID through the retained
image/ancestor checks and child image reinspection; the coordinator already binds
that SID to the authenticated owner. Machine receipt trust is unchanged. Matching
principal/image admission and rejection of an unrelated principal now pass in the
same user-owned layout (green-result.json, image6a87706e). Focused host checks run
17 tests successfully with7 Windows-only skips; independent review found no
blocking concern. Full MSI replacement and post-fix elevated bootstrap remain
native acceptance gates, not implied by this image-pin component result.

The initial checkpoint91 fixture build omitted loader.manifest and failed CS1926.
The replacement frozen fixture uses an inventory derived from the actual helper
project; build and native bootstrap pass. The reusable inventory and four quick
regressions were pushed in cad9aeb. They support native probe staging, not a change
to production package-building behavior.

Linux checkpoint91 adds a PTY response guard that requires both the exact prompt
and disabled echo after the terminal input flush. Its quick regression passes;
the actual packaged Java no-op authorization passes with the guard, child/owner
exit0, and no retained probe processes. See
checkpoint91/linux-analysis/java-auth-ready-receipt.json. This prevents a fixture
race but does not establish it as the historical checkpoint85 installer cause.
The helper is for interactive native fixture drivers; the tracked noninteractive
public-install harness does not automatically enter credentials.

Linux current pair source fingerprint
`cf5e2b517284a76c7da7e430dc6f4b83998b3d1bfac635e95ee7e7d65219d738`
comes from ee80dcf. Both RPMs and their immutable server archive were verified
before copying to the fresh guest. See checkpoint85/linux-rpm-export.json and
linux-transfer.json. The running failure fixture is
`/home/vpnfixture/cp85-rpm-failure`; its durable driver PID4658 has exited. The original public attempt returned
OUTCOME_UNKNOWN/exit2, handoffReady=false, job
`bacae2d1-5029-4e39-a69a-6cba7407c64c`, operation
`55fe0251-14e5-434f-8616-ef8a61ad86f9`. Owner4661 remains alive; no privileged
worker or package-manager process remains, and no protected job receipt exists.
Polkit records failed authentication. The private fixture credential matches the
ordinary guest account and the account is not locked. Isolated fixed /usr/bin/true
authorization passes both directly and with the same separate owner/tty-agent
arrangement, including --disable-internal-agent. PAM reported a conversation
failure on the original attempt; the installer-specific cause remains unproven. Preserve the unknown journal/inputs and do not replay this job.

Checkpoint89 also calls the actual installed Java terminal-agent launcher against
the same separate-owner fixed /usr/bin/true authorization probe. Registration,
password exchange and child exit0 pass; only that probe's terminal-agent lease is
closed after the no-op owner completes. This excludes a general failure of the
packaged Java launcher, but does not resolve the original installer exchange.
Evidence: checkpoint89/linux-analysis/java-result.json and retained guest
/home/vpnfixture/cp89-java-auth. No installer operation was repeated.

Windows checkpoint85 failed before compilation because PowerShell5.1 promoted
native stderr under `ErrorActionPreference=Stop` with merged redirection.
The ordinary-user checkpoint87 reproduction independently confirms the warning
becomes a terminating record and leaves a zero-byte capture. Existing unknown
MSI jobs remain untouched. This is a fixture failure, not evidence of a product
helper defect. The exact quick regression passed in the ordinary-user AMD64 guest after root
corrected capture and direct-child waiting. Checkpoint88 NativeAOT helper
validation, owner admission and package preflight all pass with exit0. The
original unknown MSI job is unchanged; successful MSI replacement remains open.
See the failure ledger for exact RED/GREEN evidence and superseded candidates.

Checkpoint89's read-only NativeAOT probe admits the original pending Windows job
2946b6ab-1e10-4edd-b045-8f23cc2395bc, owner8352 and its actual MSI. It returns0
after package preflight; the request digest is unchanged. A separate synthetic
job also publishes worker-ready successfully using unchanged production sources,
then exits0 and removes its own synthetic inputs. Neither probe runs installer
roles or MSI replacement. Evidence: checkpoint89/windows/result-transport.json,
ready-progress.json and worker-ready-inputs.json. Elevated coordinator/original-user
bootstrap and real replacement remain open.

Android5596 now proves one real nondebuggable ARM64 benchmark measurement with
code73 APK hash74af8c726d625964ba35a5691d2aaa53e88a0377fefe259f76b8dd55fc820330.
The initial source rejection was correct for the empty subscription selection.
After selecting current-locations, the initial benchmark failed because the old
retained relay only allowed github.com while validation defaulted to chatgpt.com.
Public guarded settings.set temporarily aligned the URL with the relay; operation
e2f98183-6313-471e-92d8-6cc4ded3fda1 completed OK with secondaryTotalMs1091.471209
and confirmed github.com:443 relay traffic. The original URL was restored and the
owned reverse/relay removed. AVC messages did not establish the failure cause;
no native ARM64 crash occurred. This does not prove the default target or VPN path.
Evidence: checkpoint89/android/discriminator-evidence.sha256 and diagnosis.md.
Checkpoint90 adds prevention coverage to the existing routine benchmark fixture
suite. The tracked relay already permits the product default; the obsolete
ignored relay caused the failure. The regression derives the real default URL,
uses no external network, and retains denial of unlisted targets. The extracted
historical policy fails;5 current tests pass. See the failure ledger.

Root booted the existing owned ARM64 AVD on5594, discovered version2.3.2, and
preserved its data without installing an older APK. The separate new5596 AVD is
the code73 benchmark comparator. Host memory admission was69% free before these
2GiB starts; the existing4GiB Tart guest and unrelated environments are preserved.

## Resumed Native Batch — 2026-09-20

Checkpoint77 was pushed as `c8f30e02f54687d662f26e592ff862038211f310` after
full prepush passed. macOS CI35529722794 exposed an outdated embedded test call;
its correction preserves terminal-receipt cleanup and adds ordinary local
compile-only coverage. The corrected full seven-test fault suite passes inside the
owned Mac VM (checkpoint79/macos-ci). The repair was pushed as
`be009403669c0a1203c2f767b7ddf3d677a4bbfb`; all five required exact-SHA workflows passed
(checkpoint79/macos-ci/commit-result.json).
The current immutable Mac pair `/private/tmp/vpn-macos-code79` built successfully
from c8f30e0; subsequent repair changes only the test harness and documentation.


An earlier fully CI-verified checkpoint is
`94dbd582e0268fb31f4522b3136520efb8c7594c` (product2.1.12).
All five required workflows succeeded for that exact SHA;
checkpoint74/commit-alias-result.json contains the managed receipt.
The earlier e2e88ad freeze remains the source of the Windows/Linux/Android fixture
packages below. Native completion is still open.

Checkpoint74 delivered a focused integration batch:
desktop cancellation returns promptly when a recovered unknown installer cannot
be cancelled, and a reusable Android installer driver forwards file-based
continuation into its action. The desktop causal RED is a virtual-time timeout;
31 focused desktop tests pass after the fix. The Android driver has original-code
RED evidence and passing quick tests, wired into release hygiene. Windows CI then
exposed two fixture portability causes: executable suffix and path spelling.
Both now have quick regressions; the final selections passed33 preflight and11
driver tests, and final Windows CI passed. See the failure ledger for exact paths.

The current macOS pair at `/private/tmp/vpn-macos-code75` uses3055e97; subsequent
94dbd58 edits affect only Android fixture tooling/tests and documentation. Root
verified its exact DMG hashes, and the guest verified the installed base signature.
After positively checking runtime OFF, root exercised owner loss and reopened the
original workspace with the new installed package. Public cancellation returned
OUTCOME_UNKNOWN/exit2 in0.17 seconds while preserving the exact original unknown
install job. See checkpoint74/macos/current-package-cancel-root-review.json.
This closes the cancellation-hang revalidation. Root also reviewed current-package
machine authorization denial and successful replacement to2.1.14 in a separate
fixture: jobb7c7c0c1-8855-42e6-b08c-ac25b206715c, operation
e26dd649-3ac1-42b6-a8d9-295c641b600e. The root-owned protected receipt is sequence4
SUCCEEDED/OK; the replacement owner recovered the exact original request and
reports installed=true, cleanupCode=OK. Downloaded target hash matches the frozen
DMG and the installed target passes strict deep signature verification. See
checkpoint76/macos-auth76/root-review.json. This ad-hoc signed fixture does not
prove notarization, rollback, GUI return or traffic continuity.

The separate denied job440b86ce-8db3-4e62-867a-3082f23a2851 is authoritatively
CANCELLED/not-started but retains approximately141MB of inputs. Production cleanup
now binds its not-started disposer, stages the current packaged helper for legacy
inputs, rechecks protected authority and safely retries exact0600 helper promotion.
Naming, repeated-owner idempotence and interrupted chmod have causal regressions.
Independent focused review found no blocking defect; integrated-focused-green
records60 tests,0 failures and1 platform-specific skip. The final expanded union
passes64 tests with0 failures and1 Windows-only ACL skip on macOS;
checkpoint77/final-union-green preserves every XML. Installed current-package cleanup now passes in checkpoint81/macos: the exact
140947456-byte denied input was removed, terminal CANCELLED/installed=false and
disposition digest remained unchanged, and a fresh owner repeated cleanup with OK.
The unrelated unknown owner remained alive and OFF. Root verified the exported
raw-evidence hashes; GUI return/rollback remain separate gates.

Installed macOS checks confirm static commands create no workspace, missing-owner
status exits2, query-created owners are disconnected/transient, and explicit serve
stays alive while disconnected. Duplicate serve incorrectly supervised an existing
owner. The corrected implementation preserves authenticated promotion of a transient
owner but immediately returns with an existing-owner message. Its causal regression
records an unwanted second polling request before repair; real process coverage
checks both transient and persistent cases. Installed DMG proof now passes in
checkpoint81/macos: duplicate persistent serve returns0 immediately; settings-show
creates a transient owner, serve promotes the same epoch, and after35 seconds
without polling the same owner remains alive and OFF. Root verified8 evidence
hashes; new owners were publicly quit and original unknown owner preserved.

Installed RPM traffic survived GUI attach, close/reopen and crash with the same
runtime identity; off succeeded but quit returned CONFLICT for the dead frontend.
The fix pins authenticated process identity at attach and releases only a proven
dead generation. Unknown/live/replacement identities remain guarded. A portable
stdin-gated JVM child exercises the actual owner quit path. See checkpoint77/linux
for causal RED and native evidence; package revalidation remains pending.

Android checkpoint78 replaces the earlier synthetic HTTP fixture with real SOCKS
byte forwarding. Foreground-service traffic succeeds, but benchmark subprocesses
SIGSEGV under ARM64 translation before SOCKS negotiation. Find Best fails without
changing activeA/pendingB; no real timings or in-flight cancellation are claimed.
Public off/delete cleanup succeeded. Compare the same source on native ARM64 before
attributing this to the product; no runtime upgrade or implementation fix was made.

Windows cp78 reached update checking but its retained fixture certificate expired
September9. Root verified public certificate dates, renewed only disposable inputs,
then confirmed ordinary-user public check/download/READY for target2.1.13 in cp80
(controller7a39aed3-e5df-44f1-94fd-36c22408ad9d, downloaded130986356 bytes).
An installation command was launched once before the remote SSH route became
unreachable. The gateway recovered and the Arch key was unlocked through its normal
prompt, creating task-owned socket vpn-control-arch81.sock. The original install
operation/prompt/outcome is being inspected; it must never be replayed on uncertainty.
The old cp78 owner was verified OFF and quit through public control. Certificate
admission now has a quick causal regression; no global trust settings changed.

Linux checkpoint79's corrupt-package scenario did not produce RPM failure proof.
The ignored driver matched `password` in Java's `trustStorePassword` diagnostic
and wrote the credential before the actual polkit prompt. Timeout and PTY loss
are not established causes. Checkpoint82 adds a strict ANSI-aware current-line
`Password:` matcher and routine harness regression; causal replay of the exact
old predicate fails and the17-test harness passes. Durable native authorization
and corrupt-RPM failure evidence remain open. Preserve UNKNOWN job
6bc79509-a517-40b4-89be-ae3f945a47e9 and its original workspace/records.

Windows checkpoint82 inspected the original cp80 attempt through the ordinary-user
public launcher: op09aa1b2b-94cc-4b64-a6ab-9908014d59c1 is CANCELLED/final,
exit130, installed=false. A subsequent explicit attempt reached visible UAC for
vpn-control-install-helper.exe. After normal UI approval, op
48e8e749-5380-447e-b13e-750676217edd / job
2946b6ab-1e10-4edd-b045-8f23cc2395bc reports OUTCOME_UNKNOWN/nonterminal,
handoffReady=false, installed=null; public version remains2.1.12. Preserve this
job and inspect its evidence; no automatic retry or successful replacement claim.
Raw ordinary-user responses and prompt captures are in checkpoint82/windows.

Checkpoint82 prompt admission was pushed as631d3fb462e01eafdd0ca8c9758282590e389236;
its exact-SHA CI is being observed. Precedingc19e9b5f37a8e8ba580758552bb22e530849c94e
has all five required workflows successful. Checkpoint83 extracts terminal handoff
admission into the routine Linux harness: a complete ACCEPTED/handoffReady response
plus exit0 survives a PTY EOF/reaping race. The old ignored driver guard fails the
extracted causal test;18 routine tests pass after repair. Evidence is explicitly
an extracted fixture regression, not a newly found product protocol defect.

Checkpoint82 Linux reached protected WAITING_FOR_EXIT but the preserved unknown
owner16278 retained a READ lock on the machine gate. It ended FAILED sequence3;
a replacement owner recovered exact jobb32f0d40-f03f-4af7-8219-808753e05ee8 /
op e0a17c7e-b47c-486e-944c-274e3343e883 with cleanupOK and intact base. This proves
blocked-replacement failure recovery, not corrupt-RPM execution.

For an uncontended RPM scenario, root prepared an independent pinned Fedora44
cloud image in /home/kardinal/vpn-control-install-vm-cp83-fedora-20260920 on Arch,
SSH2326,4GiB/2CPU. Resource admission observed13GiB available and zero PSI while
retaining8GiB minimum headroom. Existing guests/unknown jobs remain untouched.
Cloud-init completed with only a hostname warning; fresh baseRPM2.1.12 installation
and verification passed. Fresh fixture-only TLS was used without global trust edits.

Checkpoint83/native-manifest (checkpoint83/linux/native-manifest.json) records the
frozen package source fingerprint96541f180957219f0cb7fbb5a6bb88b7237fb3c5ef344a2fb16c31b2ec50c567.
The deliberately corrupted private target passed public download/hash verification
against its test manifest, reached authenticated handoff and protected FAILED seq4
(after INSTALLING). Next-owner recovery matched jobdfed9d7a-bf80-46cc-98f7-f574b0d50bfc /
op82935a95-43a6-418f-a869-c4428874064e, final RUNTIME_FAILED/cleanupOK/installed=null.
Independent rpm verification reports DIGESTS NOT OK; installed base2.1.12 remains
clean. Installer stderr was not retained. This closes this frozen RPM failure and
recovery scenario, not final-source packages, connected intent, GUI lifecycle or
successful retry. The EOF race occurred again, but the repaired harness retained
the complete acknowledged handoff instead of discarding it.

Windows source/component diagnosis remains open. Bounded worker staging did not
run a probe; root owns the next direct QGA file-write staging attempt. Existing
unknown job2946b6ab-1e10-4edd-b045-8f23cc2395bc remains untouched.

Checkpoint84: fc3e0018415b115edce2bd7346ebf1d71ed47b72 was pushed after full
prepush. Windows package CI35534449946 failed in two pure PowerShell fixture
probes with30-second timeouts; cause is under bounded investigation, so this
checkpoint is not fully verified. Checkpoint631d3fb has all five workflows green.

The explicit intact-RPM retry in Fedora2326 reused the terminal-failed workspace.
A fixture copy first failed read-only package admission before app launch; a new
private read-only copy then passed check/download. Public status overwrote READY
with the historical failure. No second installer was launched. Native outputs are
in checkpoint84/linux/native-retry-failure.json. A new quick regression failed
before the product change; DesktopUpdateService now publishes each distinct
terminal observation once per owner while retaining the complete correlation list.
Cleanup-only metadata changes do not revive old failures; new unknown/terminal jobs
remain visible. Focused recovery/cleanup/exit tests pass. Current-source native
retry is still required. The guest's retry owner remains OFF and must be inspected
before replacement; preserved unknown jobs in other guests remain untouched.

Root restored Windows QGA by stopping only two exact stale task nc transports
(479948/479968), leaving all guest processes unchanged. windows_probe84 prepared
an ignored original-user component bundle and then took exclusive ownership of
scripts/test_windows_native_fixture.py for the CI timeout investigation. The unchanged
Windows rerun passed hygiene; a speculative -File/-NonInteractive candidate is saved
only in ignored checkpoint84/windows and not accepted as a proven causal fix. Root owns
DesktopUpdateService and DesktopRecoveredUpdateStatusTest plus docs/builds/delivery.

Checkpoint84 Windows native AMD64 component checks passed on current frozen helper
sources: ordinary-user token scalars and same-user UAC original-user child launch.
SDK10.0.400 managed apphost, ordinary/elevated session1; exact input/output hashes
are in checkpoint84/windows/native-component-summary.json. This is not NativeAOT
package or MSI replacement evidence. The old unknown job remains unchanged.
Independent recovery review found a first-late-observation and publication race;
a second quick RED reproduces it, and the fix evaluates newer update state inside
the publication transform while always retaining unknown/live installation blocking.

| Task | Agent | Owned files/subsystem | Shared files reserved | Dependencies / environment | Current check / next handoff |
| --- | --- | --- | --- | --- | --- |
| Integration | root | Desktop lifecycle/cleanup fixes, evidence, docs, host builds and delivery | All shared files | One host Gradle invocation | Final focused union, prepush and checkpoint delivery |
| Windows MSI | root | Ignored native installer/evidence | No source edits | Owned Windows AMD64 guest6GiB on Arch | Public check/download READY; install accepted as09aa1b2b-94cc-4b64-a6ab-9908014d59c1; SSH restored, inspect original outcome |
| macOS | root; fixture_cert80 retired | Installed-package evidence reviewed | Root owns source | Owned Tart4GiB guest | Cleanup/repeated-owner, persistent duplicate and transient promotion pass; remaining GUI/traffic/rollback gates |
| Linux | root; linux_auth82 retired | Native evidence and harness fixes | Root owns source | Fedora2316 preserved; fresh Fedora2326 4GiB | Frozen RPM failure/recovery passes; current-package crash/quit, retry and attestation remain |
| Android | android_benchmark78 retired | Completed checkpoint78 evidence | No source edits | Remote2GiB API35 AVD5680 remains live | Native ARM64 comparison; remaining acceptance matrix |
| Review | serve_review79/mac_cleanup_review79 retired | Read-only bounded reviews complete | No edits | No VM ownership | Serve promotion retained; cleanup review has no blocking finding |

These are fresh bounded Terra/medium assignments. Earlier worker names below are
historical. The ignored checkpoint70 ownership record tracks current execution;
capacity measurements from September16 must not authorize new starts. Root restored
the normal Arch SSH hop on September20 using the authorized key passphrase, without
changing guest or installer state.

Root independently verified all22 exported Linux evidence hashes and the exact
protected-success/public-recovery tuple for job1984e6b7-b668-4ab4-95b4-a93af47f817e,
operation65da4189-d491-4343-956e-72e0a2347057. A distinct replacement owner recovered
the original request and installed2.1.13; see checkpoint70/Linux/root-review.json.
This proves the current DEB update/recovery, not transient startup or GUI traffic.

Linux worker74 reports current-source RPM success for job
5d3b32f1-fce3-438c-8701-5605dccc786d, operation
94bfa593-450f-4d5c-a9d3-26bfe79e4956, protected sequence4 SUCCEEDED/OK, and exact
replacement-owner recovery. A stale out-of-band fixture marker was preserved and
replaced with the exact frozen marker only after verifying installed base bytes.
Root verified42 exported text/state artifacts, the exact accepted/protected/recovered
tuple and seven CLI exits. The RPM binary remains remote with its manifest hash;
see checkpoint76/linux-rpm/root-review.json. GUI traffic and RPM failure/rollback
remain separate gates.

API35 public cancellation is confirmed for receipt
d8672b66-ca34-423f-9a02-58fa754db70f/session657342161. The separate observation124
failed with `Can't find service: packageinstaller`; it does **not** prove native
session disposal. Keep that check open. See
checkpoint70/android/cancellation-root-review.json. Independent cold-owner
confirmation redisplay and subsequent exact target installation are separately
reviewed in the existing checkpoint70 Android root-review records.

Windows code72 already contained complete successful nativeAMD64 builds after the
interruption. Root verified exported build records and independent guest MSI
hashes against the same-code pair receipt; checkpoint73/windows/root-review.json.
The later wrapper's existing-directory failure must not trigger another build.
Android target2.1.14 is at `/private/tmp/vpn-android-code73`; it reuses the exact
installed2.1.13 base bytes and compatible signer. Root verified both package
hashes and unchanged runtime bytes in checkpoint73/android/root-review.json.

macOS operation3d0f4c35-8184-431e-90c7-de57163f1402, job
33db51ee-dc08-4f6a-81c4-c37ae76a0a02 remains unknown after the VM stopped before a
confirmed cancellation. Earlier screenshot disappearance was not proof of Cancel:
the wallpaper gesture can hide the prompt. Root restarted the positively stopped
owned VM with detached logging and recovered the exact original tuple under a new
controller. The subsequent public `updates cancel` request exposed the bounded
response defect now covered by the new regression; no installer was replayed.

## Completed Code-First Integration Batch

The user requested completing all known implementation work before the next broad
native cycle. Finish source gaps in parallel, use cheap causal regressions while
coding, then freeze one coherent source/package set. Run complete platform scenario
batches against that freeze, collect independent failures, and fix them together.
Unknown accepted mutations remain preserved; discovery never authorizes replay or
unsafe overlapping installers. Existing native results retain their exact identities.

| Task | Owner | Exclusive source scope | Current check / next handoff |
| --- | --- | --- | --- |
| Android actions | android_code69 | Connection control; location service/ViewModel/UI callback binding and focused tests | Durable-selection response-loss fix passes15 tests; rendered benchmark target fix passes10 focused tests and Android compilation |
| Installer reconciliation | installer_code69 complete; root integration | DesktopInstallHandoff and tests | Prior worker diagnostics reset only on clean new admission;18 tests pass |
| Windows build paths | windows_execute68 complete; root review | Native Directory.Build.props and native helper tests | Canonical output paths; actual pinned-MSBuild evaluation passed, full package build deferred |
| Android fixture readiness | android_api35_68 complete; root integration | Android TLS preflight script/tests; ignored interactive driver | Exact selected ADB in child PATH before fixture/device mutation; real subprocess and early-admission coverage,29 tests pass |
| Documents/persistence | documents_code69 complete | Read-only document/spool/export/preferences audit | No established additional implementation defect; native gaps remain |
| Desktop GUI dispatch | desktop_gui_code69 complete | Desktop GUI commands/Main and HeadlessSession/ControlSupport with tests | Captured benchmark owner/revision checked in frontend and owner mutation lane;16 focused tests pass |
| Integration | root | Shared boundaries, docs, host Gradle, metadata and delivery | Batch review, final checks, then immutable artifacts and broad native pass |

Windows source audit70 found the previously listed production blockers already
closed: scoped broker factory binding, prepare-before-stop, captured CUSTOM inputs,
ordinary GUI/LIMITED autostart and original-user MSI recovery are wired. It found
no additional reachable source defect; native verification remains mandatory.
The known code batch is ready for integrated prepush after metadata. Android
focused counts are15 connection plus10 service/presentation; desktop installer18
and benchmark/session/capability16. Script suites pass29 Android and25 Windows
checks (one Windows-only check explicitly skipped on macOS, guest MSBuild probe
recorded separately). No new native scenario was started during this batch.

Independent review confirmed Android connection mutation admission remains held
through post-commit reconciliation; the proposed unrelated-revision interleaving
was retracted after tracing GUI, scheduled-refresh and service writer paths.
Do not treat missing-API tests or malformed manual probes as causal product REDs.

## September16 Current Operations

Gateway access is restored through ssh.karapsin.com:2228, then the authenticated
Arch hop socket /home/kardinal/.ssh/vpn-control-arch60.sock. The earlier failure
was pre-authentication reachability; no host VPN/network configuration was changed.

Ubuntu current-source DEB update/next-owner recovery passed (checkpoint60/linux-review).
A separate fresh Ubuntu installation now proves acquisition of absent xdg-utils,
with exactly two added packages and zero upgrades/removals. Root verified all18
raw file hashes, package inventories, APT output and empty dpkg audit in
checkpoint63/linux-fresh/root-review.json. The initial desktop-directory absence
and complete executed command transcript were not captured; status.exit is blank,
so its numeric exit is not certified. Both Ubuntu guests are stopped.

Arch public update reached protected sequence4 SUCCEEDED/OK for
job4c9e32b9-4bc2-4597-8f90-824766742dcd. Operation694afeb8-05b4-4aa6-bcf1-c182af76df10
recovered under a replacement owner with exact origin correlation; root checked
checkpoint61/linux-arch raw results. The earlier attempt reached a real terminal
polkit prompt without driver credential input, then was safely cancelled after
confirming no protected job/worker. A missing GUI agent was an incorrect diagnosis.
Arch2317 rollback is now independently verified in checkpoint68/linux-rollback/root-review.json: inotify captured original-to-backup, staged replacement, failed replacement removal and exact original restoration. Public next-owner status retained the failed job/operation identity. The guest is stopped and fixture cleanup is recorded.

Windows2314 remains the ordinary-user native package environment at6GiB. The
corrected-source build passed dependency resolution and reached native helpers.
Task-local tool discovery was repaired; an actual linker probe then isolated raw
parent-segment output paths exceeding the native path limit. Canonical output
paths and a real pinned-MSBuild regression are in this code batch. No MSI
acceptance is claimed; a new frozen package build follows source integration.

The macOS control53 guest is stopped after public off/quit and fixture cleanup.
Current corrected DMG base2.1.12 passed immediate GUI crash/reopen:32 forced proxy
traffic samples, zero failures, unchanged controller/runtime, replacement frontend
within1.45 seconds. Post-reopen hide/show was sampled; initial hide/show preceded
sampling. Root reviewed checkpoint62/macos-crash63/root-review.json. User-local
same-source update to2.1.13 recovered the exact successful receipt; root reviewed
checkpoint62/macos-update64/root-review.json. Explicit reconnect/GUI commands were
used, so automatic return intent is not certified. Full executed update harness
transcript is missing; individual outputs/correlations remain. Machine-owned
installation, rollback/interruption, actual close-button and visual gates remain.

API29 nondebuggable base-to-target installation now passed in owned emulator5656.
Exact installed target SHA441dbc8b67bff428b2bb19fdedfc9ff8543c8c9465dd56f0f77f34ce3f29246d
matches the frozen APK. Public status under replacement controller7a7724e7 reports
receipt85e5b6ba-ffd3-4124-9d78-4fd5eabe95c9/session357363557 installed=true and no
recovery unavailability. Root checked checkpoint66/android-install-recovery-root-review.json.
The earlier permission-denial operation was separately correlated through terminal
status/wait. Multiple explicit retries reused the same pending session after two
recorded driver mistakes (non-TTY EOF and a tap outside current dialog bounds).
The proposed API29 transport defect was retracted: malformed manual command grammar
caused its rejection; actual public transport succeeds. The packaged-CLI/Python
harness defect was fixed in d371254. Interactive drivers now have an explicit stdin
preflight before fixture mutation; isolated causal replay shows the unguarded driver
reaches fixture launch while the guarded driver rejects without creating output.
API35, deliberate process-loss cases, confirmation cancellation and remaining action,
traffic/document/visual gates remain open. API29 is stopped. Owned API35 emulator5658 is the only local VM/emulator,
configured at2GiB. It is idle before installer admission; native scenarios wait
for the combined source freeze.

## Delivery And Current Integration

Latest pushed checkpoint: `3f5715f30e5c9337b84b3377e18c850241b5e3ee`, version2.1.12.
All five exact-SHA required workflows succeeded; managed result:
checkpoint66/interactive-commit-result.json. Current code-first changes are not
covered by that receipt and require their own prepush, push and exact-SHA CI.

Corrected macOS pair source11efe6f8fe46bcbbde522111caf808250f3a24ff00d39bf80dcfa17fdf595780
matches794d01e (1499 snapshot entries checked); subsequent2c3aae9 changes tests/docs.
Both packages have identical code fingerprints, ARM helper minos11.0 and verified
bundle signatures. Base DMG SHA c0e402917d645299da7394efb1f4fad43ee356461d8cdaac7291d668abf4e130;
target DMG SHA9a188d037673a38f54f5fa025c0a95bdbcb2322ee5aa64d199855a535b14080a.
The earlier minos26 pair is retained but invalid for the macOS15 guest.

The checkpoint includes the frontend process-exit repair and managed visual VM
resource admission. The prior macOS CI failure was reproduced with software
rendering: cleanup returned but AWT threads kept the JVM alive. Explicit process
exit follows frontend teardown; fixed macOS workflow34820110381 passed. This is
separate from native installed-package lifecycle acceptance.

Root investigated fixture43's black screen on user request. Normal and recovery
boots failed; a clean clone with the same configuration booted. Firmware reset did
not help. Read-only APFS checking found zeroed object-map blocks and an unreadable
container keybag. Standard repair on a separate copy failed with exit8. The cause
of the corruption remains unknown; do not attribute it to RAM exhaustion without
evidence. Original firmware was restored and all disk attachments detached.
Original `vpn-control-machine-fixture43`, its full preserved backup
`vpn-control-machine-fixture43-before-repair53`, and the separate repair copy
`vpn-control-disk-repair53` remain stopped. Do not replay their unknown installers.
Replacement `vpn-control-boot-control53` boots macOS15.7.7/24G720, responds to guest
commands and shows Finder. Current-source user-local synchronous installation and
exact new-owner recovery now pass, both synchronous and asynchronous. Machine-owned
authorization denial and successful replacement/recovery also pass on the current
pair (checkpoint56/macos-machine). The runtime/GUI and rollback matrix remains open.
Evidence: checkpoint53/mac-boot-repair/recovery-result.json and fsck-repair-copy.log.

Keep at most one local4GiB macOS fixture and no local Android alongside it. Arch
may host additional Windows/Android/Linux guests after current capacity/access
checks. Historical September14 state follows; the September16 operations above supersede it. Root gracefully stopped
idle Arch2317 and Fedora2316 after checking absence of app/VPN/installer work;
Fedora's old loopback fixture server had no clients. Both QEMU processes exited;
disks, packages and receipts remain intact. Arch host has about12.7GiB available
and zero recent memory pressure; Windows2314 and Ubuntu2307 remain running.
Ubuntu old controller89494 was later reconciled off with terminal operations and
publicly quit; its workspace remains preserved. See checkpoint54/*poweroff.json and
resource-after-recovery.txt. Recheck capacity before any new guest or heavy build.
Managed visual admission covers configured allocations, live Tart discovery and
serialized reservations; direct shell/remote launches still need coordinator checks.

Committed atff8de90: Fedora package selection follows exact distribution ID then
ordered ID_LIKE, avoiding build-tool dpkg selecting DEB on Fedora. All11 focused
selection tests pass. Current-source RPM recovery subsequently passed; DEB and
Arch acceptance remain open.

Current integration:

- Direct visual preflight rejects stale primary-display statusbar geometry before
  device/output mutation. Normal reboot of owned5600 restored Pixel6/API35 geometry
  from cutout128/statusbar63 to128/128; screenshots still require fresh review.
- Shared installer handoff repair retains exact uncertain external jobs rather than
  implicitly cancelling after commit attempt. Explicit public cancellation remains
  supported. Three causal regression failures recorded before repair. This does
  not establish the exact cause of the earlier macOS native async cancellation.
- API35 SSH authentication/restart and payload52 management-SOCKS token transfer
  succeed. This proves the SSH payload chain, not all-app VPN/TUN traffic.
  Public cleanup restored stopped/default/empty state at revision44.

Evidence resides in checkpoint51: fedora-visual-{prepush,commit}-result.json,
ci-ff8-windows-failed.log, visual-python-crlf-{red,green}.log,
install-commit-boundary-{red,green2}.log and android-ssh-private/run/payload7-receipt.md.

One host Gradle operation at a time. Metadata/prepush must follow the last content
edit; no receipt from a prior content state is reusable. No release is authorized.

## Checkpoint52 Native Continuation

`3d70d75853dbd2ddb49731999547063d255f3633` passed full prepush and all five required exact-SHA workflows (checkpoint51/commit-geometry-commit-result.json). Its immutable
Linux/macOS pairs share source fingerprint
`729cbe42350b61e7d8a0bc46ecd63f6bd429dc37ae7c28da06d765a870084d6a`,
base2.1.11/target2.1.12. Source/runtime capture is host-only; native builds run
inside the owned guests. Local prepared copies were retired after both archives and guest transfers were hash-verified; retained `/private/tmp/vpn-{linux,macos}-pair-3d70d75.tar.gz` archives restore them. See prepared-copy-capacity-release.json.
Archive and transfer receipts are checkpoint51/{linux,macos}-pair-3d70d75-{archive,transfer}.json.
Fedora pair is `/home/vpnfixture/source-3d70d75/vpn-linux-pair-3d70d75`,
root supervisor40721 with durable root-build-result.json; linux_install52 now owns
that guest and public replacement gate. mac_install50 owns fixture43 and the new
verified archive `/private/tmp/vpn-macos-pair-3d70d75.tar.gz`. Prior unknown
installer jobs and failure evidence remain preserved.

The recaptured six Android scenes at build/visual-actual/android-installer-3d70d75
are rejected: SystemUI ANR overlay contaminated the frame despite geometry128/128.
WindowManager and DropBox show boot-time KeyguardService ANR amid high CPU load.
The normal Wait button dismissed it; no kill/reset. A debug-only primary-window
ANR guard has causal RED (3 tests,1failure, compilation passes) in
checkpoint51/android-anr-guard-red.log and GREEN in android-anr-guard-green.log.
The guarded recapture and six-scene review passed as recorded below.

Root reviewed payload52 raw replies/relay/target transcripts: complete token over
management SOCKS2081→SSH→selected location succeeds. This is bounded component
payload proof, not all-app TUN proof. Raw files under android-ssh-private/run/
payload52-*; public cleanup stopped/default/empty at revision44, temporary forward
removed. windows_login52 replaces the stopped Windows operator; credentials remain
private in the owned VM directory, and old login-input uncertainty must be inspected
before any repeat.

Current continuation evidence:

- Fedora RPM public replacement/recovery passed at the frozen3d70d75 source:
  installed2.1.12, job96630884-c147-4a4e-815b-eb0eb450ffa5, operation
  ffd7a8e1-8cb4-45fc-8b8a-ede9f66d2142, protectedSUCCEEDED/OK and replacement
  owner recovery matching the same correlation. Root independently read the public
  result and queried installed RPM. Guest raw evidence is
  /tmp/vpn-public-install-evidence-ugbgdqgr; freshDependencyEvidence remains null,
  so this does not certify the fresh-DEB dependency gate.
- Guarded Android capture completed and root opened all six complete frames:
  no clipping/ANR, legible state/action labels. Six new Android-only baselines were
  recorded and all six geometry/contrast/comparison checks passed. This is a subset
  baseline review, not full-platform or release attestation. Evidence:
  checkpoint51/android-installer-six-{scenes,review}.json, android-installer-six-verify.log,
  build/visual-actual/android-installer-guarded52. The capture includes the dirty
  debug-only ANR guard; final delivered-source attestation remains required.
- Remaining Windows Python CRLF scene arguments are normalized only at trusted text
  producers. An executable miniature fixture tests real wrapper/selector behavior
  and exact Gradle/stamp arguments. Binary framebuffer output remains unfiltered.

Windows ordinary-user preflight now passes on the previously installed2.1.10
(oldsource1b) nativeAMD64 package: help/version/capabilities exit0, missing-owner
status exit2/UNAVAILABLE without starting an owner. Exact interactive SID ends1000;
worker windows_login52 retained raw guest outputs and removed only its temporary
limited tasks. This clears guest login access, not current-source broker/MSI gates.

## Current Environment Ownership

| Task | Owner | Exclusive scope | Next evidence |
| --- | --- | --- | --- |
| Integration/delivery | Root | Shared source, docs, sole host Gradle | Windows frozen pair transfer; review native evidence and final delivery |
| Linux next package | linux_arch61 | Ubuntu2307 reconciliation, then owned Arch2317 only after slot handoff | DEB accepted; preserve artifacts before a graceful VM switch |
| Windows native build | windows_build60 | Windows2314 at6GiB | Python stage verified; reconcile failed interactive setup task before retry/build |
| macOS traffic | Root; capture workers complete | vpn-control-boot-control53 | Packaged proxy traffic through GUI attach/hide/close/crash; installer slice complete |
| Frontend crash recovery | frontend_crash60 | Visibility control, owner lease and constructor integration, focused tests | Causal RED captured; root reviews and runs GREEN before packaging |
| Android pair | Root | /private/tmp/vpn-android-pair-ae92601 | Both release APKs built and verified; no AVD running |
| Android native | Root; preparation worker complete | Local task AVDs remain stopped | Execute prepared API29/API35 scenarios after macOS releases local slot |

All source pairs use ae926016 product code. The Windows docs56 snapshot includes
the then-current WIP documentation delta and has its own fingerprint; subsequent
documentation edits do not modify any captured inputs. Completed workers have no ongoing write
ownership. Native operators may not start unrelated VMs or overwrite frozen stages.

## Checkpoint59 Stream Acceptance

Public Android streams already dispatch before the non-stream adapter. New desktop
transport tests exercise the actual ADB document client with a fake provider: log
tail/cursor propagation, owner replacement and post-submission loss. This is a
coverage addition, not a product defect repair. CLI-004 permits exit2 for both
unavailable transport and unknown outcomes; observation alone does not justify
changing that classification. Focused Android stream/ADB/document suites passed
37 tests with zero failures or skips. The initial new-test assertion incorrectly
expected exit2 for explicit CONFLICT; corrected to CLI-004 action-failure exit1.
No production change was necessary. API29/API35 installed tests remain required.

Root reviewed the executed sampler and verbatim installed-package captures under
checkpoint59/macos-output/guest/output59. JSON status/stats and human status/stats/logs
clients emitted output, then each exited naturally with130 when its output reader
closed; no TERM/KILL fallback occurred. Human output stayed on stderr. Forced SOCKS
token traffic succeeded before and after; controller/runtime, revision4 and all four
owned process identities remained unchanged. Review: checkpoint59/macos-output/root-review.json.
Checkpoint58 genuine captures also prove repeated JSON status/stats, logs limit0 and
real foreground-terminal Ctrl-C130. Earlier reconstructed checkpoint58 summaries are
explicitly not raw evidence and must not certify their unrecaptured claims.
GUI hide/close/crash and owner replacement remain untested in this native slice.
The host is still locked; preserve the live connection until GUI checks can resume.

## Checkpoint60 Native Progress

- Root reviewed the Linux protected success and exact original operation/job tuple
  under a distinct replacement controller: operatione53f848d-7fdc-41a1-afd6-c54414da0493,
  job3f9855f7-edf0-4be3-9fda-3968d916d06b, replacement86ffe18f-350c-4969-8648-b28acfa7e58c.
  Public target2.1.12 and dpkg2.1.12-1 agree. Raw result/summary and hash verification
  are under checkpoint60/linux-review. This closes current same-source DEB update
  recovery, not fresh dependency acquisition. The PTY wrapper hit end-of-stream EIO
  after durable child success; no installer was replayed.
- Installed macOS routing/location exports succeeded in private disconnected
  workspaces with Unicode/space paths, mode600 output and mode700 directories.
  Existing destinations were preserved; invalid output and JSON/raw combinations
  rejected. Both export types include timestamps, so separate invocations do not
  prove byte equality. Root reviewed the saved script and raw results. The first
  export archive contains an expired private owner token from an overbroad scan:
  keep it confidential/ignored and never publish it. Later captures avoid that scan.
- Proxy traffic passed561 requests across public hide/show and205 requests across
  the second deliberate frontend crash/reopen, with unchanged controller/runtime
  and revision4. Root inspected raw samples and exact admitted frontend PIDs.
  The first sampler expired before the first crash and does not certify that event.
  See checkpoint60/macos-lifecycle/root-review.json and saved scripts/raw captures.
- Immediate GUI_SHOW returned UNAVAILABLE twice after frontend-only crashes, while
  a later request succeeded after lease expiry. The causal quick regression records
  expectedOK/actualUNAVAILABLE before any product edit:
  checkpoint60/frontend-crash-causal-red.xml. Repair uses a read-only identity probe
  and exact stale-registration revocation; uncertain visibility actions must not
  replay. All24 focused tests now pass without skips. Independent review caught raw-OK
  identity acceptance and lease-expiry races; two causal failures preceded their
  corrections, and re-review found no remaining issue. Rebuilt installed-package
  retest remains open. Evidence: checkpoint60/frontend-final-green and
  frontend-review-causal-red.xml.

## Checkpoint55 Current Artifacts And Acceptance

- macOS pair at guest /private/tmp/vpn-macos-pair-ae92601 built successfully on
  macOS15.7.7 ARM64 with Temurin17.0.20.1. Base2.1.11 and target2.1.12 have identical
  code fingerprint4e10547a70bd27121fa8ac2bec715e9d98cdbb5a272256fdc2a41af59dc84bac.
  Source fingerprint3c89f3a5f543c5dad864fe9895c966251cda1bda6da1dd87d3bdf0c6b05471ac.
  DMG/package receipt: checkpoint54/macos-pair-ae92601-receipt.json.
- Installed user-local synchronous update passed from mounted base DMG through the
  public installed CLI. Job05a3b7df-96e4-47c6-8fed-e8b2126054f1, operation
  32897df4-2881-4d87-8600-d1e1c9a71f36 recovered under a new owner with the exact
  original tuple, succeeded/OK, installed=true and cleanupCode=OK. Target2.1.12
  reports runtime off. Root inspected/copied raw public results under
  checkpoint55/macos-userlocal. Async installation also passed: joba459debf-4920-412b-b540-a804d00d949c and operation
  a1f604f9-35ea-4849-9567-ee94e3c41e67 recovered the exact original tuple with
  installed=true/OK and cleanupCode=OK. Initial async acceptance legitimately had
  no job yet; the request was not replayed. Root inspected raw async wait/recovery.
  Fresh-state help/version/capabilities left state absent, and status returned
  UNAVAILABLE/exit2 without startup. Packaged ARM64 helper hash is in native-helper.json.
  These close those cases, not the whole Mac matrix.
- Linux ae92601 archive hash460de0b04408deb51b5dd26eb16fe440ea19f339843e1e047ddc6556a0584fdf
  is verified in Ubuntu. Ordinary GNU tar could not populate its read-only source
  directory; that failed tree is preserved. The existing tested
  extract_readonly_archive helper extracted a new source-ae92601 tree correctly.
  Both native builds now passed; all six DEB/RPM/Arch hashes and sizes match the
  receipt, and code fingerprints match a133e6c578f616259760f05cb54dbdc152fc958d3e14cc5788f11eaec88b90ef.
  Root reviewed checkpoint56/ubuntu-fixture-receipt.json and terminal output.
  After public off/terminal-state reconciliation and quit of the historical owner,
  the verified base DEB was installed by explicit fixture downgrade only: one
  package downgraded, no unrelated install/remove/upgrade. Public update is next.
- Android pair preparation includes the real tracked AAR/native inputs and excludes
  the runtime-source gitlink. Source fingerprint0877a6cae1ba2411666a4d2de5f38929f7354339f6eb3faa8d035039a13bb27d;
  base2.1.11/code16620 and target2.1.12/code16640. Root started sequential release
  builds with fixture signing, two workers and2GiB heap; both passed. Both APKs are
  nondebuggable ARM64 with matching signer a43b5330501b02f5558fa381c52e7f7dcdd9db362d6807d449d7bbb5e207c5a0.
  Base SHA d2a2575de17afe13974af08f6969ca9afb7364641d3a91dd0212fdeec520db5f;
  target SHA441dbc8b67bff428b2bb19fdedfc9ff8543c8c9465dd56f0f77f34ce3f29246d.
  The packaged native hash differs from the tracked input because the pinned NDK
  strips it; root independently reproduced that exact transformation and verified
  identical packaged bytes in both APKs. Receipt: checkpoint55/android-pair/receipt.json.
  Native API29/API35 use remains pending; older APK receipts below are not substituted.

Windows docs56 pair is prepared at /private/tmp/vpn-windows-pair-ae92601-docs56,
source fingerprint baf1a96a1c5c709286aadc169fa99210eaca855ca091753818d650cfef1c93cc.
Its archive SHA9941fcf905b058d4ffd72c7e0ec19f8d1b34fe1eb153252062868e1266eeb66f
is recorded in checkpoint56/windows-pair-preparation.json. It captures the verified
pinned1.13.4 AMD64 runtime; native packages have not yet been built. The first
Windows CI artifact download ended in a network read timeout; a separate retry
retains exact workflow34821933061 identity.

Current machine-owned macOS authorization denial returned terminal CANCELLED,
installed=false and preserved base2.1.11/off. Grant job85c05083-75ca-468a-939e-d1dd5fe19535
and operationc1359f99-4e9b-4585-afb4-d8f22d517116 recovered the exact origin tuple
under controller66a5ae1f-fe55-4ceb-b4f1-2ff3c2966a1f with installed=true/OK and
cleanupCode=OK. Root reviewed the raw envelopes in checkpoint56/macos-machine/raw.
Target2.1.12 signature/hash/root ownership passed; public quit and fixture/mount
cleanup passed. No runtime was started in this installer slice.

Android preparation at checkpoint56/android-next separates base no-update TLS
from target installation and preserves fixture trust through the full action.
The existing TLS and update fixture suites passed23 and8 tests respectively.
This is preparation, not current API29/API35 native acceptance.

## Historical Native Evidence And Its Limits

### Android

Frozen current-source pair uses fc82 product source, with only documentation changes
at build time and explicit test version overrides. Both are nondebuggable release
APKs with the compatible fixture signer, not production-signing certification:

- base2.3.11/code17420 SHA632d36233f69af3c689af77d4967c83ec491f3931baeacecf5469291a8310137
- target2.3.12/code17440 SHA63800963830d95d9db4b5937490aec1117e56a71858214f9d99164a4b785289e
- signer SHAa43b5330501b02f5558fa381c52e7f7dcdd9db362d6807d449d7bbb5e207c5a0

API29 AVD5594: current target, 48MiB heap-growth limit, 56,000-domain/11,536,164-byte
public import, same-owner readback and cold-process readback passed. Normal am kill
reclaimed PID4460; cold PID13689 and a new controller read the same semantic digest.
All read/import exits0. No root/run-as/force-stop/data clear or live VPN. The AVD
was shut down normally with data retained. Receipt:
checkpoint51/android-api29-current-20260914T0559Z/receipt.json.

API35 AVD5596: current base, 192MiB heap-growth limit (not48MiB), 56,008-domain /
12,488,469-byte import and retained result, normal process reclamation, cold
readback, private0600 export, no-overwrite failure and identical no-op import
passed. No-op retained the cold owner's revision0. Existing-output export returned
PERSISTENCE_FAILED/exit1 and preserved its digest. Cleanup restored empty routing
and stopped runtime. Receipt:
checkpoint51/android-pair/current-base-cold-document-receipt.md.

Earlier source33e2 fixture evidence remains useful but is not current-package proof:
real HTTPS benchmark1289ms; accepted cancellation bdfc03ea-c549-43fd-82ac-242fc9a4b891
preserving exact activeA/runtime and pendingB; successful retained diagnostics
export to a private path. Prior export rejection came from a0777 writable ancestor,
not rejection of ordinary0755 directories. See checkpoint49/android and
checkpoint50/android plus android-diagnostics/receipt.md.

Fixture trust provisioning and public app control are separate scopes. CLI-001
requires nondebuggable app control without root; it does not forbid the explicitly
authorized disposable guest-only CA setup. The existing driver copies certificates
to newly created staging, relabels only that staging, temporarily mounts it into
the guest zygote namespace and restores UID2000 before the public action. It does
not rewrite original system certificate files, SELinux policy or host trust. Keep
setup/cleanup privilege explicit in evidence, verify every actual public action
uses UID2000 without run-as, and require exact mount/proxy/forward cleanup. This
corrects the earlier tracker interpretation that treated all fixture provisioning
as forbidden. Historical receipts still cannot certify current APKs or unrecorded
public caller identity; run current API29/API35 scenarios with complete evidence.

### Linux

Fedora2316 exactbbb RPM SHA
ed6e8f912d83871437514fd695c73024019840ae893fe30a32f0d36c42bab12c:
installation, immediate GUI close/reopen1.3435s and token traffic through attach,
close, reattach and crash passed. Runtime identity remained stable; off/quit
cleanup passed. This does not prove crash re-open or current-source update recovery.
Root reviewed checkpoint50/Linux/summary.json and retained guest receipt.

New fc82 pair source fingerprint
65378a4ad1d4951020d0e059ab73bebdac91fa1bb53b8303b3587525e2961635;
pinned Linux runtime1.13.4 SHA
fdf44dd63aa9d04668f37629067aa6bd008e04b993dd3825ea829f17919af765.
Guest Temurin17 and binutils are installed. Current pair path:
/home/vpnfixture/fc82-linux-pair-retry3; build PID31868 / Gradle child31888 were
verified live, then terminated with packageDeb rejecting unsupported DEB because
dpkg-deb/fakeroot/rpmbuild were absent. Guest-only dependencies are now installed;
retry3 evidence remains intact. The new immutable retry4 produced base2.1.10/target2.1.11 DEB/RPM/Arch artifacts
and a fixture receipt. Installing an already-present2.1.10 was a package-manager
no-op, leaving old source inputs; exact frozen-base reinstall is assigned before
public target recovery. No source identity guard is weakened.

The first build failed because objcopy was absent. A second attempt correctly
rejected existing immutable stage outputs. A worker then improperly removed the
old pair directory; its contained base-build log/stage was lost, while the outer
failure logs survived. No packages or final receipt had existed. Preserve all
remaining records and do not repeat that cleanup pattern.

### Windows

Owned nativeAMD64 Windows guest:
/home/kardinal/vpn-control-windows-msi-native-20260907 on Arch. Manual MSI from
source1b, version2.1.10, SHA
1c16fa37459ff95a784c205275e889234d0896dbbc1fa1347ed9b3f1873f7aee replaced the prior
2.1.9 launcher in place. Installer exit0, engine exit0 and ordinary-user public CLI
version2.1.10/exit0 passed. Actual launcher is under parityagent LocalAppData.
Remote checkpoint50-manual-msi-receipt.txt SHA
f143f6ec821287059fa0c0743fe04072f908e250e1bed96958b485d38162461b.
This is manual installed-package proof, not public update-adapter recovery.
Later read-only reconciliation found SYSTEM msiexec8744 absent; its original outcome
remains unknown. Preserve the related historical records.

Ordinary InteractiveToken/LeastPrivilege static and missing-owner checks passed
on that older installed package. Current-source lifecycle and runtime evidence
remain required; the earlier package cannot certify the new source.

Local ARM64 guest / AMD64-emulation component evidence remains separate: scoped
broker/TUN and UAC denial preserved traffic; original-user bootstrap fixture ran
three tests with no skips/failures. Current-package/nativeAMD64 broker and full
MSI adapter scenarios remain required. The production factory already enables the
scoped broker on eligible Windows processes; preflight is read-only and UAC occurs
at explicit VPN preparation. Old HIGHEST autostart migration is active: it checks
owned XML under a local lock, rechecks, then lowers run level with schtasks /Change
and validates the result. It does not delete/recreate the task. Native DACL,
foreign-task rejection and reboot evidence remain open. Task Scheduler offers no
atomic compare-and-swap against a concurrently replaced same-name task; repeated
reads do not prove such a guarantee. Preserve this limitation without inventing a
new privileged service or disabling requested migration as an interim substitute.

### macOS

Tart fixture43 uses the clean fc82-compatible base2.1.10/target2.1.11 pair at
/private/tmp/vpn-control-macos-pair-bbb7b046, identical executable fingerprint
bfb60629266d1050c2f66e44746112d3cfaf7f638f04ec4183670e0f7daeac0a.
Base DMG SHA23d0fe05cd764fc8c8c49f8a35d3f73702c27df1fe230b25a44c9b2251b24dfa;
target SHAb73cd188fbd2b0d4c01126355bceedb603796697943baf18d4a21179f97f7cd7.

Account access is resolved. Creation records showed the original Tart image
credential authenticated at setup; it again worked through SSH and normal guest
UI. The separately generated VNC password is not the account password. No user
credential or account reset is required.

Public check/download succeeded, followed by actual authorization of job
2958cf24-59fc-45ae-8c39-60f1b785b093, operation
c9e66967-1282-4a9f-a8e3-d1179f8ca7e3. Native copyfile logged output EIO before any
rename. Protected status.json directly confirms FAILED/PERSISTENCE_FAILED seq1;
installed remains unknown. Original app and protected receipt/correlation survive;
terminal input cleanup removed only inputs. The partial stage remains under
/Applications/.vpn-control-stage-2958cf24-59fc-45ae-8c39-60f1b785b093.app.
Underlying I/O cause is unproven; do not infer host capacity as its cause.
Receipt checkpoint50/macos/receipt.json retains the native log and identities.
Older job49a33fcf-cecd-4d19-a233-47b6cc1dcf69 and its base remain untouched.

The fresh machine-install retry is now successful on the frozen fc82-compatible
pair: job9d328c5c-3bc8-4da5-9b91-6f6ee7e6e14f, operation
57b93ace-d01a-468d-a7ff-98659d09ecfb. Protected receipt seq4 is SUCCEEDED/OK;
public target recovery reports installed=true and cleanupCode=OK. Target2.1.11
main JAR SHA86425c0aa6d970798410bd631de5124f20651bf6adda41ca835980b62af70ef4
matches the frozen target. Root copied and hash-verified summary and three raw
public responses under checkpoint51/macos-success; summary SHA
2109ccbcf2fd923292d2ea91122b9b6f375a36c4bc41aaac5b19a39736cafb9d.
No stage/backup remains for this successful job. Old failed and unknown evidence
remains. Guest-only Tart Automation permission was test setup, not a product
requirement. This closes this machine replacement/recovery scenario, not local
installation, denial, rollback, GUI-return or final-delivered-helper coverage.

## Capacity And Artifact Preservation

Verified lossless offload restored10,826,780KiB host free space. Three additional
cold evidence trees (checkpoint26 macOS host source, checkpoint30 Android pair,
checkpoint33 macOS archive) were archived remotely and verified before local
relocation. Restore pointers remain. See checkpoint50/capacity/RECONCILE_RESTORE.md
and earlier RESTORE.md. Current APK/DMG pairs, VM disks, failed/unknown installer
records and required JDK/runtime inputs were preserved. Serialize host builds and
reserve headroom for VM sparse-disk growth; a single free-space observation is not
proof of sufficient peak capacity.

## Remaining Implementation And Acceptance

1. Windows public MSI update and original-user/elevated/different-approver recovery,
   protected receipt/lock handling and current nativeAMD64 public lifecycle.
2. Current-package Windows broker/configuration coverage, denial preserving activeA
   and pendingB, TUN/child cleanup, ordinary GUI/autostart and safe legacy migration.
3. Finish remaining RPM failure cases and final-source package revalidation. Fresh
   DEB dependency acquisition and exact Arch replacement/rollback are proven in
   checkpoint63 and checkpoint68 respectively. macOS machine rollback, interrupted recovery
   and automatic GUI return remain open; user-local rollback/recovery now passes
   on the checkpoint105 frozen pair.
   Current ae926016 user-local synchronous/asynchronous and machine grant/denial
   recovery are proven above;
   the3d RPM success and earlier Mac machine success apply only to their artifacts.
4. Android API29/API35 action/SSH/refresh/consent/foreground-service/process-loss and
   installer permission/cancel/corruption/retention/reconciliation matrix.
5. Remaining document expiry/principal/owner/hash/interruption/resource/persistence
   failures and GUI/private export paths; cold-read success does not close these.
6. All desktop one-owner/traffic lifecycle and scheduled-refresh scenarios through
   installed launchers, including missing-owner and transient-owner behavior.
7. GUI-versus-CLI effect comparison and remaining changed-scene capture/review.
   Six Android installer baselines passed local review and checks; their delivered
   source attestation and the broader platform inventory remain open.
8. Final metadata, full current prepush, reviewed commits/push and all five required
   workflows for the exact SHA; match final packaged evidence to delivered inputs.

Do not label skipped native checks, component-only tests, older launchers with new
JARs, mounted images or in-progress jobs as full installed-package acceptance.

Checkpoint97 Android shell preflight now proves fast and stalled SOCKS replies
through an owned ADB reverse mapping, using device127.0.0.1. The earlier probe
used nc -q1 and could end after stdin EOF before proving a handshake; it did not
prove a broken reverse route. Exact runnable probe scripts and a self-excluding
manifest are retained in checkpoint97/android-endpoint-preflight. A single
subsequent cancellation attempt is assigned to android_cancel97 with frozen
fixture copies; no result is claimed yet.

Checkpoint98 Android cancellation is now proven on the frozen nondebuggable
API35 ARM64 APK through the public legacy provider: operation
178ed42b-f3d8-4281-9c00-167930ffc2ac was accepted nonfinal, produced a new
benchmark-side stalled SOCKS event, then cancelled and waited as CANCELLED.
The relay stayed owned by one persistent Python context throughout. Cleanup
leaves revision22, only CP89, runtime OFF/unselected, no owned reverse or relay,
and all10 transfers discarded. Root verified its evidence manifest. This does
not certify the default desktop CLI document transport or API29 cancellation.

Checkpoint98 source freeze: scheduled/manual refresh outcome regressions retain
causal RED XML/logs and the70-test GREEN selection in checkpoint98. Final narrow
independent review found no blocking concern. Python focused selections pass:
provider11, SOCKS14, combined HTTPS/relay4, benchmark/probe10. Full pre-push,
metadata and a new checkpoint push remain required.

Windows CP95 base installation completed through the ordinary parity95 desktop
with MSI exit0 and the expected per-user directory. Original installer process
10172 is terminal; the Windows Installer service process1952 remains owned by
Windows and is preserved. The immutable same-source fixture and reviewed base
launcher were verified by hash/ACL. This is base installation, not public update
replacement or next-owner recovery. Evidence: checkpoint95/windows-fresh/base97-result.json.
