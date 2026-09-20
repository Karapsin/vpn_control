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
   checkpoint63 and checkpoint68 respectively. macOS rollback, interrupted recovery
   and automatic GUI return remain open.
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
