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

## Delivery And Current Integration

Last fully verified checkpoint is `3d70d75853dbd2ddb49731999547063d255f3633`: full prepush and all five exact-SHA workflows passed.
Next checkpoint `651847730584aade13feca8bc2dd16aed1ec97db` is pushed: full local
prepush and four required workflows passed; macOS failed a frontend-exit test. It contains the ANR
guard, scene-argument CRLF regression and six reviewed Android installer baselines.
Evidence: checkpoint53/visual-{prepush,commit}-result.json and ci-macos-65184773-failed.log.
The failure is reproduced locally with software rendering: cleanup and the runner
returned, but AWT threads kept the frontend JVM alive. The current dirty product
boundary explicitly exits only after teardown; three focused tests pass with no
skips. See compose-exit-diagnostic-software-red.xml and compose-exit-process-green.xml.

Current dirty work also adds managed visual VM admission with configured guest
memory, live Tart discovery, a one-guest default, capacity estimates and serialized
reservations.86 focused tests pass; direct shell/remote launcher enforcement remains
outside this slice. Host RAM exhaustion was reported by the user, who authorized
using Arch for additional Windows/Android/Linux VMs. Gateway public-key access now
requires the appropriate key; the question is pending. Keep at most one local4GiB
macOS fixture and no local Android emulator alongside it.
The pushed `ff8de90ef22fd7015ceff9620389aae56c545900` (version2.1.11) passed
full local prepush but Windows CI failed in the executable visual guard test.
Its richer diagnostics exposed a retained CR in the emulator serial emitted by
native Windows Python. The subsequent3d70d75 checkpoint fixed this and passed
all five workflows. The current uncommitted extension covers scene arguments;
all69 focused visual tests pass. It still needs its own prepush and exact-SHA CI.

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
| Integration/delivery | Root | Shared source, scenes.json, docs, sole host Gradle | Final review, metadata, full prepush, push and exact-SHA CI |
| Linux review | linux_remaining53 | Read-only Arch/DEB state and harness audit | Reconcile durable receipts; resolve fresh-DEB fixture preconditions |
| Windows review | windows_remaining53 | Read-only native AMD64 guest/evidence | Reconcile portable build prerequisites and remaining broker/MSI gates |
| macOS review | mac_remaining53 | Read-only Tart fixture43/evidence | Reconcile cache transfer/build handles before any retry |
| Android API35 | Root | AVD5596; no current worker operation | Remaining native traffic/actions/installer matrix |
| Android visuals | Root | AVD5600, guarded captures and six baselines | Reviewed subset awaiting validated checkpoint |

Prior worker handles are no longer live in this coordinator's agent inventory.
Fresh bounded read-only reviewers are recovering authoritative process state;
missing worker handles do not imply guest operations have stopped.

## Current Native Evidence And Its Limits

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

Local HTTPS update-fixture trust remains unresolved under the non-root requirement.
Do not reuse historical privileged CA bindmount setup as compliant evidence.

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
Preserve unidentified SYSTEM msiexec8744 until authoritative reconciliation.

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
3. Current-source DEB/Arch install/update/recovery/rollback and remaining RPM failure
   cases; macOS new-source asynchronous recovery, denial, rollback and GUI return.
   The3d RPM success and earlier macOS local/machine synchronous success are proven
   only for their recorded artifacts.
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
