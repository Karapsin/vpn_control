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

## September16 Current Operations

Gateway access is restored through ssh.karapsin.com:2228, then the authenticated
Arch hop socket /home/kardinal/.ssh/vpn-control-arch60.sock. Ubuntu's current-source
DEB update and exact next-owner receipt recovery passed; root independently reviewed
checkpoint60/linux-review. Fresh missing-dependency installation is a separate open
gate. Its owner was publicly quit, task-local TLS resources cleaned, and guest
powered off before starting Arch2317 at4GiB. Windows2314 remains reserved at6GiB;
Fedora2316 stays stopped. Recheck actual memory before any additional guest.

Arch's first public update reached a real terminal polkit prompt. The driver did
not supply a credential; the client reported unknown outcome. A missing GUI agent
was an incorrect initial diagnosis, disproved by the retained prompt and packaged
terminal adapter. The owner operation was subsequently reconciled with public
cancellation after confirming no protected job/worker. Installed version remains
2.1.11. A distinct interactive attempt succeeded: job4c9e32b9-4bc2-4597-8f90-824766742dcd
reached protected sequence4 SUCCEEDED/OK, and operation694afeb8-05b4-4aa6-bcf1-c182af76df10
recovered under a replacement owner with exact origin correlation. Runtime stayed
off and public quit completed. Root raw-evidence review is in progress; induced
rollback remains open. Preserve checkpoint61/linux-arch raw evidence and original correlation.

Windows now has verified Python3.13.15 alongside JDK17, .NET10.0.400 and WiX3.11.2.
Its ordinary-user corrected-source build wrapper failed before extraction/Gradle;
causal wrapper diagnostics are in progress. No Windows package acceptance is claimed.

The local macOS control53 VM remains running with the controlled proxy fixture.
The Tart guest-agent transport failed during a JDK transfer; screenshots still show
the app. Task-only SSH access was recovered; the guest-agent control transport remains
unavailable after restarting only its daemon. Guest/runtime processes were preserved. One local4GiB VM only;
do not start Android alongside it. CUA pointer actions remain unavailable, so the
actual guest close-button case is not certified.

Corrected macOS/Windows snapshots have fingerprint
2ad8dcdd49f7f43c28bea04fdf679c05b52451806b734ae4337093b2dc60830e.
Root compared all1498 snapshot entries to delivered26bba9f; the excluded submodule
was compared by gitlink. See checkpoint61/source-equivalence.json. The macOS
base2.1.12/target2.1.13 packages built with a vendor-checksummed Temurin17 JDK,
matching code fingerprints and verified bundle signatures. Inspection found the
native helper defaults to this host's macOS26 minimum; guest15 acceptance must wait
for the tested deployment-target correction (ARM11.0, Intel10.13) and a new
immutable package snapshot.
These packages are build evidence only, not native installation evidence.

| Task | Owner | Exclusive scope | Current check / next handoff |
| --- | --- | --- | --- |
| Delivery | root | Shared integration, docs, metadata, host Gradle, push/CI | 26bba9f exact-SHA CI pending |
| Windows pair | windows_pair61 | Windows2314 fixture/task wrapper, native packages | Capture pre-extraction exception, ordinary-user build |
| Linux Arch | linux_arch61 | Arch2317 fixture/public installer | Terminal credential setup, distinct authorized attempt |
| Mac access | root (worker complete) | control53 SSH / native acceptance | Task-only SSH restored; preserve live fixture |
| Mac target | root (worker complete) | Native helper preparation and focused regression | Causal RED/green reviewed; rebuild and guest acceptance next |

## Delivery And Current Integration

Latest pushed checkpoint: `26bba9f56d5e17661aced80652dcdd497ffde256`, version2.1.11
with seven Unreleased bullets. Full managed prepush passed; all five exact-SHA
workflows are pending verification. The frontend crash recovery fix is included.
Last fully verified checkpoint: `9c2e13eed434423771f0bc0d5c3daea84d9abba1`, version2.1.11
with six Unreleased bullets. Full managed prepush and all five required exact-SHA
workflows passed. Receipt: checkpoint59/commit-result.json. Frozen native pairs
still use ae926016 product code; this checkpoint changes tests and documentation. The
Windows stop-routing test correction is included; its full simulated missing-fcntl
suite77/77 and normal focused suite86/86 passed. Prior c0955b7 Windows failure is
retained at checkpoint53/ci-windows-c0955b7-failed.log.

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
3. Fresh DEB dependency installation, current-source Arch install/update/recovery/rollback and remaining RPM failure
   cases; macOS rollback, interrupted recovery and GUI return.
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
