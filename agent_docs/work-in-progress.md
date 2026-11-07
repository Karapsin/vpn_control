# Windows GUI/CLI parity: current ledger

This section is the one current parity ledger. Everything below it is retained
history. Scope is Windows, the user's last parity decision (2026-10-19). Linux,
Android and macOS native and visual work stay deferred and open, never passed.

## State (2026-11-07)

- Source: the paused checkout's parity commit `a9aed701` is merged into `dev` on
  top of `17587717`, with the paused worktree's reviewed paths ported byte for byte.
- User decisions: commit the merge once tests are green, push to `origin/dev`
  early, and use the existing `scenario-start` family with a closed list of Windows
  scenario names, a Windows adapter and one closed action to approve or deny one
  reviewed UAC prompt. There is no new generic executor. The newer private
  composition (`final-freeze-v3`, 598 paths) was reviewed: 22 paths are taken,
  most of them adapted, in a later commit, and the rest is reported to the user.
- Fixture: clone `34e354eb` of image `637199a5` runs, qualified and secured, with
  no alias, screen profiles or lease and job namespaces. It is enrolled only
  after the sources settle.
- Product acceptance: 0 of 22 matrix rows pass and the app is on no fixture. Old
  receipts in the paused checkout are not current. The ported scenario tools have
  never run natively, and no tracked code launches them yet.
- Private evidence root: `.runtime/windows-parity-20261107/`.

## Remaining, in order

1. Prove the merge's regressions on Python 3.14 and 3.12, commit and push. The full
   managed pre-push cannot finish on this Mac, so exact-SHA CI is its first
   complete check.
2. Add the taken tools, the tracked launcher, the Windows `scenario-start` adapter
   and the closed UAC action. Fix the tool defects the review predicted, each with
   RED and GREEN when it is proven.
3. Build the same-source package pair, enroll the fixture and re-prove status,
   display wake, lease and counter, direct and then MCP. By user decision, all
   scenarios run in sequence on one VM, updates may chain on it, and sign-in and
   reboot come last. The first sign-in freezes the sign-in source, so waiting
   keeps source fixes cheap.
4. Run each Windows scenario direct and then through its MCP route:
   `windows-native-cli` (15), `windows-installer-lifecycle` (8),
   `windows-scoped-vpn` (10), `windows-owner-lifecycle` (12), the 16
   Windows-applicable `document-persistence-transfer` scenarios, and
   `windows-visual` (3) with all 58 Windows scenes opened and reviewed.
5. Requalify the final source and verify `final-dev-ci` and the five exact-SHA
   workflows.

# Native tool recovery and retained parity history

## Handoff (2026-11-07)

`dev` in this checkout is clean and three local commits ahead of `origin/dev`:
the Windows lane, the 2026-11-05 checkpoint and the 2026-11-06 Windows native
tools. None is pushed and no workflow run covers them. The next task the user
named is finishing GUI/CLI parity.

Most of that work is not in this checkout. The paused
`/Users/karapsin_de/projects/vpn_control` checkout, left untouched, holds it:

- Local commit `a9aed701` on `d24c1904` changes 275 paths, 191 of them absent here.
  It includes the public `source set subscription` fix in `DesktopCli.kt` and
  `DesktopControlMutations.kt` with `DesktopCliSourceModeParityTest`.
- On top are 10 modified and 183 untracked paths, including the updater, lifecycle,
  document and TUN scenario tools and their fixtures.
- The parity ledger is the top of its `agent_docs/work-in-progress.md`, with matrix
  receipts under `.rag_index/native-acceptance` and private evidence under
  `.runtime/windows-parity-20261019/`.

At its last record the app was not installed on any fixture, and all 64 Windows
installed-package memberships and all 58 Windows visual scenes were open. The
user's last parity scope decision, on 2026-10-19, is Windows, with Linux, Android
and macOS native and visual work deferred.

## Earlier handoff (2026-11-05)

The Windows lane commit described below is followed by a local work-in-progress
checkpoint commit of every other lane that was uncommitted on 2026-11-05: Android,
Tart macOS, Windows sign-in, idle and sleep tools, scripts, fixtures and test
enrollment. The checkpoint was committed as found, without separate review or
native qualification, so its lanes keep the open items recorded below. Its next
task, the Windows sleep and related tools, finished as described next.

## Windows native tools (2026-11-06)

This round is committed locally and not pushed. The
Windows sleep route, idle proof, protected sign-in and unlock, display wake,
leases, finite counter and `readiness-reboot` pass natively on clone `246a3304`,
direct first and then through MCP and the CLI on the same sources. That clone was
then stopped by `windows-vm-deploy-stop`, a public blank start and stop passed, and
new clone `34e354eb` of image `637199a5` is running, qualified and secured, with no
alias, screen profiles, or lease and job namespaces yet. Results, failure types and
limits are in the [recovery ledger](tool-recovery-ledger.md); exact private handles
are at the top of `.runtime/tool-recovery/CONTINUATION.md`.

Fixtures now take no unexpected updates, by user decision:
`windows_vm_unattend.UPDATE_POLICY`. Sign-in source is frozen on a clone after its
first real submit, so finish edits to the remote packet, instance, guest session
and embedded login source before that; afterwards use a new clone.

Open: S3 itself cannot run on this guest, which refuses it. The libvirt provider
was not run. Android and macOS stay deferred and R1 and R2 stay rejected. Delivery
still needs the user's push decision, then exact-SHA CI; the full managed pre-push
cannot finish on this Mac.

Same-disk restart has no public route: `windows-vm-deploy-stop` is a hard quit, and a
stopped clone can only be replaced. `powerdown_program`, `existing_start_program`,
`start_observation_program` and `readiness_windows_managed_start.dispatch_program`
have no public caller. Known gaps from the 2026-11-06 reading, none attempted:

1. No route or capability reaches them.
2. A durable powerdown refuses itself: its namespace under the VM root makes idle
   visibility false, and enrolling it also blocks a later reboot.
3. A restarted actor is invisible: the actor identity reads only `qemu-started.json`,
   so lineage, status and the reservation observer report it stopped.
4. A clean stop's terminal lacks `state=submitted`, and an `existing-start` intent is
   an unclassified receipt.
5. Storage: `start` never claims it, while the existing-disk start needs a retained
   claim, and no Windows route settles a pending one.
6. `observe` needs the QMP socket that an existing-disk start requires to be absent.
7. A restarted VM would count against two reservation rows.

## Windows tool-recovery lane (committed 2026-11-05)

At the user's request the Windows tool-recovery lane was committed locally on
`dev` on 2026-11-05 (parent `2efd2569`, not pushed). It holds the nested SSH
transport fix for gateway and local reboots (`test_ssh_gateway_reboot_ended`)
and reusable generalized Windows fixture images: `windows_vm_image.py` with the
`create`, `generalize`, `capture_image`, `images`, `retire_images`,
`disk_logs`, `vm_inventory` and `vm_cleanup` API. Image schema 6 runs sysprep in
the built-in Administrator's elevated interactive session; clone `246a3304`
qualified natively and is left running as the Windows fixture. The commit also
holds routine RED/GREEN regressions for the clone failures F3 to F3e
(`test_windows_vm_image_failures`), the closed reason of unverified deploy
replies (F6a), executable-based VM process detection (F6b), the strict
fixture-home prefix of `vm_cleanup`, the Windows stale-registration projection
(F1), dispatch review of the shipped image module, the private-output harness
fixes, and the 2026-10-28 conservative Windows capacity policy that every
image-round start used. By user decision the creator pre-VM writer `7e8b2dcd`
keeps its frozen source pins and now refuses `source_epoch_changed`. Failure
types, regressions and native limits are in the
[recovery ledger](tool-recovery-ledger.md); original evidence is indexed by
`.runtime/tool-recovery/windows-lane-20261103/handoff.json`.

Open: push and exact-SHA CI were not requested. Native acceptance is still
owed: a `vm_inventory` while clone `246a3304` runs must list its QEMU and
swtpm. The F6a trigger is unresolved; read the next occurrence's `reason` and
`capture`. The F3d guest-side guard has native evidence only. Follow-ups: the
deploy policy's `no_tpm` check matches exact executable names, so a replaced
`swtpm (deleted)` passes it, and Linux, Android and libvirt helpers still
detect VMs by `argv` or `comm` only. Superseded image `0a762488` (holder
unknown) and the failed clone roots `vc-rw-f7619b39` and `vc-rw-ee0d45b1`
wait for `vm_cleanup` or `retire_images` while no VM runs.

## Native tool follow-up (2026-10-28, active)

Continue in `/Users/karapsin_de/projects/vpn_control_tool_recovery` on `dev`.
On 2026-11-05 the user moved `dev` off the verified checkpoint
`2efd2569ce39d86a991b32f68d8e89419360ac5c` with the two local commits above, so
the single already-built Android target APK update must be re-qualified against
the new HEAD before it is collected. The user explicitly
authorized the original Android lease closure and one real PackageInstaller update,
the same persisted Tart macOS restart, and the existing raw QEMU and libvirt Windows
protected sign-in, idle and lifecycle tool verification. Earlier "Windows explanation
only" and pending-approval notes are historical and superseded by this scope.

Intentional source buckets are Android-scoped durable successor/qualified filesystem
continuity and installer orchestration, the Tart renderer and provider qualification,
Windows qualified protected-input/idle/lifecycle adapters, causal regression fixtures,
portable checks under `scripts/`, and affected-test/byte-custody enrollment. Each subsystem has one implementation
owner; the coordinator owns enrollment, documentation, checks and delivery. Shared
source changes require renewed source qualification of affected native scenarios.

Full VPN Control product acceptance, VPN connectivity/reconnect acceptance, product
UI/visual review and the wider installer matrix are **skipped by user instruction**.
The Android update remains required to verify installer orchestration. Mandatory
managed pre-push checks and all five exact-SHA development workflows remain required.
Do not replay UNKNOWN operations, stop the user's VPN/gateway, restart retired Linux,
alter unrelated Virtualization.framework PID 25339, or reuse an old UNKNOWN history for a new effect.
Run at most one actual local test VM. Tart starts only after actual disk, memory and
reservation admission passes; its prior stop cause remains `off_unknown`.
Following the user's latest fresh-VM steering, prepare new remote Windows
fixtures for the positive tool scenarios while preserving the old fixtures and
UNKNOWN histories. Qualify trusted clean assets, account/custody and normal
capacity first; coordinate host mutations with the Android owner and use one
fresh Windows fixture at a time. Full product acceptance remains deferred.

Current original-operation receipts and finite progress are kept under ignored
`.runtime/tool-recovery/native-followup-20261027/`; original evidence remains at
`.runtime/tool-recovery/native-approvals-20261027/` and the single APK's original
`android-head-target-1f2025d9-8e2d-4d2d-8919-f9a785bdf7a7` directory. The
[infrastructure ledger](tool-recovery-ledger.md) retains historical outcome limits.

Android starts `0e75d7ee` and `0ed4b592` are positively closed before any VM fork. The
distinct current1e15 closing-reader correction and original-root collector are
promoted: actual Linux child control `6caaeb65` and fixed-helper collection gate
`a3383cc8` passed with complete original output and child closure. Same-AVD boot,
lease closure and the update remain open. The distinct current-authority template
is promoted after full closing-predicate review and 25 causal controls; it remains
unsealed pending genuine new-boot/native evidence. The latter start refused an
ordinary process's transition to an empty-command zombie. Its failed interval
and original UNKNOWN result remain immutable. A separately reviewed local cleanup
reaped its observer and released all three coordinator locks. Explicit factory
`1c732a53` is promoted after three real owned Linux controls: the old refusal,
two complete terminal identities, and two directory-absence witnesses. Each
retains its original UNKNOWN interval and requires a new whole-host observation.
Observer `ab09df50` has routine real-lock and fresh-context coverage. A test's
incorrect default selector was separately reproduced and fixed with actual
unset-environment RED/GREEN; final combined checks are being refreshed. The
new boot-only recipe remains unbound pending fresh admission. Tart remains off:
latest available memory is 5,790 MiB against 6,144 required despite normal pressure.
Fresh Windows blank-install plans and read-only media/capacity preflights are
prepared under the latest steering. The normal caller capacity mismatch is fixed
while preserving the raw census, every held claim and all old UNKNOWNs. New
source-qualified allocation getter and ordinary/root bridge proofs passed. Fresh
raw Windows fixture `62b489bc` has started once under positive source/terminal
closure, retaining all old claims plus its own 4 GiB. Windows installation,
guest-agent readiness and the ordinary-user session are positively qualified.
Exact new-actor storage registration and a fresh 46 GiB allocation proof passed.
Protected administrator setup `d546cbd2` passed with fresh exact account/boot
checks, protected credential verification, source closure and setup cleanup.
Canonical display wake, lease expiry/restoration and cancellation/restoration
passed. Counter `ee9a19ba` reached terminal with 80 steps and one execution.
Ordinary protected sign-in/unlock, full idle and lifecycle remain open.
Idle refusal evidence identifies unclassified guest jobs, an unreconciled
completed inspection, and a nine-field producer-order mismatch. All remain
blocking pending qualified corrections; historical reservations are retained.
Android lease release still needs an exact owned-transition guard; that source
work remains private while boot-only preparation continues.
The first 9,017-test focused pass exposed three integration
issues; all three recorded modules passed the managed failed-first rerun after
narrow fixes. The Windows capability/path and Git/process regression suites also
pass. The current-authority, Windows harness and Git-byte cohort passed 52 tests;
release hygiene passed. Final native scenarios, source freeze, version note, managed prepush, push
and five exact-SHA workflows remain open.

The independent 2026-10-20 automatic readiness/recovery implementation is tracked
in [its infrastructure ledger](tool-recovery-ledger.md). It runs in a separate
clone; Windows product parity and its original remote operations remain paused.
The ledger records task ownership, isolated fixtures, original job identities,
causal regressions and the incomplete provider acceptance matrix. It does not
supersede the retained parity history below.
Permissions recorded in that earlier campaign do not authorize terminating this
task's retained UNKNOWN work or changing the paused checkout. Use the current
infrastructure ledger and resume guide for those boundaries.

## Recovery delivery follow-up (2026-10-27)

The active recovery checkout is `/Users/karapsin_de/projects/vpn_control_tool_recovery`
on `dev`, starting from `3a753cbe830f5793d19d2b283b5fa3630a0d6d20`. Its Windows
package and Fast Checks workflows failed; Android, Linux and macOS succeeded.
The current patch owns the two CI test failures and the terminal-publication
fixture race found by prepush, their causal regressions, portable capability
coverage, dependency/byte-preservation declarations and required delivery metadata. Original logs and beforeimages are retained under
`.runtime/tool-recovery/ci-completion-20261027/`. Final managed prepush and all five
required workflows for one new exact SHA remain mandatory.

The prepush race's original stderr, timings and whole beforeimage are preserved
in that packet's `prepush-01-gateway-failure/`. The actual old delayed-release
body reproduced an empty-file JSONDecodeError; atomic publication passed the
same synchronized reader/writer schedule on Python 3.12.13 and 3.14.3. Both runs
proved owned helper closure. Evidence and hashes are in `gateway-terminal-draft/`
and the committed beforeimage provenance; these focused proofs do not replace
the final managed pass or exact-SHA CI. The regression also defers its POSIX
fixture import until after the platform skip; both interpreters passed discovery
with `pwd` unavailable and no fixture import.

Native VM/emulator lanes stay closed. The Linux retirement, single Android APK
and installer update, Tart macOS restart and Windows login/idle work need user
decisions after CI is green. Operations `575c610c` and `8042e683` stay UNKNOWN;
no replay, VPN interruption, merge to `main`, tag or release is authorized.

# Paused-checkout parity ledger through 2026-10-20

Retained from the paused checkout at the 2026-11-07 merge. It is history: nothing below is current evidence.

The user resumed Windows product parity, installed-package native acceptance and
Windows visual review on 2026-10-19. Linux, Android and macOS product-native and
visual work remain deferred; all five development CI workflows remain mandatory.
Delivery is to `origin/dev`; no release or host VPN interruption is authorized.
The retained repair history below is historical and does not override this scope.

Startup found clean `dev` at `d24c19047ec15689948404ede40f50c5ec284e77`,
version `2.2.13`, equal to `origin/dev`. Fresh managed exact-SHA verification
confirmed Fast Checks and Android, Linux, Windows and macOS package success.
Read-only `matrix-status` still reports every Windows requirement and shared
document-persistence-transfer open. No product acceptance is inferred from CI.

Current owned work intentionally spans the desktop public CLI adapter and its
causal regressions, this ledger/failure mapping, and fresh Windows fixture/native/
visual evidence. The coordinator owns documentation, source/artifact admission,
versioning and delivery. The CLI worker owns the public mode-only subscription
fix and focused Kotlin tests; independent readers audit public adapters and retained
evidence. One Windows operator owns all fresh guest actions. Private evidence is
under `.runtime/windows-parity-20261019/`.

The first product blocker, `source set subscription` without an ID, is fixed in
the public argument adapter by separating typed validation from optional legacy
translation. Owner validation/revision guards remain unchanged. Actual public
argv/transport coverage produced three failures on the preserved implementation
and passed all five tests on the fix; the 31-test adjacent slice passed. The
packaged smoke now checks human/JSON empty, remembered and explicit-ID selection,
invalid arguments, guards and readbacks. Installed Windows verification remains
open. Exact causal mapping is in `cli-entrypoint/failure-to-regression.json`.

Fresh fixture qualification must bind environment, ordinary account, credentials,
source, package/helper/runtime bytes, architecture, signer, workspace and controller.
`setupReady` never implies `productReady`. Historical closed sessions remain closed;
preserve disks, original jobs/leases/evidence and every failed or unknown outcome.
The retired CP117/MSI start routes grant no authority for new work. Protect the host
VPN and unrelated processes.

Remaining gates are every Windows-applicable scenario from
`native_acceptance_requirements.json` (native CLI, installer lifecycle, scoped VPN,
owner lifecycle, document persistence/transfer), complete DIRECT success/failure/
recovery/cleanup before the matching MCP replay, all 58 Windows visual scenes with
geometry/contrast and opened-image review, final-source/artifact requalification,
routine causal regressions, fresh version/prepush and exact-SHA five-workflow CI.
No product-native or visual result has yet been qualified for this continuation.

### Current source checkpoint and protected Windows files

The complete 51-stage managed prepush passed on the source fingerprint
`925666fba6860e321b5c88d6994c963d3d8f2d631b89366cc39b51c766adc7ed`.
That coherent 275-path bucket is saved in local-only commit
`a9aed70190cff5af2b7123981a976dc9091f7eb1`; it has not been pushed.
Subsequent regression and startup fixes require a fresh final version/prepush
receipt before delivery. `origin/dev` remains the original `d24c1904` source.

The baseline MSI and Python installer have both reached the guest through two
actual physical copies, each with its separate endpoint and transfer observations.
These four DIRECT preparatory operations qualify transfer custody only. The first
full SYSTEM intake failed at the generic single-link file guard. Its guest exit 1
is known; its original host observation remains UNKNOWN and abandoned. The exact
owned parked observer was retired once after independent identity qualification;
the original operation was not replayed or promoted to success.

A separate read-only native observation then found that both exact System32
PowerShell and Windows Installer executables are regular, non-reparse files with
two hard links, TrustedInstaller ownership and protected ACLs. The narrow successor
admits only those two fixed OS roles under protected-writer checks and retains all
observed identity, content, held/named and security comparisons. Transferred files
still require one link. The fixed full native intake passed on Windows PowerShell
5.1: original tool session `80482` exited zero, both raw streams reached EOF and
all 49 held input generations and hashes closed unchanged. Qualified receipt
`12c58a279189481e25139f87ae6d1d8d8ec46110695dd0cf521bf27d6d3b146d`
binds nine directories, four files and thirteen complete ACL observations;
completion is `c513d53ea21371bf2b1375b4b24f17b2569fc3b112ea097c6fa99cd328431d74`.
The canonical three-owner fix and its original-source causal tests are now
adopted. All 28 ordinary-task tests, including the 38-case PowerShell policy
component, passed with the verified local PowerShell runtime and no skips.
MSI signer/product admission, ordinary task launch and installation remain open.

The earlier whole-caller `__name__not` typo now has a registered routine getter and
an authentic complete-source causal regression: the old caller fails before
guest-exec, while the one-space correction executes the actual registered decoder.
The lost-acknowledgement control still retains UNKNOWN without replay. All nine
canonical recipe tests and four capability checks pass with the verified local
PowerShell runtime, without skips. This source-only follow-up does not qualify
Windows installation or product behavior. Evidence is under
`windows-product-runner/system-intake-caller-lexical-recipe-preparation-v1/` and
`windows-product-runner/windows-protected-os-pin-policy-preparation-v1/`.

The following native MSI metadata operation failed before evidence-file creation
or any installer action: guest PID 7820 exited 1 at the first `_Tables` row
consumer with `Cannot index into a null array`. Its consumed status is preserved;
the original host observation remains UNKNOWN and abandoned. The exact parked
host observer was retired once, with positive pidfd exit/absence and full EOF on
the separate disposition. Its original operation is not replayed or relabeled.
The registered complete-body getter now suppresses the two COM method success
values. Authentic before/current PowerShell peers give 24 RED plus four true-void
controls on the original and 28 GREEN on the fix. The nine-path routine proposal
is adopted. All ten canonical recipe tests and four capability checks passed
with the verified PowerShell runtime and no skips. The corrected native run then
passed: original tool session `8394` exited zero, complete 102,640-byte stdout and
empty stderr reached EOF, and all 51 source generations/hashes closed unchanged.
The original guest file handle delivered and closed the verified 74,621-byte
metadata file. Receipt `c3bcb48a850e8bb7eb4c95bb6b3a6e154fbbccca8fa0754c8063db530d9daa4f`
observes the baseline version 2.2.13 and its package identity; it does not qualify
installation. Completion is
`cdb84e1045ee126abbed4c985f75e480e84b29b92d67b2a1f0f4e1ea161a5efa`.
Evidence is in
`windows-product-runner/posttransfer-msi-metadata-rows-cause-preparation-v1/`.

The next source bucket adds the reviewed ordinary CLI/document dispatch, owned
desktop support, isolated failing-MSI consumers, updater/SYSTEM collection,
runtime/lifecycle bodies and input controls. Its 152 source paths and 56 guarded
policy-row operations are now adopted from private handoff `547417a1`; root
adoption receipt is `00be35485d4f780141978f040be83677c33156cabaf79a3270b3d1dac0ae5e81`.
These tooling associations do not close any installed or visual membership.
The canonical 85-test ordinary suite and platform capability checks passed.
The separate source/pin-only EOF normalization is now adopted from `e0ae715b`:
one trailing newline was removed, executable ASTs stayed unchanged and current
hash dependencies were renewed. Historical beforeimages remain exact; the
historical loader's one test-input hash renewal is explicitly labeled.

The original nine-module run then exposed a test-cleanup defect: 263 tests ended
with two failures and 23 errors after an expected causal failure left fake
interpreter globals installed. Three inner `TestCase.debug()` calls skipped their
registered cleanup stacks. The owned `TestCase.run()` correction preserves the
original exceptions and always executes those cleanups. Its authentic whole-source
regression reproduces the leaked globals and failed real Python child launch on
the original, then restoration and a successful child on the fix. The seven-path
proposal `ac3a8e33` and report-only metadata-disposition proposal `b4ba5ece` are
adopted through 18 source paths and 15 guarded policy operations. Root adoption is
`aed19e00210859927735cef1572236c46a93fd7a4c30ee45401c99da9d31db5b`.
The original nine modules now pass together in one interpreter: 264 tests, no
skips, receipt `5bae4b37ca398c2aa8e4b02ea669aa5222dbd1e7b15c9cc78e42864d698667db`.
All ten recipe tests and four capability checks also pass without skips,
receipt `079d6cd50b5568e13677e9f24167f183a0a72d8e7d220f8b35f5e46793be8079`.
Production planner/owner/PowerShell task bytes remain unchanged by this adoption.

The first actual ordinary publisher initialization passed: original tool session
`10294` exited zero, both streams reached EOF, and all 59 held input generations
and hashes closed unchanged. It created only the private qualification directory;
no source endpoint, file transfer, task or installer was started. Qualified
receipt is `b162a00903e362b48c9a88625c2d98fe8c61306b6ac3e51f17c8def63ff84df8`,
completion `652f005569492859ad07c7ac20dd0622d1e5e3b72982ffc6b32e4fc5ccc015f7`.
The following transfer handoff needs an explicit export of the same original
phase's raw native result and plan; its whole-source causal correction remains
private. Initialization will not be replayed. Publisher/responsive-document and
postboot routine enrollment, final version/prepush and delivery remain open.
Three-file publication, ordinary task qualification, Python/app installation and
all 64/58 memberships remain open.

### Fresh fixture admission work

The fresh Arch/KVM deployment is `d493a373-1d2c-4ab0-bfd4-e93575019dce`
at `/home/kardinal/vc-win-d493a3731d2c`, 6 GiB RAM, four CPUs, 96 GiB disk,
loopback VNC 5955, Enterprise Evaluation amd64/en-US and distinct fresh ordinary/
administrator accounts. Setup qualification observed Windows 11 Enterprise
Evaluation 25H2, build 26200.6584, an ordinary non-administrator desktop account,
its Explorer session and the SYSTEM QEMU guest agent. Actual MCP
`windows-vm-deploy-secure` rotated the temporary administrator secret, disabled
automatic sign-in and removed password-bearing setup files; a separate MCP status
confirmed completion. The qualified private context is
`windows-fixture/native-environment-context.private.json`. `setupReady` and
`setupSecured` are true; `productReady` is false. No app is installed yet.

The first preflight refused `package_integrity`: an unrelated missing pacman sync
database advisory precedes the one policy-correct swtpm UID difference. Preserve
the raw native result and helper beforeimage under
`.runtime/windows-parity-20261019/windows-fixture/`. A narrow parser repair and
causal helper/whole-preflight regressions now pass: authentic before two tests/four
designated assertion failures, fixed two passes and the full 18-test module green.
No host package,
repository configuration or CA-directory metadata change is authorized or needed.

Four historical running capacity claims still account for stopped actors. Exact
original start/reset-stop receipts and fresh same-boot PID/start-generation
absence are joined under `windows-fixture/direct-running-claim-reconcile/`.
The Windows operator closed only these four capacity rows through existing
correlated-observation/release APIs after a fresh recheck and copied-ledger guard
qualification. The real closure receipt is
`windows-fixture/capacity-closure-real/closing.json`
(SHA-256 `ef3709fb415eb16cc0fa2978d31684e04c3563d1904c014e0db16d04171ff5c0`).
All eight exact ledger-operation children exited zero with complete raw streams.
Original ledger bytes, jobs, leases, unknown product outcomes, disks and evidence
remain preserved; the three pending 12 GiB claims are unchanged and counted.
The pre-start privileged census found no running VMs; only the new deployment was
then started. No old guest/session was restarted, and no raw ledger edit or guard
bypass occurred.

### Current test-tool and transfer work

The first managed prepush stopped waiting at its unchanged 3,000-second agent
suite limit. The separate original worker continued naturally. Both original
processes are now absent; its final result is 6,963 tests across all 513 selected
modules, with two assertion failures, one error and 200 skips in 3,537.226 seconds.
This is a failed run, not a managed prepush receipt. Full original artifacts and
52 source beforeimages are retained at
`prepush-failure-investigation/natural-worker-terminal-v1/`; the managed timeout
and its separate worker custody are retained under `outer-timeout-v1/`.

Two existing routing-diagnostic tests assumed a Python child had emitted bytes or
exited before a 50 ms measurement. Their actual failures were an empty stderr
prefix and a still-live parent classification. Explicit readiness fixes those
fixtures without changing production measurement budgets; both authentic
before-source assertions reproduce RED and the complete 14-test module is GREEN.
The generated Android batch-shell test also exceeded its 30-second fixture limit
during its first normal case. Original exception output did not retain that
child's raw channels, so the historical cause remains unknown. Separate controlled
latency and changed-file diagnostics preserve their own originals; their canonical
59-method check completed naturally in 1,002.877 seconds with no assertion
failures, one fixture-loader error and one expected platform skip. Both streams
reached EOF and all 50 held sources were unchanged. The loader incorrectly
dedented an authentic method whose multiline string contains column-zero lines;
it failed before the historical child could start. An unchanged-byte class wrapper
now passes the actual before-loader RED/current GREEN and the same real delayed
before-30/current-252 scenario: two focused tests pass in 99.551 seconds, with both
EOFs, positive process closure and all 50 input generations unchanged. The routine
module now has 60 methods; no complete 60-method pass is inferred. The production
generation guards passed their early and final changed-file scenarios. Exact
scope and receipts are `evidence-audit/installer-completion-v1.json`
(SHA-256 `5f4a5739dd52b6afe765c1b824f1724a6dd15d8322b8c42caa0facdb282c4b1b`).

The selected suite intentionally ran serially because its source isolation
reviews were absent or stale. Its measured total could not fit the aggregate
3,000-second command limit. Managed-only consecutive batches of 16 modules retain
the exact original order and complete coverage. A scoped runner owner now requests
the existing cooperative SIGTERM cleanup on timeout and retains the original
process, lease and both streams through closure. Eight new controls, actual
before-source RED/GREEN and the 126-test adjacent slice pass. A fresh complete
managed prepush remains required after all content and version edits.

The unrelated desktop update-watcher fixture now supplies an in-process no-op
sleep function while preserving the production watcher, 300 attempts and
ten-second observer. The otherwise reachable fake executable exits 97 as a
tripwire. Actual JVM before-source RED reaches that tripwire; the fixed five-test
suite passes. The original full-suite timeout's unretained phase remains unknown.
The joined receipt is
`cli-entrypoint/unrelated-desktop-failure/tripwire-causal-v1/summary.json`.

The user additionally requested a reusable MCP tool accepting generated programs
and automatically using saved-file transport for oversized commands. The new
`program-start`, `program-status` and `program-collect` path is in progress, reusing
the existing internal SSH automatic-program transport. A real kernel E2BIG
before any child starts now selects one saved-file plan for the same immutable
program; the preserved owner fails that witness and the fix executes it once.
Status observes the same operation; timeout, disconnect or lost acknowledgement
never permits replay. This owner preserves collected output and operation records;
it does not guarantee remote process survival through an active SSH disconnection.
The 60,000-byte outer command limit remains, with the separate Windows command
limit measured in UTF-16 units including its terminator. The final combined
53-test slice passes. The earlier configured-host DIRECT small/oversized programs and
the matching actual MCP programs all pass, with identical source hashes across
entrypoints, exact argv/cwd/Unicode streams/exit 7, pending reconciliation without
replay, both EOFs and unchanged source closing. The oversized 126,544-byte source
would require a 634,823-byte inline command; its saved loader is 3,735 bytes. The
joined receipt is `program-tool-native/native-direct-mcp-qualification.json`
(SHA-256 `d286099b9a9899e27bde4236b04a7367b3ebf13ff6173737b50c9225ac2f29b1`).
These are SSH tool proofs, not Windows product results. The Windows QGA engine
will compose through the same Python API; no second public Windows language is
advertised.

A final coordinator guard refuses these POSIX-owned program actions on Windows
before importing the POSIX keeper. Three focused client/dispatch tests pass,
including a controlled missing-import failure on the preserved dispatcher. This
seven-line server change required retiring the verification channel's original
source context before preparing a final current-source channel. The narrowly
owned retirement helper passed 16 focused tests, its actual owned-channel exit,
independent process/socket absence, authentic terminal publication and matching
current-MCP ENDED observation. The first read-only probe exposed a default-config
argument mismatch; its original refusal and helper beforeimage are preserved,
with actual before-source RED/current GREEN. The joined receipt is
`program-tool-native/retirement/retirement-qualification.json`
(SHA-256 `4f10f09e419f1e0f97424459b55f40fe8e66e76a0945a0828c384a30c9a6232b`).
No old READY context is adopted, no unknown program is restarted, and a new
current-source channel was subsequently prepared after finite dependency enrollment.

The first enrollment selected 552 of 598 modules and preserved exact coverage in
35 serial batches of at most 16, plus one SSH gate. Its canonical policy is
`676e7fe83f5326c05f65986f2cdbd5721d478f87f0455e4e5ec729ec4b1eeeb9`;
the apply receipt is `dependency-enrollment-final-private/canonical-verification-receipt.json`
under `prepush-failure-investigation/` (SHA-256
`ab1c33d1d31bd98043a8ea0095aba5bbe8541477a65039df8485fb0151b30d45`).
This is dry selection, not a passing prepush receipt.

The new `315960df-9513-4764-a39c-ca602d36df76` channel reached READY and SELECTED.
Its small current-MCP program passed, but oversized operation
`bc6ed15f-36ba-492a-88ac-13eaca58fa10` ended UNKNOWN with `SshConfigError`.
The worker retained only the error class, losing the original message, traceback
and inner admission result. Capture absence is not proof that nothing started.
Exact read-only reconstruction and nine fresh channel observations pass; the
original cause remains unresolved. All 26 original source generations, request,
worker/owner records and raw SDK frames are preserved. The joined read-only
boundary is `program-tool-native/final-748-676/read-only-causal-boundary.private.json`
(SHA-256 `27f37cecb4b0366f7872e9343ac1094788482c045163a4cbfb879cfbf32624ac`).

After proving program owners closed and keeper absence, the second explicit
owned-channel retirement passed native quiescence, its sole exit request,
independent original PID/socket absence, authentic ENDED publication and current
MCP ENDED observation. The original oversized UNKNOWN was not replayed or promoted.
The joined retirement receipt is
`program-tool-native/final-748-676/retirement-315/retirement-qualification.private.json`
(SHA-256 `b11b80b0fff6e4d4522bf6c1b554e750634531f34af4a4c3ad7fcb47076a55d0`).
The two explicitly owned correlations are the helper's entire retirement scope;
all 20 focused retirement tests pass and all original source holds are closed.
The narrow diagnostic fix preserves the outer exception and passes the existing
private capture callback through the same read-only observation; no new query,
retry, admission decision or deadline is introduced. Bounded private evidence
includes phase, message, structured traceback, suppressed typed refusal/context
and captured original status data. Capture/write/overflow failures preserve the
primary failure and custody. Initial admission within the validated operation
scope reports privately then rethrows the same exception; earlier bootstrap,
imports and intent reads remain outside this diagnostic scope.

The final two-module slice passes all 33 tests, including 12 new controls, with
all source generations unchanged and no active SourceSessions. Independent
review is clear. The owned handoff is
`program-tool-native/worker-diagnostics-preparation/owned-handoff.json`
(SHA-256 `903e84d882e2808efc26913dc066bc97d1173abcb3a077b29f0f80f27126bb09`);
its focused summary has SHA-256
`ef63a1728be2b2d63849d2cb4351f84c74f5d67edd9a3941a31a1e4654c72acf`.
The diagnostic policy update is applied as exact SHA-256
`638f701294ac2fd69e40ead2780c4dd28cb17a94dfcffdb5b1fd9fbaeab6bc21`.
It renews three test rows, declares one archival-data beforeimage with no runtime
scope, and adds 11 exact ownership edges without widening directories or globs.
All 20 source byte and identity pins closed unchanged. The apply receipt is
`prepush-failure-investigation/dependency-enrollment-diagnostic-private-v1/canonical-apply-receipt.json`
(SHA-256 `c57ffb8b7a03e0aa93b77aac84365e7cbe23a972fe75f7fba5f668be86d0d29e`).
Dry selection remains 552 of 598 modules with the same 35 serial batches and SSH
gate; no passing prepush is claimed. At that checkpoint, fresh direct/current-MCP
qualification remained open and all seven prepared Windows native requests were
unsubmitted and on hold. The original oversized cause remains unresolved.

The user requested five hours of idle persistence after an unused fresh SSH
channel expired under its original 60-second policy. New independent channels now
emit `ControlPersist=18000`. A complete emitted-prepare argv test fails on the
preserved 60-second producer and passes on the five-hour producer; all 55 focused
tests pass. Connection-attempt and launch deadlines, historical embedded sources
and ended identities are unchanged. Evidence is under `five-hour-idle/`.

Fresh whole-caller checks preserved a missing RPC argument and an absent caller
global, both before guest command submission. Separate native Windows attempts
preserved omitted XML RunLevel for a genuinely Limited task and a 35,599-unit
encoded command that could not start. The saved-source bootstrap then refused a
file owned by Administrators: SYSTEM's default token owner differs from its user
SID. Explicit owner assignment qualified the saved source, and the single V5
ordinary-user task passed its SID, session, non-elevation, quoting, stream and
closure checks. Its exact task was removed and independently absent. The joined
context is `windows-fixture/native-environment-context-qualified-ordinary.private.json`;
the causal map is `windows-fixture/causal-map-after-token-v5.json`. New direct
boot/PID checks also pass the original SYSTEM bootstrap and reject the wrong boot
before file effects. Routine enrollment and matching current-MCP acceptance remain
open; no app or product scenario has run.

Two further infrastructure failures are preserved separately: an absence query
omitted progress suppression and emitted PowerShell CLIXML on stderr; its corrected
native query passes. An atomic directory helper named its C# method `New`, which
PowerShell resolved as a constructor; native failure and positive original-root
absence precede `CreateExclusive` native GREEN. Their canonical consumer is the
new pure `windows_artifact_transfer` producer used by the complete QGA engine.
Exact ACE flags, original directory/file identities, retained token lifetime and
boot/PID closing are being qualified before package transfer. Neither generic
user-program stderr nor product acceptance is inferred from those repairs.
The retained QGA reply/capture owner is also being promoted into the canonical
`windows_qga_transfer` module, with tests exercising its actual consumer rather
than copied current helpers. Private review found reply-cursor, source/capture
closing and exception-custody gaps; the canonical owner and complete emitted
callers now pass independent static review, 42 primary local cases, one
non-replay refusal and 32 fault cases. Single sequential inert streams of the
full 131,228,020-byte MSI and 29,452,944-byte Python installer match their hashes.
The joined local receipt is
`windows-fixture/qga-transfer-preparation/final-canonical-v11-qualification-summary-v2.json`
(SHA-256 `f810171cba11774ea13cd4b2f2a72e5d6dd4fee9d4683413f9ed7f41eeaf0af6`).
These simulated-peer results do not qualify native Windows execution. The final
routine slice has 35 tests: 32 pass and three PowerShell-only cases are skipped
on this coordinator. The owned handoff is
`qga-transfer-preparation/routine-regression-qualification/owned-handoff.json`
under `windows-fixture/` (SHA-256
`908c2475f2e81057cff1d7cdc162724e04150f42ab60de4f9e261587f21ae501`).
All source holds are closed; native causal cases and the complete canonical
direct/MCP procedures remain open. No guest artifact transfer has started.

The ordinary-user task planner, retained PowerShell owner and retained Python
process owner now use their actual canonical sources rather than duplicate
private implementations. The focused module runs 13 tests: 12 pass and one
PowerShell-only case is skipped on this coordinator. This addresses the
routine-coverage gap for the original omitted-RunLevel XML: matching independent
Limited/Interactive native facts are
required, rather than accepting an omitted XML field alone. Exact original XML,
validator source and native 13-control evidence are preserved. Local producer
tests and native PowerShell causal tests are separate gates; coordinator platform
skips do not qualify the original Windows behavior.
Final review also found an extra ComHandler accepted alongside the expected
Exec. The preserved immediate planner fails the actual validator regression;
the fix requires exactly one Actions container and its sole Exec. The current
native packet adds that refusal to 14 controls without changing the original
13-control receipt. Two exact-byte Git attributes protect the canonical
PowerShell owner and raw original XML; all 15 checkout tests pass, including
actual old-attributes conversion RED and current preservation GREEN.

The exact baseline 2.2.13 MSI from successful Windows run 39012808166 is held and
hash-verified on the fresh Arch host, with no guest installation. The pinned
Python 3.13.15 AMD64 installer is acquired and catalogue-verified; native PSF
signature and resulting interpreter admission remain open. Artifact receipts are
under `artifacts/`. No historical guest or connection was restored.

The remaining native UAC visual baseline requires a filtered administrator's
interactive desktop, while the product VM deliberately uses an ordinary user.
An isolated `windowsUacVisual` setup purpose is implemented for a future separately
owned blank visual VM. Legacy four-key setup dictionaries, standard-account
autologon, ordinary qualification, spec serialization and the live product guest
remain unchanged. The final source-bound 49-test slice has two platform
skips. New boot/Explorer FILETIMEs remain exact decimal strings, including values
above JSON's exact-number range; Explorer must be `C:\Windows\explorer.exe`.
Native visual creation/capture is not yet performed; securing and requalifying
the same filtered-administrator session, actual native UAC capture and image
provenance still require direct and matching MCP qualification. The visual
contracts require real full-screen capture, full-pixel comparison, exact-source
provenance and opened scene review; an additional programmatic secure-desktop or
consent-subject observer is not a required gate.
The thin remote collector uses the existing capture-local route and copies the
original owned frame unchanged to `windows-uac.png`; all 12 focused tests pass
and independent review is clear. The coordinator host stamp stays truthful;
actual remote Windows context remains in the original native journals. This
qualifies local collection only, not a UAC scene or image verdict.

### Current trust, recovery and private adoption boundary

The later channel `546de964-29aa-4b9c-8ea6-332b1c549182` qualified all four
small/oversized DIRECT and actual fresh-SDK MCP programs at the final 748/638
source boundary. Each retained exact 147-byte stdout, 17-byte stderr, exit 7,
both raw EOFs, source closing, keeper absence, identical-request reconciliation
and conflict refusal. All 26 original source pins closed unchanged. The 65 SDK
RPC servers are observations and submissions around four actual programs, not 65
program starts. The joined receipt is
`program-tool-native/final-748-638/native-direct-mcp-qualification.private.json`
(SHA-256 `55b5b9302d8e5bc6f6e1f0f3c1e712fc26e1c5e9b5155b38bea4e91153edf612`).
It is separate from the earlier `d286099b` receipt above.

Subsequent `known_hosts` drift makes channel546's original READY authority stale.
The retained old/new hashes are `c907aa5b` and `20bb94d7`; equal size does not
establish equivalent trust, and the change is not an append. Its actor/cause and
key equivalence remain unproved. Do not restore trust bytes or reuse that READY
record. The original drift evidence is
`windows-fixture/known-hosts-drift-before-diagnosis/drift-preservation.private.json`
(SHA-256 `5111993c9951a817612ce13064eba933d01f99d675f5fdf39514debddde9b7cd`).

Two separately admitted large carriers completed automatic stdin source transfer:
470,783 bytes for the exact host-actor cleanup and 1,853,826 bytes for the once-only
original PID4120 status query. The latter retained its original carrier child,
exit zero, both raw EOFs and source closing; no new guest exec or endpoint replay
was submitted. It establishes `created-terminal-observed` for the original create,
including its bound bootstrap and empty probe file. It does not qualify the full
original operation `ba9620b4-e5d3-4f61-82a9-ee4ce38522ec`. That full probe remains
`unknown-unverified`: original local owner57875 and SSH58163 are absent, their
completion custody is lost, and original dual EOF/source closing remain unproved.
The later status receipt is
`artifacts/original-pid4120-status-direct-preparation-v1/packet-final/operator-joined-status-observation.private.json`
(SHA-256 `9d4b748bd9977220031dbb487e48e0d8dea59d640dc972e41ced50625ea58846`).
It supersedes the earlier guest-status UNKNOWN only for that create component.

Stage A applied fourteen exact source/fixture overrides plus policy
`33f6144e` while retaining all sixteen original DIRECT sources through retirement.
Canonical helper `49a9fa28`
and test `ba8be2c2` pass all 37 routine methods in 18.755 seconds; diff check is zero.
Receipt `stage-a-canonical-adoption-v1/root-canonical-adoption.private.json` has
SHA-256 `19a6067480b6baf486631de3364eed1e427587c0b07c1be96158bc1a787371d1`.
The exact owned retirement `9c0d9d65-e136-4baf-b8ec-9e09a20d0cdf` then completed:
retained outer80423 and exit-client2108439 both exited zero with dual EOF,
independent absence and original-channel ENDED publication/readback. Root verified
all thirteen joined records and decoded native output. The adjudication is
`stage-a-native-retirement-546-v1/root-retirement-adjudication.private.json`
(SHA-256 `a405c991fac3d7f6f872d1ec12d1c2820454968a7da91569cf29b6c7562c9fad`).
It preserves the original UNKNOWN/lost-custody limits and grants no trust equivalence.

Stage B's thirty exact source overrides and policy
`b204105250d461301f8f3c4b3f3c70700439293c8bf77152d12d627d7a3456dc`
are now applied against accepted Stage A `33f6144e`. The joined packet is
`metadata-consolidation-final-staged-packet-v1/handoff-final.private.json`
(SHA-256 `050ef135c0d071e457866d5f8854ba5711c5d25dbf71bb76246d2c350c071214`);
root verified all thirty before/candidate generations and seventeen handoff references.
Canonical focused checks across seven modules pass all 203 distinct methods.
The bare-Python run skipped one MCP SDK case; that same case then passed in
`.agent_venv`, leaving no unresolved skip. Root rechecked all 44 adopted source
hashes and the policy after these checks. The code/policy closure receipt is
`stage-b-canonical-adoption-v1/root-canonical-adoption.private.json`
(SHA-256 `df8f3de570f416e399af17b1b41a778e7c0a3b9471f33412ed689c51a5fb4470`).
The earlier bf05 nineteen-test and capture 121-test receipts retain their original
pre-adoption scope. Neither the canonical slice nor the separate bf05 native
status component establishes native product acceptance. At that post-check
checkpoint, documentation/version updates and a fresh channel were still pending.

The order is actual546ENDED, then Stage B exact adoption/checks/source-policy freeze,
then NEW normal prepare/select and current DIRECT/fresh-SDK MCP tool proofs, then
seven freshly generated native callers. Do not prepare a channel before Stage B and
then change its bound sources. At that checkpoint, no fresh channel or full native
rerun had started; subsequent channel267 observations are recorded below. No
unknown operation or consumptive status query is replayed.

All seven complete native reruns remain open, as do all 64 Windows/shared
memberships and all 58 visual scenes. The app is not installed. There is no current
passing prepush receipt or pushed continuation commit. Final source/artifact
admission, validation, versioning, push and exact-SHA CI remain outstanding.

### Fresh channel267 prelaunch and diagnostic retention

The later `26708975-2783-4f95-bd72-cf5bda811155` channel reached READY/SELECTED.
DIRECT small program `2525f4ef` qualified, but oversized operation
`c79d4b6e-12d7-4869-961b-6f0e1e8895c4` raised prelaunch `SelectionUnknown` through
`automatic.bind -> _route_sha -> selection.selected_route_options`. Its original
job/intent/owner/child/terminal are absent; all thirty source pins stayed unchanged.
The original cause remains UNRESOLVED; no matching MCP program had started at that
failed checkpoint. Later distinct operations are recorded below.
Evidence is `program-tool-native/stage-b-b204-native-v1/oversized-original-failure-before-diagnosis/`.

Actual diagnostic1 then lost its own result/raw bytes while serializing captured
stderr bytes as JSON. This does not explain c79. Separate local complete-entry
controls reproduce that failure, v2's empty binary readback rejection and v3's
same-byte replacement adoption; private v4 corrects them in nine inert cases with
zero network/program starts. The map is
`program-tool-native/stage-b-b204-native-v1/diagnostic-retention-qualification-v1/handoff.private.json`
(SHA-256 `4ba329a1ace321624a528eb1a008dfcf64531aeb736d6e453725efbe998eb2c1`).
Actual diagnostic2 (exec59233, natural exit0) then built `PlannedArgv` once, with
four complete zero-exit same-call admissions, full raw streams and source closing.
Its twelve traced `FileExistsError` events were caught existing-directory/lock
handling, not `SelectionUnknown`/`ChannelUnknown`. No program/argv was executed and
no canonical fix was made. This current observation does not recover diagnostic1's
LOST outcome or establish c79's cause.

The preceding b204/0b0d source window qualified all four SSH tool cases: retained DIRECT
small `2525f4ef` (without rerun), new DIRECT large `e5ffaccf`, MCP small `1ee7a205`
and MCP large `7e6ed39d`. Each has exact 147/17-byte stdout/stderr, exit7, owner
closing, raw dual EOF, source closing, keeper absence and duplicate/conflict checks.
Large 634,823-byte inline argv becomes a 3,735-byte saved-file loader. Root verified
274 physical records and thirty source files through unchanged full generations;
41 SDK RPC servers represent four actual programs, with zero Windows guest actions.
The joined proof is
`program-tool-native/stage-b-b204-remaining-proof-v1/native-direct-mcp-qualification.private.json`
(SHA-256 `f88104b12b0fdfe995ef362d312915d7c6044205f04028430c87b25a761858ba`),
with root adjudication `root-four-program-adjudication.private.json` in that directory
(SHA-256 `fba549716ff1d11e5accd09f22a24af79bf7c59be26da58840b6df7249ab8671`).
These results leave original c79 UNRESOLVED and diagnostic1 LOST.

A private routine candidate retains the 37 retirement methods and adds nine exact
whole-entry diagnostic controls: 46 GREEN in 4.429s, handoff
`channel546-diagnostic-retention-routine-v1/handoff-final.private.json` (SHA-256
`61bfb1d43c4fcca93a878568536df751a5c146e78df53241456bb2eecddafb63`).
Their exact routine wiring is adopted; source-current canonical diagnostic46 passes
in the final 88-method check below. These three wrapper routine-enrollment gates
are closed; canonical37 alone was never their causal RED witness.

The seven bf05 callers' local guest17/request7/whole-outer18 GREEN preceded native
submission. The first prerequisite b7 then reached original-operator UNKNOWN
(observation98/exec73992 exit1) across a terminal-publication gap. One later pure
LOCAL status recovered the original component terminal and matching owner-close:
exit0, dual EOF, qualified inner result and source closing. Root held 442 physical
files/221 source rows unchanged; no new start or remote query occurred. Receipt
`windows-fixture/seven-engineering-b204-native-v1/root-b7-recovered-component-adjudication.private.json`
(SHA-256 `89b4fd740117f0f0e42d07f3451f7907b17ce53ae26cdc7e5c248bf0f5e2c426`)
qualifies that recovered component, not original-operator success. The remaining
six callers are held. The final private program candidate e286 has actual whole-
worker before0b0d UNKNOWN/current redacted PENDING until the exact original publisher
naturally closes; late known terminal validation stays strict. Its separate private
9f1 false-PENDING foreign-operation defect is corrected to UNKNOWN without actor
lookup. The program slice passes 37 methods (25 retained+12 new), 15.857s, under
`program-source-closing-gap-private-v1/handoff-final.private.json` (SHA-256
`577992cb58251d263b41fb36293c963f68e69e56040152b4766e206c14f8d807`).
Stage C adopted it; final source-current canonical program37 passes. Routine
enrollment is closed; fixed-source native proof remains OPEN.

The final recipe S preparation recorded 31 adoption targets, 32 current readers
and five routine methods, including whole manifest-path DIRECT/MCP, actual old312b
post-exec replacement RED/fixed d03 GREEN, FIFO and three terminal/EOF routing
variants. The missing-POSIX-capability witness is old3 ERROR to current5 declared
SKIP, not native Windows execution. Its live UAC producer consumes the exact
normally registered helper; original N and all seven identities remain frozen,
without successor launch authority. Handoff
`windows-fixture/native-packet-recipe-successor-v1/final-successor-handoff.private.json`
(SHA-256 `e85de32ad4f637f8e04ca9a0e75efca393750d6c5728341c929891a316d2db3f`).
Recipe S is adopted, with its final five source-current methods passing after the
fixture-isolation correction below.
Existing canonical UAC
foundations plus private31 foundation and13 whole-outer passes create no new
canonical feature, visual-purpose VM, screenshot or native visual acceptance.
Stage C applied 42 exact source/fixture targets and policy9e558, with candidate
closing and policy last; receipt `stage-c-canonical-adoption-v1/adoption.private.json`
(SHA-256 `ed41525cdd58151ddd4775d5fc1d7dae88ac0be33a13b4ba7eb2b1b3313fa81d`).
The first canonical88 run remains FAILED with two recipe routing setup errors in
stdout-EOF and dual-EOF: `inspect.getsource(guest.qualify_instance)` unavailable.
The fixture imported a canonical test alias while staged source was active, then
left its global guest/package binding pointing to deleted temporary source. This
was a test-fixture isolation defect, not a product/native failure. Handoff
`recipe-routing-canonical-failure-private-preparation-v1/handoff-final.private.json`
(SHA-256 `c095504a2dea32bfbf22bc9efcdbf5bda82b91485df9cd35ba2088aad6e1dd5f`)
preserves the original errors and source beforeimages. The strengthened same
routing oracle produces actual old-boundary RED3 failures/0 errors under a preloaded
worker, then fixed five-method GREEN, covering three cold variants, warm normal,
and exact module/parent-alias restoration. Earlier preloaded-old PASS was masking
evidence, not a causal witness; two private pretest import/setup mistakes remain
separate retained harness failures.

Stage D adopted only boundary41806/helper0a51 plus policy3a4eaf, leaving production
e286 unchanged; receipt `stage-d-canonical-isolation-adoption-v1/adoption.private.json`
(SHA-256 `421242a931c19fa6a335ea22f2097308bc2bdb3d0a6e432ea93872a8005ede4e`).
Its final canonical check passes all88 methods in16.885s (program37, retirement/
diagnostic46, recipe5) and fresh platform probes (two import/seven capability),
with all43 held source hashes and full nine-field generations closed unchanged.
Joined receipt `stage-d-canonical-isolation-adoption-v1/joined-validation.private.json`
has SHA-256 `e0d15f8f9224e060b5b3381c19a9089e96c121bbb671e72d3b8543f973b72e37`.
These local routine-enrollment gates are closed at the final source. Earlier
four-tool proofs retain their b204/0b0d scope. At that checkpoint, fixed-source
native first fresh T and the remaining six callers had not run, and full current
prepush had not started; subsequent first-caller/prepush observations follow.
No push or app installation has occurred. The task, all64 Windows/shared memberships and
all58 visual scenes remain unfinished.

### First post-adoption caller4835 refused before program loader

Original operation `4835b6ea-e758-44b0-b024-0972f8fe6594` remains UNKNOWN. Its
130,341-byte wrapper carrying114,293 source bytes transferred through automatic journal
`b9ab4023bd544d08a5e0451e18b67260`, but selected-channel admission refused before
the program loader. Typed refusal is `master_closing` / `fd_changed`, wrapped by
`SelectionUnknown` / `SshConfigError`; the exact changed FD/master type and original
cause remain UNRESOLVED. The program launch capture is null, with no captured
program bytes or EOF proof. This is not an executed-program or Windows acceptance
result. Original evidence and all84 reviewed source pins are preserved in
`windows-fixture/post-program-adoption-prerequisite-preparation-v1/native-run-v1/first4835-unknown-preservation-v1/preservation-index.private.json`
(SHA-256 `86702dc6f43df4af79d9b89ec1747d17b843880821ca9e02cfa3cc854519cbf7`);
its automatic-journal complement `b6c8df1f` records absent execution-intent and
submission-returned files. No replay or remaining-six start is authorized.

A separate private FD-enumeration false-refusal case is now causally qualified:
authentic whole providerfb8dfa observes listener3 then a removed listed FD99 and
returns `fd_changed`; candidate179c97 positively joins the listener and passes.
The one-line change skips only per-entry readlink `FileNotFoundError`; missing
required listener, changed birth/lost stat and `PermissionError` still refuse.
Private55+4=59 methods PASS16.824s. Handoff
`master-fd-enumeration-private-v1/handoff-final-v2.private.json` (SHA-256
`009c4f96e8e71e621d36d848a9b2bbe578c00527b047cc9a90faf24f838bd205`)
binds qualification523eda03 and source freeze63deda28. The unchanged same case
naturally ERRORs with `fd_changed`/exit1 when whole beforefb8dfa is selected as
CURRENT, and passes with179c97 in the59-method suite. The skipped original entry
is unclassified; this controlled case does not identify the original4835 FD/type
or cause. Private test-placement, witness-order and report-writer preparation
failures remain separate retained harness observations. Actual267 retirement and
subsequent FD-fix Stage B adoption are recorded below.

Original frozen8e55 prepush90637 naturally FAILED with one gateway fixture
`writerAliveAtReturn` assertion; all managed workers closed and root returned1.
Its injected writer used a .16-second sleep, so sufficiently late observation
invalidated the liveness assertion. The original scheduling specifics were not
retained. The fix holds that exact writer on an owned Event until its actual join;
the same existing routine adds a bounded delayed-base-join condition. Authentic
full before plus that identical fixture condition naturally REDs at the unchanged
assertion, while Event-release current GREEN and the14-case private class pass.
This is a local test-oracle mechanism, not original4835's native cause. Handoff
`gateway-stage-prepush-failure-private-v1/handoff-routine-final.private.json`
(SHA-256 `f0d24c0a8d451fa66f3ebb5809ec6eda36da740a2a6b954a9a96031f5ed0d00e`)
preserves exact before/control/fix boundaries.

The twelve-source retirement-profile/gateway Stage A is actually adopted:
helper18ab, retirement testcf8, gateway testa854 and policy21df. Receipt
`stage-e-profile-gateway-adoption-v1/adoption.private.json` has SHA-256
`468884d65bd012a5c7de152ad1b336331713abc15b004fce4a8ac89ea3b028b4`.
Canonical retirement50+source-stage52=102 PASS36.782s; the historical output filename
`canonical-64.stderr.bin` does not change that count. Pure LOCAL real-original
preflight qualified17 program members/50 held proofs and both absent execution
markers, with zero native calls/exit claims/source16 changes; receipt
`stage-e-profile-gateway-adoption-v1/local-original-preflight.private.json`
(SHA-256 `4ec358ff3dcaa78ab471ef31c828a331ef49949111620fdf23ecdbda04578992`).
That preflight made no native claim. Subsequent once-only retirement
`3f7beb36-9cb7-44ca-920c-d32f5e784060` naturally returned0 on originalexec11155;
the normal publisher and final original status are ENDED, with nativeActionAllowed
false. Native probe, inner exit0, exit request, independent absence and final status
all retain complete dual EOF/zero exits. Root qualification holds98 records,
including all50 historical proofs and16 unchanged sources:
`windows-fixture/267-retirement-preparation-v1/retire-call-preparation-v1/root-qualification.private.json`
(SHA-256 `f49f564a8188c76ddbcabef82bfa1185e63cbfe2e9ddf95422534cbc28aff26e`).
This closes only original267; original4835/c79/b7 outcomes remain unchanged.
FD-fix Stage B then adopted exactly four reviewed sources (provider179c/teste5b5/
fixturea3ab) with policy21df unchanged and no policy write; receipt
`stage-b-fd-adopter-private-preparation-v1/adoption.private.json` (SHA-256
`6ed71d3b02276f5daa1f148ba676a3474e5d9980c252ddde45c4de43cd7b4002`).
Fresh provider59+retirement50=109 PASS14.526s, originalsession7246 natural0;
`canonical-focused.stderr.bin` in that adoption directory has SHA-256
`eeebbd4eb137ec7ce422c37fdc320e714346cdd5c239dfb96d7aeaf40b16af68`.
The FD routine-enrollment gate is closed at the adopted source, without identifying
original4835's cause. At that checkpoint, four-tool proof and native-seven successor
plans were private and no new channel had been created; later observations follow. No passing current prepush or push exists. All other
native callers remain unstarted; the app is not installed and all64 Windows/shared
memberships and58 visual scenes stay OPEN.

### Current four SSH tool proofs after267 retirement

Fresh channel `11dda7ac-6cad-4eb1-9bd4-d46f8a9ade94` was prepared, observed READY
and selected with idle18000; all three original calls naturally returned0, receipt
`3af388db4117b0c465e1855d050cdc6b271e524111efabc64f1000ba6bf1423d`.
Four actual programs (DIRECT small1870/large851d, fresh-SDK MCP small0e5f/large4ea8)
qualify: deliberate exit7, exact147/17-byte stdout/stderr, complete EOF/source
closing, same-ID/same-PID duplicates and changed-body conflicts. Large126544-byte
source uses automatic saved-file transfer within the60000-byte command bound.
Root joins33 unchanged source generations/hashes,608 held records/5207328 raw bytes
and141 local actors positively absent;66 SDK RPC servers are four program starts.
Proof `program-tool-native/post267-stage-b179c-native-v1/native-direct-mcp-qualification.private.json`
has SHA-256 `e85c9f444ce53089cd674deaa68c8a542faeada32fdfbef4fe551cc0f732306a`;
root closing `e1840795` preserves original unknowns and old267 ENDED.
Before these calls, source review found normal `SystemExit(0)` skipped d03's
post-exec guard. Engineering21's finally loader guarded all four actual calls;
the reusable getter fix has actual natural-process before/current RED/GREEN.
Stage F then adopted six reviewed source/fixture paths and policy688 last, receipt
`stage-f-held-sdk-recipe-adoption-v1/adoption.private.json` (SHA-256
`9e20ef17160d80e3f504fcc4ed76026854127de7e40505a8c270ff19fe3ca4f3`).
The existing five-case family passes canonically in5.678s, original25904 natural0,
`canonical-five.stderr.bin` SHA-256
`3cfcd30e55440b7f731ee02b59e5c377885706a7fe6c8c8d2193f614b2cc742b`.
This source-current unit regression gate is CLOSED, with no production/native
failure claim. Policy renewal changes only two existing pins/three scope edges;
selected source16/core/e286 stay unchanged, so the four tool proofs remain valid
for their consumed runtime sources. At that checkpoint, Windows-seven execution
was pending and these tool proofs had made no guest action. Subsequent DIRECT
native observations follow. The app is still not installed. All 64 installed-package
memberships and all 58 visual scenes, fresh prepush and push remain OPEN.

### Current Windows prerequisites and remaining acceptance

DIRECT and fresh-SDK MCP infrastructure qualify canonical probe, six causal
cases (expected three RED/three GREEN) and XML policy (before `TOKEN_TASK_XML`,
current 14 GREEN), with natural exit 0/full EOF/source/owner/PS5 actor/boot closure.
Prior QGA/namespace/diagnostic routine gates remain qualified; full chronology is
in [the failure map](parity-failure-regressions.md). Original `8ced` guest and
`9226` host-operator UNKNOWNs remain unchanged; guest PID `6244` has a separate
known exit 1. Host-only retirements and exact old-three cleanup qualify; fresh
causal scopes/later MCP probe remain retained, without replay/child-absence claims.

Managed prepush `93618`/PID `81475` naturally failed/fully closed at its first
release-hygiene command; preserved logs remain in
`checkpoint-prepush-current-prerequisites-v1/`. No passing receipt follows from it.
Authentic failed-script `e007` bytes/name remain unchanged; exact path/SHA archive
correction `0894` has whole-before RED/current six-case GREEN (`e9bb6599`).
Core nine-path adoption `a714b1e0` fixes isolated diagnostic import, stale capability
counts, direct-entry discovery and host `generation` shadowing; canonical recipe
eight/platform sixteen pass with explicit PowerShell/no skips. The host whole-entry
causal pair retains actual TypeError/virtual-FD evidence; actual read separately
qualifies `3b46c5e7`/`5a2ae30f`. Private controls do not qualify installed acceptance.

Late self-review separately found the test Path alias reset by Python 3.14's
initializer. Preserved `117de` constructor RED/current `42933` GREEN uses an
alternate-root peer; no whole alternate-checkout/native flow is claimed. Two-path
successor adoption `e39a449b` updates that boundary and policy `939e` only; current
standard-module host routine passes one case/no skips (`df9b69b5`). The earlier
core eight/sixteen results precede this alias successor; fresh prepush remains due.

At this evidence checkpoint, the source hold was released and bindings were being
renewed for four unchanged, still-unsubmitted DIRECT preparatory operations:
MSI endpoint/transfer and Python endpoint/transfer, producing two physical copies.
Those preparations close no product membership; full product-scenario MCP remains
required. The app remains uninstalled; all 64 installed-package memberships and
all 58 scenes remain OPEN. Baseline/fixed-package acceptance, visuals and fresh
final-source prepush/dev delivery with all five exact-SHA workflows remain required.
At this evidence checkpoint, no commit or push had occurred.

### Retained-evidence reconciliation

The stale companion count is already resolved by the final retained O qualification
at `.runtime/mcp-ci-d24c19047ec15689948404ede40f50c5ec284e77-readonly-O-2026-10-17/final.json`
(SHA-256 `9f116cd5808ce3e3ddf7fd61e4c20cb71e9f878394dc9516a9a12e49082a3278`).
Its independent resource closing at
`.runtime/mcp-next-O-collector-owner-preparation-v1/closer-template-v1/actual-O-resource-closing-v1/closing.json`
(SHA-256 `784a57775afca707ed39827c07695fc2ae90cfc481f521c4014a762edb24088b`)
qualifies validation/resource closure with no native product claim or collector replay.
The failed N report remains unchanged: its sealed Linux plan had 102 entries but
the companion expected 99. O retains those obligations and adds the original
receipt test plus its new regression: 104 Linux obligations (93 Fast, four direct
cleanup, seven direct enrollment). The separate Windows tooling plan has 102
retained identities plus the Function source-body routine, totaling 103.
These source-bound tooling results need no duplicate broad audit solely for the
old count mismatch. They do not qualify current deployed product callers.

The current Windows matrix has 48 memberships (CLI 15, installer 8, scoped VPN 10,
owner lifecycle 12, visual 3); 16 shared document scenarios also apply to Windows.
The Android-only 48 MiB case remains deferred. All 64 applicable memberships are
open. The manifest requires 58 Windows scenes, including eight native surfaces.
Private reconciliation and verified identities are in
`.runtime/windows-parity-20261019/evidence-audit/summary.json`.

## Earlier MCP repair history

The user deferred the Windows parity plan on 2026-10-15 and requested the
MCP/tooling repair described below. The later instructions in the active chat
permit subagents and authorize stopping all prior unknown or historical test VM
sessions and SSH connections before fresh validation. Preserve disks, fixtures,
source edits, original evidence and durable job/lease records; no purge or replay
is authorized. Do not resume Windows product acceptance, H14, visuals or the original
Windows plan without the user resuming it. Linux, Android and macOS product-native
and visual work also remains deferred. No release.

The latest pushed repair checkpoint is
`a5cd9b73d49ff0b52f4a04a29a9122d4fe48b173`. Its preceding cold full audit
passed all 7,421 executed tests, including the separate SSH gate, and its fresh
managed prepush passed all 17 commands. Those receipts qualify that checkpoint
only. Windows then reached previously blocked tests and failed its CP117 step:
497 tests, 11 failures, 100 errors and 148 capability skips. The selector did
not broaden its input: 206 existing methods became reachable after seven module
setup errors were repaired, and 30 new routine cases passed. Keep all 67 explicit
test specifiers and every applicable native scenario.

Original Windows logs, all 111 failure blocks and exact checkpoint beforeimages
are retained in `.runtime/mcp-ci-a5cd9b73-windows-failure-v1/` and
`.runtime/mcp-ci-a5cd9b73d49ff0b52f4a04a29a9122d4fe48b173-readonly-v19-2026-10-16/`.
The finite repair covers inert POSIX recipe/source contexts, genuine local POSIX
capability boundaries, strict byte inputs and complete-program carriers, and
native PowerShell fixture prerequisites and output contracts. Production source
authority, private-file custody, ownership, non-replay and command/chunk bounds
remain required. Original failures stay failed; each new cause needs its actual
preserved-source RED and fixed-source GREEN, routine coverage and applicable
native CI proof. The checkpoint's Android, Linux and macOS workflows passed; no
completed delivery is claimed for it. Fast Checks failed two actual emitted
Android transport fixtures at their 150-second outer timeout. Their original
supervisor budget was 1,800 seconds, but the blocked phase and detached-worker
closure were not retained. Keep that original outcome unknown; do not infer a
slow interpreter, raise the timeout blindly, replay an unknown operation or
delete its evidence. The exact logs and 23 immutable inputs are preserved in
`.runtime/mcp-ci-a5cd9b73-fast-failure-v1/`. A fresh inert local diagnostic must
observe the same submitted supervisor through its natural terminal outcome,
with phase/stack evidence and both streams, before selecting a repair.
The original CI collector and Git SDK closed with
their unchanged source brackets and all 87 HTTP children reaped. A GitHub TCP
timeout is retained separately from the definite Windows failure.

The corrected focused slice passed 653 tests on both Python 3.12.15 and 3.14.3,
with 141 platform skips per run. It includes both original emitted Android full
flows and all 82 Windows workflow specifiers. The preserved native-caller
counterfactuals failed their seven positive cases on each interpreter; fixed
cases passed. Namespace repairs retain the actual source filenames and genuine
module imports. Public-source custody still refuses oversized or changed inputs;
private and undeclared inputs retain the original reader's authority. A physical
read demonstrated access-time changes alone;
stable generation comparisons retain all nine ownership/object/size/nanosecond
fields. These local results do not claim native Windows acceptance.

The fresh inert Android diagnostic completed naturally in 72.295 seconds, with
both streams at EOF, the supervisor reaped and the original worker terminal.
It did not reproduce the historical Linux timeout. The two test callers now
derive their 1,820-second capture bound from the unchanged supervisor's 1,800
seconds, its existing five-second wait and 15 seconds of fixture cleanup grace.
They retain uncertain journals and every observed raw prefix, and close only
the harmless subprocess handles they actually created. Six routine controls
cover real EOF/raw collection, partial timeout streams, owned-child closure,
storage failure and registered cleanup retention. The original two bodies and
scenario assertions remain intact. Actual retained caller code failed under a
scaled cutoff; the fix passed with identical saved child bytes, arguments and
READY-to-release input timing. The original Linux blocked phase stays unknown.
Evidence and closing receipts are in
`.runtime/mcp-repair-execution-2026-10-15/focused-final-v22/` and
`.runtime/mcp-android-direct-timeout-diagnostic-v1/actual-whole-worker-001/`.
Fresh final full audit, managed prepush and all five exact-SHA workflows remain
required. Previously closed environments remain closed; no release is authorized.

The following paragraphs retain the earlier checkpoint history and evidence.

The first repair delivery, `843c4740474a7b1c4038c51f7a941500dae0ce01`,
passed the managed prepush (6,695 pooled agent tests, 186 platform skips) and was
pushed to `origin/dev`. Windows CI then failed importing the core source capture;
that SHA is not a completed delivery. Original logs and ten exact beforeimages
are preserved in `.runtime/mcp-windows-core-capture-failure-843c4740474a/`.
CPython 3.12.10 gives pathname and descriptor `ctime` different Windows meanings;
the old loader compares them directly. The original exception did not retain its
failed field. The repair preserves full generation checks separately for each
API and cross-binds comparable object metadata. A preserved-function regression
and the native Windows counterfactual distinguish this mechanism; final new-SHA
prepush and all five development workflows remain required.
The unchanged-file assertion reproduced RED on the exact preserved function and
GREEN on the fix using physical file IO and the documented Windows metadata
projection. The expanded 28-check slice passed, with two native Windows bootstrap
skips; 102 selector and seven workflow/checkout controls passed. A macOS temporary
path alias in the new wrapper initially failed after successful capture; its
beforeimage and failure remain preserved, and resolving the owned fixture root
passed the same assertion. Evidence is the packet's `causal-local-v1/`,
`causal-local-v2/` and `dependency-review/`; these local results do not claim
native Windows acceptance.

Fast Checks on the same first SHA was subsequently cancelled after 45m14s;
GitHub's annotation explicitly says the 45-minute job limit was exceeded. Its
agent-test phase consumed 40m43s after setup, and 13 later steps never ran.
There is no per-module timing artifact, so no particular slow or hung test is
inferred. Original logs, selection and beforeimages remain in
`.runtime/mcp-fast-checks-timeout-843c4740474a/`. The workflow repair gives the job
90 minutes and the agent-test phase 50 minutes while retaining every command,
selection and the existing managed-command bound. Causal coverage runs an inert
saved producer under scaled real deadlines read from the original/current
configuration; the actual new-SHA GitHub run remains required proof.
The identical completion assertion was actual RED on the preserved 45-minute
configuration and GREEN on the fix. All four deadline controls passed, including
refusal beyond the 50-minute phase cap; 102 selector and nine workflow/checkout
controls passed. The parser found no errors across 1,344 source versions, and
all five saved-producer children closed. Exact raw streams, markers and identical
producer bytes remain in `.runtime/mcp-fast-workflow-budget-843c4740474a/`.

The healthy local prepush v8 was deliberately cancelled before that workflow
edit. Its 3,280 partial timing observations are not a passing receipt. Exactly
one guarded signal went to its owned runner; the worker/session/fixture closed,
the lease is free and source closing matched. Evidence is
`.runtime/mcp-repair-execution-2026-10-15/prepush-final-v8/cancellation/`.
Fresh final prepush and exact-SHA delivery follow the final workflow/content edit.

The second delivery, `c68058eb64f8452207bf2091bd2950e5a06231da`, passed a
fresh managed prepush (6,660 pooled tests, 184 platform skips) and was pushed.
Windows then passed core import, all seven fingerprint checks and all nine
collector controls. Its new native counterfactual stopped at the fixture's strict
metadata assertion: `os.utime()` did not establish distinct creation/change
clocks. The actual fixed capture had already succeeded. The original failure,
numeric metadata and exact beforeimages remain in
`.runtime/mcp-ci-c68058eb-failure/`. The fixture correction must physically set
and verify the owned file's change clock, retain the strict assertion and prove
the preserved original capture RED and fixed capture GREEN on Windows.

macOS on that same SHA failed the resource-monitor test's assumption that a
50-millisecond timeout always lets a fake child journal its startup. The monitor
retained the uncertain receipt and live child. The original log and exact
beforeimages remain in `.runtime/mcp-ci-c68058eb-macos-failure/`. Deterministic
dispatch/timeout coverage must preserve one attempt, no replay and child survival;
the original physical subprocess scenario and fresh native CI remain required.
Neither failure authorizes relaxing production guards or claiming that SHA green.

Both fixture corrections reproduced their retained assertions RED and passed
GREEN. Windows' portable clock model retains physical file/descriptor IO; its
12 controls passed without skips. macOS used actual owned subprocess dispatch
with a gated child journal; all 15 routine controls passed without skips, with
one dispatch, an uncertain receipt and an advancing surviving child. Every owned
test process closed. These are tooling fixtures, not deferred product acceptance.
Evidence is `.runtime/mcp-core-native-setup-c68058eb/summary.json` and the macOS
packet's `focused-v1/causal-summary.json`; actual new-SHA Windows CI remains required.

The new dependency declaration initially omitted the exact original macOS test
hash. Selection correctly refused it. Its preserved manifest reproduced RED;
adding the reviewed original hash passed the same selection and all 102 selector
and checkout controls, retaining every scope and historical pin. Evidence is
`.runtime/mcp-repair-execution-2026-10-15/fixture-dependency-check-v10/`.
A physical Git `autocrlf` roundtrip also reproduced RED with the old attributes
and GREEN with exact byte preservation for both new macOS inputs; the Windows
beforeimage stayed exact under both. All eight Git children and temporary roots
closed. Evidence is the Windows failure packet's `checkout-roundtrip/summary.json`.
Fresh versioning, managed prepush and all five exact-SHA workflows follow these
final content edits; none of the retained failed runs is relabeled successful.

The user's subsequently identified current SSH client is explicitly excluded
from cleanup. It received no signal. Previously closed sessions remain closed;
no global-zero-SSH claim applies while that user client is open.

Fast Checks on `c68058eb64f8452207bf2091bd2950e5a06231da` subsequently
completed its affected suite inside the revised time budget but failed: 6,660
tests, 18 failures, 135 errors and 175 skips. Its 153 failure blocks represent
150 distinct test IDs across 36 modules. The complete original log, 58 exact
beforeimages and disjoint 77/40/36 ownership matrix remain in
`.runtime/mcp-ci-c68058eb-fast-failure/`. Android and Linux passed that SHA;
Windows, macOS and Fast Checks failed. It is not a completed delivery.

The healthy local prepush v10 was cancelled before these further edits. Exactly
one identity-guarded signal went to its owned runner. Its SDK, worker, descendants
and fixture closed, the lease is free, and source closing remained
`4f344a9366e4229e83e2e1d3ff4774f21b1bdc61f884d0db05bc01800f59476b`.
Its 1,627 partial observations supply no final unittest count or passing receipt.
Evidence is the execution packet's `prepush-final-v10/cancellation/`.

Runtime diagnostics distinguish local Python 3.14.3 from hosted Python 3.12.15.
Isolated owned Python 3.12.14, 3.12.3 and 3.12.15 runtimes leave the prepared
environment and user configuration intact. Actual copied-source 3.12.3 cache
creation followed by 3.12.15 consumption reproduces both strict code-identity
refusals: unchanged timestamp-valid bytecode has different line tables. Preparing
3.12.15 first passes the same guards. The original hosted bytecode was not
retained, so that exact artifact remains an inference. Evidence is the Fast
packet's `mixed-patch-cache-v1/`; no source guard is relaxed.

All seven historical gzip builders likewise reproduce their fixed-output
refusal on Python 3.12; changing only the gzip OS-header byte restores all 14
original output hashes. Their execution is confined to inert historical test
graphs, outside the current public adapter/import closure. The scoped fixture
compatibility repair preserves every production source and authority pin.
Missing annotation context also reproduces on Python 3.12 in extracted/inert
test helpers. Those findings led to the finite corrections and causal checks
recorded below; the original failed workflow remains failed.

MCP startup now captures the loader and native custody backend from held raw
source in a private package before native requests. The complete original entry
really refuses unchanged timestamp-valid Python 3.12.3 bytecode under 3.12.15;
the fixed entry passes with private fresh source, unchanged cache generations
and no native effects. The actual entry proof and eight bootstrap controls
are in the Fast packet's `entry-source-bootstrap-v1/`. Fast Checks prepares its
Python runtime and dependencies before hygiene and installs only the qemu-img
prerequisite for owned file tests; it starts no VM. All strict code/source guards
remain intact.

The subsequent source-frozen slices reconcile all 153 original blocks: 151
blocks representing 148 test IDs pass locally; two original Linux-native cases
still require the next hosted run. Both Python 3.12.15 and 3.14.3 pass the 40-case
slice and the complete 245-case historical base/server slice, with 62 existing
Windows-only skips. The historical gzip slice and catalogue pass all 59 checks
per runtime without skips. Preserved actual RED/GREEN also covers the newly
exposed fixture mistakes: missing local import, already-byte program output,
complete original base source, function-local gzip imports, synthetic action
hash binding and nested unittest module setup. The final routine lifecycle
counterfactual uses the exact full unfixed file under its actual owned filename;
its fixed routine checks pass both runtimes. No native capture or historical
source/authority pin was refreshed. Evidence and exact ID/receipt links are in
`common-focus-v3/`, `common-focus-v4/` and the corresponding failure packets.

The remaining Linux cases are the diagnostic output classifier and one-use HTTP
listener. The latter's new routine control preserves the exact old positive
method and uses a real server-first close, TIME_WAIT row and EADDRINUSE before
its strict served assertion. The fixed client sends FIN before the real parser
dispatches and must reach strict served without replay. Darwin probes preserve
both actual served receipts but cannot prove Linux binding policy; they are not
claimed as causal Linux RED. The unchanged worker and ownership/free-port guards
remain strict. Windows CI additionally enrolls the raw bootstrap and held
historical archive controls. Final versioning, fresh SDK/native staging,
managed prepush and all five exact-SHA workflows remain completion gates; prior
VMs stay closed and the user's current SSH client remains untouched.

The next managed prepush, v11, found one additional isolated runner fixture
failure: its copied MCP omitted the newly required loader and custody backend.
Its original partial failure and 117-input archive remain preserved; its runner,
worker, SDK, fixture and lease closed before edits, and source closing matched.
The exact unchanged positive then reproduced RED with the full missing-loader
trace. Adding only the two explicit copied inputs and finite dependency scopes
passed that same assertion and all nine self-input checks on Python 3.12.15 and
3.14.3, with no skips or leaked children/descriptors. Historical pins, accepted
beforeimages and unknown-dependency refusals remain unchanged. Evidence is
`.runtime/mcp-runner-self-input-failure-d2290d35/`; v11 remains cancelled and
supplies no passing receipt.

Fresh twelve-tool SDK checks and inert saved-file SSH staging passed under their
recorded source bracket. The receiver verified exact saved bytes without executing
the inert source; commands remained below 60,000 bytes, all owned sessions closed,
and original records stayed unchanged. A separate invalid-input UNKNOWN remains
preserved and is not replayed. Final metadata, a new source freeze, fresh tool and
staging qualification, managed prepush and all five exact-SHA workflows follow
the runner fixture correction. No prior VM or connection is restored.

The next delivery, `308172ff07e7246a02129ec436193ed9bc81f44e`, passed
all 17 managed prepush checks (6,702 agent tests, 187 skips, zero failures/errors)
and was pushed with a clean worktree. Windows then passed the native core,
collector, loader bootstrap and fingerprint groups, including the actual
Python 3.12.10 creation/change clock RED/GREEN discriminator. The historical
archive group passed eight cases but errored in two retained-context controls:
their POSIX-only dependency import legitimately leaves `closure.base=None` on
Windows, before the intended source-mismatch predicate can run. The complete
original Windows log and 64 exact commit beforeimages remain in
`.runtime/mcp-ci-308172ff-evidence-2026-10-15/windows-failure/`.

The same two original methods reproduced those exact errors under only that
missing-dependency state on Python 3.12.15 and 3.14.3. Supplying the actual current
producer for each negative case preserves its real filename, mismatched full
source hash and strict `package-fixed-source` assertion; its original reference
and bytes are restored on success or exception. A new routine control runs both
cases from the unavailable dependency state and checks restoration. The same two
assertions and all eleven module controls then passed on both runtimes without
skips or leaks. Production code, all historical source/authority pins and finite
dependency scopes remain unchanged. Local causal evidence is in that failure
packet's `local-causal-v1/`; its private harness syntax error is retained separately
and is not project RED. The original remote runs remain untouched. Fresh final
metadata, managed validation and all five workflows for the next exact pushed SHA
remain required; the failed Windows run is never relabeled successful.

Android, Linux and macOS subsequently passed that same SHA. macOS reran the
original resource-monitor scenario twice, with all fifteen checks passing each
time. Fast Checks exceeded its explicit fifty-minute agent-test phase after the
27-test serial close gate. Its complete log has no terminal worker report or
per-test progress identifying the slow or stalled test, so the cause remains
unknown. All five original terminal results, annotations, exact beforeimages and
the source-derived serial topology remain in
`.runtime/mcp-ci-308172ff-evidence-2026-10-15/`; this SHA is a failed delivery.

The follow-up gives only explicit hosted CI calls two deterministic complementary
shards in separate checkouts. Complete global selection and unknown-dependency
refusals precede partitioning; default managed checks, include selection, runner
isolation pins and the existing time bounds remain unchanged. A final job requires
both current-attempt parents to succeed and verifies source-bound complete,
disjoint coverage. Bounded public progress omits private identities, reasons and
raw output; missing closure, source drift, cancellation and incomplete evidence
cannot produce a successful receipt. The retained serial selector and original
workflow support a physical scaled workload counterfactual. This demonstrates
partition throughput, not the unobserved cause of the hosted timeout.

Static inspection also found an unbounded EOF receive loop and teardown in the
inert local QGA test fixture. The repair adds absolute work and cleanup deadlines,
EOF and line bounds, and cleanup through exact owned handles. The original
28-case native method and production dispatcher remain unchanged. Its preserved
reader regression requires an actual physical EOF witness before the completion
watchdog, distinguishing causal failure from startup delay. Original helper
beforeimages and independent reviews remain in the same packet's
`native148-bounds/`. On both Python 3.12.15 and 3.14.3 the preserved reader produced
the sole expected failure after verified kernel EOF, all ten fixed controls
passed without skips, and the original 105-test module passed with eleven
platform skips. Every owned child and log handle closed; source closing matched.

The first CI-focused run exposed two test issues: an undeclared optional YAML
import and an old tail oracle counting the new public artifact step as build
work. Exact failed source and logs remain in `fast-timeout/shard-repair/focused-v1/`.
The corrected strict standard-library reader runs with site packages disabled;
the tail reader admits only the entire exact public uploader block. Actual
preserved-source RED/current-source GREEN pairs cover both failures without
changing the original validation assertions. Both runtimes passed 53 focused
checks, including the serial deadline RED/two-checkout GREEN, cancellation,
privacy, unknown dependencies and current-attempt coverage. The selector and
runner input slice also passed 98 checks per runtime, and workflow syntax passed.
All source brackets and owned resources closed. Evidence is in `focused-v2/` and
the execution packet's `final-integration-v14/`.

Native Linux acceptance, final metadata, fresh managed prepush and all five
workflows for the next exact pushed SHA remain required. No old VM or connection
is restored; the user's identified client remains untouched.

Managed prepush v14 stopped at its first whitespace check because the workflow
had one extra blank line at EOF. No test worker started; the SDK closed with
unchanged source. The complete failed check and exact workflow remain in
`prepush-final-v14/`. The same check reproduced RED before removing that single
blank line and passed GREEN afterward. Fresh final receipts follow this edit.

Managed prepush v15 found four failures in the old workflow reader's single-job
assumption. Its 3,414 partial observations comprise 3,399 successes, eleven skips
and those four failures; no final unittest aggregate or passing receipt exists.
The owned runner was cancelled once and fully closed before edits, with unchanged
source. Its final report, partial timings, original sources and closing evidence
remain in `prepush-final-v15/`. A static review also identified the discovery
fixture's missing copy of the new evidence helper.

The original two test files then reproduced the exact five failures on Python
3.12.15 and 3.14.3; the original compiler-order counterfactual still passed.
The clean causal evidence and full beforeimages remain in
`.runtime/mcp-fast-interpreter-order-failure-2026-10-15/red-v2/`.
An earlier harness cache-prefix failure is retained separately and is not project
RED. The fixes scope the reader to explicit jobs, reject duplicate local labels,
admit only the exact two first-shard suffixes and complete public uploader, and
copy the one missing helper. Original action equality and source guards remain
intact; checks now also cover preparation in both shard jobs. Fresh focused GREEN,
final managed validation and all five exact-SHA workflows follow this checkpoint.

The next delivery, `9a6d4b3cf4850750253af8339a12b9d7b425e5f1`, passed
all seventeen managed prepush checks, including 6,761 pooled tests with 187
platform skips. Android, Linux and macOS packaging passed on that SHA. Windows
then failed its tooling fixture step with twelve failures and 41 errors; Fast
Checks' first shard failed five whole-observer cases at `boot-binary-trust`;
the second shard failed five preparation cases at `source-lock-birth-changed`.
Neither the local receipt nor the three successful workflows qualifies this SHA
as a completed delivery. Complete logs, exact pushed beforeimages and the
53-block Windows diagnosis remain in
`.runtime/mcp-ci-9a6d4b3c-windows-full-v1/`; the Linux five-block log is in
`.runtime/mcp-ci-9a6d4b3cf4850750253af8339a12b9d7b425e5f1-fast-main-failure-v1/`.

The second Fast Checks shard's completed log records 3,562 tests with one
failure, four errors and 115 platform skips. All five cases hit the same earlier
source-lock birth guard. The fixture invokes the actual read-lock constructor,
which observes a positive Linux process birth, then writes the synthetic value
123 into its private process table. The unchanged production closing guard
correctly refuses that inconsistent identity; Darwin's unavailable process birth
had masked the fixture mismatch. The fix retains the observed positive value and
uses the existing synthetic value only when the original constructor has no birth.
Its preserved-source regression must exercise actual closing checks over owned
physical source/process-table files, with an explicit Linux metadata model on
Darwin and the original five genuine Linux cases still required in CI. Evidence
and exact pushed beforeimages are in
`.runtime/mcp-ci-9a6d4b3cf4850750253af8339a12b9d7b425e5f1-fast-shard2-once-v1/`.

Managed prepush v17 was deliberately stopped before this further edit. Exactly
one guarded signal went to its owned runner; the SDK, runner, worker, descendants
and fixture closed, the same pinned lease inode is free, and source closing stayed
`a85806323c5a781f7c6bfe404c163e7b163ccbe10f1a83699f861c1071c0d12e`.
Its 1,222 partial observations comprise 1,219 successes and three skips; there is
no completed unittest aggregate or passing receipt. Evidence remains in
`prepush-final-v17/cancellation/`. Fresh final checks are required after the fix.

The next test-only repair preserves production sources and historical authority
pins. Exact Git attributes protect authenticated C#, PowerShell and provenance
bytes. Historical public source labels use held source without importing POSIX
coordinators merely to obtain filenames; remote Linux recipe fixtures use a
scoped POSIX path view, with physical POSIX custody cases explicitly marked by
capability. Portable helpers retain their actual source. Other corrections use
binary fixture reads, disjoint case directories, strict UTF-8 bytes and the
existing authenticated complete-program carrier with unchanged bounds. The Linux
whole-observer fixture supplies a fresh owned executable copy under the existing
current-UID trust policy, with source generation and copy closing checks.

Finite preserved-source regressions cover checkout conversion, source context,
Python fixture IO, complete PowerShell transfer and owned executable preparation.
All five groups reproduced authentic-source RED and passed the same positives
GREEN on both Python 3.12.15 and 3.14.3, with unchanged source and closed owned
children/streams. The checkout routine passed eight controls; source context ten;
owned binary six; Python IO five; PowerShell seven with one honest native skip.
Original consumer batches also passed. Evidence remains in each failure packet's
focused or wave1 directory and `focused-final-v17-freeze-v2/final-closing.json`.
Selection first refused a missing original campaign-test digest; preserving that
failure and adding only the exact pushed baseline digest passed the same gate.
Original applicable native cases and fresh final managed prepush remain required.
The native decoder parameter collision remains a candidate until the old/current
Windows pair runs.
The native target-owner failure has no retained stderr and its cause remains
unknown; the exact original factory and assertions remain, with both streams
included in the status assertion. No synthetic result qualifies that native case.
All four new Windows regression modules are explicitly enrolled in package CI.

A private read-only CI collector separately confused dynamic run titles with
workflow names. Its original incomplete result is preserved. A corrected private
collector binds workflow identity to the exact pushed manifest, definition IDs,
paths, attempt and SHA, and treats skipped optional jobs as metadata rather than
missing logs. The old collector was identity-checked, stopped once and reaped;
all 49 owned CLI readers closed before edits. This diagnostic repair changes no
production MCP authority or CI outcome. Original failed runs remain failed.
Previously closed VMs and connections remain closed, and the user's identified
SSH client remains excluded from cleanup. No product-native or visual work resumes.

The current repair plan and copyable prompt are:

- `.runtime/mcp-repair-handoff-2026-10-15/plan.md`
- `.runtime/mcp-repair-handoff-2026-10-15/next-agent-prompt.md`

The original Windows plan remains preserved at
`.runtime/windows-only-handoff-2026-10-14/plan.md`.
The previous detailed WIP and capsule are retained in the new handoff's
`before-handoff/` directory. Full evidence remains in
`.runtime/agent-tool-reproducibility-audit-2026-10-15/`.

## Repair snapshot before final validation and delivery

Dirty dev work is based on `e167a73ee8acd7fbb9844380dc12f310f537d0e6`.
The original full audit is terminal FAILED: 7,074 tests, 177 failures, 62 errors,
189 skips; all owned audit workers closed. Its failures and the four later focused
failures remain preserved. Current focused CP117 (324 tests, 75 Windows-only
skips), SSH/tmux/keeper (269), residual/native routes (52), source loader (13)
and dependency selector checks pass after reviewed repairs. The selector also
applies every matching finite declaration to statically resolved source readers;
an explicit declaration cannot silently disappear when a loader becomes static.
These focused results
do not replace the final affected selection, intentional full audit or prepush.
The old MCP process's unresolved Linux loader reflects stale loaded declarations;
fresh selection also exposed missing archival mappings. Finite reviewed mappings
and source-mutation refusal tests repair the latter without widening authority.

Both original hosted fixture builds succeeded. DIRECT collection verified;
MCP build run 38698053628 is complete but its original artifact is not collected.
Neither validates current dirty source. At this snapshot, no final version bump, final managed
prepush, task commit/push or current-SHA CI has occurred.

The owned secured Windows deployment 71872a25-5f16-496f-957f-8b1133eccf7a
has no app installed and productReady=false. All six prior QEMU guests and their
TPM are stopped; the historical SSH tunnel and its autostart job are stopped.
The expanded closure includes SSHFS mounts and the old ADB server. The old tunnel
LaunchAgent and both SSHFS keepers have persistent autostart disabled; their
definitions remain preserved. Closed things must not be restored. Fixture files,
original outcomes and reservation bytes stay
preserved. Historical disk cleanup is already complete; do not repeat it. The
host VPN and service infrastructure remain intact. Closure evidence is under
`.runtime/session-reset-2026-10-15/` and
`.runtime/session-keeper-no-restore-2026-10-15/final-state.json`.

## Current ownership and evidence

This intentionally spans source loading/selection, saved-file SSH transfer,
argument-driven VM infrastructure, observer/ownership guards, route fixtures,
causal tests, Windows CI enrollment and agent procedure documentation. Product
code, native runtime binaries and deferred product acceptance stay outside scope.
The coordinator owns this ledger, final scope review, versioning and delivery.
Separate workers own dependency declarations, CP117 route fixtures, SSH/tmux
fixtures and pin chains, residual audit tests, and environment session closure.
An independent reader reviews the full public tool surface. Source edits began
only after the original audit's three workers were reaped, their sessions absent,
fixture roots removed, and a fresh local census found no active test bracket.

Current execution evidence is `.runtime/mcp-repair-execution-2026-10-15/`.
The original handoff/audit evidence remains unchanged. Focused checks precede a
final source freeze, affected selection and intentional full audit; the final
managed prepush receipt must follow the final content and version edit.

Focused repair evidence:

- `.runtime/mcp-repair-cp117-routes-2026-10-15/repair-evidence.json`: route mocks,
  oversized self-source harness, exact historical labels and sealed context;
  original harness RED and current GREEN, with production guards retained.
- `.runtime/mcp-repair-ssh-2026-10-15/summary.json`: frozen/current authority,
  current tmux pin chain, explicit account/home fixtures, keeper closure source
  graph and invalid-host configuration reads; causal RED/GREEN and no native effects.
- `.runtime/mcp-repair-residual-tests-2026-10-15/summary.json`: sticky temporary
  ancestor seam, explicit timestamp pyc, AST route namespace, finite route mocks
  and complete captured policy copies; actual before/fix outcomes retained.
- `.runtime/mcp-repair-handoff-2026-10-15/dependency-repair/summary.json`: finite
  dependency declarations and unknown/mutated-source refusal, with actual RED/GREEN.
- `.runtime/agent-tool-reproducibility-audit-2026-10-15/cached-recovery-custody/causal-receipt.json`:
  three cached recovery/probe imports replaced by request-scoped source loading;
  identical RED/GREEN assertions cover seven routes and closing drift.

The macOS historical staging start is fenced because it implicitly selected a
previous Tart guest/account. Its separate explicit-context staging path has 43
passing controls, including physical current-Mac filesystem and boot observations,
bounded transfer/capture and artifact closing. It neither starts/restores a guest
nor establishes deferred product acceptance. Evidence is
`.runtime/mcp-repair-execution-2026-10-15/macos-generic-stage/test-evidence.json`.

Fresh SSH channels take an explicit configured host and isolate new journals by
that host. Historical global journals retain original read/closure authority only;
UNKNOWN correlations cannot be replayed or adopted. Channel selection follows
the actual configured aliases and refuses unavailable explicit selections.

Automatic oversized SSH programme handling passed 38 canonical focused checks
with no skips and six actual causal RED/GREEN pairs.
The existing operation owner selects saved-file transfer before submitting a
generated Python carrier that would exceed 60,000 bytes. A private immutable plan
binds source, route and configuration; bounded chunks carry the complete file,
then a short filename/hash loader executes it once with the original stdin.
Ambiguous failures remain UNKNOWN. Unsupported oversized forms refuse before
effects. This is internal transport for existing admitted operations, not new
arbitrary remote execution authority. Native transfer validation and the full
audit follow this snapshot; old sessions are never restored for these checks.
Evidence is
`.runtime/mcp-repair-execution-2026-10-15/ssh-automatic-program/evidence-owned-final.json`
and `canonical-final-after-loader.log` in the same directory.

The final generic SSH slice passed 157 checks with no skips; the original keeper
slice passed 40. Evidence is `.runtime/mcp-generic-channel-context-2026-10-15/summary.json`
and `.runtime/mcp-keeper-legacy-fence-2026-10-15/summary.json`.
The standalone source loader now authenticates its custody primitive before
executing it. An actual preserved-source RED proves the previous symlink ordering
failure; 26 focused checks and three compatibility checks pass. Four native
Windows checks skip locally and are enrolled in Windows package CI. Evidence is
`.runtime/mcp-source-loader-bootstrap-2026-10-15/summary.json`.

Fresh MCP checks exercised all 12 tools and the inert native transfer passed
DIRECT and MCP with unchanged original records and no restored sessions. The
first full audit then stopped at its serial close gate because reviewed current
dependency pins still named the transport before automatic submission. That
failure and all beforeimages remain in
`.runtime/mcp-repair-execution-2026-10-15/full-audit-v4/`. Reviewing 14 current SHA
bindings across 11 files restored the current chain; 206 checks completed, with one
expected skip for absent historical state. Historical source and authority pins
remain unchanged. Evidence is
`.runtime/mcp-current-pin-refresh-2026-10-15/summary.json`.

The native execution catalogue also needed the one new fixed automatic helper
declared. Actual preserved-source RED and GREEN cover the original future driver,
held-helper capture and unknown/missing dependency refusals. Its 22 checks and a
59-check entrypoint/close/resource slice pass. Final selector controls pass 102
checks; 1,505 current/baseline source versions have no unresolved mappings. The
affected plan selects 499 of 556 modules; the intentional audit covers all 556.
Evidence is `.runtime/mcp-native-catalogue-automatic-2026-10-15/summary.json`
and `.runtime/mcp-repair-handoff-2026-10-15/dependency-repair/final-summary-v3.json`.

The next intentional audit passed its 27-test serial close gate. Its 555-module
pool completed 7,228 tests with 22 failures, seven errors and 191 skips; all three
workers closed, and source was unchanged. All 24 modules that failed in the
original handoff audit passed in that run. The 29 additional failures came from
stale fixtures: an empty selected route, incomplete private SSH inventories,
iteration of guarded oversized plans, an inline PNG producer hitting the command
bound, a process-wide Windows platform mock, a missing authentic original host
producer, a formerly restricted valid host alias, and an oversized inert diagnostic
bootstrap shared by the gateway reconciliation tests. The unfixed sources and
complete failure logs remain in
`.runtime/mcp-repair-execution-2026-10-15/full-audit-v5/`.

Eleven exact original cases reproduced RED before the test-only repairs and
passed GREEN afterward. The expanded 11-module slice then passed 352 tests with
21 justified platform skips; all 29 audit failure identities and the new
oversized-diagnostic non-dispatch control passed. This retained the historical
compression/source assertions, source and ownership guards, and 60,000-byte
command limit. Two existing finite dependency declarations gained reviewed current
test hashes without changing their scopes or dropping historical versions.
The final parser reviewed 1,513 source versions with no errors, and 102 selector
checks passed. Evidence is `.runtime/mcp-audit-v5-fixture-focused/` and
`.runtime/mcp-repair-execution-2026-10-15/original-failure-reconciliation-v2.json`.
At this checkpoint, the final native qualification, version note, managed prepush
and exact-SHA delivery verification still follow; none of these earlier results
is a final prepush or CI receipt. Prior VMs and connections remain closed.

The subsequent automatic SSH qualification executed its saved program with the
expected exit 23, complete stdin and both output EOFs; its remote journal verifier
exited 0. The private collector then counted its authority file as a fourth wire
event. That original UNKNOWN and all beforeimages remain unchanged. A separate
read-only inspection validated the three exact events and source closing without
any replay or new connection. The exact preserved collector fragment reproduced
RED, and the same positive assertion passed with explicit event admission. Its
nine routine controls and 38 automatic-program peer checks passed without skips.
An earlier wrapper import failure is retained separately and is not causal RED.
The final dependency parser reviewed 1,515 source versions with no errors; all
102 selector checks passed and the plan selects 500 of 557 modules. Evidence is
`.runtime/mcp-native-automatic-closure-2026-10-15/`. Final stage qualification,
managed prepush and exact-SHA delivery remain separate gates.

Review then found a POSIX permission assumption in the synthetic collector test
wrapper. Its preserved code reproduced RED with an isolated writable Windows
mode projection; the pure input fixture passed the same assertion, and all 47
collector and automatic-program checks passed without skips. The exact original
fragment and production custody guards remain unchanged. This routine collector
module is also enrolled in native Windows package CI. Evidence is
`.runtime/mcp-wire-evidence-windows-portability-2026-10-15/`. The first final
prepush was intentionally cancelled before this edit: all owned workers closed,
its 1,212 partial test observations had no failure, and no successful receipt is
claimed. A new final prepush is required.

Final native staging and refusal checks completed under their recorded source
bracket. A separate strict census found two interactive SSH connections; the
user's explicit instruction to close all connections authorized their exact
identity closure. The subsequent census found no VM/SSH actors or SSHFS mounts,
with keepers disabled and prior records unchanged. Original failed census
observations remain failed; their original cause was not recorded, and no later
observation rewrites them. Nothing was restored. Evidence is
`.runtime/mcp-native-final-2026-10-15/final-native-v6-closure.json`.

Never change captured source/policy/dependencies while a tool/native/test source
bracket is active. Inspect original terminal/closing receipts before any replay.
For every failure, preserve original evidence and unfixed source, obtain actual
causal RED/GREEN and enroll required coverage without weakening production guards.
Finish the MCP repair with reviewed scope, version_bump, fresh managed prepush,
explicit reviewed paths and origin/dev push, then all five required workflows
green for that exact SHA. No release or main merge.

### 2026-10-16 — remaining MCP audit fixtures

The intentional full audit of all 576 discovered modules closed with a failed
575-module pool: 7,392 tests, two failures, one error and 195 platform skips.
All three affected modules had passed the earlier managed prepush. The audit's
restrictive umask and empty Python cache exposed additional fixture assumptions:
an intended public directory became private, the conversation deadline expired
before its intended stdout EOF phase, and a bytecode test used the parent's cache
location instead of the isolated child's normal cache. Original source, complete
streams, exact tracebacks and natural process closure are preserved in
`.runtime/mcp-repair-execution-2026-10-15/full-audit-v6/`. That audit remains
failed. The preceding 53 validated paths were saved locally as `ce740ac`; this
checkpoint has not been pushed and grants no passing full-audit claim.

The remaining changes belong to the same MCP repair. Fixtures explicitly set
and verify their intended permissions, allow one existing protocol slot for the
complete cold conversation while preserving deadline UNKNOWN and non-replay
assertions, and calibrate the isolated child's actual pre-guard cache location.
Coverage includes both permission masks, controlled startup latency, physical
EOF evidence and the authentic old bytecode fixture in real copied layouts.
Production ownership, source, deadline and non-replay guards remain unchanged.
The preserved old sources and current scenarios still require actual causal
RED/GREEN, followed by a passing intentional full audit, a fresh managed prepush
and all five workflows for the final pushed SHA. No closed environment is
restored, and product parity, H14 and product-native/visual work remain deferred.


### 2026-10-16 — exact-SHA tooling fixture follow-up

Commit `30901b9f793f72534dae3441e45b67c3587719e8` reached origin/dev after
all seventeen managed prepush checks passed. Its intentional full audit covered
581 modules and 7,462 tests, with 201 justified platform skips. Those receipts
qualify that source only. Android, Linux and macOS packaging succeeded, but
Windows and Fast Checks failed; this delivery remains incomplete.

Windows preserved 77 failure/error blocks (six failures and 71 errors) from its
527-test CP117 batch. The earlier 67-test native batch passed with nine skips.
The complete original logs, exact pushed source archive and cause ledger remain
in `.runtime/mcp-ci-30901b9f-windows-failure-v1/` and the matching read-only
collector directory. Fixture causes include incomplete finite public-source
contexts, a POSIX recipe context that ended before complete program production,
text-mode writes of authenticated source bytes, and task extraction that selected
a nested catch instead of the outer catch and complete finish branch. The command
cap and native successor cases must be rerun after these earlier guards pass.
The production source, custody, ownership, non-replay and validation guards remain
unchanged.

The stage guard reported source refusal without retaining the two actual hashes;
which raw pin differed remains unknown. The exact tracked ACL helper is eligible
for Git newline conversion, so targeted attributes and real Git checkout controls
will prove this concrete byte-authority gap without refreshing either sealed pin.
The same finite audit identified two additional guarded public credential inputs,
`windows_task_admission.ps1` and `windows_credential_validity_qga.py`; these are
newly discovered eligibility gaps, not observed original credential failures.
Each unchanged guard gets independent checkout coverage. Private operational
inputs remain outside the inert public-source registry.

The native module control also overconstrained missing commands and admitted only
Cmdlets although a genuine PowerShell function can implement Get-FileHash. Its
original command types were not retained. The fix requires actual trusted module
and command-type provenance, the existing physical ACL/hash oracle, and a third
fresh native invocation of the exact retained C script against the same data and
sanitized environment. A portable typed-filter model is separate evidence. Native
proof must observe the function and the exact original predicate RED; it cannot
conditionally pass when either is absent. The original PowerShell parser error
IDs/extents were likewise unretained; new parse-only old/current controls preserve
them while keeping both original native task scenarios mandatory.

Fast Checks completed its agent-test stages, then failed installing pinned NDK
28.2.13676358 with `Error on ZipFile unknown archive`. The downloaded archive was
not retained, so the external acquisition cause remains unknown. Complete main
and verifier logs plus the exact workflow and preparation script are preserved;
no product defect or reproduced source RED is claimed for that download failure.

The original CI collector ended naturally with failure. All 244 accepted HTTP
children, readers and full output streams closed; all 3,012 frozen source rows
were unchanged, and HEAD matched origin/dev. Its independent closing receipt is
`collector-independent-closing-v1.json` in the matching collector directory.
Only then did the reviewed fixture edits begin. Required coverage uses the same
positive assertions on preserved unfixed source and the fix, both Python 3.12.15
and 3.14.3, genuine Git checkouts, and the enrolled Windows native tooling cases.
Fresh full audit, managed prepush, normal version note and all five workflows for
the next exact pushed SHA remain required. Previously closed VMs and connections
stay closed; product acceptance, H14 and visual work remain deferred.


The fixture follow-up is now focused GREEN on both Python 3.12.15 and 3.14.3.
Seven actual before/current positives per interpreter cover the complete source
context and module hooks, including an explicitly portable command-type model.
The unchanged old caller expressions also reproduce incomplete outer/final and
finish sections; all three independent real Git checkout guards reproduce RED
with the exact C attributes and pass GREEN with targeted byte rules. Per runtime,
the context/environment peer batch passed 93 tests with four genuine native skips,
and the caller/checkout batch passed 269 with 64 native skips. These overlapping
focused counts are not a full-suite aggregate or local Windows acceptance.

A final evidence audit found that successful native causal tests swallowed their
captured stdout and discarded temporary evidence with the runner. The retained
uncommitted source has its own original fingerprint, not an invented Git commit.
Actual old ca1 nested file writers and the complete e97 caller method reproduced
the missing-receipt assertion on both interpreters; the same positives passed with
the fix. Four new portable binary/partial/typed controls and the complete 16-test
environment module passed, with one genuine native skip. The complete 10-test
caller module passed with two genuine native skips. Nine strict caller controls
reject replayed, missing, reordered, altered, foreign and malformed frames.

The logger retains exact public synthetic streams, terminal flags and existing
native proof dictionaries. Ordered 8,192-byte chunks, unique capture identities,
whole-stream hashes and complete manifests fit the unchanged 16,384-byte collector
line guard; neither the native calls nor their acceptance assertions changed.
Synthetic portable markers are contained and cannot qualify a native case. The
new authenticated before-fragment has one additional exact byte rule, bringing
this follow-up to six targeted rules. Source/dependency guards remain strict.

All 102 selector controls passed on both interpreters in the first focused freeze
and again on the current interpreter after the logging-only delta. The final
finite parser checked 1,421 current and changed-baseline source versions with no
errors; selection is 514 of 581 modules. Independent closings qualified all known
children, captured EOFs and unchanged source/HEAD before any further edit.
Evidence is in `.runtime/mcp-ci-30901b9f-focused-v1/`,
`.runtime/mcp-ci-30901b9f-focused-v2/` and the referenced owner packets.
The final version note, fresh MCP surface check, intentional full audit, managed
prepush and all five exact-new-SHA workflows still follow this checkpoint.
Original failures stay failed and preserved; nothing closed is restored.

The next delivery, `fd4a3c77e8935c4c5669e61a26bbfca41e171850`, passed
Fast Checks and Android, Linux and macOS packaging. Windows failed two native
batch assertions because an inert fixture executed a target-Linux definition
prefix that imported unavailable `fcntl`. Its CP117 batch did not run. The full
original logs, exact source archive and closing receipts remain in the matching
`.runtime/mcp-ci-fd4a3c77*` evidence directories. All original collection actors
and streams closed before the ten reviewed fixture/dependency paths changed.

The fixture now copies the authenticated AST, removes only the proven unused
target-only import and exact timer setup calls, and leaves emitted program bytes,
source pins and complete operation assertions intact. Finite review also found
the same assumption in direct and copied Dismiss fixtures. Independent missing
capability models distinguish these predicted paths from the observed native
failure; the signal-only model honestly requires POSIX, and genuine Windows
counterfactual evidence remains a required CI case. A focused run then exposed
escaped nested traceback text in the test harness. Its full original trace and
unfixed source are retained; joining raw tracebacks fixes reporting while keeping
the exact-cause check. The same aggregate reproduced three failures on the real
unfixed source in both Python runtimes; its diagnostic subcase passed after the
one-line fix, while two further source-context failures remained preserved.

The direct and copied old modules then exposed a missing compression-fixture
lifetime: they are isolated from the module cache, and their decorated methods
do not expose the original producer through wrapper globals. Supplying those
actual modules to the existing scoped historical gzip context preserves the
original generated-source guard and global standard-library behavior. The exact
unfixed aggregate and both-runtime fixed positives retain this causal evidence.

Both-runtime focused fixture and finite dependency checks passed before this
checkpoint. The four authentic beforeimage/provenance resources and only the
reviewed dependency edges join the existing dirty bucket. Original failures stay
failed; prior audit and prepush receipts do not cover this follow-up. Fresh full
audit, managed prepush and all five exact-SHA workflows remain required. Closed
VMs and connections stay closed; product acceptance, H14 and visual work remain
deferred, and no release is authorized.

The next frozen full audit retained 7,496 test outcomes, including 23 errors and
204 platform skips. Managed prepush stopped at its fifth command with the same
22 Windows errors; four preceding commands passed and twelve were not started.
Its older global receipt was rejected. Both failed runs ended naturally, with
all owned workers, sessions, streams, fixtures and source captures closed before
further edits. Their full original traces and source archive remain in
`.runtime/mcp-repair-execution-2026-10-15/full-audit-v10/` and
`.runtime/mcp-fd4a3c77-repair-2026-10-16/prepush-final/`.

The Windows errors were a missing helper name in copied function source. A real
local import now travels with the common function. Full-inventory review found
thirteen current copy sites in ten consumers and four retained copies. The new
routine regression copies the actual function into the legacy namespace and
runs its unchanged positive, stale-child and foreign-listener assertions. The
preserved unfixed function produced three exact NameErrors on both interpreters;
the same assertions passed after the fix.

The separate cleanup error was a cached-versus-fresh ancestor generation
mismatch. The original trace did not retain which ancestor or field changed.
A controlled sibling mutation reproduced the exact predicate on the preserved
method; the same positive passed using the existing test-owned root boundary.
Actual root and descendant generation guards, producer pins, the 155-record
tuple assertion and the old cleanup TypeError remain intact. Three routine
controls cover the sibling mutation, owned-tree tampering and eight partial
admission cleanup points. Cleanup begins before any descriptor admission.

The strict focused process check also caught four descriptors left open by the
provider credential test's two in-process generated operations. A separate
import-only check opened none. Each actual operation owned a parent directory
descriptor and a job directory descriptor. The test now closes those exact
namespace-owned handles in nested cleanup, after checking their path identity,
private directory mode, owner and noninheritance; it verifies EBADF immediately
and checks the whole descriptor set on exit. The preserved test leaked four
handles on both interpreters and the same original assertions passed without
leaks after the fix. An initial private proof used the wrong copied repository
layout and was refused for the wrong cause; that failed attempt remains failed.

This follow-up changes three test files. Both-runtime focused checks and ordinary
dependency selection qualify their actual canonical source before the next
normal version note, full audit, managed prepush and exact-SHA CI attempt.
The manifest needs no new opaque loader or digest update. Original failed
receipts stay failed; closed environments stay closed. Product acceptance, H14,
visual work and release remain deferred.

The next exact development commit, `a59ad586d64d2d5359be92ed4255e9981b426298`,
passed Android, Linux and macOS packaging but failed Fast Checks and the Windows
native MCP checks. All original job logs, beforeimages and source proofs remain
preserved. Fast's main job stopped at the first real Gradle configuration-cache
probe, while dependency POM resolution failed. Its underlying HTTP/backend cause
was not retained and remains unknown. The skipped shard-zero artifact and failed
coverage verifier are consequences of that earlier failed step.

Windows retained 86 native test outcomes, including five failure events and ten
platform skips; CP never ran. Four failure events reached actual programme
emission with no archived base bound to the recovery closure. The remaining
native counterfactual inherited the historical factory loader's inert importer,
so the old diagnostic incorrectly passed. The testcase coordinator now holds
the existing authenticated full base through the actual before/current calls
and restores the original reference. Executable archived testcases compile
their verified original bytes with genuine coordinator builtins and their real
retained filename/package. The pure production-factory loader, QGA bytes and
producer pins remain unchanged.

Two new routine controls exercise the actual missing-base and importer
boundaries. Preserved whole-E source produced two and four subtest failures on
both Python versions; the same controls passed on the fix. All nine candidate
boundary cases passed with one genuine Windows-only skip. Static propagation
review found no additional instance across strict MAIN73 and CP45 cases. Those
original native Windows scenarios remain mandatory in the next exact-SHA CI.

The Gradle probe already captured both complete streams but discarded their
prefixes when reporting each failure. It now retains those complete captured
streams. The same early-detail regression failed on the whole original E probe
and passed on the fix on both interpreters. Five routine cases preserve first
and second failures, missing-reuse refusal, actual argv/two-probe success and
the original timeout, without retries or real Gradle/network calls. Hygiene
runs these cases verbosely before the unchanged real two-probe check; the probe
and its new routine script are covered by the existing PR path filter. This is
a diagnostic-retention repair, not a claimed fix for the unknown resolver cause.

Only the new, executed controller digest is appended to its existing dependency
declaration. All previous 174 rows, scopes, accepted versions and fifteen
resource pins remain intact. This MCP-only follow-up deliberately spans its
test coordinator, diagnostic script, hygiene wiring and workflow selector.
Completion requires fresh managed checks and all five workflows successful for
the final pushed SHA. Closed environments remain closed; product parity, H14,
visual acceptance and release remain deferred.


The next exact development commit, `3a7f6d3414f25c232f2512112ed527c819a7bb21`,
reached the Windows CP117 batch after its main native tooling checks passed.
The CP117 batch retained 532 outcomes: four failures, four errors and 157
platform skips. Its complete original log, eight trace blocks and exact 372-file
source archive remain in `.runtime/mcp-ci-3a7f6d34-windows-failure-v1/` and the
matching exact-F collection directory. All five exact-F runs then completed:
Fast Checks and Android, Linux and macOS packaging succeeded; Windows failed.
The collector and every owned actor, raw stream and source capture closed before
any source edit was authorized. That failed delivery is not relabeled successful.

Five fixture failure types are addressed in one explicit MCP-only bucket.
Four Dismiss cases lost the archived base when their module ran independently;
the module hooks now hold the authenticated historical base, recovery reference
and public-source context for the complete unittest module lifetime, including
setup-failure cleanup. The preserved whole F module reproduced the four actual
`_QGA` errors; the same four original positives passed with the lifetime fix on
both supported Python interpreters.

The cold PowerShell check used a command lookup that could alter the catalog it
was observing. The new source-selected observation avoids autoloading and
retains exact before/after counts. The preserved guard failed and the same
positive passed against a real, explicitly controlled PowerShell catalog on
both interpreters; six routine controls also passed. This component proof does
not identify which branch caused the original Windows PowerShell 5.1 compound
refusal. The actual physical ACL, hash, environment and exact-old-script native
scenario remains required on Windows.

The successor constructor emits a source witness before its terminal record;
the caller had required the terminal record to be the first bytes. The strict
observer now accepts exactly the complete two-record grammar. A separate writer
control wrongly required an authenticated stdin frame for the original bounded
inline parser call. Its actual raw trace retained `authenticated-frame-required`.
The correction recognizes only that declared finite inline shape and preserves
its source, command and transfer bounds. Both components have actual preserved
F RED and fixed GREEN evidence. Full failure streams now travel through a small
public chunk schema after the owned child returns, with byte counts and hashes,
8,192-byte chunks and the unchanged 16,384-byte collector line limit. The
constructor's earlier unreported child branch is not inferred from this proof.

The task-consumer fixture inserted an unescaped single quote inside an existing
single-quoted generated literal. Its replacement uses the matching double-quote
form. The actual preserved method failed the complete emitted-source contract
and the fixed method passed on both Python versions. A genuine owned Python
failure child separately proved that the original nonzero return guard still
fails, that the unfixed caller loses its diagnostics, and that the corrected
caller retains both complete streams through the existing bounded carrier.
These controls assert the real coordinator importer and held source generation;
they do not fabricate a PowerShell result. The original Windows task-consumer
failure retained only `1 != 0`, so its underlying native child cause remains
unknown until the unchanged native scenario and new native counterfactual run.

All frozen production bodies, action hashes, semantic pins and acceptance
assertions remain intact. The shared base test stays below its existing one-MiB
source guard. Six authentic beforeimage/provenance resources are added. The
raw-hashed Shortcut JSON and retained enrollment YAML receive only their exact
byte-preservation rules; parsed-only provenance does not gain a raw byte guard.
The merged dependency declaration preserves all 174 existing rows, prior
versions and fifteen resource pins. It appends seven finite lists across four
existing rows and one new five-input declaration for the enrollment regression,
for 175 rows total.
Private source-controlled checks completed with actual RED/GREEN on Python
3.12.15 and 3.14.3. Their owned actors, raw streams and source handles closed
before integration; honest platform skips are not native success.

A sixth failure type was found by strict native coverage verification. Four
required Temurin cleanup methods had no native start or finish records; only
55 of the required 59 Linux identities qualified. The successful 511-module Fast
union does not establish those four native cases. The ordinary Ubuntu package
job now explicitly invokes the exact cleanup class verbosely after its unchanged
native-JDK launcher command, under the existing unconditional Temurin 17 setup
and fail-fast step. The preserved whole F workflow produced the exact missing-
enrollment failure on both interpreters; the fixed same positive and six routine
controls passed. The controls reject conditional, dispatch-only, ignored,
duplicate and launcher-dropping enrollment. The original 59 identities and
coverage guard stay intact: those four cases must run successfully in the next
actual Linux job, while the other 55 retain their actual Fast provenance.

The reviewed sixteen-path code and evidence batch was applied after both
exact-F verification processes and their source readers closed. The source
bridge verifies the exact 3,031-to-3,038-file change, preserves all nine original
physical modes and creates the seven new files privately. Every other source
byte and mode remains unchanged. The batch still needs fresh focused checks,
the normal final version note, the intentional complete agent audit, managed
prepush and all five workflows successful for the next exact pushed SHA. The
earlier failed receipts stay failed. No VM, SSH connection, job or lease is restored, replayed or purged.
Windows product parity, caller product acceptance, H14, product-native and visual
work remain deferred; no release is authorized.


The final static review also found an LF-only assumption in the new Linux cleanup-enrollment test. The preserved `b4990b38` test fails its actual positive on a physical CRLF workflow; the reviewed `bb9f2913` parser accepts LF and CRLF after raw evidence verification, rejects lone CR, and keeps all hostile workflow controls effective. Both Python 3.12.15 and 3.14.3 proved that same positive RED before the fix and GREEN afterward; all six current cases pass without skips. The eight owned children, all streams and held inputs closed in `.runtime/mcp-ci-3a7f6d34-temurin-coverage-v1/crlf-repair-v1/actual-focused-v1/closing.json` (SHA-256 `ea73f9fa64f4776f108f503d1edb9717907b72faf54816ea53ab060091661dc5`). This is a portable source-input regression, not a claim of native Windows acceptance. The finite dependency declaration only appends this reviewed source digest; all previous entries remain.


The final managed prepush exposed a separate Windows packaging-graph fixture
failure: its second successful Gradle invocation reran the native-helper task
instead of reporting UP-TO-DATE. The original log did not retain Gradle's
invalidation reason. A closer diagnostic of the unchanged actual test, with
the known relative Python cache prefix and only --info added, reported newly
created cache directories under the native source file-tree input. This is a
measured reproduction; the original run's unrecorded invalidation reason is
not inferred from it.

The fixture now gives Gradle's Python children a fresh absolute cache under
the owned fixture root, outside the native input tree, through a copied child
environment. The original three-call test routinely supplies a hostile
relative parent prefix and allows actual bytecode writes; its UP-TO-DATE,
intentional bundled-runtime mutation and installer assertions remain strict.
No Gradle inputs, outputs, task policies or product runtime source changed.
The existing nine cases remain in Fast Checks and managed prepush.

The authentic before and reviewed fix each ran the same real Gradle positive
on Python 3.12.15 and 3.14.3. Both before cases failed only the UP-TO-DATE
assertion after the measured cache-directory invalidation; both fixes passed
all three invocations, including the deliberate runtime rebuild. All four
children, ten Gradle calls, streams and held source descriptors closed, the
parent environment was restored, and all 3,038 frozen source bytes and modes
remained unchanged before integration. Full raw output and physical projects
are retained with the causal summary c0adfd1b5d20c23af93c168c6145a00a4472be40c3ddb9dd0ee2d8964f41d90a.
The new content still requires its canonical focused checks, a final version
note, a fresh managed prepush and all five workflows for the next exact SHA.


Exact development SHA `dff1f4723f323909109d62f845ec1e3e10eec4f6` reached
the Windows CP117 step and failed one of 555 tests (157 skipped). The complete
767,186-byte job log remains SHA-256
`544b6761525b98ee169a2be58b8c1c91ab598a29fb817748808b2fb01b4694cb`,
with the original failure packet `fd7c90c95aa19fe7e86cb25a93667bc7ebd5dc9e12b0f7f27620d4b6329c9f79`
in `.runtime/mcp-ci-dff1f472-windows-failure-v1/`. The controlled native child
returned `PUBLIC_NATIVE_HASH_MODULE_RUNTIME` before the expected missing-command
outcome. Its actual ModuleBase, Module.Path and PSHOME operands were not printed,
so the underlying comparison cause remains unknown. The original F native
inner failure remains unknown as recorded earlier; this checkpoint does not
claim either native cause fixed.

The reviewed change adds diagnostic output immediately before the same module
root comparison. It reports 35 public command/module/runtime/process-environment fields (including the child process PSModulePath presence and value) through
bounded UTF-8/Base64 records: at most 4,096 bytes per field, a 262,144-byte
aggregate diagnostic bound and 16,384 bytes per rendered line. Diagnostic
collection is best effort and cannot admit the command or replace the original
guard failure. Every existing module, runtime, ACL/hash, cold-state and native
assertion remains unchanged; the saved-file carrier and 60,000-byte command
bound remain in force. This is a diagnostic checkpoint, not native acceptance.

Five isolated controls parsed the complete saved script and exercised null
function, null cmdlet, oversized-field and equal-base paths under the verified
portable PowerShell engine. All five children and their streams/source readers
closed in the model-only receipt
`.runtime/mcp-ci-dff1f472-module-provenance-diagnostic-v3/private-control-v1/closing.json`
(SHA-256 `820db5ae691d15a8f5e38884c430a03a51b05e6fe410e538dba3196130d935ab`).
These controls establish bounded, nonmasking diagnostic behavior; actual Windows
operands and the original native scenario remain required in the next hosted
run. The finite dependency declaration appends only this reviewed current test
digest, retaining all 175 existing loader rows, all 15 resource pins, every
historical digest, scope and reason.

This three-path checkpoint requires its own focused checks, normal version
note, fresh managed prepush and all five workflows for its exact pushed SHA.
Earlier successful G source receipts do not authorize the changed checkpoint,
and the failed G workflow remains failed. Windows product parity, caller
acceptance, H14, product-native and visual work remain deferred. No VM or SSH
connection is restored or created, no unknown job or lease is replayed or
purged, and no release is authorized.


### 2026-10-16 — MCP PowerShell provider repair after diagnostic checkpoint H

This remains the MCP-only repair bucket. Windows product parity, caller acceptance, H14, and product-native/visual work remain deferred. Historical VMs/connections remain closed and are not restored; original evidence, fixture files, unknown job/lease records and the protected user SSH client remain intact. Saved-file/chunked transfer, the 60,000-byte command bound, ownership, source authority, validation and unknown-outcome non-replay guards remain required. No release is authorized.

Diagnostic checkpoint `e14f6b04726885df28c0d49313f43dbf22752b01` preserves the original guard. Its actual Windows PowerShell 5.1.26100.33438 children both discover a genuine Utility `FunctionInfo` backed by the manifest and defining PSM1. Both selected and defining-script `ModuleBase` values are `PSHOME`; the old guard incorrectly requires the manifest directory. The copied empty-module-path environment and sanitized environment both reach that same guard and exit 1. This does not establish environment sanitization as the cause. The separately retained exact-C child exits 11 because its Cmdlet-only precheck rejects the observed Function. The historical F inner failure remains unresolved.

Original H job 116999730028, exact run 38908990406/attempt 1, full 775731-byte log SHA-256 `6b668cb3373b54355589e581419cc7dce11180947b211b895caad27f0efdd103`, two 35-field records and exact immutable source are retained under `.runtime/mcp-next-H-windows-provider-diagnostic-v8/actual-H-e14f6b04-once-v1/6c360b4c5fae41ad9c6e7f3e0ba748d6/`. Capture closing `ea57765089eec1415b8e6412829730d0a21c2cac1ac729e5f56f62745e6f42fc` and independent review `7c56e17709a13789097ef6d036ac2e60885ba9a2c3fdaf15ab7b45bbd5d791db` qualify capture and 16-reader/32-stream closure only. They do not prove native repair, unprinted nested-object identities or manifest encoding. H Windows failed; H is not an accepted final delivery.

A separate actual PowerShell parser failure was preserved before repair: null `EndBlock.Traps` is the first failing `.Count`, with the two nested Traps collections likewise nullable. The original v3 source/raw failure ZIP `255f87f306e8af49dd8ba7829aa17fb93e3a82f962f8bc2b8582f01429ca5156` and typed diagnostic `96b8966619065bcd3bfe014d1b6f4b32ae5721c9c12ea7f72d1861bf21442fe9` remain. Actual same-manifest v3 RED/v4 GREEN, genuine empty-array acceptance and all three nonempty-trap refusals closed as `7c865299c480d6866981781bc946b6ab75efdf27290080f08fb82b93f701cf1d`. Mac Cmdlet export-graph/hash side evidence `fa6b19d8d5856cbad79d9ab7dd0b1855680a7ee41b93d2095abc75a7a5202c8c` is not Windows Function or ACL acceptance.

Diagnostic-only collector failures were also preserved: a missing README admission after the normal version roll, then a display-name versus workflow-path mismatch. Exact preserved-source predicates reproduced RED and GREEN on Python 3.12.15 and 3.14.3, retaining unexpected-path, SHA, repository, branch, event, attempt and bound refusals. V7 was explicitly stopped only during owned-reader-complete backoff, exit 130; its 16 readers closed without unknown outcomes. V8 completed naturally. None of these reader operations cancelled CI jobs or restored native environments.

Required coverage for the repair is the preserved G guard beforeimage versus current provider decision, real parser null/empty/trap cases, and the actual Windows manifest/nested-script/export identity plus ACL/hash operation. Exact C and environment sanitization keep independent evidence roles. Final current-source focused checks, fresh all-12 MCP verification, intentional complete agent audit, fresh managed pre-push checks, and all five required workflows for the final pushed SHA remain delivery gates; diagnostic or component passes cannot replace them.

The private component checks now closed without qualifying Windows repair. Python 3.12.15 and 3.14.3 each retained the authentic 433-byte G document-boundary same-positive RED, current GREEN, and five routine passes (closing `cdfdf85c733bdd5bfe7e0904e9c58136cf75fb20bcea3e7f566a9ccc9f1f1113`). The final actual PowerShell subset retained whole-program syntax success, old nullable-Traps parser RED/current parser GREEN with encoding, empty-array, trap and Function-schema controls, and authenticated H normalized-origin old-G-decision RED/current-origin GREEN with twelve refusals (closing `4729539a29270a030a2612fc0f4e3016881a4bcaf4c7fb19e95b30edaf9e3ae8`). All accepted children, streams, held sources and descriptors closed. The Python cohort used the preserved pre-comment candidate; the final producer differs only by the reviewed comment. These are component/source-causal results; the complete current Windows Function provider graph, physical ACL/hash positive, exact-G whole-script native RED, and independent exact-C control remain required on the next exact pushed SHA. No interim candidate digest is accepted as current source authority.

The first complete audit of frozen source `01ac055964d9df67649d425c3fe52aea57b2ec02913c842359df348cb5cac4c2` completed 7,532 tests with one failure, no errors and 211 skips. The failure was the inherited setup socket assertion at original line 46 of `test_ssh_gateway_tmux_ready_reconciliation.py`; the canonical-symlink test body was never reached. Its eight-second socket wait included unacknowledged startup before the deliberate 6.1-second delay. The original child startup or exit cause remains unknown because that fixture did not retain stage diagnostics. The complete failure packet `0a191f7ae23b8667a0bca94d221826518129c39e066b9fb95d87524036c14b9c` and 17-source beforeimage archive `322d27d3cb814980660a67145a31a8d0b48eeb892f5451b23aafe5a21caa7faa` are preserved under `.runtime/mcp-after-e14f6b04-final-repair-2026-10-16/full-audit-v1/first-failure-event-preservation-v1/`. The failed audit and the separately passing 6,912-test managed pre-push run both closed all owned resources; their old receipts do not validate subsequent edits.

The owned late-ready fixture now acknowledges child entry after the real release return, checks the exact nonce/PID/socket, and then starts a fresh bounded eight-second socket wait. The real 6.1-second delay, original unknown/no-ready assertions and all ten original test bodies remain. Its finite parent and cleanup lifetimes cover the admitted phases; product timeouts and ownership/non-replay rules are unchanged. Failure diagnostics retain complete bounded snapshots as lossless chunks and explicitly do not claim producer EOF. The whole genuine 9,921-byte before module and parsed provenance are routine fixture resources, with one current-reader declaration limited to those two inputs; all previous declarations and resource mappings remain intact.

Actual controlled three-second pre-entry workloads on Python 3.12.15 and 3.14.3 each produced the original line-46 socket assertion RED with zero errors, then current GREEN. Each runtime also passed all 22 real ready/status cases, including four new regression controls and the original publication, adoption and symlink scenarios. Closing `566cbbb5b1b22e0af7f88474b2933277daa98b494e8feba663e4e0599b3b5a62` under `.runtime/mcp-late-ready-fixture-repair-2026-10-16/causal-run-54afae86-1532-4669-be10-c71a5f4da063/` qualifies six original children, twelve complete streams, source generations and descriptor closure. This proves the controlled timing gap; it does not establish the original transient child cause or native Windows acceptance. Fresh final-source MCP checks, complete audit, managed pre-push and exact-SHA five-workflow delivery remain required. Historical VMs/connections stay closed; product-native, visual, H14 and Windows product parity work remains deferred. No release is authorized.

Ordinary dependency selection then correctly rejected the new current-only declaration because it analyzes both the current and committed baseline generations at a changed source path. The actual baseline blob is byte-equal to the preserved 9,921-byte before module. The corrected declaration lists only those two reviewed digests, keeps the same two resource paths and preserves unknown-generation refusal. Original failure streams and unfixed sources remain under `.runtime/mcp-late-ready-selector-declaration-failure-v1/`; the original selector child exit code was not retained by its outer wrapper and remains unknown. Before correction, the same positive regression produced the actual selector `SelectionError` on both Python versions (one error each, closing `34433d4722ceb7c656a964065dc995a657d10f71ed4c5ce8e1d442fb05060279`). After correction, all five routine regressions passed on each version (closing `cd90a2e921e799710eb973f7f998af9f682a9aad898ebc26684343850c2e0854`). Ordinary selection then completed once with 517 of 584 modules and all 17 changed paths (closing `1a332ecec39d27c7c92310fd0f972b3ba9044299eb6ffb36ae6764b3f7720da6`). All owned children, complete streams and held source descriptors closed before the next documentation or version edit. These focused passes do not replace the fresh final-source gates.

### 2026-10-16 — MCP provider encoding after checkpoint I

Checkpoint `72d140131a2c5ab4a81bfe5ede5e0171b355fa8e` completed four required workflows successfully, but Windows failed its native MCP environment control. The current child exited 1 with `DecoderFallbackException`: strict UTF-8 `GetString` rejected byte A9 at index 128. The original provider file, BOM and code page remain unknown because that attempt did not retain the PSD1/PSM1 bytes. Full original job log SHA-256 `958c7b6818fa1e748c7be18f150ec053c8215f6577c91e751d246c2a1e83adc5`, exact source archive `d10f9d1b24ee29fbd6c6f68c3268306184a738a60eaed798e84d7ac37b5b6009` and lossless failure packet are preserved under `.runtime/mcp-next-final-I-source-proof-v1/`. All original CI readers and frozen source resources closed; I remains a failed delivery checkpoint.

The generic decoder still defaults to strict UTF-8. Actual provider callers now select no-BOM encoding from the observed PowerShell engine: Windows PowerShell 5.1/Desktop on Win32/.NET Framework uses its actual default code page; Core uses UTF-8. Both encoder and decoder use exception fallbacks, and the decoded text must round-trip to the exact original bytes. Explicit Unicode BOMs remain terminal, unsupported or malformed encodings still refuse, and literal-manifest, typed export-graph, source-origin, hash, cold-state and physical ACL/hash guards remain required. There is no guessed code page or UTF-8-to-ANSI retry.

The authentic whole I program is retained as a byte-pinned routine beforeimage. The routine encoding regression asserts its actual strict-decoder RED before launching the corrected GREEN on the same controlled legacy-encoded manifest. The earlier isolated component closing `568759b4498f02a4af1b28097d1dc8ced910bd56579bfbb76410af66751ef76c` proves that controlled format difference, all retained parser controls and encoding refusals; it does not identify I's missing original input. The new exact Windows scenario separately requires whole G/I/current/C outcomes `1/1/0/11`, the original C/G proofs, an actual I decoder exception, matching held provider bytes and policy context, and the corrected physical ACL/hash oracle. No component result substitutes for that native scenario.

A separately pinned wrapper holds the unchanged I carrier or current carrier, data and actual provider files. Current decode sites must join their exact buffers and existing hashes to those held inputs. Records distinguish per-process custody from cross-case equality; no continuous cross-case lock is claimed. Fresh constructor-owned nonces, finite filenames, pending-record refusal and original exception preservation remain mandatory. Actual source-selected wrapper controls passed all 22 modeled cases plus normal return, exit 11 and terminating-error paths; all four children, eight complete streams, 628 runtime files and source/FD resources closed in receipt `0293e7e0ce8ef54249e973fbbbb0beec253d2a172d6c134d3f9718e6d4c8011b`. These are component results, with no Windows provider acceptance claim.

The Windows MCP step always uploads its exact run/job/attempt-owned evidence root after it starts. Both full provider pairs, partial records and original native streams survive failures; the finite artifact manifest reports actual presence and never claims upload completion or native acceptance. This separate 40 MiB evidence channel preserves the existing 16 MiB job-log, 12 MiB provider-packet, 60,000-byte command, saved-file and chunk limits. Existing fixtures and dependency history remain intact; only the two reviewed loader generations/scopes and two new raw PS1 byte attributes are added. Final-source focused checks, all twelve MCP tools, the complete intentional audit, fresh managed pre-push and five successful workflows for the exact final pushed SHA remain required. Historical VMs/connections stay closed, unknown jobs/leases remain preserved, and product parity, caller acceptance, H14 and product-native/visual work remain deferred. No release is authorized.


### Windows native provider path ingress after J

The exact J95f18a92 Windows artifact preserved original SourcePath and DataPath spellings below `C:\Users\RUNNER~1\AppData\Local\Temp`. The unchanged custody wrapper rejected their noncanonical spellings at `PUBLIC_NATIVE_CUSTODY_ARGUMENT_PATH` before provider files or either I/current native body were read. The caller now admits the original data name with the genuine source bootstrap first, holds its original ancestors while resolving it, and rechecks canonical and original file/parent identity, all generation fields except access time, exact bytes, SHA and closing guards. It then uses that admitted canonical owned directory for the four case scripts. The wrapper, native programs, argv structure and custody/proof schemas remain unchanged.

Four routine controls passed without skips on both exact Python 3.12.15 and 3.14.3. They include an authentic retained 183-byte J setup with exact whole-source/offset/hash provenance: the same physical input produces one actual assertion failure with zero errors before the fix and passes after normalization; the other controls preserve identity/bytes and refuse original symlinks or a same-byte foreign file. Windows uses real GetShortPathNameW and reports unavailable/non-distinct aliases as capability skips; that Windows branch has not been run locally. The isolated official macOS PowerShell 7.5.4 component selected and executed only the exact preserved wrapper argument loop: the genuinely admitted POSIX `//` alias returned 1 with the original guard marker, then actual caller normalization and direct canonical spelling each returned 0. This is explicitly a synthetic non-Windows alias component, not Windows 8.3 or full-wrapper acceptance.

The once-only private cohort closed naturally with all five original children reaped, full raw streams retained, no truncation, unchanged 3,051-file J source and 628-file official engine, unchanged parent environment and descriptor counts 4 to 4. Evidence: `.runtime/mcp-J-native-argument-path-normalization-proposal-v5/actual-once-v1/closing.json` SHA `2dbdd05371fabacd4f44b340120538944b0fd85696117e12f46f155157ee0bfa`; guard component SHA `6f7e2f9c9cf613f52bc6ef725859ca9400e4e85c73ab0b49c7ab9203a3ef8f6a`. Canonical focused checks, a fresh managed prepush receipt, the next exact-SHA four-role native Windows scenario and all five required development workflows remain delivery gates. No release or product-native acceptance is inferred.


### Direct Linux cleanup enrollment after J

The preserved exact-J collector refused `linux_union_fast_case_not_success`. The complete Fast command module lists omitted the Linux enrollment and Temurin continuity modules; its successful disjoint 513-module union supplied no started or finished rows for the six enrollment methods. The Linux direct native step correctly ran its separately assigned four Temurin CleanupOwnershipTests methods. Original evidence and the three complete raw log paths/hashes remain bound in `.runtime/mcp-ci-95f18a92-linux-obligation-failure-v1/packet.json`, SHA `bcb1af06a3620b47ab6707e0ffd9414108297f0f3bf300bd7363cbeeeab60785`.

The Linux workflow adds a separate unconditional `Verify Linux cleanup enrollment guards` step running the full existing enrollment module with verbose unittest output. Its seven methods include the original six unchanged bodies and a new check requiring the genuine ordinary Linux job to execute this exact command unconditionally. The original two native-JDK commands and their guards remain byte-identical. The existing dependency declaration retains its exact five input edges, all 177 loader rows and 16 resource channels; only the reviewed current enrollment-test digest is appended.

The same seven-case program and argv ran against the authentic J workflow and corrected workflow on both exact Python 3.12.15 and 3.14.3. Each original workflow produced exactly one assertion failure with zero errors or skips; each corrected workflow passed all seven cases. All four original children closed naturally, all eight complete regular stdout/stderr files were retained, copied input bytes/modes/generations stayed unchanged, and eight held input readers reread and closed with descriptors 4 to 4. This was regular-file capture with no pipe-EOF claim. Actual proof: `.runtime/mcp-J-linux-enrollment-coverage-repair-v1/actual-focused-v1/closing.json`, SHA `2a5dff07fc92392de3b7dda0da894fb974370dc5272e54bad7650ac5dd529518`. It does not establish native Windows acceptance.

Final canonical focused checks, normal version metadata, an intentional full audit, the complete fresh managed prepush tier, and all five required development workflows on the next exact pushed SHA remain pending. The new direct Linux step must demonstrate all seven case successes, and the original Windows four-role native scenario remains required. No release is authorized.


### K CI follow-up: provider identity and buffered guest commands (2026-10-17)

This intentional bucket contains the PowerShell fixture producer/parser regression, guest-input producer/protocol tests, finite dependency metadata and this work record. All exact K failures, unfixed beforeimages and complete traces remain preserved. Windows current refused at `PUBLIC_NATIVE_HASH_FUNCTION_NESTED`; the offending live name/type was not recorded and remains unknown. Its provider files are intact; the script decode join was not reached. The graph change replaces display-name classification with the defining ScriptBlock object identity and genuine binary assembly plus the actual nonempty manifest-exported cmdlet subset. Existing path/PSHOME/type/manifest/decode/hash/function-export/source-body/closing guards and wrapper/four-role schemas remain. Local proof `6a01de870c68c2fba4984c91dda23e76170960b332f961ff01fdd63bb8e135cb`, independently closed by `1567f8027d4a2e498f86fe0c58c1c2184c0d1f5f7588745d8840b753c5138507`, qualifies both Python versions' exact inline K selector RED/current genuine typed fixture GREEN and graph refusals. This synthetic component neither identifies K's unprinted operand nor substitutes for native Windows ACL/hash acceptance; its harmless function is never invoked.

The separate Fast shard-2 observer failure retains an UNKNOWN historical reason/stage (packet `44f137e22a5487c3ab117013d40ee402cdf41dc19ed9306547c650c638b26bfc`, beforeimages `815a260528f0775f4c08641f5f2488425ebe0eb5791b13d1750387ceced48291`). The bounded raw-read fix addresses a deterministic physical-pipe case where BufferedReader-prefetched commands wait for new kernel readiness. It preserves command/deadline/EOF/schema/source/native/non-replay guards. Eight ordinary POSIX tests cover coalesced progress, partial completion, exact 8192/over 8192 bounds, empty/valid/malformed EOF and invalid coalesced decisions, using actual emitted source and inert native callbacks. Their controlled checkpoint is not a claim about the original CI cause or a production timeout change. All eight original private invocations closed naturally on CPython 3.12.15 and 3.14.3. Each authentic old positive had exactly one assertion failure and no errors at the final pre-EOF ACK assertion: three complete commands were physically buffered with kernel readiness false and no ACK before EOF; after the same EOF, the owned child exited 0 and emitted all three packets. Each current positive, all seven additional buffer controls and the unchanged original observer case passed on each interpreter. The original driver `f4681` nevertheless recorded `expectedOutcomeQualified:false` for the two old REDs because its unittest summary-line parser did not admit that authentic failure rendering. Those primary records (`26a1737b62a0176b6a43e0d2624aaa6804f3078529aedce3ef06fa0502ccbc65` and `9ec996fcc6fbd76c4ea3b18ffec4be8dc130fda81a1b6c2f116f94f1df041ef7`) remain unchanged. The separately reviewed all-eight DATA closing `a3cec9880e00887516dae54d5f242d525a75e0a54ff174586b0a62b1c53c366d` qualified two expected REDs and 18 current passes with no errors/skips, preserving the driver's false results without replay. Its 173 readers closed FD4→4. The successful original observer cleaned its private fixture after closure; its retained full unittest stream and source-FD/key/owned-closure attestations qualify that local pass, without a claim that deleted temporary raw files remain available. Root's natural-terminal inventory `732130f113381bb01bfda682950138801d6851ce7a1ad8a014356919738f66ab` records no replay and byte-identical source before/after (`f4171089e2ff3016be7b8641a8ac58a4e1fe788f96baa6fa924bfd6d7a135f05`, all 3051 K source files).

Metadata appends only the three reviewed current test digests; all 177 loaders/16 resource channels, scopes, reasons, old hashes and unknown refusals stay. Existing parser/guest modules enroll the new routines through ordinary affected selection; no loader-row invention, committed fixture, raw attribute or workflow change is needed. After final content, normal version/fresh source freeze and focused/lifecycle/full-audit/managed-prepush gates remain, followed by reviewed push and all five exact-SHA workflows. The original native Windows G/I/current/C `1/1/0/11` scenario remains mandatory. No historical VM/SSH restoration or deferred product/parity/H14/visual acceptance is claimed.


### Focused observer fixture root and startup evidence (2026-10-17)

The frozen canonical focused run completed 24 passes and one original-observer startup failure, with no errors or skips. Its original `UNKNOWN` startup reply and complete source beforeimages remain preserved in `.runtime/mcp-L-focused25-original-startup-failure-v1/packet.json` (`be56acef06c79051dcc363f7422870499e9b8a884568b3f67f4b1bd3b0e7073d`); independent closing `ddcb8e619fa9d9fb7165820736864ab8a82e8711691febdd1b6ea82cd220c21c` qualified source/engine/resource closure. The inherited TMPDIR was 157 bytes and the resulting fixture QMP path was necessarily beyond the 103-byte fixture bound, but the old child stderr was deleted: its actual errno and historical startup cause remain UNKNOWN. A controlled long-path witness must not be relabeled as that unrecorded original errno.

This test-only correction creates a fresh owned short AF_UNIX fixture root without changing inherited TMPDIR, the production input producer, or source/native guards. Startup failures retain the full reply and the exact owned constructor's naturally closed stdout/stderr before assertion cleanup. Three POSIX ordinary routines cover the original source-lifetime flow under long and short inherited TMPDIR and controlled startup-refusal evidence retention. The inline 89-byte constructor and 1735-byte startup beforeimages remain authenticated against exact `860b6b7b7692c2177f719d9d610af9ce220e70b9d4eea0b03d22b7d089193643` source bytes; current-file `inspect.getsource` needs no ignored historical path or new committed resource.

All six original private probes closed naturally on CPython 3.12.15 and 3.14.3 with expected outcomes. On each interpreter the authentic before variant produced exactly two designated assertion failures and no errors: the controlled 177-byte socket path yielded actual `OSError: AF_UNIX path too long` and child exit 1, and the original startup body failed the required retention oracle for the owned controlled exit 23 child. The current causal pair and short-root control all passed on each interpreter: six current passes and four expected before assertions total, with no errors/skips. This controlled socket cause is established for that witness; the earlier focused startup errno remains unknown. Current startup diagnostics retain actual raw streams and reply before the assertion. The independent all-six DATA closing `d1754f4d3ea74db7b35a4ad8131387890204bd6bcd1b419715e775f505d8b6eb` qualified these expected outcomes and resource closure, with 75 readers closed FD4→4. Successful source-lifetime flows cleaned their temporary raw files after closure; their retained unittest streams and source-FD/key/owned-closure attestations qualify the pass without claiming those deleted files remain available. Complete source before/after all six is byte-identical (`c083`, all 3051 frozen K sources/`0b8`); no canonical edit or production/native acceptance is inferred from these private probes. The finite metadata change adds only this test's real self-source scope and its reviewed final digest to the existing row, preserving all prior versions, other scopes, reasons, 177 declarations, 16 resource channels and unknown-mapping refusal. No fixture resource, byte attribute, workflow or production change is introduced. Final version/freeze, canonical focused and required lifecycle/audit/prepush checks, reviewed push and all five exact-SHA workflows remain required; original Windows native acceptance is still pending.


### Native Function provider source-body representation (2026-10-17)

The original L native Windows refusal remains the distinct `PUBLIC_NATIVE_HASH_FUNCTION_SOURCE_BODY` subtype. Its actual runtime AST kind and failed comparison operands were not printed and remain UNKNOWN. A separate local genuine-engine observation produced `FunctionDefinitionAst` for an imported function; that observation is not the missing Windows operand or native acceptance. The source-body proposal retains the existing `ScriptBlockAst` path and adds a typed `FunctionDefinitionAst` path with exact function name, parent/body identity, authenticated file origin, full definition/body text and offset comparisons. Existing provider graph, PSHOME/path, decoder, held hashes, exports, source and closing checks remain. The original full native scenario and G/I/current/C `1/1/0/11` outcomes are still mandatory; exact-C missing Get-FileHash/exit 11 is the intentional negative control, not a newly claimed defect.

The prospective ordinary parser routine embeds the exact 266-byte old L guard (SHA `c67bdb81bd3553827c69ed29bf0f6bba4c5025928083a1ba9b74a3dc28aec86d`, line 265 of native source `86c71bec00a939539d80add9d5a89cdb8c304bd79c30af9b2dd2b44a5533b963`). It holds its own real source and sibling producer, authenticates inline fixture/control bytes, and imports a genuine typed function without invoking its harmless body. The actual private cohort closed on Python 3.12.15 and 3.14.3: the preserved old guard returned 1 and the current resolver returned 0 for the same genuine imported-function scenario; each common-positive unittest produced exactly one assertion failure and zero errors on the old guard, then one pass on the current resolver. The legacy-body positive and all eleven AST/type/name/cardinality/text/offset/origin/wrapped-root refusals passed on both versions. Root collected the original cohort naturally with exit 0. Independent retained-data qualification is `/Users/karapsin_de/projects/vpn_control/.runtime/mcp-L-source-body-real-engine-measurement-v1/routine-proposal-v1/independent-cohort-data-closing-v1/closing-v2.json` (SHA `be41d5aad5410a5eb2382887fd2417ca81eff25f2b4cea2ea5811de83846a2e8`, 30433 bytes): 49 readers closed, FD 4 to 4, both outer Python children naturally reaped with full pipe EOF, and saved engine/copy opening and closing tables equal. The inner PowerShell outcomes are retained CompletedProcess/raw evidence; no separate inner PID receipts or deleted temporary fixture files are claimed. This genuine local Core 7.5.4 component proof does not identify the unprinted original Windows operands or replace the required Windows native scenario.

The finite metadata proposal appends only the reviewed current producer/test hashes to their two existing rows. The parser's exact seven scopes already include self and sibling producer, so no new scope or loader bypass is needed for `_bootstrap_source(Path(__file__))`. All 177 loader declarations, 16 resource channels, old hashes, scopes, reasons and unknown-mapping refusals remain; no committed fixture, byte attribute, workflow or broad table refresh is introduced. Root's normal version update follows final content. Fresh focused/lifecycle/audit/prepush checks, reviewed push and all five exact-SHA workflows including original Windows native acceptance remain required. No VM/SSH restoration or deferred product/parity/H14/visual claim is made.

### Exact-SHA Windows causal enrollment after M (2026-10-17)

All five required workflows succeeded for `bba6fd39c01f2e86bfc1e94c10a0a48c9877d20d`, but its stricter retained-evidence validation remains failed. The original private verifier first refused `sources:finite-file-cap-accounting`: its expected 37,276,203-byte sum was stale against the authenticated current source-derived 37,283,378 bytes. A separately pinned one-literal correction preserves the 40 MiB root bound, every file cap and all other guards. The original collector exit 1 and report remain unchanged under `.runtime/mcp-ci-bba6fd39c01f2e86bfc1e94c10a0a48c9877d20d-readonly-M-2026-10-17/`.

The corrected retained-data diagnostic qualified the current four-role provider/source-body components, including the existing 102 causal identities plus the source-body routine. Its full Windows predicate still failed: nine wire-evidence methods, the setup held-handle method and four ordinary HTTPS deadline methods had no outcomes. Their three modules appeared in the printed workflow commands but were absent from both actual `selectedTestIds` sets. The exact M source archive confirms all 14 methods still exist. The selector intentionally intersects `--include` with affected modules; successful 81- and 566-test summaries therefore did not establish these missing scenarios. Diagnostic `fcf551e368afccf54025adbb3528e554791a87601b9cf0e981ee9357e05219c0` and independent resource closing `73cc5a4b331b64e44e8daec154bb2da6aa87f6b1af11a36464604ff1835971be` preserve this failure. The six additional invalid-data controls and final conjunction were not reached.

This bucket adds explicit `--audit --baseline HEAD` to the two Windows causal gates, retaining their complete ordered 10- and 73-selector lists and existing native capability, evidence upload and failure policies. The same include filter and serial runner execute those explicit lists; ordinary MCP and Fast affected selection retain their existing semantics. A byte-pinned complete M workflow beforeimage and real tiny-Git selector/runner regressions cover the unchanged-module omission and corrected enrollment. Those portable controls establish enrollment policy; the next exact-SHA Windows run must supply the actual native outcomes.

The actual common positive on the preserved M workflow produced two designated assertion failures and zero errors on each of Python 3.12.15 and 3.14.3: only the changed inert control ran, while the unchanged explicit control was absent. The corrected three new routines and three unchanged include controls passed on both versions, twelve current passes with no errors or skips. The 32 retained raw files and both naturally closed original handles are joined in `.runtime/mcp-next-N-native-coverage-v1/dependency-owner-v1/final-focused-summary.json` (SHA `647b11a331b8a605e58410a866147bf8f53f9c6ddf90ed5dca2b0df71152c7c3`). An initial test-authoring failure is separately retained: inserting CR before LF constructed valid CRLF, so the lone-CR refusal correctly did not occur. Its source and failed result remain unchanged; the corrected invalid-input constructor normalizes CRLF before replacing LF with a lone CR. No selector or parser guard was relaxed. Literal dependency discovery covers the exact workflow and beforeimage; all 177 loader declarations and 16 resource channels remain unchanged.

Final-source focused checks, all twelve MCP tools, the intentional full audit, normal version metadata, a fresh complete managed prepush and all five workflows for the next pushed SHA remain required. Historical VMs and SSH connections stay closed, unknown jobs and leases stay preserved, and product parity, caller acceptance, H14 and product-native/visual work remain deferred. No release is authorized.

### Receipt collection test oracle after N (2026-10-17)

Fast Checks for `d8edfc54e2eb7ade6c566d20818f4c25b3d89283` failed because the interrupted-admission receipt test compared complete `os.stat_result` values. The original Linux log records only an access-time change; modification and change times stayed equal. Its full log remains in `.runtime/mcp-next-N-ci-failure-2026-10-17/job117315921199-v1/`, and complete unfixed sources are retained under `.runtime/mcp-next-O-atime-failure-v1/preservation-v2/`. The test now uses the existing recovery reader's SHA and generation pin, retaining content, inode, owner, mode, link-count, size and modification/change-time checks plus the once-only write assertion. Production code is unchanged.

One ordinary regression executes the same receipt-collection test with an access-time-only observation, changed content and a same-byte inode replacement. Both real metadata APIs retain their own no-follow semantics. The authentic N target produced exactly one assertion failure at its original line 57 and zero errors on each of Python 3.12.15 and 3.14.3; the corrected full ten-test module passed on both versions without errors or skips. Initial fixture compatibility failures are preserved separately, including Python 3.14's constructor rejection and its different `Path.lstat` dispatch. The constructor counterfactual is an expected compatibility error, not the access-time RED. All five final children closed naturally with ten complete pipe streams and FD 4 to 4. Closing `.runtime/mcp-next-O-atime-failure-v1/actual-causal-v3/closing.json` has SHA `4190700cc57f10ed00769411cf4b340d76764b682c3ff482837faf05af394859`; Root separately verified every final child report, terminal and raw stream.

All four N package workflows succeeded, but N remains failed. Its private verifier also stopped before Linux qualification; retained-source inspection found a stale 99-case companion check against the sealed 102-case plan. The original top-level `ValueError` did not print its operand, and Windows qualification was not reached. That original report and its outcome-neutral resource closure remain unchanged; no native acceptance is inferred. The successor must preserve all prior obligations and explicitly include the original receipt test and its new regression.

This test-only bucket includes the existing test module, this work record and the normal changelog note. The completed 7,568-test/584-module N audit remains evidence for its original source. The follow-up requires fresh affected checks through the complete managed prepush tier and all five workflows for its own exact pushed SHA; it does not relabel the N audit or require a duplicate intentional audit. Historical VMs and SSH connections remain closed. Product parity, caller acceptance, H14 and product-native/visual work remain deferred; no release is authorized.

### Automatic readiness and recovery delivery buckets (2026-10-24)

This delivery comes from the separate recovery clone and intentionally spans several
dirty buckets, which are committed together because the tests of each depend on the
others' sources:

- the shared readiness coordinator, its SSH transport migration and the callers it
  moved, with their causal fixtures and reviewed-loader pins;
- the CP117 historical re-pin cascade that the transport migration required;
- exact literal action routes and pure request fences before readiness, with the
  AST contract test;
- test-isolation fixes, the managed-runner stdin fix and the shared-worker umask and
  socket-root fixes found by the TEST-006 full audit, and the durable program status
  race, the gateway fixture cleanup wait, the runner's Darwin zombie-group cleanup
  and the test-timing flakes found by the managed pre-push and its load sweep, and
  the Windows, Linux and Python 3.12 portability fixes, six hosted agent shards and
  the re-pinned creator listener identity fix found by exact-SHA CI;
- the Android staged update substitution and the stage-1 Windows creator pre-VM
  closure with its Fast Checks root-census enrollment;
- the `TEST-006` managed checks: every failure in one pass, failed-first reruns, and
  the agent stage planned as the SSH-close gate then the two hosted CI shards, with
  one non-recursive failed-level regrouping and a SIGTERM-first launcher timeout;
- the infrastructure ledger, resume guide and this record.

The remote Claude Code project configuration commit is merged before the managed
pre-push tier. No native step is part of this delivery: the creator closure runbook
and the remaining provider lanes start only after the exact pushed SHA passes all
five required workflows. Windows product parity stays paused and no release is
authorized.
