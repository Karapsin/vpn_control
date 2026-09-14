# Work In Progress

## Objective And Boundaries

Finish the entire GUI/CLI parity plan on Android, Linux, Windows and macOS:
matching public behavior, persistence, runtime effects, progress, cancellation,
packaged native acceptance, visual review, reviewed pushes to `origin/dev`, and all
five required workflows for the exact delivered SHA. The goal remains incomplete.
No release, tag, main merge, publisher or runtime-version upgrade is authorized.

Product authority: [contracts.md](contracts.md), especially CLI-001..008,
STATE-001..005, DESKTOP-001..008 and TEST-001. Command authority: [cli.md](cli.md).
Historical checkpoint notes are preserved in Git at
`a4a5b74350e76c3f5706b29bce601713a6a39e13:agent_docs/work-in-progress.md`.
Use current source and the evidence below instead of historical completion claims.
All evidence paths below are relative to `.runtime/parity-evidence/` unless stated.

VPN, installer and elevation effects are limited to positively identified owned
VMs/emulators. Preserve the host VPN, personal workspaces, unrelated VMs, existing
AVDs5580/5582/5584/5590/5592 and excluded `agent_docs/.Rhistory`. A timeout does not
permit killing or replaying a runtime/installer. Unknown jobs retain correlation
and inputs until authoritative reconciliation. Only root owns shared Gradle,
version metadata, staging, commits, pushes and exact-SHA CI. Workers use bounded
assignments, one writer per file and one operator per native environment.

## Current Delivery And Work (Checkpoint48)

Checkpoint47 is pushed as `5f6c2d41fcf428123f6cc512532e57fafce028e2`, version
2.1.10. Full managed prepush passed. Its five exact-SHA workflows are pending;
managed follow session42310 remains live. Previous checkpoint46
`60ed33aabf699c2a437dba5535fdd861e2421e3f` has all five workflows successful,
including Fast34792865872, Android34792865849, Linux34792865877,
Windows34792865810 and macOS34792865863 (checkpoint46/commit-result.json).

Current implementation slice fixes ordinary GUI shutdown losing its queued DETACH
when Main immediately cancels the frontend scope. A quick deterministic test
reproduced replacement ATTACH returning BUSY; a separate virtual-time test caught
teardown returning before the bounded detach. Evidence:
checkpoint47/frontend-close-red2.log (8 tests, exactly two expected failures).
Normal Main teardown now awaits closeAndDetach before endpoint/scope disposal;
the best-effort AutoCloseable path and crash lease expiry remain intact.
Focused integrated validation passed26 tests with zero failures/skips
(checkpoint47/frontend-close-green2.log); new packaged immediate-reattach evidence
remains pending. Changes belong to root/handed-off frontend_lease47 in connection, Main
teardown and the connection regression tests. No other product files are assigned.

Full prepush exposed a distinct diagnostics-test isolation failure: normal commands
were bound to the temporary endpoint while direct export read default host owner
metadata. The existing failing test is retained in
checkpoint48/diagnostics-prepush-failure.xml and diagnostics-reproduce.log.
The test now binds export and rejects fallback startup, asserting exactly one
fixture export. Integrated diagnostics/frontend checks passed; no host workspace
or product export behavior was changed. Full prepush must be rerun for this edit.

Windows checkpoint47 broker component passed actual ordinary-user UAC approval:
one exact existing test executed, zero skips/failures, child readiness and exact
stop proved; no new staging directories or remaining owned processes/tasks.
Receipt: checkpoint47/windows-broker/receipt.json. Frozen current test classes
exercise an installed dabd product copy on Windows ARM64 with x64 emulation;
this is component evidence, not native x86_64/current-source package certification.
Public CLI TUN traffic subsequently passed eight commands, a real TUN adapter
and unproxied synthetic-address token traffic with RX/TX increments. Public
off/quit and exact routes/adapters/stages/process cleanup passed. Evidence:
checkpoint47/windows-tun/receipt.json. The same installed-source/architecture
limits apply. Current same-source packages and denial-preserves-A remain gates.

Previously delivered Linux scope: Linux native GUI guard argument builder, its causal test,
and the checkpoint47 record. Root independently reran all twelve guard tests successfully.
The native harness now imports the canonical X11 collector and argument builder;
the former duplicated regex missed an actual owned window and its empty baseline
option caused argparse failure. Native result checkpoint46/Linux/summary.json
records installed source33e2 RPM SHA
b962a3d3add17990549f9af6e8f039f527feaccd5d8db4b0e073bcb2c5f0eb4a.
Token proxy traffic and stable runtime identity passed before/after GUI attach,
normal close, reattach and frontend crash. Public off/quit passed, all five task
roots have no live processes, and display servers were preserved. No-tray hide
returned UNSUPPORTED with the window accessible. Immediate reattach was
UNAVAILABLE until the fifteen-second frontend lease expired; the causal regression and normal-teardown fix above address this behavior. This evidence is for
source33e2, not a claim of current exact-SHA packaged certification.

Windows checkpoint46 proves ordinary-user installed-package proxy token traffic,
public off/quit and no remaining owned processes/listeners. It uses installed
dabd2.1.9 on ARM64 Windows with x64 emulation, not native x86_64/TUN evidence.
The fixture uses the committed exact stream reader and mixed-in port selector;
actual Windows red/green evidence and root review are under windows-runtime.

| Task | Agent | Owned files/subsystem | Shared files reserved | Artifact/environment | Current check / next handoff |
| --- | --- | --- | --- | --- | --- |
| Integration | Root | WIP, reviewed Linux guard/tests, builds/delivery | All shared protocol/model/build files | Host build only | Exact-SHA CI and next checkpoint |
| Android | linux_tls_manifest_retry | Ignored fixture only | All Android source reserved | Exclusive5596; frozen APK2.3.10 | Correct DNS relay and public owner discovery before cancellation scenario |
| Windows broker | windows_broker47 | Ignored native fixture/evidence only | No tracked edits | Exclusive owned ARM64 guest, x64 installed dabd | Exact one-test loopback helper gate; frozen tests in checkpoint47/windows-broker/frozen-tests |
| Linux native | Completed linux_observation46 | Two guard/test files handed to root | No product edits | Fedora2316 source33e2 RPM | Native lifecycle passed with immediate-reattach limitation |
| Frontend fix | Root after frontend_lease47 | Connection, Main teardown, regression test | All other shared source reserved | Host tests |26 focused tests pass; next prepush/native package |
| macOS preparation | Root after mac_pair47 | No active edits | Root owns builds and VM | fixture43 old job retained | Guest Tart exec access verified,18GiB virtual free; host physical capacity limits builds. Plan same-SHA CI base plus one version-overridden target; preserve visual evidence |

Checkpoint45 product fixes have direct causal and passing evidence:

- Desktop delayed authorization: original gate fails public updates-status flush
  acknowledgement. The fix accepts only exact installation identity/readiness,
  using final=true inspection envelope and final=false embedded installation.
  Forty-one focused desktop tests passed. Logs: checkpoint45/desktop-exit-red.log
  and integrated-focused-green.log.
- Android CUSTOM handoff: original code rejects blank-URL CUSTOM descriptors.
  Root review also caught false pending-restart for ordinary profiles containing
  both stored JSON and a raw URL; a separate regression failed before preserving
  ordinary URL precedence. Forty Android tests passed without skips. Logs:
  checkpoint45/{android-custom-red,android-ordinary-red,android-final-focused-green}.log.

Native evidence and remaining limits:

- Current33e2 fixture-signed nondebuggable APK2.3.10, versionCode17400, SHA
  `43134bcb7d8d8a569703c11f5c327b504780aea1f923681fa7925a23f4691656`,
  was built from a clean tree, verified against the existing signer, upgraded with
  adb install-r and pulled back with matching hash. API35 fixture add/show worked;
  initial selection failed on invented raw JSON containing top-level remarks.
  Correct CUSTOM wrapper fixed the fixture. Native A ON/status is authoritative,
  selected=active and pending=false; staging B preserves runtime A and sets pending=true.
  Plain off and exact cleanup succeeded. Root independently verified the receipt
  chain in api35-native/root-readiness-review.json. Subsequent cancellation setup
  failed before a cancellable operation because the relay rejected Android DNS;
  no cancellation/traffic success is claimed. Final state is empty/stopped/no reverses.
- Prior2.3.9 API35 run proved the original metadata loss after successful ON;
  invalid off--interactive did not prove plain off failure. Current readiness
  native acceptance is still open. Historical gated TLS cancellation proves only
  candidate-probe cancellation, not device tunnel traffic or active verification.
- Windows original-user installed dabd package: capabilities exit0; missing-owner
  status exit2/UNAVAILABLE. Actual on/status receipts show running proxy-only with
  matching active/selected IDs and no pending restart. Peer failed on the alias
  collision above. Public off exit0 cleaned the owned sing-box. No token traffic
  claimed yet. The earlier large summary was PowerShell extended-object metadata,
  not large capabilities payload or demonstrated QGA deadlock.
- Root Windows follow-up establishes setup/on/status/off/quit all OK and clean
  cleanup in checkpoint46/windows-runtime/root-result.json. Peer did not run a
  token exchange because the fixture selected the saved config instead of the
  actual process config; next run derives -c from the owned runtime process.
  Root also confirmed ordinary-user read denial for its SYSTEM-created temp script
  and granted read only to the exact hash-verified script. Earlier quote-escaping
  attribution was incorrect. Root-live2 failed because two mixed listeners exist, one for management.
  The selector now requires the public mixed-in listener; actual routine regression
  rejects the old type-only predicate and management-only input. Root-live3 then
  passed exact unique-token traffic through public port59188. Every setup/on/status/
  off/quit step returned OK; Task Scheduler exit0, no owned app processes and no
  fixture listener remained. Reviewed receipt: checkpoint46/windows-runtime/
  root-live3-reviewed.json. Artifact is installed dabd2.1.9 on Windows ARM64/x64
  emulation; no TUN/UAC/MSI replacement/GUI continuity claim.
  These fixture failures need reusable admission coverage before final matrix closure.
- Linux old run 7687617b18 has incompatible provenance with the currently present
  harness and no frontend log. Other later old-RPM attempts have Skiko GL errors.
  DISPLAY is inherited by xprop correctly. None proves a current-source lifecycle
  failure. Frozen helper12470ea814b5b99962d474124a9448dd71b1eafd50d328aeefb63283c3b35af0
  is retained in /home/vpnfixture/lifecycle46-prep-20260914T0302Z/; do not certify a
  subsequent edited harness using this hash. Use windowquit, never destructive
  windowclose, and correlate each fresh frontend PID/starttime/window.
- macOS fixture43 was authoritatively STOPPED; started only that existing VM in
  durable tmux vpn-mf43-recovery45. Old app/owner/worker processes were absent.
  Job49a33fcf-cecd-4d19-a233-47b6cc1dcf69 retains inputs/correlation and protected
  WAITING_FOR_EXIT sequence2; installed base remains2.1.8. Public operations status
  returned UNAVAILABLE without starting an owner or altering receipt. This VM-loss
  observation neither validates nor rejects current late-ack code. Do not replay
  its worker or discard inputs; fresh live-owner current-package proof remains.

## Historical Checkpoint Evidence

The following sections retain prior evidence and limits. Current ownership,
delivery status and corrected classifications above supersede their progress
statements; an old open item is not automatically a current implementation gap.

## Implemented And Locally Tested

- Shared control registry, typed request/result envelopes, epochs/revisions,
  deduplication, operation ownership, document transport and controller/frontend
  separation exist. Full public-path/native coverage remains a separate gate.
- Android human watch/follow now retains the redacted envelope summary on stderr.
  A causal test failed without that branch, then Android/shared stream selections
  passed: checkpoint37/android-human-stream-{red,green}.log.
- Windows scoped broker candidate binding and read-only owner/helper admission are
  enabled in the factory. Failed cleanup remains owned for retry. Focused Mac,
  proxy-runtime and Windows admission tests passed in
  checkpoint37/desktop-reviewed-green.log. Whole-GUI elevation and autostart
  migration are still pending production native validation.
- macOS exited-coordinator detection returns OUTCOME_UNKNOWN after a nonterminal
  receipt without committing, cancelling, releasing or replaying the job.
- Windows coordinator constructor admission and original-user launcher primitives
  compile. The original-user primitive is included in the helper build inputs but
  remains unbound to production bootstrap. Identity/admission and failed-child
  handling require real interactive and adversarial acceptance before activation.
- The Android update fixture handles Windows publication/lifetime semantics and
  rejects a CN-only leaf before launch. Existing routine hygiene loads the SAN
  tests. Host fixture/native-helper Python selection passed32 tests.
- New dirty CA guard tests passed23 lifecycle and11 trust tests. The native JUnit
  guard regression reproduced a false pass caused by Assume; it then passed3 tests
  when assumptions were rejected. Actual Windows AOT analysis failed IL3050 on
  copied pre-fix source and passed with zero warnings/errors after the generic
  marshaling fix. Evidence: checkpoint39/windows-token-diagnosis/
  aot-analyzer-offline2-20260913T193559Z/{receipt.json,red-build.txt,green-build.txt}.
  Routine Windows compiler tests now enable the same analyzer with an explicit
  official NuGet feed; an initial empty-feed NU1100 failure is also preserved.
  These results do not replace final prepush.

## Native Evidence Obtained And Its Limits

| Scope | Authoritative evidence | Limit |
| --- | --- | --- |
| API29 current APK | checkpoint37/android-api29-native/android-current-source-api29-20260913T2115Z/066-native-api29-receipt-summary.json | Source064 signed nondebuggable2.3.7→2.3.8; host CLI is compiled component, not installed CLI package |
| API35 current APK | checkpoint37/android-api35-native/diagnosis/terminal-receipt.json | Same signed pair; earlier legacy-hash fixture failure is still unexplained |
| Windows fixture TLS | checkpoint37-windows-tls/{completion,cleanup}.json | Actual ARM64 Windows guest with x64 native Python; no MSI/VPN |
| Windows coordinator | checkpoint37/windows-native-compile/final-receipt.json | Actual protected ProgramData execution; original-user test compiled but its interactive branch was not proven by that run |
| macOS coordinator exit | checkpoint37/macos-dead-coordinator-adapter/result.json | Current compiled adapter plus real exited process and synthetic PREPARING receipt; not packaged replacement |
| Linux public replacement | checkpoint37/linux-public-recovery/terminal-receipt.txt | Older same-source2.3.1→2.3.2 pair, not current-source/fresh-dependency proof |

Both Android runs hid confirmation with HOME, lost only the application process,
explicitly resumed the same installer session, installed2.3.8/build17360 and
reconciled installed=true. API29 receipt13fb4f9d-720f-4ae6-b363-264af20b9fea /
session1269035325; API35 receipt2f3f7da4-235a-4eea-92eb-1dbf8af0c6e3 /
session1542811151. Temporary CA/proxy/reverse/fixture resources were cleaned.
Source/APK/signer identities: checkpoint37/android-current-pair/receipt.json.

API29 current large-document chain passed against that exact target APK: v7 input
12,488,469 bytes / 56,008 domains, import revision1, retained result, complete
readback, new-request no-op at revision1, private export and no-overwrite rejection,
then app-only cold reopen with exact persisted contents. Runtime remained stopped.
Cold owner revision0 is a new epoch, not data loss. The frozen CLI generates request
IDs internally, so exact-ID retry was not proven by this run. Evidence:
checkpoint37/android-current-pair/api29-large-document-current/receipt.json.

The API35 diagnostic attempt proved that a current OpenSSL subject-hash filename
fails and the legacy filename succeeds. It does not explain the preceding run,
which already used a legacy hash. The new staged-name guard prevents the proven
setup error before a bind mount; do not invent a cause for the earlier failure.

Linux job240efb62-fbfd-4209-8bfd-e746acbd41ac reached SUCCEEDED/OK and owner89494
recovered runtime-off. An older task owner17373 was first verified runtime-off and
stopped through public quit to release its gate. Guest authentication was restored
and TLS resources removed. No installer/package manager was killed.

Current Linux package acceptance now includes Fedora44 direct RPM replacement
2.1.4→2.1.8 and Arch archive replacement2.1.4→2.1.8, plus static installed CLI
checks without runtime/workspace creation. Evidence: checkpoint39/
linux-rpm-replacement-34776528312/receipt.json and linux-arch-package-gate/receipt.json.
These are package acceptance, not same-source public update/recovery. Owned guests
2316/2317 were shut down normally. A malformed read-only hop exposed the Arch host
runtime inventory; no host mutation was performed; keep exact guest identity checks.

Native JUnitCore exit0/OK is insufficient proof: assumptions can skip execution.
Earlier Windows interactive receipts were invalidated for this reason. The
assumption-aware retry first exposed missing fixture DOTNET_ROOT forwarding, then
an ineligible SYSTEM/session0 actor. Neither established a product token-capture
failure. Root's later direct apphost probe proves session1/WinSta0/shell65782 and
identifies the actual failure in TokenScalar: TOKEN_ELEVATION rejects an eight-byte
buffer with ERROR_BAD_LENGTH24; four bytes succeeds. Earlier source-line inference
that GetShellWindow failed was incorrect. Evidence:
checkpoint39/windows-token-diagnosis/root-{direct-completion,token-size}.result.json.
The new routine current-token fixture reproduced ERROR_BAD_LENGTH24 with the old
eight-byte buffer and passed with four bytes (zero compiler warnings/errors).
Immutable evidence: checkpoint40/token-scalar-{red,green}/{manifest,run.result}.json.
This is real Windows ARM64/x64 component evidence, not MSI/UAC acceptance.

Current macOS CI DMG inspection passed for exact source a4a5b743: DMG SHA256
7e60d2a704fe1c06aea73da24e1288860e2054763b4096e51d574c0df5967a34.
Launcher, installer worker and runtime are arm64. Static CLI help/version/
capabilities and missing-owner status passed without creating fixture state.
Ad hoc codesign verification passed; Gatekeeper rejected the unsigned-default CI
package as expected. This is read-only mounted-app evidence, not installation.
Host evidence: /private/tmp/vpn-control-macos-current-inspect-20260913T2220Z/artifact.
The exact test DMG was detached and removed from the VM; pending job inputs remain.

## Active Ownership And Fixtures

| Owner | Files or environment | Current check / next handoff |
| --- | --- | --- |
| root | WIP, shared build/delivery; exclusive Windows VM | Native original-user diagnostics/coordinator execution; exact-SHA CI fix integration |
| desktop_export_failure_audit39 | Exclusive Fedora2316/Arch2317 operator; export source frozen | Complete same-source public update recovery after Linux ownership transfer |
| windows_aot_regression39 | Windows compiler fixture dependency tests | Failed Windows CI causal regression and fixture fix; no VM or JVM activation |
| mac_fixture_recovery40 | Owned Tart guest; Mac installer; Handoff, OperationRunner, ControllerOwner, HeadlessSession and focused tests | Late authorization retains exact worker; serialize resume/cancel and preserve runtime-stop/commit/response-ack ordering |
| windows_msi_native_cutover | Ignored original-user diagnostic bundle only | Capture full native permission error; root alone executes in Windows VM |
| windows_apphost_desktop39 | Exclusive Android5596 native actions | API35 benchmark passed; next Find Best cancellation/recovery |
| windows_token_diagnosis39 | Linux handoff only; no active environment ownership | Transferred exact routes/current fixture state to Linux operator |


- Windows VM: `.runtime/visual-vms/windows/qga.sock`; ARM64 guest/x64 emulation.
  Preserve unrelated processes. QGA PID status can be stale after PID reuse; use
  unique result tokens/files. Interactive user visualagent is session1; SYSTEM
  session0 is not an eligible GetShellWindow test context.
- macOS Tart `vpn-control-visual-macos`, admin@192.168.64.3. Preserve GUI/owners
  25488/25489/26289/26290 and relays59022/59023/59024. Watcher26736 was absent
  at the latest read; no agent stopped it. Pending job
  e4c4d691-a967-4902-96cc-bf77cccfebfc remains PREPARING; never replay it.
  Verified backups are in checkpoint37/mac-capacity-backup and
  checkpoint37/mac-capacity-backup-current. Free space was1,623,840KiB after exact
  inactive-artifact cleanup. The new a4a source fixture base2.3.3 built and was
  captured; target2.3.4 failed terminally in jpackage temporary-image creation with
  ENOSPC. No target/final receipt exists. Recovery owner must preserve source,
  runtime, base completion, and signing policy; no build is live from that failed run.
- Linux SSH route: port228 kardinal@ssh.karapsin.com, then archlinux, then the
  owned guest. Current gateway socket is recorded in
  checkpoint37/linux-gateway-control.json; revalidate sockets before use.
  Preserve recovered Ubuntu guest2307 and owner89494.
- Fresh dependency guest on Arch:
  /home/kardinal/vpn-control-install-vm-20260913-deps-2311, QEMU3185756,
  port2311, 2vCPU/2GiB. Current2.1.8 DEB clean installation passed: baseline had
  no xdg-utils, desktop-directories or VPN Control; targeted APT added only the
  app and required xdg-utils, postinst registered the desktop entry. Static CLI
  passed without display/workspace/runtime. Guest receipt:
  /home/vpnfixture/current-deb-clean-dependency-34776528312/final-receipt.txt.
  Read its launch.json for exact guest SSH inputs.
- Fresh Android5594/5596 contain signed source064 target2.3.8. API35 was stopped
  after cleanup; API29 is assigned to document verification. Do not clear state.

## Remaining Implementation And Acceptance

1. Finish Windows fixed native installer bootstrap/original-user/coordinator
   integration; prove ordinary/elevated owner and another approving administrator,
   real successful MSI replacement, denial, receipt recovery and lock release.
2. Exercise the enabled Windows broker through current packaged GUI/CLI: actual
   A/pending B, UAC denial continuity, complete supported CUSTOM/resources, TUN and
   exact child termination. Then remove whole-GUI elevation/HIGHEST autostart and
   migrate only app-owned registration. Separate native x86_64 proof is required.
3. Complete current-source desktop installers: DEB/RPM/Arch recovery/rollback
   (fresh current DEB dependencies/postinst now passed); macOS local/machine authorization, replacement,
   rollback, pending recovery and GUI return. Component proof is insufficient.
4. Close Android native action/SSH/refresh/foreground-service, consent denial,
   cancellation and process-loss matrix on API29/API35. Installer positive recovery
   is proven; all permission/cancel/corruption/retention cases remain in scope.
5. Close large-document cold reopen, persistence/resource failures, transport
   expiry/principal/owner/hash interruption and private no-overwrite exports on
   current packages. Keep56,000 domains, over11MiB and48MiB Android heap.
6. Prove desktop one-owner and traffic continuity through GUI attach/hide/show,
   close/crash, CLI disconnect and scheduled refresh; validate missing-owner and
   transient-owner lifecycle behavior through installed launchers.
7. Complete GUI callback/CLI effect comparison, picker/clipboard/QR alternatives,
   localization and changed-scene captures, including five Android installer states.
8. Review every changed path, update metadata after final content edits, obtain
   current full prepush receipts, push reviewed commits and verify all five exact-SHA
   workflows. Revalidate final packaged/visual evidence against delivered source.

Keep each distinct native/manual/integration failure's causal quick regression in
routine checks and retain the native scenario. Never label a skipped test,
compile-only test, older launcher plus new classes, or a mounted app image as a
successful current installed-package acceptance run.

## Checkpoint40 Integration Evidence

- Direct file export now passes the real cold-owner 64MiB CLI regression with
  500,000 domains; selected export tests:24 total, zero failures, one platform
  skip (`checkpoint40/export-green9.log`). Review also added acknowledgment-loss
  success retention, non-content metadata preservation, and protocol-error
  classification. Causal acknowledgment-loss and cold-start OOM REDs were reproduced in
  checkpoint40/export-{ack,cold}-red; the tested fixes are restored.
- Positive Android credential commit/fresh-store/new-epoch test compiles
  (`checkpoint40/android-ssh-reopen-compile.log`); native execution still pending.
- macOS same-source fixture build recovery completed with both base and target
  restored, not an updater installation. Final receipt SHA256
  `751dd0a6acc485c074a4b84b5607768df900ec10b4fc5cb0a9cfeef8254f27d6`,
  target2.3.4 DMG SHA256
  `2bb3df3b623c0e3853e17fc6eb59a2ccdc39c530feeeb143c69a6d23351db0ee`.
  Fixture regression suite37 passed; actual replacement requires sufficient
  disposable guest storage and preservation of the older pending job.
- Linux Ubuntu2311 failed terminally when its stale2GiB guest OOM-killed the
  build. Current setup already uses6GiB; a deterministic argv regression failed
  at2GiB and passed after restoring6GiB. Owned retry2318 has6GiB and preserved
  da81/runtime provenance. No installer/update acceptance claimed.

- Windows coordinator sources compile natively after qualifying the wait helper
  namespace. The native test then exposed a positive-case gate retained into a
  negative case; the fixture now resets only its unique test directory between
  cases. Final native execution is pending unreliable QGA observation; QMP
  confirms the VM running, so no process or VM restart is authorized by timeout.
  Latest immutable bundle: checkpoint40/coordinator-native-bootstrap-5c25debe69ef43dc9e37cb9484405acb.
  The production JVM installer still uses the existing adapter and does not
  activate the new native bootstrap. Full UAC/MSI acceptance remains required.

- macOS user-local actual same-source public updater and next-owner recovery passed
  on frozen a4a pair2.3.3→2.3.4. Job48ccc0a5-97d5-4dc0-833e-4c7d195a1f80
  reached SUCCEEDED/OK seq4; relaunched target reported installed=true and
  cleanupCode=OK with original controller/request/operation correlation. Fresh
  user-local path did not overlap the preserved old pending machine job. Runtime
  remained off; owned owner/server and temporary TLS materials were cleaned.
  This is headless user-local evidence; machine-owned authorization and GUI
  return remain separate acceptance gates. Root receipt review is in progress.

## Current Native Recovery Results And Open Defect

- Ubuntu same-source public recovery passed for frozen da81 source, base2.1.7 to
  target2.1.8. Operation770423aa-d91a-4f91-87e1-8f1ab68a9052 and
  job1e0f6bfa-3dd2-47ea-acc7-636f0c606d0b recovered on the replacement owner;
  receipt SUCCEEDED/OK. Evidence: checkpoint40/linux-current-public-recovery.
  Guest2318 was shut down after terminal cleanup. This is not bb79 package proof.
- macOS user-local same-source replacement passed for the frozen a4a fixture,
  base2.3.3 to target2.3.4; job48ccc0a5-97d5-4dc0-833e-4c7d195a1f80 recovered
  installed=true on the replacement owner. All15 manifest-listed evidence hashes
  verified: checkpoint40/mac-user-local-recovery. It is not bb79 package proof.
- The distinct machine-owned Mac job697bf383-698c-4e41-ba6d-8d05930211ae remains
  AUTHORIZED/OK sequence1 after approval arrived beyond the initial wait. The old
  owner operation1a60aa37-776c-4088-9e20-14f5760dead9 remains OUTCOME_UNKNOWN;
  base2.3.3 is unchanged. Preserve worker, inputs and correlation; no manual
  commit/replay/cleanup. Causal quick regression now fails with attempted cancel
  on timeout: checkpoint40/mac-late-auth-red-causal.{log,xml}. Fix in progress.
- Windows original-user probe completed with PERMISSION_DENIED. Exact scheduled
  task is Ready/result1 and no helper process remains; full error diagnostics
  are next. Evidence: checkpoint40/original-user-root-final. This is neither
  successful original-user execution nor MSI/UAC proof.
- API35 public benchmark produced secondaryTotalMs841.071083 with real relay TLS
  traffic; interactive Find Best accepted VPN consent and activated the winner.
  Public off and fixture deletion completed; final runtime stopped. Evidence is
  under checkpoint37/android-api35-native. Remaining action/failure matrix stays
  open; do not infer Find Best preserves selection as benchmark does.

## Checkpoint41 Work Under Review

- Windows compiler dependency fixes have a source-list closure regression with
  isolated bb79 RED evidence; the host guard passed. Native-only compiler tests
  skipped on macOS, so the failed Windows CI gate still needs a new verified push.
- Mac late authorization focused selection executed29 tests successfully and
  skipped12 Windows-only cases. Further review found cancellation admission during
  reserved resume, retrying exit-arm without replay, and foreign-result job binding
  defects. Fresh owner mac_resume_race_review41 controls OperationRunner and
  ControlInstallSessionTest to close them before final acceptance.
- Windows autostart ownership/explicit migration selection passed18 tests. It is
  under review for exact path/legacy registration ownership and query failures;
  migration is not activated and whole-GUI elevation remains unchanged.
- Original-user native diagnostics prove Capture succeeds for ordinary user/session1,
  then StartSameHelper fails CreateProcessWithTokenW with Win32 error1314. Evidence:
  checkpoint40/original-user-root-diagnostic/runs/7d7986b430814340a6e595f5be4dbfea.
  Fresh owner windows_original_user_launch41 owns the launcher and focused tests.
- Native coordinator5c25 emitted its exact admission marker and native completion,
  but its PowerShell wrapper3512 remained live without an apphost at observation.
  No restart/termination was performed. Component marker is not full lifecycle proof.
- Fresh android_cancel_native41 owns API35/5596 cancellation acceptance; previous
  cold-CLI attempts reached already-completed operations and do not close that gate.

## Checkpoint41 Freeze Evidence

The reviewed code slice contains the Mac retained-authorization fix and cancellation
admission/cleanup safeguards, Windows original-user launch fallback and compiler
fixture dependencies, and Windows autostart ownership inspection/explicit migration.
No release or whole-GUI elevation removal is part of this checkpoint.

- Focused current Kotlin union:56 tests executed, zero failures/skips
  (`checkpoint40/mac-resume-race/green3.log` and retained XML). Three resumed-job
  races failed causally before their fixes; pre-commit stop failure also reproduced,
  while ambiguous-commit no-cancellation safety stayed green. Exit arming retries
  without another commit; pre-commit unconfirmed cancellation permits only owned
  cancellation retry. Full prepush remains required after final metadata.
- Windows current launcher compiled in the owned ARM64/x64 guest and actual
  ordinary-user/session1 native probe passed, including real helper launch and
  forced1314 fallback branch with child identity checks. Frozen current fixture:
  `checkpoint41/original-user-fallback3/runs/a990829a202f449ba24279adde559f2a`.
  This is component evidence, not MSI/UAC/elevated-or-other-admin acceptance.
- Root verified all Fedora evidence hashes and actual exact operation/job recovery
  in `checkpoint41/linux-fedora-public-recovery`. Frozen source remains da81.
- Root verified64 Android evidence files in
  `checkpoint37/android-api35-native/native-cancel-retained`. Before and after the
  cancelled0/2 Find Best operation, selected B remained pending while active A and
  its runtime ID remained unchanged. This does not prove cancellation after a
  candidate runtime replacement or general traffic continuity.
- Old Mac machine job697bf383 accepted public cancellation and its cancel byte is1,
  but protected receipt remains AUTHORIZED/OK sequence1 with no observed coordinator.
  Owner38162 and watcher38203 remain; no quit/manual cleanup/replay was performed.
  It cannot certify the new source and remains an unresolved native fixture gate.
- Arch2317 public authorization attempt failed; exact authentication/terminal
  correlation is being rechecked before any new attempt. Preserve unknown work.


## Checkpoint42 Follow-up

Checkpoint41 was pushed as `11bb41d657f66a7f927dedc993539ebf4bef9ce4` after
managed prepush passed. Exact-SHA Windows CI failed because the original-user
fixture invoked `OriginalUserLaunchProbe.dll` while its configured assembly name
was `vpn-control-install-helper`. Android, Fast Checks, Linux and macOS passed. This is not a verified delivery.

| Task | Owner | Exclusive files | Check and next handoff |
| --- | --- | --- | --- |
| Primary installer failure | mac_failure_result42 | DesktopOperationRunner, DesktopInstallHandoff and their session/handoff tests | Causal RED retained; focused GREEN; authority boundary review |
| Windows fixture and delivery | Root | DesktopWindowsOriginalUserLaunchTest, WIP, metadata | Cross-platform causal RED retained; shared assembly/output naming GREEN; final prepush/push pending |

The macOS failure regression reproduced a known precommit runtime-stop failure
being replaced by CANCELLED after protected worker settlement. Internal primary
failure metadata now preserves that failure through cancellation cleanup. Receipt
success and other authoritative terminal outcomes retain precedence. Both causal
RED and focused GREEN evidence are under ignored `checkpoint42`; no new native
macOS acceptance is claimed.

The Windows fixture regression parses the actual generated project and compares
its assembly identity with the paths used by the native invocation. It runs on
all hosts before the Windows-only probe. The old naming mismatch failed locally;
the fixed fixture derives project, DLL and executable names from one value.
Windows native execution and exact-SHA CI remain required.

Arch2317 subsequently completed a fresh single public update and exact replacement
owner recovery: job `8b8609bd-9152-4cf4-9d87-1c7cb847f151`, operation
`85123384-21a4-49f6-ab65-2b97f4d13b3d`, protected SUCCEEDED/OK sequence4,
installed version2.1.8. Root verified all five local evidence hashes in ignored
`checkpoint41/LinuxArch` (repository root). The new owner exited through public
quit; fixture TLS service/materials were removed. This proves frozen da81 source,
not current11bb. The earlier live-owner guard failure occurred before replacement;
it does not prove rollback. Old watcher1621 for an unrelated-to-success retained
fixture job had no terminal receipt and was left untouched for its own timeout.

Root also verified all eight hashes of the retained Mac unknown-cancellation
bundle. It proves cancel=1/AUTHORIZED and absent coordinator only; the cause of
coordinator loss is unproven. Preserve this fixture without replay/manual cleanup.
Non-English Windows autostart absence detection is a confirmed remaining defect;
English message matching must be replaced with language-neutral absence evidence,
without treating generic query failure as absence.


## Checkpoint43 Windows Integration Delivered

Checkpoint42 (`aee113bd1918a75cb363e1e8d29ed74ad741830a`) and checkpoint43
(`dabd111d466373467bdc2bd58787d39df1eee6f8`) both passed managed prepush and
all five required exact-SHA workflows after pushing to origin/dev. Checkpoint43
uses version 2.1.9 with six Unreleased notes. Its managed receipt is in
`.runtime/parity-evidence/checkpoint43/commit-result.json`.

| Task | Owner | Owned files | Evidence and next gate |
| --- | --- | --- | --- |
| Native MSI public binding | Root | DesktopWindowsInstaller, coordinator launch test, WIP/version | Sole native coordinator launch; frozen package/UAC/MSI recovery still required |
| Fixed helper admission | mac_failure_result42, finished slice | Helper admission wrappers/common lease, admission tests, import policy | Focused GREEN; physical identity, manifest and failed-cleanup launch rejection |
| Autostart locale queries | windows_autostart_locale42, finished slice | Autostart manager and tests | Causal localized query RED, focused GREEN, compiled read-only scripts ran in owned Windows guest |

The new installer binding retains the packaged native helper, creates the exact
correlation before launch, passes the native owner FILETIME, and verifies the
returned ShellExecute process image before releasing its process handle. The
native coordinator creates its original-user child; the JVM no longer starts
legacy PowerShell workers. Protected receipt/commit/recovery remain authoritative.
No whole-GUI elevation or VPN production-enablement change is included.

The shared helper admission preserves exact application/helper pins, PE and
manifest checks, and cleanup ownership. Review found that partial cleanup could
leave launch parameters usable. Its quick regression failed before the closing
state fix; cleanup retry remains possible but launch is blocked from first close.

Autostart failed queries now require exact language-neutral ABSENT evidence,
never an English error substring or generic exit1. Native evidence mapped missing
GetTask to FileNotFoundException, so only that call's matching HRESULT establishes
absence; connection/folder errors remain unavailable. The compiled task and Run
scripts both returned exit0/ABSENT with empty stderr in the owned Windows guest's
SYSTEM context. This is read-only component proof, not original-user enable or
migration acceptance. A routine Windows test executes the real classifier on
missing/wrapped-missing/COM-denied/generic exception cases.

Focused union:55 tests executed, zero failures, one Windows-native classifier test
skipped on macOS. Evidence is in ignored `checkpoint43`; two initial fixture
assertions were corrected (identity fields instead of object equality, and exact
Windows quoting). Full prepush and privileged-helper review passed. Current
package native MSI grant/denial/elevated-owner/other-admin/recovery and the
final-source parity matrix remain required. Old unknown native jobs stay preserved without replay or kills.


## Checkpoint44 Native Verification In Progress

| Task | Agent | Owned files/subsystem | Environment/artifact | Current check and next handoff |
| --- | --- | --- | --- | --- |
| Delivery and package freeze | Root | WIP, routine hygiene wiring, metadata | Host build only; frozen dabd macOS pair | Both builds passed; review fixture regressions before next prepush |
| Android candidate cancellation | android_remaining_native43 | Ignored relay and native evidence | Exclusive API35 emulator5596; historical signed 2.3.8 APK | Controlled validation HTTP request marker; active-verification recovery remains separate |
| Linux GUI observation | linux_package_native43 | linux_gui_fixture_guard.py and its tests; ignored native harness | Exclusive Fedora2316, display :97; older da81 RPM2.1.8 | Bind windows to fresh live process; native X11 crash remains unresolved |
| macOS replacement | mac_next_fixture43 | Guest fixture/evidence only | New vpn-control-machine-fixture43; same-source dabd base2.1.8/target2.1.9 | Embedded versions, arm64 and signatures passed; public replacement/recovery next |
| Windows prerequisites | windows_token_diagnosis39 | Read-only tool inventory | Exclusive disposable Windows QGA guest | Locate actual x64 JDK/AOT/WiX; return environment ownership before installation |

Both macOS DMGs were built with the task-owned Temurin17 arm64 JDK and explicit
Gradle version properties. The initial Homebrew-JDK attempt failed the packaging
vendor guard and did not produce an accepted base package. Frozen hashes and logs
live under `.runtime/parity-evidence/checkpoint44/macos-pair`. Guest inspection
confirmed matching logical code, distinct 2.1.8/2.1.9 metadata, arm64 launchers and
packaged native workers, and strict/deep ad-hoc signatures. Root-owned base app is
installed only in the new disposable guest. Public replacement is not yet proven.
Old macOS uncertain installation journals and owners remain untouched.

Android relay attempts exposed fixture defects: relay lifetime, unsupported
probe destinations, and completion before cancellation observation. None proves
mid-probe cancellation. A controlled HTTP validation target is being used to
hold a real candidate request; this cannot certify active-runtime replacement
recovery. The earlier unintended inventory force-stop on5596 was reported to the
user and recorded in checkpoint43/android-inventory/force-stop-incident.txt.

Fedora's older installed package passed proxy traffic and stable runtime identity
checks, but its software-rendered GUI crashed in libX11 XVisualIDFromVisual via
Skiko/AWT drawing-surface lookup. A stale window might have received automation,
so attach/hide/show/close/crash acceptance is explicitly withheld. The new quick
fixture regression must reject foreign windows, PID reuse, dead frontends and
crash reports before lifecycle probes. Keep the native crash scenario: this
guard fixes evidence admission, not the rendering defect.

Current-source inspection also confirms DesktopAppServiceFactory enables scoped
Windows runtime through isPotentiallyEligible; the constructor's false default
is not proof that production is disabled. Native TUN/UAC/traffic evidence is
still required. The existing HighestAvailable migration helper remains inactive
because its two-read ownership guard is not an atomic replacement operation;
do not wire it into a public action without addressing that race.

The Linux guard's nine injected boundary tests pass, including process-stat
parsing, missing-process races, zombie/PID reuse, X11 query failures and failure
receipts. Routine release hygiene invokes them. A guarded renderer-only guest
launch identified a fresh window on PID10294/starttime731820 and cleaned its
exact GUI/controller afterward. That native receipt used the guard before its
final error-reporting hardening, and does not prove the full lifecycle sequence
or resolve the earlier renderer crash. The final guard was copied with matching
SHA-256; evidence remains under the owned Fedora GUI fixture.
