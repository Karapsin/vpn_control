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

## Delivered Checkpoint And Current Dirty Work

Checkpoint38 is pushed as `da81c52df0b5f45ea59189f586e8e77d47045006`, version2.1.8,
eight Unreleased notes. All15 managed prepush checks and all five exact-SHA required
workflows passed. Required run IDs: Fast34778462577, Android34778462664,
Linux34778462616, Windows34778462624, macOS34778462593. Advisory VPN also passed.
Evidence: checkpoint38/{prepush-result,commit-request,commit-result}.json.
The previous a4a5b743 checkpoint failed Windows IL3050; the generic marshaling
fix and routine NativeAOT analyzer regression are in this verified checkpoint.

The next intentional dirty slice covers desktop direct file-export transport and
its real constrained-client regression, Windows native coordinator bootstrap/child
lifecycle and scalar-token regression, plus macOS test-fixture build recovery, Android credential reopen coverage and a
regression retaining the existing6GiB Linux build-VM capacity.
These changes are uncommitted; version metadata has rolled to2.1.9 and requires new full prepush
and a separate exact-SHA push. Native helper activation in the JVM remains pending.

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
| root | WIP, shared build/delivery; exclusive Windows VM | Actual scalar RED/GREEN; export focused tests; native proof review |
| desktop_export_failure_audit39 | DesktopControlDocuments, ActivationServer, Cli, Exports, PublicCliClient startup and focused tests | Real 64MiB public-client export regression; native metadata/publication review |
| windows_aot_regression39 | Native helper sessions/original-user launch and focused fixtures/tests | Bootstrap lifetime fix; current-token regression; no JVM activation |
| mac_fixture_recovery40 | Owned Tart guest; prepare_desktop_update_fixture and focused tests | Preserve successful base, recover target packaging after terminal ENOSPC |
| windows_token_diagnosis39 | Exclusive Ubuntu2311 Linux fixture/recovery operator; no shared fixture script edits | Revalidate existing authenticated Arch hop; prepare immutable same-source DEB pair |
| windows_apphost_desktop39 | AndroidSshCredentialVersionsInstrumentedTest only; handed off | Positive fresh-store/new-epoch credential test added; root compile passed; native verification pending |

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
