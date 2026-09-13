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

Checkpoint37 is pushed as `a4a5b74350e76c3f5706b29bce601713a6a39e13`, version2.1.8,
seven Unreleased notes. All15 managed prepush commands passed; 27 reviewed paths
were committed. Exact-SHA Fast Checks, Android Release APK and macOS Desktop
Package and Linux34776528312 have passed. Windows34776528323 failed NativeAOT
compilation: IL3050 on Marshal.SizeOf(Type) in the original-user launcher. A causal
analyzer regression reproduced IL3050, then passed with the generic-overload correction; this push is
not CI-complete. Advisory VPN Integration passed.

Evidence: checkpoint37/{prepush-result,commit-request,commit-result}.json and
checkpoint37/commit.log. The commit monitor may not publish its result until CI
is terminal. Older checkpoint36 `064adbbd7df81cc7928b920e77b12da22ccdf312` failed
Windows fixture portability; the repair has current native Windows evidence.

The next dirty slice intentionally covers Android CA staged-filename admission,
its causal tests, an assumption-aware native JUnit evidence gate, and Windows
fixture runtime-root forwarding and NativeAOT compatibility. Reviewed focused
checks pass; it needs version_bump, a new full
prepush receipt and its own reviewed push. No prototype helper activation or full
parity completion is claimed by these changes.

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

Native JUnitCore exit0/OK is insufficient proof: assumptions can skip execution.
Earlier Windows interactive receipts were invalidated for this reason. The
assumption-aware retry first exposed missing fixture DOTNET_ROOT forwarding, then
an ineligible SYSTEM/session0 actor. Neither establishes a product token-capture
failure. A subsequent eligible visualagent/session1 run with shell handle65782
and zero assumptions also failed Capture with UNAVAILABLE; that failure now needs
precise native diagnosis. Evidence: checkpoint38/windows-executed-junit/interactive-completion.json.

Current macOS CI DMG inspection passed for exact source a4a5b743: DMG SHA256
7e60d2a704fe1c06aea73da24e1288860e2054763b4096e51d574c0df5967a34.
Launcher, installer worker and runtime are arm64. Static CLI help/version/
capabilities and missing-owner status passed without creating fixture state.
Ad hoc codesign verification passed; Gatekeeper rejected the unsigned-default CI
package as expected. This is read-only mounted-app evidence, not installation.
Host evidence: /private/tmp/vpn-control-macos-current-inspect-20260913T2220Z/artifact.
The exact test DMG was detached and removed from the VM; pending job inputs remain.

## Active Ownership And Fixtures

| Owner | Files or environment | Next handoff |
| --- | --- | --- |
| root | Shared integration, WIP, metadata, host Gradle, delivery | Review dirty slice; finish exact-SHA CI |
| android29_large_document_current38 | Only emulator5594 and ignored evidence | Current APK watch/follow/owner-loss slice; large document chain handed off |
| windows_token_diagnosis39 | Windows QGA VM and ignored diagnostic harness | Identify eligible-actor Capture failure; coordinate analyzer execution |
| windows_aot_regression39 | Original-user launcher C# and its Kotlin compiler test | Causal NativeAOT regression and IL3050 fix; no VM ownership |
| linux_remaining_gates39 | Owned Linux guests and ignored evidence | Preserve current DEB receipt; prepare RPM/Arch native gate |
| mac_recovery_gate39 | Owned Tart guest; read-only recovery diagnosis | Preserve current DMG evidence; identify safe pending-job reconciliation |
| android35_tls_diagnosis38 | CA trust/preflight helpers and dedicated tests; slice handed off | Root review and routine checks |
| native_junit_evidence_guard38 | New Java test gate/tests and test-matrix text; slice handed off | Root review and native harness adoption |

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
  inactive-artifact cleanup; the2GiB capacity target is not met.
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
