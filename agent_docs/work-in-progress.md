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

Last fully verified checkpoint is `7dbcffb72f3eef67827cdc1b8c1b3297f8e5857e`.
The pushed `ff8de90ef22fd7015ceff9620389aae56c545900` (version2.1.11) passed
full local prepush but Windows CI failed in the executable visual guard test.
Its richer diagnostics expose a retained CR in the emulator serial emitted by
native Windows Python. A portable CRLF-emitting regression now reproduces this
locally; normalization passes all67 visual tests. Other exact-SHA workflows still
require terminal verification. No checkpoint is fully delivered until all five pass.

Committed atff8de90: Fedora package selection follows exact distribution ID then
ordered ID_LIKE, avoiding build-tool dpkg selecting DEB on Fedora. All11 focused
selection tests pass. Current-source packaged RPM/DEB/Arch recovery remains open.

Current integration:

- Direct visual preflight rejects stale primary-display statusbar geometry before
  device/output mutation. Normal reboot of owned5600 restored Pixel6/API35 geometry
  from cutout128/statusbar63 to128/128; screenshots still require fresh review.
- Shared installer handoff repair retains exact uncertain external jobs rather than
  implicitly cancelling after commit attempt. Explicit public cancellation remains
  supported. Three causal regression failures recorded before repair. This does
  not establish the exact cause of the earlier macOS native async cancellation.
- API35 SSH authentication/restart succeeds. Held-live relay fixture resolved the
  earlier listener-lifetime failure, but payload7 still has no relay traffic proof.
  Public cleanup restored stopped/default/empty state at revision39.

Evidence resides in checkpoint51: fedora-visual-{prepush,commit}-result.json,
ci-ff8-windows-failed.log, visual-python-crlf-{red,green}.log,
install-commit-boundary-{red,green2}.log and android-ssh-private/run/payload7-receipt.md.

One host Gradle operation at a time. Metadata/prepush must follow the last content
edit; no receipt from a prior content state is reusable. No release is authorized.

## Current Environment Ownership

| Task | Owner | Exclusive scope | Next evidence |
| --- | --- | --- | --- |
| Integration/delivery | Root | Shared source, scenes.json, docs, sole host Gradle | Final review, metadata, full prepush, push and exact-SHA CI |
| Linux native update | Root | Fedora2316, ignored fixture/evidence | Rebuild fixed-source immutable pair, public RPM recovery |
| Linux selection fix | linux_reopen49 | DesktopUpdateService and Linux update tests | Source ready;11 focused tests passed |
| Windows public CLI | windows_x64_inventory49 | Native AMD64 MSI VM on Arch | Reliable ordinary InteractiveToken fixture, static/no-owner/lifecycle gate |
| macOS native updates | mac_install50 | Tart fixture43 and native evidence | Machine and user-local sync success; trace async cancellation |
| Android API35 | android_gates51 | AVD5596 | Current-base cold document chain complete; remaining native actions/installer matrix |
| Android visuals | windows_apphost_desktop39 | Android scene provider/inventory test only | Provider ready; native capture awaits environment/build allocation |
| Failure ledger | android_api29_52 | New agent doc only; AVD5594 shut down | Reviewed ledger and retained API29 evidence |
| Capacity | fixture_capacity50 | Verified cold-artifact relocation only | Completed restore manifests; no current artifact ownership |

No new Windows worker was created when the agent tool reported its thread limit.
Reusing an existing worker does not permit a second operator in its VM.

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

Static/no-owner/lifecycle batch dispatch has not yet produced accepted evidence.
The next fixture uses a fresh ordinary InteractiveToken/LeastPrivilege task and
user-writable correlated output, avoiding fragile Run-dialog typing.

Local ARM64 guest / AMD64-emulation component evidence remains separate: scoped
broker/TUN and UAC denial preserved traffic; original-user bootstrap fixture ran
three tests with no skips/failures. Current-package/nativeAMD64 broker and full
MSI adapter scenarios remain required. Old HIGHEST autostart migration is dormant;
two reads plus unconditional task replacement cannot prove ownership-safe mutation.

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
3. Current-source DEB/RPM/Arch install/update/recovery/rollback; macOS local/machine
   successful installation, denial, recovery, rollback, cleanup and GUI return.
4. Android API29/API35 action/SSH/refresh/consent/foreground-service/process-loss and
   installer permission/cancel/corruption/retention/reconciliation matrix.
5. Remaining document expiry/principal/owner/hash/interruption/resource/persistence
   failures and GUI/private export paths; cold-read success does not close these.
6. All desktop one-owner/traffic lifecycle and scheduled-refresh scenarios through
   installed launchers, including missing-owner and transient-owner behavior.
7. GUI-versus-CLI effect comparison and changed-scene capture/review, including six
   Android installer states, geometry and intentional baselines.
8. Final metadata, full current prepush, reviewed commits/push and all five required
   workflows for the exact SHA; match final packaged evidence to delivered inputs.

Do not label skipped native checks, component-only tests, older launchers with new
JARs, mounted images or in-progress jobs as full installed-package acceptance.
