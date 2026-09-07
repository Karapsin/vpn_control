# GUI/CLI Parity Native History Through 2026-09-06

Historical notes preserved verbatim from the prior work ledger. Status, version,
process IDs and handles below are historical observations, not current authority.
See [work-in-progress.md](work-in-progress.md) for the active ledger.

# Work In Progress

## Active Goal And Safety

Complete GUI/CLI parity on Linux, Windows, macOS and protected nondebuggable Android
ADB. The goal is NOT complete. Requirements: [contracts.md](contracts.md), especially
CLI-001..008 and STATE-001..005. Command/specification inventory: [cli.md](cli.md).
Historical implementation-gap descriptions there are superseded by current status
below where explicitly noted; the requirements themselves remain unchanged.

User authorization covers test VPN and installer/elevation only in agent-owned
disposable VMs/emulators. Never touch host VPN, personal data or emulator5580.
Only positively identified task AVDs5582/5590 may replace synthetic app data or use
disposable fixture CA trust. No release/main/tag/publish authorization. iOS is future
work, outside this goal. Preserve locally ignored agent_docs/.Rhistory; exact local
exclude is in .git/info/exclude, not shared .gitignore.

## Verified Checkpoint

HEAD/origin/dev: `60f8db884588047bea6eb1f108aea3d4c2ade07d`, version2.1.2.
Full prepush830 passed. Required exact-SHA workflows all succeeded:
Fast34029939692, Android34029939631, Linux34029939702, Windows34029939715,
macOS34029939822. Advisory integration34029939666 also succeeded. Windows installers
now use the prepared GUI/CLI image. This evidence does NOT validate newer dirty work.
Current batch has Unreleased notes, version unchanged2.1.2. Full prepush cell59
passed all requested checks after build19963. Subsequent native failures and added
regressions invalidate reuse of that receipt; another final content/metadata check
is required before commit/push. No new commit/push exists.

## Work Ownership And Speed Plan

Latest continuation evidence (2026-09-06, not pushed):

- Linux public INSTALL replacement SUCCESS (bounded, not full parity):
  Original failed VM repair97a03c installed ONLY xdg-utils (no removals/upgrades),
  then exposed legacy postinst error93066f: no writable system menu directory.
  Native1e374f confirmed /usr/share/applications755 existed but desktop-directories
  absent. Root created ONLY /usr/share/desktop-directories root755 and configured
  the task package successfully6b1e75. This manual repair is NOT proof new worker
  fetched missing dependencies. Current-package headless postinst regression
  d2bf2c RED5/1, agent owns minimum resource override. Native xdg algorithmda8a1c:
  directory phase1235..1254 selects writable desktop-directories under XDG_DATA_DIRS
  or /usr/local/share/:/usr/share/; empty globals fail1272 even with no .directory.
  APT-worker two-file overlay /tmp/vpn-linux-apt-fix-9540bc92.tar.gz SHA
  9912b09cbd168be8a9b3c8aa0ac949824b8d1c7c607e705be19b75f5f2a5cc32,
  guest /home/vpnfixture/apt-fix.tar.gz. Native test/image build ec3b4e GREEN10s.
  Preserved published failed image at /opt/vpn-control-published-failure-9540bc92;
  deployed metadata-only current worker clone7105c5, original main
  1ac1fc51504f6ddc9fbd61184e5d40e4dc5c233033f8379a81e0667a3379cfb2,
  fixture5ac664c06f62c808b8c495d838d6504c681f8e8aaf19f0c4b2cce3509b095b68.
  New evidence /tmp/vpn-public-install-evidence-okjojky0, owner
  d66e60ea-fa9b-41d1-97fa-c4905cb73a7e. Trusted2.0.18 downloaded/verified122053228B;
  real polkit0a47e7 granted3d3467. CLI6 ACCEPTED/handoffReady, operation
  3109d160-4412-44d1-bbd2-6abec6a7e290, jobf204f2ce-6d10-4d76-a04a-e58fad4fc94f.
  Descriptor-verified root receipt31fb18 sequence4 SUCCEEDED/OK; dpkg8e105d
  install ok installed /2.0.18-1; no active installer/owner. A mistyped read-only
  job lookup8e105d failed;31fb18 uses exact CLI job. Harness ebb70e later fails
  --version check because published legacy target lacks headless CLI. Do NOT
  claim harness whole-pass, current-source recovery, relaunch, or missing-dependency
  native success. /opt now actual published2.0.18, no current fixture marker.
  Both remote control PTYs92919/9541 idle, QEMU64406 still foreground VM.
- Windows native C# compilation and pure policy VERIFIED, no broker launch:
  exact source snapshot /tmp/vpn-broker-native.Z6osQa/windows-vpn-broker.cs SHA
  9dbe6ca26d20e760c043ef4a69680e572b6c556ffa977fe7fcf9fd4c6eee3bbb.
  Raw/compressed source via encoded command returned no QGA handles5f5645/63e61e;
  read-only process probea403dc showed no remaining compiler/previous PowerShell.
  Short command + hash-checked loopback artifact fetch compiledf8269e GREEN;
  pure policy script policy.ps1 returned d09869 POLICY_OK8: DNS/WS allow,
  cache confinement, foreign host/cache/ACME/Tailscale/SSH path rejection.
  This ran via QGA as SYSTEM in owned Windows VM, not standard-user/UAC/TUN
  evidence. No child runtime was launched. Temporary HTTP58944 session37391
  stopped78b7eb; source/script retained. Windows actual start/status/stop remains.
- Android FindBest first integrated union26962/664a71 GREEN39s; second atomic
  commit/rollback union45987/5f1248 GREEN7s35tests (FindBest6), no skips/failures.
  Subsequent synchronous-interactive admission regression17958/aab529 RED1/1:
  FIND_BEST omitted from early-ACCEPTED consent handshake. Agent owns fix and
  then stale SSH dialog/picker revision guards + typed restart. Do not use earlier
  APKs/host launchers as verification of newly written FindBest implementation.
  Sync handshake production fix compiled in94908, but SSH new helper regression
  currently compile-RED3ffc79 unresolved AndroidSshDraftControl; agent implements
  helper/wiring next, wait for coherent freeze before app test. This is not a
  behavioral SSH RED yet. Changelog2.1.3 has1 Unreleased FindBest bullet.

- Linux public install reached real polkit and package execution, then FAILED:
  Both earlier task owners absent0eed09, status UNAVAILABLE. Preserved prior
  /opt image as /opt/vpn-control-before-workspace-fix-9540bc92; installed new
  metadata-only root-owned test clone d20cee. Original main76546341a8323f80652da3577361fab656c83e1bf81436f4ff25a0670da4e998,
  fixture55dd913b5d6da71e4e56f77b91d260ca3be68b4ec1a364f20acb3dabf7f99f91.
  Evidence /tmp/vpn-public-install-evidence-e979dmjp; owner
  76d885f7-1db7-4ab2-8053-3062c9cbfd50. Trusted release2.0.18 DEB122053228B
  downloaded/verified; actual pkttyagent prompt078669 grantedb7fae9 asvpnfixture.
  Public CLI6 ACCEPTED/handoffReady with op1fb83135-e13e-42a0-84d4-1d042ac3aef2,
  job44ccd04d-fb44-4113-9699-024bfefd9879; owner exited. Protected receipt
  sequence4 FAILED/RUNTIME_FAILED a87739, not UNKNOWN. No installer process
  remained556a8d; dpkg log proves archive unpacked but not configured.
  Root read-only audit76ba7a identified missing declared xdg-utils dependency.
  /opt/vpn-control NOW actual published2.0.18, whose --version requires display;
  old package CLI limitation must not be mistaken for same-source parity proof.
  Do NOT reuse the prior fixture marker/launcher as if still new-source code.
  Guest package database has vpn-control2.0.18-1 unpacked/unconfigured. No repair
  executed yet. Read-only7ec2b9 shows targeted apt install xdg-utils would add
  ONLY xdg-utils and configure vpn-control (0 upgrades/removals, no recommends).
  Read-only534a5c shows direct local-archive APT retry refuses already-broken
  dependency state; preserve this boundary, do not add global repair to worker.
- Debian worker now uses exact protected package.deb with APT --assume-yes
  --no-remove --no-install-recommends --reinstall install, noninteractive; checks
  apt-get before authorization and cleans only fixed protected payload names.
  Inert actual-dispatch regression initially hit test shell identifier error;
  corrected fixture alias then TRUE RED96175/8e3cdc/f32bd3 expectedAPT/gotdpkg.
  Fix11904/a39650 GREEN9s, Linux worker/installer/Arch13tests4platformskips.
  New worker has NOT been deployed/retried natively. Next root: repair or reset
  only this disposable fixture's known partial package state, freeze/deploy new
  image, retry public path; preserve all failed receipts and image backups.
  Remote monitoring PTY9541 and controlPTY92919 idle onarchlinux; QEMU64406
  remains foreground task VM. Dedicated guest credential reset through passwd
  prompt only, no credential in repository or logs.
- Android missing public FIND_BEST confirmed RED96175/8e3cdc expectedACCEPTED
  gotUNSUPPORTED through actual reader. Agent owns full authoritative executor,
  guarded probes/cancellation/actual-vs-pending rollback, GUI delegation, and
  narrow DesktopAndroidAdbClient binding hunk. SSH draft/picker guards and typed
  owner RESTART are next actual implementation gaps, not just missing evidence.
- Windows generated-config policy4regressions RED79739/acf7f4. Agent fixed
  exact-context DNS/WS URL paths, protected per-job cache, managed SSH inline
  key capture without persisted mutation; authoritative C# repeats constraints.
  Custom scoped configs still explicitly gated, not complete parity. Native C#
  pure compiler/policy test and broker UAC/start/stop remain pending. Root union
  verification89968/4e0ede GREEN5s after frozen slice. Android FindBest app
  implementation currently PARTIAL: wait for agent coherence before app compile.
  Changelog automatic tenth-note roll now sets canonical version2.1.3; no release,
  commit, push, or final prepush. Prior snapshots remain labelled2.1.2.
- Latest macOS worker C compile-only c73cb6 GREEN -Werror, no execution:
  /tmp/vpn-mac-worker-recheck.UvJnLS, source
  76c6e249ec019e5a606967587a0db7c719858a640126f8938cfc5f5b7843e3c8,
  binary b03673f4bb84df5f56570390c03c81f50403fb1fb8e19450f1e4e6086076d93c.

- Linux x86 native startup failure diagnosed/fixed, not installer success:
  public harness c80498 rejected copied root image mode775; root normalized only
  task-owned /opt/vpn-control with chmod -R go-w. Retry505650 then failed owner
  startup in /tmp/vpn-public-install-evidence-enu34uni, workspace775 under umask002.
  Read-only192e78 confirmed generic headless startup failure and no live owner.
  Changing ONLY that disposable workspace to700 made identical launcher settings
  show succeed878221, ownerb37d3c9d-6aad-4e25-a666-e03afdd96368. No installer ran.
  Regression63029/831749 RED missing private workspace ancestry; new helper now
  creates missing POSIX workspace directories atomically700 across lock/log/state/
  endpoint entry paths. Existing directories are never chmodded; endpoint ancestry
  checks unchanged. Focused host3703/45aa3c GREEN10s.
  Frozen seven-file source overlay /tmp/vpn-linux-workspace-fix-9540bc92.tar.gz
  SHA da4b3fbff96a71550a555791a6d2cb78ad2ff441bec5bfc5558402a38ffa15be,
  copied through authorized SSH route to guest /home/vpnfixture/workspace-fix.tar.gz.
  Guest build/test under umask002 GREEN84acb1/32s. New public image settings show
  b53363/f888aa GREEN at /tmp/vpn-workspace-umask-OMnvhW/nested/workspace:
  owner7100069a-6a2b-4227-b0b7-8a826b999062, directories700, endpoint600.
  Remote control PTY92919 idle; QEMU PTY64406 remains foreground task VM, do not
  send shell commands or Ctrl-C there. /opt image is still OLD fixture; next step
  freeze/install rebuilt metadata-only image after verifying old test owners off,
  then retry real public installer. No host VPN/build/install changes.
- Android cancellation outer phase regression RED831749 then GREENdcdb7e
  (AndroidUpdateControlTest7/0). Fix reconciles terminal receipt before/after
  installer handoff callback. Delayed interactive async ADB token race independently
  reproduced dcdb7e: client previously detached on RUNNING before token existed.
  Agent fixed detach to wait for protected Activity launch or terminal outcome.
  Fresh native resume/independent redisplay remains unproven; do not upgrade prior
  API29 evidence. Combined host verification16536/1154fe GREEN35s: desktop46
  tests/0 failures/1 Windows-native skip; Android7/0. Changelog now9/10
  Unreleased bullets, version still2.1.2. No full prepush/new commit/new push.
- Windows scoped broker Kotlin slice compiled dcdb7e; focused process/status/stop
  regressions passed, native Windows test skipped on macOS. Fixed C# broker and
  real JNA transport exist but native compilation/UAC/start/stop remain pending.
  Public standard-user gate and whole-GUI elevation unchanged pending validation;
  injected-only broker is NOT final parity. Agent audits config paths/compiler next.

- Android API29 actual installation after process loss VERIFIED3e913c/209d1b.
  Diagnostic build27933 GREEN; nativeb61fb2 isolated ARCHIVE_SIGNERS_UNAVAILABLE.
  AOSP Android10 getPackageArchiveInfo collects verified certificates only when
  GET_SIGNATURES is set, but returns SigningInfo only with GET_SIGNING_CERTIFICATES.
  Regression92861 RED2/1; API29-only BOTH flags fix9857 union/release GREEN22s,
  still consumes only verified SigningInfo signers; API30+ unchanged.
  Fixedbase /tmp/vpn-android-session-native.qcxMoA/base-api29-signers-fixed.apk
  SHA7245a4d8a05d00348e9afa708d6291d89c9506f87e70a598ff36a7a620978e6b.
  Nativeb5cf26 same fixture download READY (all39413990 bytes). Noninteractive
  install3521be INTERACTION_REQUIRED/no session. Real unknown-source setting
  grant then installer confirmation observed in saved screenshots under taskdir.
  First op45fe0853-a1b6-4238-a5f8-c67fc34c408f handoff-only OK/installednull,
  receipt7d6cbc55-b071-46a5-9987-c5d3e22b4bc2/session319814476. Visible Cancel
  button tapped707,1298; aeca24 exactreceiptfailed/installedfalse. Outer phase
  incorrectly remained installing; Android agent owns regression/fix.
  Retryop830f7e06-28e2-42c0-bc99-090aaa0c66e8 creates receipt
  73045966-2050-4eae-a599-81ad77e57d7f/session1707366383. Known-off6afe7e;
  am kill ef8518 removed taskPID14284 (not force-stop), OS dialog persisted.
  New owner4455c226-5883-4d66-aae8-3eb048267948 recovered SAME receipt/session.
  Explicit resumeop8d17c9f2-789e-4af6-b9df-d2dccb375a99 remained awaiting-user;
  do NOT claim this command completed/resumed UI independently. Original OS
  confirmation still visible; real Installbutton887,1298 accepted. Fresh owner
  c15fb027-8203-4607-8768-0476a3e5ee35 reports SAME receipt installedtrue;
  Android package16460/2.1.3 corroborates but did not substitute callback evidence.
  Post-cleanup restarted owner2a317bf0-09d4-424c-b1a7-d0f27856eeda still reports
  exact installed receipt209d1b. AVD5582 now2.1.3 targetc5a0.. (older frozen
  source without latest signer fix/diagnostics); NEVER silently downgrade to2.1.2.
- Android fixture cleanup complete: original proxy null restored; exact reverse
 53934 removed; verified exact CA mount874780 unmounted only inzygote176;
  known-off task app force-stopped to drop inherited trust; adbd uid2000 verified.
  Fixture server12871 stopped60f181/exit130. APKs/screenshots/cert/private key
  and inert task-owned device files retained for evidence, host trust/5580 untouched.
- Remote x86 VM CREATED/BOOTED by root: PID4005754 on archlinux, foregroundQEMU
  ownedPTY64406, disk/home/kardinal/vpn-control-install-vm-9540bc92/task.qcow2,
  UbuntuNoble20260826 official image checksum verified; BIOS/KVM4CPU/6GiB,
  user-mode localhost2307, no shared folders/taps/existing VM changes.
  Host-controlPTY92919 currently running guest work. Guestvpnfixture uid1000,
  cloud-init DONE, Java17.0.20 and polkit active. VM native desktop app-image
  build859a73 GREEN4m20s. Source archive
  /tmp/vpn-linux-native-source.nfGgms/source.tar.gz SHA18fbdae6feba45b0997098f1215dab86d343cd52d5a4ca65f175b6c84721f1b5
  transferred through rpi+archlinux and verified inside guest at
  /home/vpnfixture/parity-source-9540bc92. Only tracked/unignored source inputs,
  no local caches/credentials. Bundled Linux runtime preparation + incremental
  app-image build now live92919; poll SAME handle, no restart on observation timeout.
  No actual Linux installer or VPN run yet. Guest-only polkit password not set.
- Mac journal/Linux/Windows/ACL union96083 GREEN29executed/1skip; native home
  exportdcb974 GREEN2. Frozen/tmp/vpn-mac-home-transfer.rQIUus/bundle main
 548bfd32821e36f8249d0d90de49633914cb306cde641ed75fc02ba6f18e1afa,
  tests9d7521fdea20ad18cc4f5f74cd2c5ae6a52da10e2caa366bda09f54df9287089;
  guest/Users/admin/vpn-mac-transfer-9540bc92-0b94-4b46-a13a-79fc0ae3987d.
  C worker compilee9a38d GREEN -Werror, not executed; later cleanup edits require
  recompile. New MacInstaller/native errno tests22229 GREEN6s; adapter remains
  unbound pending actual DMG/recovery proof. Windows scoped VPN agent now owns
  production runtime-handle + authenticated privileged-child vertical slice;
  must not remove existing GUI elevation before working replacement is tested.
- Remote x86 route user authorized: ssh -p228 kardinal@ssh.karapsin.com, then
  ssh archlinux. Root live PTY64406 is on archlinux prompt. Credentials must NOT
  be written into repo/logs. Bare ssh rpi failed DNS; explicit route succeeds.
  User explicitly requires a VM: remote hosts only host/start the task VM;
  builds/installers/VPN tests run INSIDE it. Readonlyc896a9 confirms x86_64/KVM,
  22GiB available RAM/843GiB free home. Existing shutoff arch-dotfiles-test and
  vpn-control-win11 are unrelated and untouched. xorriso/qemu-img/python3/curl/
  ssh-keygen installed. Linux agent adapts new task-only KVM cloud VM preparation;
  no host package installs or network reconfiguration. VM not yet created/booted.
- Android target33632 GREEN24s, frozen target-2.1.3.apk in
  /tmp/vpn-android-session-native.qcxMoA, SHAc5a0ce9f96fbaad9c4bc1caa248aaccdf55f5432528221e0dd52eaed2a880ddc,
  version16460. Both APKs apksigner verified same local debug certificate;
  base is NONdebuggable version16440 (dumpsys1fffa2), not stable release signing.
  Loopback fixture server12871 lives on53934, exact GitHub-path responses only,
  no forwarding. Owned5582 AVD name positively verified. Original http_proxy=null.
  Transient CA622de961.0 under/data/local/tmp/vpn-install-session-ca-qcxMoA,
  copied system certificates then bind-mounted in zygote64 PID176 namespace onto
  /system/etc/security/cacerts. Known-off task app force-stopped only to inherit
  trust; adbd unrooted and uid2000 verified. Reverse53934 + emulator-only proxy
  127.0.0.1:53934 active; restore/remove exact setup after native work, host trust
  and5580 untouched. Private key stays only task tempdir.
- Android native40f6fa check OK available2.1.3/compatibletrue. Download22ac7f
  failed RUNTIME_FAILED after all39413990 bytes; no install/session occurred.
  Owner9c8d360e-ed5c-4bbc-adb1-6340755c2738, failed operation
  c5e5b601-c84b-43e6-8185-b51f8b82d7e9. PackageParser warns only unknown
  queries/property elements; cause not yet established. Android agent adds
  allowlisted verification reason regression; rooted diagnostic must not weaken
  checksum/version/package/signer checks. Rooted access not used for public CLI.
  Diagnostic regressioned909b compile RED (new typed reason absent); fix pending.
  Standalone shell app_process APK metadata probe5985ec killed137, inconclusive,
  NOT a product failure. Its own files remain /data/local/tmp/vpn-session-*qcxMoA.
- Mac executable-lock focused56101 GREEN; natived4bc57 GREEN2 confirms existing
  executable SH lease excludes replacement even before first gate creation.
  Frozen /tmp/vpn-mac-executable-lock.EY8B4B/bundle,
  main a7f6bf01e1a34242514143485acdb226e33656551efd750d40df8f841136f967,
  tests e88802b17ae449767cac7a2a4b08fe33b84b5c244328150399ddd33fbfbf4e3c,
  guest/private/tmp/vpn-mac-executable-lock.gleyz0. System gates untouched.
- Linux harness grammar regressionaf8091 RED4/1 then one-line fix; root4e5c2d
  GREEN4. Actual install blocked on architecture prerequisite, not permissions:
  stopped owned Tart Linux is ARM64; trusted latest2.0.18/build16360 publishes
  Linux x86_64 only. No matching existing VM/image found. Existing local
  dist/arch/vpn-control-arch-x86_64-2.0.0.tar.gz actually has ARM64 launcher;
  preserve it but do NOT use as x86 evidence. Agent preparing isolated QEMU
  x86_64 bootstrap with user-mode network, no host VPN changes or release.
- Android19354 GREEN release + debug instrumentation compile30s. Five synthetic
  installation-state visual scenes added; inventory testb39657 GREEN1. Captures
  and baseline review remain open. Base2.1.2 frozen
  /tmp/vpn-android-session-native.qcxMoA/app-release.apk,
  SHA555b1810662aaf415de6a30756b66127a42720c60147cfa9dc96a19ad041952e.
  Owned5582 public preflight3f6622 off/rev0; install-r d02e38 succeeded without
  clearing data. Public updates statusbb8c98 OK ownerd9fd2e8b-766a-4e0e-a723-58eae5a13c6f,
  idle/no receipt/recoveryUnavailablefalse/legacyPins0. Test-only target APK
  build33632 active using command-line -PvpnControlVersion=2.1.3, no canonical
  version edit; must freeze separately and never silently downgrade after a
  successful native update. Actual session install/recovery remains unverified.
- Shared UI/model full task selection65025 GREEN (model UP-TO-DATE, UI reran).
  Docs/diff checkea3467 GREEN before the additions recorded here.
- Android26769 GREEN focused install/lifecycle/recovery/update/inspection plus
  shared UI presentation2. InstallControl8, lifecycle4, receipt recovery3 passed;
  handoff state survives journal failure. Recovery test now correctly preserves
  separate IDLE update availability rather than inventing a checked update.
  Backup-only AtomicFile discovery, fail-closed corrupt journal handling and
  terminal callback-capability cleanup are implemented. Native API29/35 session
  confirmation/install/recovery remains pending. Status catalogs7c16e1 passed.
- Mac fresh app-image38192 confirmed GREEN11s (local-only Homebrew JDK guard
  override, no packaging policy change). Frozen host
  /tmp/vpn-mac-public-startup.wT4W9p/vpn-control.app, guest
  /private/tmp/vpn-mac-public-startup.mIAyH1/vpn-control.app.
  Corrected public76360/022d8d GREEN: settings show bootstraps missing owner,
  two status calls retain controller acf9d506-4316-4772-b4cb-b6a8d6024547,
  runtime off/revision0, Unicode-space workspace2, guarded quit exit0.
  Initial95252 expected status bootstrap incorrectly; status deliberately does
  not bootstrap (DesktopCli.kt). UNAVAILABLE was expected missing-owner behavior,
  NOT a product admission failure. Test-only alternate-main bundled-runtime
  probeb0430d passed Windows/Linux/Mac admission; production image unchanged.
- Mac executable first-gate race regression27356 RED7/2: before any gate exists,
  an already-running process must retain executable SH lock so a later installer
  cannot replace its image. Agent authorized narrow fix after this regression;
  native locking rerun required. Does not invalidate the older public bootstrap
  observation, but next packaged build must include the fix.
- Linux public installer preparation scripts added; root7888fb GREEN3 fixture
  tests. Read-only review then found unsupported --timeout flag in harness;
  agent adding grammar/actual status-shape coverage before fixing to
  --timeout-seconds. No Linux public installation attempted. Existing three
  passing tests do NOT prove command grammar or successful installation.
- Android focused90351 RED12/2 after latest session/UI changes: expected
  confirmationLaunchedBeforeJournalFailureStillReportsHandoff and additional
  recoveredSessionUsesOwnerReservationAndNeverCreatesAnotherSession. Agent owns
  fixes plus AtomicFile backup/corruption recovery and terminal callback cleanup.
  Earlier20289 passed before these changes; do not reuse as current validation.
  Installation-state labels added across66 catalogs; localization check passed
  with existing untranslated warnings. Shared UI visual inventory remains open.
- Mac focused91456 GREEN7 executed/3 opt-in skips. Native7e1162 GREEN3 on owned
  macOS VM: explicit local private receipts without machine fallback, native
  PID/start/UID/executable identity, atomic receipt replacement with retained old
  reader and cancellation. Suspected fstat ABI failure did NOT reproduce; no
  speculative ABI fix authorized. Frozen /tmp/vpn-mac-receipt-native.Op8jNM/bundle,
  main b0cba7b3952a9dae376011272ff890ad1c226ba0c24f15e545f00071b0eda4bf,
  tests bfc3338ceae268e1207bb2b393fa999b897c1b6dc34add462f6f3c16e35e71c6.
  Guest /private/vpn-mac-receipt-9540bc92-0b94-4b46-a13a-79fc0ae3987d
  is task-owned uid501 mode0700, created through VM-only sudo. No actual install
  or host VPN action. Worker/adapter still unfinished. Generic explicit receipt
  authority extension approved for recovery; never try local after machine error.
- Mac Main admission focused30240 GREEN15 executed/2 native skips. App-image
  build30638 handle is now missing; generated app directory exists but final
  completion was not captured, so do not claim verified packaging. No active host
  Gradle client observed before90351. Native execution remains root-centralized.
  Linux agent reassigned to public INSTALL harness with production trust intact,
  test-only metadata-downgraded cloned image; no publish or trust-URL bypass.
- Arch/Mac focused13468 GREEN29 executed/6 platform skips (35 total). Arch public
  verified dispatch/capability now enabled, actual package installation still pending.
  Mac policy nativef9201a GREEN2 inownedVM: realhome denyACL/defaultroots/admin
  Applications775 and isolated shared/exclusive locks. Frozen host
  /tmp/vpn-mac-policy-native.JZLTOj/bundle, guest/private/tmp/vpn-mac-policy.3UXObT.
  Agent now binds MacProcessAdmission in Main with existing actual-pending callback;
  public packaged startup and full macOS worker still unverified.
- Android journal/recovery62885 productioncompile passed, testcompile failed at
  AndroidUpdateInstallControlTest27 (Unit compatibility check() has no code).
  Fixed assertion uses typed execute(UPDATES_CHECK); next focused rerun active.
  Session receipt is persisted before create and recovers exact originatingURI;
  terminal callback/GUI synchronization and full native confirmation remain pending.
- Windows public initiating INSTALL with actual UAC denial VERIFIED59f91d: fresh
  retry-visible1 under C:\Users\visualagent\AppData\Local\Temp\vpn-public-install-dFxcKi.
  Real update check/download v2.0.18 MSI125153348B passed. Standard owner4092,
  controllerb4ec520c-3ca4-4f4b-9b70-2d25847e2d06, installclient6548. Screenshot
  /tmp/vpn-spool-native.B6O7OG/public-install-visible-uac.png (5cee8e) visibly shows
  real PowerShell UAC; root Esca64a28 denies. INSTALL + retained operationstatus
  both final CANCELLED/exit130, operationbe9cd1e4-c5a2-4b68-9c6c-b8b71628c0ce;
  owner remains alive/off/revision0, explicit quit succeeds. QGA6740 terminalexit0.
  First run6248 also cancelled but had NO observed prompt/denial; exclude it from
  consent evidence. VM screen was stale/asleep (9:41 while guest12:09); harmless
  Shiftf6524c woke it and refreshed clock before fresh retry. No successful MSI
  replacement, elevated-owner/original-user or next-owner recovery proof yet.
- Arch native89007 RED5/1 reproduced safe archive failure: tar listing omitted
  --verbose while parser requires metadata. Fixed resource overlay; native4bebaa
  GREEN5 (real GNU safe/hostile archive, private extraction, exact-temp replacement/
  rollback/unrelated-backup preservation). /tmp/vpn-linux-arch-native.0g94mi/bundle
  mainb00352ad782efd713eb61f509b35c37f7cc0abaff4f1f2ac23e417a4496848cb,
  tests9380324c203fc4173d000b521199a1be0b09f09fc6290d32de26713507901905.
  Pre-fix main preserved outside bundle. OwnedLinux VM stoppedcc62d3; no production
  install/package manager/VPN executed. Arch service/capability enablement now
  implemented, focused union pending. Host28276 prior GREEN18/6native skips.
- Mac read-only layoute01e4c proves root/admin /Applications775 and home/Library/
  ApplicationSupport deny-everyone-delete ACLs were rejected by initial admission.
  Native-derived admin group + bounded deny-only ancestral ACL policy implemented;
  strict final roots/gates/executable unchanged. Final focused/native rerun pending,
  no Main binding. Sticky writable executable regression/fix already in28276.
- Android PackageInstaller intermediate40623 GREEN13 (lifecycle3/installcontrol4/
  interactions4/inspection2). New journal-before-create regression0ffe79 compileRED
  expected missing PREPARING/sessionCreated/staged; agent now closes this process-
  death window, exact-session recovery, durable terminal callback and GUI state.
  Native new-session installation still unverified. No active root native jobs.
- Combined53243 GREEN49 executed/1 opt-in native skip (50 total): corrected Linux
  client6, terminal6, endpoint4, CLI8, headless5, public install session8, Linux
  service4, capabilities2, Mac admission3/process3/native0/1skip. Post-fix Linux
  correlation/unknown behavior now verified. Isolated Mac native4d2582 GREEN1 in
  already-running owned visual-macos VM (not stopped because root did not start it).
  /tmp/vpn-mac-admission-native.db6RQb/bundle main SHA256
  5a85b2c0e952e48942501b73f6c980b1108bb8d3e081096e6db9cdf84b621bec,
  tests a7d3a1374152312fec6a33471ec9bc1e99e35d2cb4a3a060212bee540717849e.
  Guest /private/tmp/vpn-mac-admission.UncO05. Real Darwin metadata/ACL/F_GETPATH/
  flock tests passed using dummy image identity, actual process path independently
  verified. No Main binding/default-root/packaged-launcher or installer proof yet.
- Windows preparation PID4464 terminal75cc0b exit0: prepared-fixture/
  TEST-ONLY-install-image.zip, archive SHA256
  3e241069fcf233561badf0a2be97d437e5d86e632a30dd6c9728a469d84ffb25,
  fixture main55f7412f44a075916b57ffd4793f637f47d13ce6157a10736f8fc384ca776296.
  Metadata only changed from2.1.2/build16440 to1.0.0/build1; no production trust
  change. No public launcher/installer executed. No active root Gradle/native jobs.
  Changelog now8 Unreleased entries, version remains2.1.2; no new push/prepush.
- Linux client56137 RED6/2 failures reproduces terminal wrong-operation acceptance
  and transport-unavailable after acceptance being misreported as definitive failure.
  Agent fixed both; post-fix51822/64771 stopped at unrelated Mac test compilation
  (missing staged class, then internal-type visibility). No post-fix client verdict yet.
- Windows fixture stage source clone completed, read-only hash checkeb5590 matches
  frozen /tmp/vpn-spool-native.B6O7OG/public-install-frozen.dFxcKi/ main8e2f65b2,
  corea3a374c1, model67412750. Guest clone is
  C:\Users\visualagent\AppData\Local\Temp\vpn-public-install-dFxcKi\source-image.
  Original image preserved. QGA stage1036 monitoring timed out, its handle later
  missing; independent guest inspection/hash checks confirmed completed files.
  Reviewed prepare.py now runs as exact guest PID4464, last poll90757b live; it
  creates prepared-fixture with test-only older metadata, no URL/trust changes.
  No public installer/launcher executed yet. Do not restart on polling timeout.
- Current ownership: Android agent implements full PackageInstaller session/pin
  retention recovery (not installed-version inference); Linux agent extends captured
  worker to Arch with safe archive preflight/unique backup; Windows agent implements
  new macOS admission native/fake tests, unbound until verified. Root native/builds
  centralized; require compile-safe freeze across desktop agents before next union.
- Admission/capability union89819 GREEN28 (Linux admission6/process5, Windows
  admission9/process4/control-only2, capabilities2). Linux advertises DEB/RPM only,
  Windows MSI; static capability is not runtime readiness. Native Linuxc4ad77
  GREEN15 in owned Tart VM (includes real flock/symlink/FIFO native cases plus
  pending-state fake regressions); frozen /tmp/vpn-linux-pending-admission.TtKhY4/
  main SHA256 e3bbe889c571c671087d1f6473d732c727868d3832eadddabda1360f56f96444,
  tests SHA256 d6f57976ef7653701cd396a1e9847592fe3048c159834bc0682fef7a0ea41236.
  No public installer/production gate touched. VM stopped71bdf3 after checks.
- Linux CLI lease union90001 GREEN28 (client5, terminal6, endpoint4, CLI8,
  headless5). Subsequent review queued stricter terminal operation/request identity
  checks; do not reuse this receipt for those edits. Client pins an authenticated
  endpoint and retains its terminal agent past initial async acceptance until
  protected handoff readiness; polls status, never blocking operation wait.
- Linux service union63893 GREEN45 executed/1 Linux-native skip (46 total): service4,
  correlation7, installer4/1skip, existing UpdateService4, public install session8,
  handoff9, Windows prepared9. DEB/RPM dispatch/recovery/settlement now reaches the
  protected Linux adapter with exact correlation/frontend; terminal CLI lease still
  being wired. Arch/macOS installation still incomplete.
- Root review found Windows pending-control classification was unconditionally
  disabling normal status bootstrap even with absent/clear gate. New regressions
  and pending-observed callbacks select control-only only after validated pending
  byte under retained shared lock. Linux now uses the same bounded classifier;
  malformed/exclusive gates still fail closed. Root owns Main/admission changes;
  focused verification pending. Android agent owns Linux CLI terminal lease helper,
  installer agent owns Linux capability metadata, Windows agent audits macOS worker.
- Native Android27549 GREEN, complete public CLI run against APK2b9b0502 on owned
  API29 emulator5582, data preserved. All56,000 domains: import34.44s, show16.55s,
  retained wait16.44s, guarded same-content reimport33.77s, export17.94s. Private
  mode0600 and exact exported domain list verified; second export18.06s rejected
  PERSISTENCE_FAILED without changing file hash. Final status0.99s confirms same
  owner93574b52-095c-4270-98c6-b206d8e117d1, revision0, runtime stopped. Evidence
  /tmp/vpn-android-export-verify.qM97bT/; export SHA256
  cde731b4199d0b0ee4444a8801c40b5c363c287e3a0c70de87fb6ee7cb3fb9dc.
  This supersedes the export failure for this fixture, not all transfer/lifecycle
  requirements. Root has no active Android native harness after terminal0065b7.
- Shared export focused tests79781: 22 PASS (streaming export5, document codec6,
  inspection5, character import6). Combined command failed Android compilation at
  AndroidControlReader timestamp reference; fixed using java.time.Instant with
  eight shared-export timestamp-equivalence cases. Android rerun56466 GREEN25:
  response3, reader15, documents6, warm/fresh48MiB pipeline1 including export.
  Release32873 GREEN24s. Frozen APK in /tmp/vpn-android-export-verify.qM97bT/
  SHA256 2b9b0502ba5dc9aa8f1c8b4ae9ab8609b42b325c05db0375f7839e4ae1d947c1.
  Public preflight10419 confirmed owned5582 runtime stopped/revision0; install-r
  e41a2c succeeded without app data clear. Fresh public harness launched from same
  directory, native results pending. Emulator5580 and host VPN untouched.
- Windows pending-control startup union90797 GREEN27, no skips: startup2,
  admission8, process admission4, public install session7, exit gate4, completion2.
  Native pending-control/public installer evidence is still pending. Windows agent
  prepares a disposable artifact-only older-metadata fixture, without production
  manifest trust changes. Linux agent now owns public INSTALL adapter wiring and
  coordinates DesktopUpdateService edits with Windows owner.
- Installer union93913 GREEN69 executed/3 Linux-native skips (72 total). Public
  install session7, exit gate4, GUI completion2, headless session9, owner1, handoff9,
  frontend identity4, durable journal10, Linux correlation6, Linux installer3/1skip,
  request3, worker2, pipe0/2skip, Windows prepared9. Includes exact correlation,
  authenticated frontend identity, uncertain cancellation retaining nonterminal state,
  protected failed-terminal cleanup and previous-owner mutation/reconnect barrier.
  Native public installation remains untested; no all-platform installer claim.
- Windows owner next implements bounded control-only pending admission: retain
  shared executable lock, bypass only validated pending byte for fixed status/list/
  cancel operations, prohibit owner bootstrap/GUI fallback. Wait/watch/follow cannot
  retain a shared binary lock while waiting for installer exclusive replacement;
  pending interaction must be explicit instead of deadlocking. Android export
  integration is frozen awaiting shared writer tests/API freeze.
- Export53646 RED confirms the native symptom deterministically: unchanged48MiB
  pipeline reaches import/status/show then OOMs in routing export and reports
  INVALID_ARGUMENT. Heap android-routing-memory-evidence-8317604716599519236.
  Shared inspection runCatching masks fatal allocation as argument error. Android
  agent owns response/spool integration and fatal-error handling; installer agent
  now owns shared byte-equivalent pretty exporter/escaped-content writer + tests.
  No export input/heap cap changes or native success claims.
- Linux durable correlation adapter/tests are frozen awaiting root union: requireNew
  before staging, identifiers-only journal before watcher, no local NOT_STARTED
  after any coordinator attempt, exact watcher absence/exit before local retirement.
  Six new tests cover replay/unknown admission, recovery, local proof and inaccessible
  receipts. No UpdateService/Main/public Linux INSTALL binding yet.
- Native69565 terminal PARTIAL/RED: preserved API29 owner
  c539c3e3-b0fd-4706-b19f-60c580341fb6 remains revision0. Import34.12s/11,816,419B,
  routing show16.83s/11,816,542B, retained operation wait16.63s and guarded new-request
  no-op34.24s ALL PASS. Operation2edcf58f-b7e6-4cef-b86a-b38c82924093 retained exact
  data/revision. Export fails1.05s exit1 INVALID_ARGUMENT with warning
  ACTIVE_RUNTIME_IDENTITY_UNAVAILABLE. Do not call it an OOM without evidence.
  `/tmp/vpn-android-cold-replay.G17HtY/document-export.json` and full per-command
  receipts preserve evidence. Harness stopped before no-overwrite/finalstatus;
  Android agent owns diagnostic + fast regression. No app clear or VPN action.
- Windows public installer59827 compiles and PASSES42/43 tests. Remaining
  unknownCancellationDoesNotBecomeTerminalOrPermitNewInstall fails; owner is fixing
  it plus protected terminal cleanup and prior-owner pending mutation/reconnect policy.
  No native public installation has run. Current dirty batch has7 Unreleased bullets,
  product version remains2.1.2; no new commit/push.
- Android92033 GREEN all57 tests plus release APK build30s. Two fresh48MiB JVM
  pipeline passes, serializer7/cold-read/cleanup and broad reader/settings/observer
  coverage pass. Frozen APK `/tmp/vpn-android-cold-replay.G17HtY/app-release.apk`,
  SHA256 `294d8eff3f9e67049518fad0c53dd56f8c29345b2b64b85128ce3083cdda87a1`.
  Preflightc30301 confirmed old owner493c73e0...off/revision0; install-r1b02f2 succeeds
  on owned5582 without app clear. Public full harness69565 now running from that
  fresh directory using unchanged frozen19963 desktop launcher. Initial status OK,
  revision0; import/read/retainedwait/no-op/export/no-overwrite still pending.
- Cold-start42710 RED2/11 reproduced missing cold cache in serializer and second
  independent48MiB JVM; cleanup admission3 passed after83708 fix. ReadFrom now seeds
  weak frozen cache only after complete successful stock decode and EOF/hash/count.
  Broader92690 PASSES56/57, including TWO fresh48MiB JVMs sharing the same committed
  file. Remaining serializer assertion expects original object after successful
  changed-wire read replaced the single-entry cache; agent verifies proper equality
  then stable identity on repeated identical bytes. Release APK still not rebuilt.
- Initial Windows public binding compile233c91 fails unresolved privilege enum in
  ControllerOwner; assigned agent fixing exact supported code and completing recovery.
  Agent now owns DesktopControlSupport public reachability/CLI regression and narrow
  GUI typed handoff handling in Main, coordinated with Linux owner. No public INSTALL
  success or capability-completion claim yet.
- Cleanup83708 RED1/3 reproduces private erase IOException escaping the owner
  completion callback. Android agent owns finally-safe lease/result completion fix.
  Root also identified cold-start gap: write-primed serializer cache does not prove
  existing large-file reopen then no-op. Add unchanged48MiB cold-store regression
  and seed a cache only after complete successful stock decode/full disk digest,
  not merely successful writes. No APK build until this is covered.
- Native API29 read-only preflight1801eb still reports owner
  493c73e0-42e4-45b9-a5d2-c043b2e7a24b, revision0, stopped. Heap growth limit48m
  (large-heap property512m is not the ordinary app limit). Existing committed large
  configuration is preserved; no install/app clear/VPN action in this preflight.
- Root located existing DesktopFrontendProcessIdentity.read authenticated frontend
  endpoint/PID/start/same-installation seam and sent it to INSTALL owner. Use existing
  registration UUID plus this read/revalidation rather than treating every attached
  GUI as permanently unsupported. Native worker still validates stronger identity.
- Android storage35148 PASSES21 tests after serializer fixtures were explicitly
  frozen with toPreferences (preferencesOf alone was mutable in pinned AndroidX).
  Serializer6, ConfigurationStore9 and unchanged48MiB full pipeline pass, including
  first import/readback/exact retry/new-request no-op. Earlier32577 already passed
  pipeline/state but failed3 serializer fixture assertions; correction preserves
  separate mutable-input tests. No new APK/native replay yet; rare channel-close
  cleanup regression is next before release build.
- Linux terminal nonfallback50007 native success: real identity/password prompt
  observed, AUTHENTICATION COMPLETE, fixed /usr/bin/true exit0. Separate43788 real
  prompt then Ctrl-D produces pkttyagent unexpected-EOF failure and no authorization;
  selected cancellation test accepts126/127. Each JUnitOK2 means1 executed/1skip,
  not2 independent successes. This supersedes no-prompt d675a6 cancellation inference.
  Host terminal6+endpoint4 passed32577. Guest overlay files
  `/tmp/terminal-nonfallback-main.jar` and `/tmp/terminal-diagnostic-tests.jar` select
  the tested versions ahead of frozen admission bundle. Their SHA256 values are
  `be58dfacc04c6754cee610878f76c2cf09f622dbd766185a95e6164a17c45ff5` and
  `4544cafec8c4107cab987042547fe2f6d53ecc277d79eff7eabd8319d1fb4053` respectively.
  Owned VM stopped after
  terminal evidence; no package manager/VPN action occurred.
- Terminal diagnostic23edaf identifies native exit127: `No authentication agent
  found`, despite lease readiness. Official pkexec uses parent PID as expected;
  polkit process-fallback lookup returns early without a login session before using
  the fallback agent. Installer agent is adding regression then removing fallback
  only for explicitly requested terminal leases; GUI authorization stays unchanged.
  Root will rerun the owned VM prompt fixture, not count generic127 as cancellation.
- Windows agent now owns public INSTALL session/owner/AppService/OperationRunner
  integration and focused session regression. Protected job uncertainty must remain
  recoverable/nonterminal, runtime stop follows actual authorization, exit follows
  WAITING_FOR_EXIT and response acknowledgment; installed is not inferred from handoff.
  Linux agent retains terminal/endpoint/admission and narrow Main ownership; Android
  agent retains storage cache and pipeline. Root owns all native/build/test execution.
- Native Linux admission38c58e PASSES13 tests on owned ARM64 VM: admission5,
  process4, architecture flags2, actual native2. Tests prove no-follow symlink
  rejection, nonblocking FIFO without writer, shared/exclusive util-linux flock
  compatibility and no inherited lock after child exec. No production gate or
  installer touched. Frozen bundle host `/tmp/vpn-linux-admission.o2cL5V/bundle`,
  guest `/tmp/vpn-linux-admission-o2cL5V`, main SHA256
  `dcd5d89a99c1fea0cf2eabe4086b882d773108a13fde3b91c2a1d99d7aa76447`, tests SHA256
  `9f98353f32b6b003d653a239a5eb0175a213190c0d7bd7ebc53f667357965e6f`.
  Owned VM started65728 and remains running for terminal diagnostic follow-up.
- Native terminal authorization remains RED: harmless fixed pkexec /usr/bin/true
  success-mode ab0819 returns127 immediately without a visible prompt. Cancel-mode
  d675a6 reports JUnit OK2 (one selected method, one assumption skip), but NO prompt
  or user cancellation occurred; do NOT count it as cancellation proof. Agent is
  adding bounded stderr diagnostic for fixed command; no package manager involved.
- Public installer integration must resolve new-client access during pending gate:
  current Main Linux/Windows admission precedes command routing and blocks new CLI
  status/cancellation/reconciliation processes. Existing initiating client remains
  connected, but full parity requires a safe control-only route that cannot start
  a runtime/owner and is still accounted for before executable replacement.
- AndroidX1.1.2 local bytecode confirms transformAndWrite unconditionally rereads
  storage; adding collectors cannot avoid the no-op transaction allocation. Approved
  next slice: per-DataStore weak immutable Preferences cache with complete disk
  SHA256/byte-count revalidation via private unlinked stream spool, stock decode on
  miss, cache only after successful write, no cross-store mutable retention. Exact
  file/schema compatibility and failed-write/corruption tests remain mandatory.
- Exact-string reuse60770: shared26 tests PASS; Android48/50 pass. No-op now
  passes full parsing and reaches persistence (heap45.57MB), then fails inside
  DataStoreImpl.transformAndWrite -> readDataOrHandleCorruption -> serializer
  readFrom -> protobuf readRawBytesSlowPathRemainingChunks. Heap evidence suffix
  android-routing-memory-evidence-13918833913315166112. Production-factory
  ConfigurationStore assertSame still fails, disproving the wrapper-only explanation.
  Agent is checking DataStore read/cache/collector semantics. No heap/input reduction;
  no fresh APK/native proof. Earlier exact-request replay success remains valid.
- Windows read-only native token diagnostic97055 confirms why prior1346 fails:
  owner token is primary, linked limited token is impersonation/Identification.
  Owner-primary duplication succeeds, linked-primary fails1346, linked-identification
  copy succeeds. This rules out the tested ABI-control failure; no child, installer
  or privilege adjustment occurred. Diagnostic script and guest log are under
  vpn-spool-native-B6O7OG. Do not claim a same-account primary launch path exists.
- Root static review caught ARM64 Linux open-flag ABI differences in the new
  admission adapter before native execution: kernel ARM64 fcntl.h defines directory
  and no-follow bits14/15 versus generic16/17. Installer agent owns fast architecture
  regression and correction plus native nofollow/FIFO proof. Source:
  https://raw.githubusercontent.com/torvalds/linux/master/arch/arm64/include/uapi/asm/fcntl.h
- Android no-op heap review identifies duplicate normalized domain strings, not a
  whole raw document. Shared parser owner is adding optional immutable committed
  token reuse with exact normalized equality; full parsing, validation, fingerprints
  and changed-string ownership remain required. Android reference wiring and test
  factory correction are frozen pending shared overload; pipeline remains RED until
  rerun, no new native build/test yet.
- Android integrated streaming13192 RED2/49 (47 pass). Same48MiB pipeline now
  passes first import, status, routing show AND exact-request replay at revision1.
  New-request/same-content no-op still OOMs before success. Heap evidence
  `/var/folders/vq/zns5cfbd6zd64jw8hfgzzczr0000gq/T/android-routing-memory-evidence-12488187195738563229/heap.hprof`.
  Separate ConfigurationStore projected-no-op test fails assertSame for equal but
  distinct committed state during transform. Agent is distinguishing production
  cache identity from test Preferences-wrapper behavior and retained domain copies.
  No new APK/native test yet; preserve current API29 data and unchanged fixture.
- Shared streaming96887 PASSES24 tests: external input5, character request4,
  document codec6, routing character import4, configuration inspection5. Exact
  input-only extraction, canonical all-UTF16 escaping, incremental >11MiB input,
  legacy routing differential behavior,128-depth ignored JSON and12MiB repeated
  domain text are covered. Android private-spool/admission integration is present
  but its focused pipeline/native replay has not run against this implementation.
- Linux owner endpoint96690 PASSES16 tests: owner tuple4, terminal lease5,
  descriptor permissions3, activation4. Optional strict PID/startTicks/UID metadata
  must be from the exact authenticated endpoint; helper verifies controller, same
  user, native start ticks and identical trusted installed image. Legacy metadata
  absence is explicit interaction required. No terminal authorization or public
  INSTALL proof is implied. Async INSTALL must retain terminal agent until actual
  protected authorization, not merely until the accepted operation response.
- Installer agent now owns Linux startup protected admission adapter/tests matching
  the worker's flock and pending gate. Windows agent is investigating native token
  duplication1346; shared parser work is frozen unless Android exposes a defect.
- Installer cancellation regression66507 RED (1/13) reproduced coroutine
  interruption escaping as CancellationException despite unacknowledged external
  worker cancellation. Handoff now returns OUTCOME_UNKNOWN with exact jobId and
  retains retry ownership; confirmed cancellation still propagates interruption and
  closes the worker once. Follow-up51119 PASSES23 tests: Handoff9, WindowsPrepared9,
  LinuxTerminalAuthorization5. Generic operation runner/public INSTALL wiring must
  still preserve this uncertainty as nonterminal/recoverable; this component fix
  alone does not establish public cancellation correctness.
- Linux client-side terminal authorization lease compiles and5 focused tests pass.
  It registers fixed pkttyagent against owner PID/native start ticks, uses separate
  EOF readiness fd and controlling TTY for credentials, and closes only its owned
  unprivileged agent. No native terminal prompt has been exercised. Installer agent
  now owns optional strict endpoint owner identity tuple and verification helper;
  root retains public session/handoff integration ownership.
- Windows native token probe21417 is RED: owner/linked token same SID/session and
  limited elevation checks pass, then DuplicateTokenEx fails1346 before creating a
  child. No installer or worker was launched. Evidence is guest
  `vpn-spool-native-B6O7OG/linked-token-probe-elevated.log`; original-user spawning
  remains unproven, including worker command length and different-admin identity.
- Native Linux7fba6d PASSES all11 request/worker/installer/pipe tests (0.784s),
  including the3 previously skipped host methods. Actual inherited-pipe framing,
  truncation/byte-count rejection and cancellation without producer EOF are covered;
  privileged worker entry/package manager/public INSTALL are NOT exercised.
  Host bundle `/tmp/vpn-linux-install-pipe.VEs88m/bundle`, guest bundle
  `/tmp/vpn-linux-install-pipe-VEs88m`, main SHA256
  `6c21c670ca33108743149445ac308d5460f4926694e795d8c5b42db1ac8a4b98`, tests SHA256
  `bb591aac503c0ca5cdc6b65d782d2e288ee1ac54284a77cac19d01747da4686c`.
  Owned Tart Linux VM was started23434, accessed with tart exec as admin UID1000,
  then stopped after terminal success. No installer/VPN action was performed.
  Initial host jar command could not resolve Java; explicit Homebrew JDK17 rebuilt
  tests.jar before native execution, and guest hashes above identify the tested files.
- Linux framed-input union19169 PASSES24 tests with3 Linux-only skips (27 total):
  request3, worker2, installer3/1skip, pipe0/2skip, WindowsPrepared9, Handoff7.
  This validates host compilation, framing metadata and cancellation ownership,
  not native Linux pipe behavior or privileged installation. The worker now reads
  request/package/commit through inherited stdin rather than user-writable paths;
  native pipe verification and terminal-only authorization remain required.
- Shared streaming request/domain parser work is assigned to windows_export_finish;
  android_session owns private input spool, admission lifecycle and no-op integration.
  They coordinate signatures before edits. Root owns all Gradle/native execution;
  installer_integration continues Linux native fixtures and authorization.
- Android cache/projection69065 PASSES27 tests. Release62780 builds and installer
  correlation/prepared/handoff25 tests pass. Preserved-state native39622 now PASSES
  status, full routing show (11,816,542 bytes/all56,000 domains), and final status on
  actual API29/48MiB without clearing app data. APK SHA256
  `de592bd4fd387b59ab32f65d36990e5e948f482fb5c2ebeabb188e05e05925b4`, evidence
  `/tmp/vpn-android-readback.SYPzpW/`. Owner493c73e0-42e4-45b9-a5d2-c043b2e7a24b
  remains off/revision0 in this new owner epoch.
- Full replay remains RED: host44530 first-import/status/show passes, then repeated
  request decode OOMs before admission; observer4 tests pass. Native73708 reimport
  fails after17.73s, while poststatus succeeds with unchanged owner/revision/off.
  Evidence `/tmp/vpn-android-replay.z3bb2i/`; old frozen launcher masks contained
  resource failure as INCOMPATIBLE_PROTOCOL. Next change streams input to a private
  spool and preserves canonical fingerprints, parser validation and duplicate/no-op
  semantics; no heap increase, fixture reduction or app-data reset is permitted.
- Windows standard-user installer adapter is ready for public binding subject to
  authenticated frontend identity, durable correlation recovery, authorization before
  runtime stop and protected WAITING_FOR_EXIT before exit. Elevated-owner original
  user handling remains unfinished. A bounded same-account linked-token probe is
  prepared but NOT executed; it cannot prove different-admin identity or full worker
  command-length support. Public INSTALL remains unimplemented.
- Diagnostic92406 establishes the remaining post-import failure at
  AndroidConfigurationStore.snapshot/committed -> repeated direct-domain parsing,
  before status projection. Agent is implementing exact immutable-Preferences
  identity reuse and sharing that decoded state with ProfileStorage collectors;
  mutable transaction inputs must bypass cache. Heap evidence ends5953746696869192596.
- Linux safe-input design now uses framed inherited stdin for request/package and
  commit, avoiding privileged opens of user-writable paths and new interpreter
  dependencies. Pre-install readers alone may time out; never kill the package
  manager. Implementation/testing is ongoing. Preserve headless CLI authorization:
  disabling pkexec's internal agent alone is not proof of terminal-only support.
- Projection/structured routing-show36752 compiles and shared regressions pass;
  Android reader15 pass, but real48MiB post-import status still OOMs before its
  status marker. This supersedes any inference that removing the GUI text join
  alone fixed native readback. Agent is isolating repeated decoded-state lifetime
  and any remaining projection allocations with synthetic stack/heap evidence.
  No new APK was installed; native committed large configuration is preserved.
- Android post-import regression68548 is RED after first import+spool output pass:
  immediate status uses AndroidRuntimeObserver.controlStatus -> GUI persisted-state
  projector -> joins all direct domains into editor draft text. Routing show has
  the same unnecessary GUI draft plus export-to-JSON/parse-back duplication. Agent
  is fixing control projection separately from unchanged GUI draft semantics.
  Native normal logcat provides allocation size/contained error but no deeper OOM
  stack; do not claim an allocation stack was captured from the device.
- Installer correlation17017 passes14 tests (journal7, prepared7); its requested
  EndpointTest glob matched no class. Correct endpoint permissions32347 was then
  explicitly run and passed. Recovery still needs proven prelaunch/UAC-denial
  disposal so cancellation does not permanently block later installs, plus terminal
  journal pruning; agent owns those follow-ons, unknown launches stay blocked.
- Linux adapter/watcher/sharedprepared/handoff60469 passes20 tests with1 Linux-only
  native publication skip (21total). No privileged Linux installer ran. Safe
  nonblocking/no-follow input opens and native verification remain pending.
- Streaming3938 PASSES31 focused tests: shared codec6, Android documents6,
  reader15, serializer3, real-spool48MiB pipeline1. Release47300 builds successfully.
  Frozen `/tmp/vpn-android-streamed.1J20UZ/app-release.apk` SHA256
  `22177450856af771d02f4599eec01ccaff9d9491a46a2ed929cd32f8faafb4cb` installed only
  owned5582 after status confirmed off/revision0. Public30430 import now SUCCEEDS:
  34.47s,11,816,419 stdout bytes,revision1, owner
  `a2a5067d-5e08-4162-93a1-5165b8633345`. Immediate routing show and status return
  OUTCOME_UNKNOWN. PID24478 remains alive; normal logcat20:43:04 reports main-thread
  OOM allocating6,881,288bytes and provider parcels the contained error. No fresh
  crash-buffer event. Preserve committed emulator state for recovery/read proof;
  do not clear it. Harness stopped before retained wait/no-op/export checks.
  Evidence and unchanged public harness are in that same fresh temporary directory;
  launcher is old frozen19963, not a newly certified desktop package.
- Owned codec regression49804 PASSES at unchanged48MiB/56k/extra7MiB pressure,
  now exercising actual source-slot-consuming production encoder. Generic UTF16
  compatibility/nonmutation tests remain; old non-consuming failure premise is
  documented. This does not resolve post-import native state/read memory pressure.
- Windows agent now owns durable workspace-local controller/request/operation/job
  correlation and receipt-only recovery; records never authorize/replay a worker.
  Linux agent owns adapter/watcher and root-ancestry checks. Shell FIFO-open race
  remains an explicit blocker until bounded native-safe input opening exists.
- Windows protected receipt gate now PASSES native43613 elevated (all3 methods)
  and61765 standard (read/publication pass; elevated-only method skipped). This
  supersedes earlier replacement/link-count failures for frozen
  `/tmp/vpn-spool-native.B6O7OG/receipt-reader-WzdNCm.zip`, SHA256
  `5a083b4083a87dae877f75ef1731ccb8582ca51f60c93659fcc14b465d6dbdae`.
  Focused60483 passed before that bundle. Cleanup815141 removed only exact test
  job cc0b72ef-614d-4bb6-adbf-3d20eec215a8 and its synthetic status; shared root
  preserved. Fixture is regenerable, not user data. No MSI/public INSTALL claim.
- Android92678 passes12/13 tests and now reaches durable stage=committed revision1
  in48MiB. It still OOMs constructing output in executeDocument; response delivery
  remains failed, so large-import acceptance is not complete. Agent owns streaming
  shared result encoding plus real private-spool publication/pipeline coverage.
  Serializer compile and byte/type compatibility checks passed in this union.
- Windows1073 focused union passes. Native29277 now performs replacement, but
  reading the already-open old receipt fails strict link-count validation after
  unlink (test49). Windows agent owns a narrow prior-validated read-only STATUS
  handle exception; new opens, cancellation files and multiple links stay strict.
  Frozen `/tmp/vpn-spool-native.B6O7OG/receipt-posix-TcV4Xv.zip` SHA256
  `3b5d36207a6ffe764ffd731f1b32d7543cdcc95306d9f89466c1eeda26094de8`.
- Linux worker/request focuseded8911 passed: request injection validation, fixed
  argv, shell syntax and nonprivileged parser execution. No privileged worker
  execution, package replacement, original-user watcher or public Linux installer
  acceptance is established. Adapter/watcher work continues independently.
- Android serializer e6fe3d/6b217f fails compilation because PreferencesProto and
  relocated ByteString are absent from the compile API. Agent is correcting the
  dependency/API boundary; this run provides no new memory/persistence evidence.
- Windows native60500 isolates the receipt issue: classic class10/flags1 succeeds
  without a reader, fails access denied with a retained reader, and class65/flags3
  succeeds with old-reader bytes unchanged and new-reader bytes replaced. Its
  fresh probe directory was removed by its own scoped cleanup. Windows agent is
  applying this tested replacement behavior; full backend native rerun still
  required, including retained file link-count validation.
- Root reviewed operation-result handling for future INSTALL binding. Exploratory
  regression14934 exposed exit2-to-RUNTIME_FAILED normalization, but attempted
  direct preservation47122 violated the shared ledger's explicit prohibition on
  completing owner jobs from transport/waiter failures. The speculative edit and
  invalid terminal-result test were removed; existing operation semantics remain
  unchanged. Installer outcome-unknown needs an owner-side reconciliation design,
  not a transport error forcibly stored as a terminal operation.
- Receipt replacement follow-on58022 passes focused backend/store/export tests.
  Native42014 still FAILS: leaf-only replacement removes prior error32 but now
  returns access denied (5) while the old receipt reader is retained. Preserve
  that regression and reader semantics; Windows agent is investigating the
  required native replacement semantics without widening ACL/sharing policy.
  Frozen `/tmp/vpn-spool-native.B6O7OG/receipt-fixed-CRLwGi.zip` SHA256
  `7e2749facc40d3caa52d26193fc51ece62c16858865fbc47f0c0e93f73b2e2c9`.
- Standard-user native24517 passed protected read and actual C# publication;
  the elevated-only replacement method was skipped by assumption, so its JUnit
  `OK (3 tests)` output does not override elevated90294/42014 failures.
- Android serializer follow-on is approved only as a compatible allocation fix:
  same Preferences protobuf schema/file/single store, delegated reads/default,
  exact-size byte-array serialization instead of oversized OutputStreamEncoder
  temporary. Require all-type byte differential and full48MiB pipeline proof.
  Factory/serializer changes are not yet verified and do not constitute migration
  or a constant-memory guarantee.
- Native Windows installer90294 now proves protected default-root reads and the
  actual C# atomic private-record implementation, but its elevated receipt
  replacement regression FAILS with Windows error32 at JnaWindowsInstallNative
  rename. Windows agent owns this newly reproduced replacement defect. Frozen
  bundle `/tmp/vpn-spool-native.B6O7OG/installer-current-e2tlc8.zip` SHA256
  `5d69fb32ee14f971f0bc7f1e1990f933279b9c5102c4820c58173e315d03f1b3`.
  Exact disposable fixture job `cc0b72ef-614d-4bb6-adbf-3d20eec215a8` remains for
  rerun/checked cleanup; shared ProgramData root must be preserved. Initial35972
  failed only on an outdated runner allowlist before fixture/test execution.
- Android consumable payload7479 passed7/8 focused tests; full pipeline remains
  RED, now in protobuf CodedOutputStream.writeStringNoTag during Preferences
  serialization rather than the prior encoder final String copy. No durable
  commit/native success yet. Android agent is investigating bounded compatible
  serialization; do not skip this new peak or claim the large-import gate passed.
- Installer75247 compiled the exact Windows CLI-to-GUI sibling launcher resolver
  and atomic worker record changes with focused checks passing (native-only test
  skipped on macOS, then exercised in90294). Public install binding still needs
  async final-response exit correlation, captured frontend identity, cancellation
  and durable recovery. Linux fixed protected worker work has started separately;
  macOS worker remains unfinished. No public capability was enabled prematurely.
- Follow-on installer32630 passed the prepared/handoff/captured/request union
  after confirmed cancellation resets READY/admission and JVM input records use
  flushed temporary publication. Backend/store focused run50d2ab passed17 tests
  (12 backend,5 store), including retained ProgramData ancestor witness lifetime
  and fail-closed races. Native default-root receipt read/replacement is being
  prepared; neither focused result proves public INSTALL works.
- Android diagnostic66931 remains RED. Synthetic heap analysis locates the
  11,692,889-byte encoder buffer plus parsed-domain backing storage at the final
  String allocation; no large original raw-request array remains strongly held.
  Android agent is refining the local callback to a privately owned consumable
  payload that can release source strings while encoding, without mutating shared
  model/repository lists or changing persisted syntax. This is work in progress,
  not a passed memory test. Keep existing failure tests until stronger equivalent
  pipeline and native retry/no-op/read evidence justifies any fixture replacement.
- Windows export publication now passes all 27 native tests as both standard user
  (61574, elevated=0) and elevated test user (30739, elevated=1). This verifies the
  same-directory leaf rename fix without relaxing retained-handle sharing. Frozen
  bundle: `/tmp/vpn-spool-native.B6O7OG/publication-36005.zip`, SHA256
  `a38a1bee7a2b22a742265588b2db2f3d74c58f7718ea070e4aafa83213ca4010`;
  main jar `213e1c837b434813df71b127b058902b8b01fbc8d98e2a2746483d979bf9e2d0`,
  tests jar `d07ea81c23cda1a0db5ad82d960eca76497c7ad10742a8d9e67c20f74c32c252`.
  Windows ARM64 with x64 JDK emulation, not native x64 package certification.
- Android typed routing union43710 passed35 tests. Full 48MiB pipeline fixture
  classpath failure42230 is fixed. Reruns80687/17698 now reproduce a real OOM in
  AndroidStringListCodec.encode: final byte-array-to-String copy before persistence
  completes. The test returns RESOURCE_EXHAUSTED with unknown commit outcome;
  the required large import still fails. Original stack is captured only from the
  synthetic test fixture. No new APK/native API29 success is claimed.
- Windows prepared installer/handoff/captured worker/request union28272 passed19
  tests after fixing the missing GetSystemDirectoryW binding. Production launch
  adapter compiles, but public INSTALL, native UAC/handoff, original-user recovery
  and protected receipt ancestry remain unfinished. Confirmed cancellation reset
  and atomic commit publication are the next focused changes.
- Existing frozen APK76067d public Android location benchmark completed via async
  acceptance and owner-bound wait on owned5582: operation
  `a2da51cd-8ea4-4719-ac5f-c73177a53319`, owner
  `ab66c8c4-b496-45d3-9914-a9889042ae6d`. Runtime remained off, revision0 and selected
  location unchanged. Null timings prove no successful network measurement; this
  is bounded completion/telemetry evidence, not connected benchmark certification.
- Owned Tart Linux VM was orderly stopped after its native24-test pass; host VPN
  and emulator5580 remain untouched. Root HTTP server for the frozen Windows
  bundle is port56471, session29848; older ports returned empty replies and were
  not treated as live test jobs.

Three parallel agents plus root; no new scope. One host Gradle invocation at a time,
root assigns token and verifies terminal handles. Native VM work is independent.
Use focused tests between changes, batch full checks at a coherent freeze. Finish
actual executable commands before adding general-purpose infrastructure. Root owns
docs/version/prepush/reviewed staging/push/exact-SHA CI. Multi-bucket dirty work is
intentional; preserve other owners' edits and do not hide unfinished paths.

| Owner | Current exclusive focus | Next milestone |
| --- | --- | --- |
| root | All native/Gradle execution, review and checkpoint | Independent native runs without agent permission waits |
| android_session | API29 streaming input spool/admission/no-op integration | Same48MiB first import/read/replay/no-op pass |
| windows_export_finish | Public Windows INSTALL session/owner binding and recovery | Truthful tracked handoff and focused public command tests |
| installer_integration | Linux terminal authorization and startup admission | Native prompt success/cancel and control-only client access |

Environment reset removed the previous gui_location_reference/native_cli_checks
agents; replacement agents above have the exact evidence and non-overlapping owners.
Permissions changed repeatedly during recovery. Consult the current developer
permissions for each agent; do not infer them from another agent's settings. Root
currently has unrestricted execution again; restricted agents should send bounded
commands to root or use their applicable approval path without indefinite waits.

## Cumulative Implemented Baseline

Environment reset interrupted50154 build observation; its terminal receipt is lost.
Replacement combined build19963 succeeded (Android release and Mac app image), with
ADB client18/document client6 tests passing. Frozen artifacts and hashes are recorded
in `/tmp/vpn-parity-current.St0sO7/provenance.txt`; APK SHA256
`76067d086c433c4c9fbb72ac8597b2df4899ae3c17cc392ad9147f6b017a0479`.
Benchmark public owner-binding regression15850 failed before adding the missing
LOCATIONS_BENCHMARK binding;19963 proves the fix and explicit stale-owner preservation.
Current native Mac smoke45665 passed using the unmodified frozen app image, including
>10MiB routing import/result/private export, streams/QR and isolated disconnected
owners. This is current app-image evidence, not DMG/install/live-traffic certification.
Android API29 retry12130 failed: import lost its owner during a main-thread OOM;
revision remains0 and runtime is off in the replacement owner. Crash mapping points
to ProfileStorage.encodeList newline join during commitControlRouting, not the fixed
input parser/normalization stages. Evidence: `/tmp/vpn-android-routing-iterable.GroFjr/`.
An additional client error wrapper mislabeled ownerless OUTCOME_UNKNOWN as
INCOMPATIBLE_PROTOCOL for explicitly owner-bound requests; regression33390 reproduces
that separate issue. Fix48457 passes21 tests (CLI JSON5, Android CLI10, document6),
accepting only canonical local transport failures, not ownerless domain results or
forged metadata/private data. AndroidStringListCodec extraction preserves old newline
syntax; its48MiB regression70743 XML confirms2 tests/1 StringBuilder-growth OOM.
Its handle was lost during reset, but XML timestamp16:03:32 and no live Gradle client
were verified. Memory implementation and native retry remain pending.
Exact-size ASCII/UTF16 encoder attempt64401 still fails the48MiB regression at the
final String copy, so it is not a completed low-memory fix. The agent is mapping
retained input/list/storage copies before another APK cycle. Narrow owner OOM
containment regression98656 failed2 cases before implementation;41003 passes16
tests (resource boundary3/settings13), including known durable commit preservation
and propagation of unrelated fatal errors. Native large-import success remains open.

- Shared registry, grammar/DTOs, guarded writes, deduplication, operation tracking,
  explicit asynchronous/unknown results.
- Desktop authenticated loopback, separate controller/GUI, settings/languages/SSH,
  subscription/location/source/routing operations, drafts/visibility/shutdown,
  actual versus pending configuration, logs/status/stats streams, UTF8/QR/private exports.
- Android protected Binder UID+DUMP provider; settings/SSH/source/subscription CRUD,
  location edits/selection/removal/import, routing/app rules, updates check/download/
  cancel/dismiss and interactive APK handoff. Earlier nondebuggable API29/API35 proof
  covers authorization rejection, consent denial/grant and native start/stop.
- Android service-destruction deadlock reproduced and fixed; isolated frozen-APK
  active-location import/stop proof exists. This does not prove every retained-service path.

These are cumulative implementation/evidence statements, not full-plan completion.

## Large Documents: Current Dirty Work

ControlDocumentCodec removes the logical document size ceiling while preserving
schema/duplicate-key/depth/redaction rules; ControlProtocolCodec frames stay1MiB.
Snapshot documents handle nested retained results. Domain parsers still materialize
Strings; no constant-memory parsing claim. Shared97397 passed30 tests including>10MiB.
Desktop normalized-result regression2870 failed before migration;6735 passed4 tests
including70,000-domain commit and exact retained retry without a second revision.

DesktopControlDocuments is wired through authenticated ActivationServer with bounded
chunks, opaque references, owner/principal/context/kind binding and hashes. Large
responses defer lifecycle acknowledgment until client verification and ACK flush.
Endpoint capability metadata retains explicit old-owner small-command compatibility.
Transient owners retain transfers; GUI/CLI logical codec sites are migrated.

Secure spool uses Linux retained directory streams, native Darwin descriptor-relative
IO and Windows pinned handles/ACL checks. Initial macOS SecureDirectoryStream failure
was fixed without dropping parent protections. Mac44559 passed spool4/parent3.
Windows spool normal10/elevated10 evidence: /tmp/vpn-spool-native.B6O7OG/receipt.txt;
read receipt for exact bundle hashes/provenance. Separate appended C# installation-ID
test failed and is NOT part of the green spool claim. No fresh native Linux run yet.

Desktop union6070:33 tests,1 expected publication-retry failure,3 Windows-only skips.
Fix retains sealed repeated responses, rejects conflicting publication without
discarding original, and invokes its callback once. Union86410 PASSED (33 tests,
3 Windows-only skips), including large GUI/CLI, activation, endpoint, Parent5/Spool4
and reply replay. Full resource/expiry/interruption/public-package coverage remains.
New actual packaged smoke98415 exposed typed desktop operation status/wait returning
only summaries/current revision instead of retained output (Android already returned
the retained result). Fast regression74887 reproduced it. Fix preserves original
result/revision and changes only inspection requestId; pending typed status is ACCEPTED
and nonterminal.82575 passed34 with1 Windows-only skip, including large result after
a later revision, operation cancellation/wait, publication6, writer/spool/parent and
GUI install-finality/Handoff tests. Raw human operation summaries remain unchanged.
scripts/test_packaged_cli.py now checks >10MiB routing import, retained result, private
export/count and no-overwrite on public package builds; Python harness10 tests pass.
It now also exercises implicit owner bootstrap from a configuration command (not
only explicit serve), checks durable readback and disconnected state, then sends
owner-bound quit and verifies endpoint cleanup. Harness12 tests pass; native Mac
run83025 passed the expanded smoke against the same frozen19963 app image. No host
VPN, autostart or installer action was performed.
Fresh Mac app-image native rerun45665 passed;98415 used the older frozen Mac package
and is retained as failure evidence. Linux/Windows current public package reruns remain.

AndroidControlReader.executeDocument is added; legacy execute stays bounded until
provider integration. Settings normalized fingerprints now use logical codec.
47598 reproduced large-owner-import failure;79406 passed38 tests (Settings13,
Reader14, Refresh11): one70,000-domain commit/exact retry,>10MiB logical response,
sanitized malformed input. Public refresh missing-owner binding passed29225 for
id/active/all and explicit stale-owner preservation.

Android private document transport is now wired alongside the unchanged legacy API:
AndroidControlDocuments + AndroidControlDocumentProvider use shared transfer storage,
UID/context-bound references, explicit seal/submit, bounded upload descriptors and
bounded result chunks. AndroidControlTransferSpool creates0600 files only in the
owner's Context.cacheDir and immediately unlinks them; no named payload survives.
73559 passed2 spool tests;86358 passed24 document/spool/legacy/reader tests, including
>10MiB data, exact chunk retries, invalid seal/offset/UTF8/URI rejection, caller
isolation, expired metadata with retained active consumer and no resurrection.

DesktopAndroidDocumentClient/ADB/AndroidCli now speak that protocol, retain bounded
ADB subprocess frames and only fall back on explicit unsupported begin before
domain effects.7066 reproduced old CLI input cap;86059 full client union passed.
Continuation-owner regression37517 then reproduced adoption of a replacement owner;
79966 full union passed with the outer owner guard. Frozen native artifacts are in
`/tmp/vpn-android-document-artifacts.vFkizX/`: release APK SHA256
`4ac1d8e0af473538cddec8812c3e8a24d6e9f6d2edee5bbe5b2bf2448bc17f93`.
API35 public packaged CLI import of11.9MB/56,000 domains, exact routing readback,
same-owner retained result, guarded no-op revision1 reimport, private0600 export and
no-overwrite all passed. Final status preserves owner/revision1/runtime off. Root read
provenance receipt; evidence: `/tmp/vpn-android-documents-api35.9s2F1H/`.
API29 with actual48MiB heap failed with OOM parsing the outer request; API35 success
does not resolve that failure. New ControlCharacterSource parser avoids whole outer
JSON String/ByteArray input copies; Android provider now consumes a bounded stream.
Shared parser/codec7 tests passed after ASCII Unicode-escape regression fix.
Android union70272 passed after a test-only compile fix, covering resource failures
as redacted UNAVAILABLE rather than malformed input, plus postcommit storage retry.
Android union70272 has22 tests, no skips/failures. Streaming release build46958 passed;
frozen APK `/tmp/vpn-android-streaming.cs3QY5/app-release.apk`, SHA256
`77868df7f249c09ff3c5dedf7aae0a7c48ac1cf937679388b4fd3caed6612f6d`.
Same API29 fixture still failed:37,748,744-byte StringBuilder growth allocation
exhausts actual48MiB heap. Upload/seal/hash succeed; latest traced attempt reports
OUTCOME_UNKNOWN, no domain commit (revision0/runtime off). Evidence:
`/tmp/vpn-android-documents-api29-streaming.XMRgOc/`. Android agent reproduced this
with forked48MiB JVM/UTF16 strings24217. Bounded compact accumulator80625 passed9 tests
including the same48MiB regression and full UTF16-unit/escape compatibility. Android
Reader/Documents plus release92537 passed; APK `/tmp/vpn-android-compact.5LlwrT/app-release.apk`
SHA256 `0184165465b4f12791481f8892e123eca2a22d1e4f51218f8e8c8159d5703b90`.
Native retry still fails with a different42,991,624-byte allocation after the outer
parser fix; exact later stage is being isolated. No large API29 success claim yet.
That stage was canonical fingerprint JSON encoding: regression16262 reproduced it;
streamed canonical writer/digest24668 passed11 shared and14 Android tests, preserving
exact old hash bytes including UTF16/malformed units and suffix flags. Release94280
APK `/tmp/vpn-android-fingerprint.9Lxdk0/app-release.apk`, SHA256
`b3905d5cd6470ff75a78579c5441fc7df7b750ea72482f9c82be52dea2189753`.
Native retry now reaches a correlated owner operation, but routing-domain import
allocates27,525,128 bytes and masks OOM as INVALID_ARGUMENT; revision remains0/off.
RoutingRulesTransfer's whole-list join followed by split is the next targeted fix.
Shared routing regression17423 reproduced that join allocation;53326 passed model1
and core8 after iterable normalization, preserving per-entry tokenization/order/distinct.
Android's resource-error classification regression failed in22653; replacing the
resource-swallowing catch passed32736 (54 Android tests including benchmark6,
reader15, settings13, location actions5, refresh11 and routing4). Fresh APK19963 above
is ready for the actual48MiB native retry; do not infer native success from unit tests.
Domain strings and result serialization still materialize; no constant-memory claim.
Remaining transfer
work includes streaming no-overwrite client exports, resource/expiry/interruption
cases and final all-platform public package evidence.

Client file UTF8 output no longer constructs document-sized byte arrays for writing
or byte counting. DesktopExportUtf8 uses8KiB buffers, preserves old malformed-surrogate
replacement semantics, and feeds existing private/no-overwrite native file writers.
79200 passed18 tests with1 Windows-only skip (19total): encoder3, private writer6,
Android CLI10. Includes11MiB generated text without intermediate String and large
native Mac private text export. Raw stdout streaming/exact-byte/stderr-only failure
follow-on passes18811 (29passed/1 Windows-only skip), including DesktopRawExportTest3:
desktop/Android bounded exact UTF8 with no success suffix, second-chunk sink failure
stops immediately with stderr-only failure, guarded desktop export unwraps only content.
Expanded98491 passed30 with1 Windows-only skip, including real QR subprocess, JSON
authenticated exports and location CLI end-to-end tests. Publication regression77904
then reproduced3 missing guarantees: interrupted output leaves final, final becomes
visible early, and racing destination is not preserved. Private partial output with
size/hash verification and retained-parent no-overwrite publication is implemented;
publication6 is green on the host in82575. Native Windows43105 exposed volume-GUID
path handling; Linux16519 exposed ARM64 open-flag ABI differences. Both fixes are in
the current artifact. Native Linux25169 now passes24 tests (1.885s), guest task
`/tmp/vpn-export-publication.8S7Cbh`. Windows retry53619 reached25 tests but failed4
positive-publication cases with sharing violation32 in publishExportNoReplace;
read-only log47608 confirms terminal result after QGA observation timeout. Agent is
fixing the retained-parent rename, not weakening directory share protections.
Receipt: `/tmp/vpn-spool-native.B6O7OG/publication-native-receipt.txt`.
The preceding Windows24850 failed only test-bundle download; replacement task server
31897 on localhost56470 works. Keep the server only while native retries need it.
Native rename probe25918 (normal token/elevated0) proves absolute Win32 and NT
RootDirectory-relative rename both fail32 with the existing strict parent pins,
but NT leaf-only/same-directory/nullRootDirectory succeeds. This permits testing a
same-parent private partial design without relaxing directory share protections.
Probe-only22916 failed execution policy before running;25918 uses process-local
PowerShell policy only, no machine policy change. Production Windows fix is pending.

Fresh Linux native class-bundle tests passed18; mixed native public-launcher smoke
passed13 commands including11.5MB routing, Unicode paths, private export and exits0/1/2.
Real child-bootstrap failure came from inherited _JPACKAGE_LAUNCHER; regression88264
failed, targeted child environment fix96035 passed, native bootstrap then passed.
Root read `/tmp/vpn-linux-transfer-native.wn1fPQ/receipt.txt`. Retained old launcher
plus dirty jars and copied full JDK is mixed evidence, NOT current package certification.
Owned Tart Linux VM restored stopped; no VPN/runtime connection was exercised.

## Android Refresh: Current Dirty Work

GUI/worker/CLI share application-owned refresh ledger/admission. One actual runtime
route is captured. Cache commit preserves actual A separately from pending B;
partial/cancelled rows distinguish fetched from committed. Scheduled Find Best
retains existing foreground service and restores pinned A, without requiring an
Activity; candidate search uses caches, not a second untracked fetch.

44648 passed40 tests. Scheduling regression64078 failed then45060 passed11: valid
route-preparation failures reschedule, stale guards remain effect-free. Native test
found generated active-verify-in listener not recognized by custom-tag-only lookup.
33284 reproduced generated-tag and unsafe-listener failures;71047 passed17 tests and
assembled release. Frozen current native APK:
`/tmp/vpn-android-retained-refresh.vGlv8N/app-release-port-fixed.apk`
SHA256 `5837756d0f6a03570e2bc0c42b26bee400dd21bd88e1caf5448e3ae5d6204d04`.

Agent-reported API35 native evidence under same temp directory:

- fixed-*.json: connected HTTPS refresh removing cached A preserves actual runtime;
  removal of pending B clears only pending selection.
- cancel2-*.json: cancellation after1/2 sources returns130/CANCELLED, committed=false,
  unchanged revision and both source outcomes.
- scheduled-run1-operations/scheduled-terminal/scheduled-after.json: real background
  WorkManager/JobScheduler refresh+Find Best succeeded without Activity, same service
  remains foreground, selected candidate becomes actual runtime.

Both API29 and API35 pinned-A recovery, connected refresh/cancellation and scheduled
success passed against the frozen APK. Root read and executed assert_evidence.py
in the evidence directory successfully; it verifies both-platform outcomes and
exact APK hash. Both task AVDs were orderly stopped after public OFF, fixture stopped,
and disposable CA mounts disappeared. Task AVDs were subsequently restarted for
document verification;5580 remains untouched.
Disposable CA trust affects task5590 only, never host/5580 or product TLS. Live traffic
proof remains distinct from native service start/stop and refresh HTTP success.
Older /tmp/vpn-android-deadlock-fixed.rN0Mn6 APK proves cleanup only.

## Desktop Installer: Current Dirty Work

Owner-local cancellation recovery70109 passed5 tests: failed cancellation retains
worker and validated jobId, explicit retry does not reauthorize, confirmed cancel
releases once, committed handoff rejects cancellation, close preserves uncertainty.
This is not durable next-owner recovery. Read-only wiring audit still finds public
UPDATES_INSTALL unsupported, no production DesktopPreparedInstall adapter, legacy
workspace marker helpers, missing protected receipt/request correlation, and runner/
GUI/exit acknowledgement integration. Do not advertise INSTALL support yet.
Root added a narrow GUI safeguard: ACCEPTED/nonterminal install results no longer
close the frontend; only final OK handoff does. DesktopInstallCompletionTest is
passed in82575 with the desktop publication/Handoff union.

Handoff/request validation/protected storage/locking and immutable read-only input
mode have focused tests. Production INSTALL handler/helper/owner handoff remains
UNWIRED; no installer success claimed. Native C# installation-ID case-alias test
failed: LCMapStringEx positive length produced no NUL, StringBuilder marshaling read
trailing memory. Explicit buffer/exact-length conversion passed the unchanged native
regression with spool union11/11. Direct JNA admission passed6 pure tests plus2 native
Windows tests (8/8 normal-user), including100 repeated Unicode/case identities and
actual shared/exclusive locking. Root read admission-receipt.txt in the spool evidence
directory. Actual default ProgramData ancestor permissions exposed a startup failure.
The fix accepts attribute permissions only with a retained non-delete-sharing child,
exact canonical parent/child linkage and reinspection; final objects stay strict.
Normal-user native admission11/11 passed, including both launcher names with missing
legacy gate and no ProgramData writes. Root read admission-default-programdata-receipt.txt.
Protected task-child receipt IO23035 passed PREPARING/AUTHORIZED/CANCELLED under
inherited SYSTEM; backward/terminal rewrite regression65749 failed then49930 passed.
Root read installer-worker-receipt.txt. These prove component behavior, not actual
packaged launcher execution, UAC, MSI installation or full worker handshake.
BLOCKER: subsequent adversarial native36034 disproved the metadata-only retained
child guarantee: DeleteFile succeeded and parent reparse installation then succeeded.
Earlier positive admission tests do not cover this attack. Installer owner is adding
a regression and data-read/list-directory access so deny-delete sharing participates.
Access-mask regression96278 reproduced missing data-read permission; focused union
28452 passed after fix. Captured C# adversarial77093 now blocks deletion with32 and
parent reparse with145 (empty attrs-only baseline still succeeds). Refreshed Windows
union passed37/37 ordinary user and37/37 elevated after fixing test JSON command
quoting and including the native test resource. Includes JNA admission/pins, C# witness,
private export6 and UTF8 encoder3. Root read witness-export-receipt.txt in the spool
evidence directory. This does not prove a public installer handshake or installation.

Architecture: captured fixed original-user MSI worker plus elevated fixed protected
coordinator, never elevate user-writable JVM/jars. Prove original interactive user
using trusted native token/process/session evidence; elevated owner can be another
approving administrator. After worker creation unknown outcomes retain operation
identity and block another install until reconciliation. Installed remains null
until established. Inventory/wait app copies, never kill them.

Direct JNA admission matches protected17-byte gate: shared byte0 lock, pending byte8
checked AFTER lock, privileged byte16 reservation. Missing legacy gate is a no-op,
not creation/UAC. Native installation-ID normalization must match case aliases.
Use agent's tested final C# algorithm, not older draft instructions.
Explicit CLI serve may use CLI image while frontend uses GUI image; default bootstrap
already maps to GUI. Fix only targeted explicit-serve pairing with PID/start/user/
installation proof; arbitrary sibling executables stay invalid.

## Full Remaining Completion Gates

1. All desktop GUI/CLI/Android large transfers, client exports and failure/retry tests.
2. Android Find Best/benchmark/stable GUI targets/streams, refresh recovery, SSH native
   loading, process lifecycle and live traffic.
3. Desktop INSTALL workers/admission/receipt reconciliation and real native installer
   evidence on every supported desktop platform.
4. Functional operation-specific Windows VPN elevation before removing whole-app
   UAC/HIGHEST autostart behavior.
5. Android installer reconciliation/cleanup (current handed-off APK8-pin limit),
   actual installer confirmation/recovery evidence.
6. Remaining GUI capability/warning/error/localization/QR scenes/four-platform visual
   review; GUI detach/crash must preserve traffic and single runtime owner.
7. Current exact-SHA public packaged CLI evidence: Linux DEB/RPM, Windows MSI/native
   x64, macOS DMG, Android API29/API35; stdout/stderr/exit codes/Unicode paths.
   Windows ARM64 x64-emulated testing is not native x64 proof.
8. Every checkpoint: scope review, final version_bump, fresh full prepush, reviewed
   explicit-path commit/push dev, all five exact-SHA workflows green. Continue full
   goal after checkpoint; no release/main action authorized.

## Historical Detail

[parity-history.md](parity-history.md) preserves prior evidence and design notes,
including obsolete gaps and superseded receipts. Update this current handoff first.
