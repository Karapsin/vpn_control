# Agent Visual Validation

Authoritative behavior is `UI-001` through `UI-008` and `VISUAL-001` through `VISUAL-009` in `contracts.md`. This guide covers environment selection, capture, automated verification, agent inspection, receipts, and diagnosis.

## Components

| Path | Purpose |
| --- | --- |
| `visual-tests/scenes.json` | Required scene, stable-element, capability, and review-batch inventory. |
| `visual-tests/environments.json` | Pinned local and hosted providers plus capability boundaries. |
| `visual-tests/baselines/<platform>/` | Canonical Git LFS PNG objects. |
| `scripts/visual_platform.py` | Local probe/bootstrap/start/stop, provider plan, hosted dispatch, capture, and report ingestion. |
| `scripts/capture_visual_windows_qemu.py` | QMP-controlled UAC launch plus headless VNC capture in the managed Windows client VM. |
| `scripts/capture_visual_macos_tart.py` | Headless VNC capture of Gatekeeper and authorization surfaces in the managed macOS Tart VM. |
| `scripts/visual_regression.py` | Pixel comparator, geometry validator, diffs, reports, and contact sheets. |
| `scripts/visual_review.py` | Exact-SHA review queue, scene verdicts, evidence receipt, and GitHub status. |
| `.github/workflows/visual-regression.yml` | Agent-dispatched hosted fallback capture on ephemeral GitHub runners. |

Generated VM state stays in `.runtime/visual-vms/`. Screenshots and reports stay under `build/`. Review sessions and receipts stay under `.rag_index/`. None are committed; only intentional Git LFS baselines are tracked.

## Scope

A targeted development review may name one or more affected platforms. A release review always includes every scene on Android, Linux, Windows, and macOS. App-owned scenes require PNG and geometry JSON; OS-owned scenes require a full-screen PNG. The agent opens every image, normally in six-scene batches, and records a verdict for every individual scene.

Synthetic fixtures freeze time, traffic, progress, data, locale, animations, window position, display scaling, and font selection. Capture must never use the operator's real workspace, credentials, subscriptions, or active VPN/runtime. Every local or hosted subset writes `capture-<provider>.json`, binding its environment fingerprint, scene files, manifest, and checked-out target SHA; comparison refuses a missing, stale, modified, or incomplete provenance set. JSON provenance hashes use canonical parsed content so Windows CRLF checkout rules cannot invalidate otherwise identical evidence.

An OS-owned scene may declare pixel-coordinate `ignore_regions` only for an unavoidable platform surface outside the subject under review, such as the Windows taskbar clock or Android notification date. The comparator validates every rectangle, excludes it from both ratios, and still fails if exclusions cover the whole image. The subject itself must remain compared and must also pass agent review.

## Provider Selection

Inspect the local-first plan:

```bash
python3 scripts/visual_platform.py plan --platform android
python3 scripts/visual_platform.py plan --platform linux
python3 scripts/visual_platform.py plan --platform windows
python3 scripts/visual_platform.py plan --platform macos
```

The planner routes each scene by required capability. Android is local-only:
the agent bootstraps and starts its isolated API 35 emulator because hosted
macOS workers do not expose the nested Hypervisor framework required for it.

- `app`: deterministic Compose application UI;
- `native`: repeatable platform-owned dialog, window, tray/menu, notification, or installer UI;
- `secure_desktop`: Windows UAC and macOS Gatekeeper/install confirmation.

Local capture is preferred. If the local provider is absent, bootstrap and start it:

```bash
python3 scripts/visual_platform.py bootstrap --platform <platform>
python3 scripts/visual_platform.py start --platform <platform>
```

Android uses an isolated Pixel 6/API 35 AVD. Linux and macOS use an isolated native session or pinned Tart VM. Windows uses an isolated Windows 11 client session, the existing `vpn-control-win11` libvirt guest, or the QEMU disk managed by `bootstrap_windows_visual_vm.sh`. A QEMU disk alone is never treated as ready: after the agent has completed Windows setup and verified the fixed display/capture prerequisites, it records that check with `scripts/mark_windows_visual_vm_ready.sh --agent-confirmed`. Windows media and license acceptance remain vendor-controlled; set `VPN_CONTROL_WINDOWS_ISO` to an official local ISO and `VPN_CONTROL_WINDOWS_DRIVER_ISO` to the UTM Windows guest-tools ISO when first creating an ARM64 guest. The agent must verify the Windows image against Microsoft's published digest before use.

The Android QR scanner visual fixture reasserts its fullscreen window contract whenever it
regains focus. Its instrumentation guard rejects any status-bar pixels in the scanner's top
band before the host framebuffer handshake proceeds. This prevents a preceding native scene's
SystemUI transition from intermittently leaking status chrome into `android-camera-qr`.

After the managed Windows guest is ready, capture its secure-desktop scene from the host without exposing or reusing the operator desktop:

```bash
python3 scripts/visual_platform.py capture-local \
  --platform windows \
  --driver "python3 scripts/capture_visual_windows_qemu.py" \
  --output build/visual-actual/windows \
  --scene windows-uac
```

The Windows VM exposes a loopback-only headless VNC framebuffer; the capture driver uses it for UAC instead of opening a host window. The macOS Tart VM keeps its built-in UI closed and uses the guest's VNC service through `vncdotool` from `agent_tools/requirements-mcp.txt`:

```bash
python3 scripts/visual_platform.py capture-local \
  --platform macos \
  --driver "python3 scripts/capture_visual_macos_tart.py" \
  --output build/visual-actual/macos \
  --scene macos-gatekeeper \
  --scene macos-install-confirmation
```

Neither secure-surface driver activates Screen Sharing, a VM display window, or another host workspace.
On macOS, the Python VNC client connects only to a loopback relay; Apple-signed `/usr/bin/nc` owns the
guest-network connection. This keeps capture independent of Local Network privacy grants that can be
invalidated when Homebrew Python is upgraded. The driver waits for the guest VNC route after every
managed reboot and refreshes Tart's reported IP before retrying a failed VNC action.
The install-confirmation scene leaves guest wall time current because moving time backward can suppress
Authorization Services sheets; its time-dependent menu-bar and Dock pixels are already excluded from
automated comparison. If a Screen Sharing edge tab appears, the driver dismisses it and captures in the
same VNC session so it neither recreates the tab nor clicks outside the secure sheet.
The macOS driver builds from a cached guest-local checkout pinned to the requested SHA, so Gradle never
writes into the host's shared worktree while another platform is capturing. Before every secure scene it
verifies the Tart helper's Screen Recording and Finder Automation grants, clears stale authorization,
notification, Finder, application, and Dock residue, resolves permission requests queued before TCC
repair, and compares the unobscured framebuffer perimeter with the canonical guest before proceeding.
Its isolated package build opts into Compose's documented Homebrew-JDK override so a managed JDK update
cannot strand the secure capture before the Gatekeeper scene is launched.
Before secure capture, it performs a managed-guest reboot and verifies the boot timestamp changed. This
clears macOS's short-lived administrator authorization cache so consecutive captures still show the sheet.
It captures Gatekeeper before install confirmation so the
Dock state is reproducible, verifies that each secure dialog actually appeared, waits for the guest-local
dialog process to exit, and retries a missing secure surface from another verified clean boot. It rejects
or clears and retries blank VNC framebuffers and transient overlays
instead of stamping unusable evidence, including narrow upper-right Screen Sharing or sidebar tabs.
Hosted macOS capture resolves both the initial Java Screen Recording consent and macOS 15's deferred
private-window capture consent after the empty Finder dialog is visible, before writing native evidence.
File dialogs and menu-bar popups use the same external framebuffer handshake in the managed Tart VM.
The tray fixture pins the popup anchor and extends its visual-only auto-hide timeout, then refuses to
capture unless the named popup window is visible; dialog teardown is likewise verified before the next scene.

The agent may dispatch hosted fallback for non-blocked scenes:

```bash
python3 scripts/visual_platform.py dispatch-hosted \
  --platform <platform> \
  --target-sha <full-sha>

python3 scripts/visual_platform.py download-hosted \
  --platform <platform> \
  --target-sha <full-sha> \
  --output build/visual-hosted/<platform>
```

`dispatch-hosted` passes only the scenes that the provider plan routed to the hosted capability. Download those files into the platform's combined `build/visual-actual/<platform>/` directory alongside any local secure-desktop captures, then run comparison and ingestion once over the complete platform set. Hosted jobs never compare or attest by themselves.

When a new baseline set is needed before the capture workflow has reached `main`, push an exact candidate commit only to a temporary `visual-preflight/**` branch. That branch trigger captures every hosted-capable scene on all four platforms and still excludes secure-desktop scenes. The agent reviews and records the downloaded evidence on `dev`, then removes the temporary branch; it is not a release or publishing path.

Hosted jobs use pinned Ubuntu 24.04, Windows 2025, and macOS 15 images. Windows hosted runners cannot satisfy `secure_desktop`, so `windows-uac` remains blocked until a local Windows client VM is available. A provider plan with any `blocked` scene is not release-capable.

After capture, stop only an environment recorded as started by the agent:

```bash
python3 scripts/visual_platform.py stop --platform <platform>
```

The stop command refuses to touch pre-existing environments and does not stop VPN Control or `sing-box`.

## Exact-SHA Review

Start a targeted review through `visual_workflow` or the CLI:

```bash
python3 scripts/visual_review.py start \
  --target-sha <full-sha> \
  --platform android
```

For a release, use all platforms and post the pending status:

```bash
python3 scripts/visual_review.py start \
  --target-sha <full-sha> \
  --platform android --platform linux --platform windows --platform macos \
  --release --post-status
```

Verify and ingest each captured platform:

```bash
python3 scripts/visual_platform.py verify \
  --platform <platform> \
  --target-sha <full-sha> \
  --actual-dir build/visual-actual/<platform>
```

Call `visual_workflow(action="status")` to get the next contact-sheet batch. Open every returned image and record every scene through `visual_review`, using exactly one of:

- `pass`;
- `product_defect` with the visible defect;
- `expected_change` with the intended change;
- `infrastructure_failure` with the failed provider or capture condition.

Non-pass verdicts require notes. Completion succeeds only when every automated result and every agent verdict is `pass`:

```bash
python3 scripts/visual_review.py complete \
  --target-sha <full-sha> \
  --post-status
```

The receipt hashes screenshots, geometry, reports, environment and manifest definitions, and all verdicts. The posted `vpn-control/agent-visual` status includes the receipt digest prefix. A partial review never posts release success.

## Failure Handling

- `product_defect`: add the fastest deterministic regression, fix the product on `dev`, and repeat normal validation.
- `expected_change`: inspect the complete platform set, update only intentional Git LFS baselines on `dev`, and rerun for the new SHA.
- `infrastructure_failure`: retry the owned environment, bootstrap it, or use a capability-compatible hosted fallback.
- Automated false positive: correct the comparator, geometry contract, frozen fixture, or baseline on `dev`; it is not waivable for the current SHA.

If a release candidate fails after `main` was fast-forwarded, return to `dev`, make and validate the correction, push it, and repeat the explicit release sequence. Do not patch `main` directly.

Read `build/visual-reports/<platform>/report.json` first. Each compared scene includes a full-resolution diff and baseline/actual/diff contact sheet. Geometry errors identify clipped, missing, overlapping, undersized, unlabeled, or low-contrast elements.

## Baselines

Install Git LFS before recording. Baselines may be changed only during development after a complete agent-reviewed platform capture:

```bash
python3 scripts/visual_regression.py record \
  --platform <platform> \
  --actual-dir build/visual-actual/<platform>
```

Commit all intended LFS pointers, run the full pre-push tier, push `dev`, and restart visual review for the new exact SHA. Release mode has no record or waiver operation.
