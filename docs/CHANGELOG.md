# Changelog

Release notes for VPN Control. New non-documentation changes accumulate under
`Unreleased` until the repository version policy rolls them into a release section.

## 2.0.14 - 2026-09-04

- Run release metadata validation through Python so the stable publisher works with non-executable script checkouts.

## 2.0.13 - 2026-09-04

- Ignore nondeterministic macOS guest chrome in secure-dialog visual comparisons.

## 2.0.12 - 2026-09-04

- Make Windows VPN preflight and cross-platform visual capture deterministic under cold or variable platform UI state.

## 2.0.11 - 2026-09-04

- Harden visual capture synchronization, native surface cleanup, and VM readiness checks.

## 2.0.10 - 2026-09-04

- Stabilize native visual surfaces and prevent duplicate managed Windows VM starts.

## 2.0.9 - 2026-09-04

- Make visual release capture deterministic across hosted and managed VM environments.

## 2.0.8 - 2026-09-04

- Use the reliable gVisor TUN stack on Windows.

## 2.0.7 - 2026-09-04

- Retry missing macOS secure surfaces and reject upper-edge capture overlays.

## 2.0.6 - 2026-09-04

- Reset cached macOS authorization state before repeatable secure captures.

## 2.0.5 - 2026-09-04

- Stabilize managed macOS packaging and deferred private-window capture consent.

## 2.0.4 - 2026-09-04

- Keep synthetic visual regression fixtures path-portable on Windows.

## 2.0.3 - 2026-09-04

- Make visual capture regression tests independent of Git LFS materialization.

## 2.0.2 - 2026-09-04

- Harden Windows VPN readiness and cross-platform visual capture reliability.

## 2.0.1 - 2026-09-04

- Harden exhaustive VPN probes and keep direct desktop routes outside the TUN.

## 2.0.0 - 2026-09-03

- Keep exhaustive Android and Windows VPN probes routable.
- Keep Android exhaustive VPN fixture arguments intact.
- Added fail-closed SSH Routing through an SSH relay.
- Added repository agent lifecycle tooling and documentation search.
- Renamed SSH Routing settings to SSH Routing.
- Kept exact-SHA CI watcher output compact.
- Added manual location diagnostics, persistent headless serving, and release-gated cross-platform VPN integration.
- Normalized user-facing terminology guard paths across platforms.
- Centralized product contracts and added the fixed navy UI with an automated cross-platform visual release gate.
- Make visual validation agent-owned with isolated local or ephemeral hosted environments and exact-SHA review receipts.
- Made agent visual environment tests portable across native path formats.
- Unified cross-platform versioning, fixed navy UI, and agent-owned visual release validation.
- Hardened hosted visual capture bootstrap for Android, Linux, Windows, and macOS.
- Made macOS package smoke tests enforce the canonical cross-platform product version.
- Prevented hosted Windows runner consoles from obscuring native visual evidence.
- Made Windows update-installer captures retain the visible setup wizard for review.
- Routed hosted Android visual capture through the arm64 macOS emulator when Linux KVM is unavailable.
- Cleared first-run macOS screen-recording consent before native screenshot capture.
- Hardened Android emulator startup in the visual regression capture workflow.
- Finalized deterministic QR scanner chrome and four-platform visual baselines.
- Stabilize deterministic Android visual fixtures and QR export evidence.
- Prevent macOS visual capture onboarding overlays.
- Accept macOS visual screen-recording consent deterministically.
- Capture macOS native dialogs through isolated framebuffer evidence.

## 0.1.7.3 - 2026-08-30

- Established the four-part version baseline corresponding to legacy release `v0.1.143`.
