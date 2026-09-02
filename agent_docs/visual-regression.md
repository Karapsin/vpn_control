# Visual Regression Operations

Authoritative behavior is `UI-001` through `UI-008` and `VISUAL-001` through `VISUAL-008` in `contracts.md`. This guide covers manifest maintenance, capture-driver output, fleet enrollment, baseline bootstrap, and failure diagnosis.

## Components

| Path | Purpose |
| --- | --- |
| `visual-tests/scenes.json` | Required scene and stable-element inventory plus comparison thresholds. |
| `visual-tests/baselines/<platform>/` | Canonical Git LFS PNG objects. |
| `scripts/visual_fleet.py` | Dedicated-runner preflight, fingerprint, driver invocation, and completeness check. |
| `scripts/visual_regression.py` | Stdlib PNG decoder/comparator, geometry validator, diffs, reports, and contact sheets. |
| `scripts/check_ui_theme.py` | Fixed palette/root-theme regression guard. |
| `.github/workflows/visual-regression.yml` | Exact-SHA release-only four-platform gate. |

`build/visual-actual/` and `build/visual-reports/` are generated and ignored. A release run always uploads whatever evidence exists, including failed partial captures.

## Scene Maintenance

`scenes.json` is exhaustive by contract. A scene contains:

- a stable `id` used for its PNG and geometry filenames;
- every supported platform that renders it;
- `required_elements`, matching stable semantics/accessibility IDs emitted by the capture driver;
- `geometry_required=false` only for OS-owned full-screen surfaces whose native accessibility geometry is not portable.

Update the manifest whenever a tab, submenu, dialog, state, control, native picker/consent/elevation/installer surface, or supported platform changes. App-owned screenshots emit both `<scene>.png` and `<scene>.geometry.json`; OS-owned scenes emit the PNG. The driver freezes time, traffic counters, progress, data, locale, animations, and window placement.

Canonical scenes use English. Stress scenes cover long German labels and Arabic RTL without multiplying every scene by every catalog; all catalogs remain covered by localization checks.

## Capture Driver Interface

Each enrolled runner configures `VPN_CONTROL_VISUAL_CAPTURE_COMMAND` to an executable command. `visual_fleet.py` invokes it without a shell and appends:

```text
--platform <android|linux|windows|macos>
--manifest <absolute scenes.json>
--output <absolute output directory>
```

The driver must use a clean synthetic fixture/workspace and must never connect, disconnect, inspect, or mutate the operator's real VPN Control workspace. It captures every manifest scene for that platform and returns nonzero on any navigation, screenshot, semantics, or native-surface failure. Output completeness is checked before comparison.

Android app UI uses Compose `captureToImage`; system bars, VPN consent, document pickers, camera/QR, share chooser, package installer, and VPN notification use UiAutomator full-screen capture. Desktop app UI uses the real Compose window at fixed geometry; native file dialogs, tray/menu-bar states, Linux backends, Windows UAC/MSI, macOS DMG/Gatekeeper, and update confirmation use platform desktop automation. Stop after the native chooser/installer surface; unrelated third-party target content is outside scope.

## Fleet Enrollment

Register one persistent interactive runner for each label set:

```text
self-hosted,vpn-control-visual,android
self-hosted,vpn-control-visual,linux
self-hosted,vpn-control-visual,windows-vm
self-hosted,vpn-control-visual,macos
```

Common requirements:

- a dedicated account and fixed display configuration;
- JDK 17, Python 3, Git LFS, repository build prerequisites, and the enrolled capture driver;
- `VPN_CONTROL_VISUAL_FLEET=1` and `VPN_CONTROL_VISUAL_CAPTURE_COMMAND` in the runner service environment;
- animations, screen saver, notifications, auto-updates, night shift/color adaptation, and font substitution disabled;
- no personal workspace, subscription, credential, or active VPN on the runner.

Run `scripts/setup_visual_runner.sh <android|linux|windows-vm|macos>` on the runner host. Run `scripts/setup_visual_runner.ps1` inside the Windows guest for guest-side prerequisites. Registration tokens and service installation are operator steps and are not stored in this repository.

Platform setup:

- Android: Pixel 6 API 35 x86_64 emulator, portrait canonical state, disabled animations, deterministic system image, plus landscape/font-scale stress passes.
- Linux: 1280x800 at 100%, fixed desktop theme/fonts, a usable tray host, and separate native/AWT backend captures.
- Windows: the Linux host drives the existing `vpn-control-win11` libvirt guest through QEMU guest agent; set `VPN_CONTROL_VISUAL_WINDOWS_VM=1`; keep guest resolution/theme/DPI fixed and capture the secure-desktop UAC flow through the enrolled guest automation.
- macOS: 1280x800 at 100%, fixed appearance/fonts, and Screen Recording plus Accessibility permission granted to the runner and automation driver.

Preflight without requiring an existing baseline during first enrollment:

```bash
python3 scripts/visual_fleet.py preflight --platform android --allow-missing-baselines
python3 scripts/visual_fleet.py preflight --platform linux --allow-missing-baselines
python3 scripts/visual_fleet.py preflight --platform windows --allow-missing-baselines
python3 scripts/visual_fleet.py preflight --platform macos --allow-missing-baselines
```

The generated `machine.json` fingerprint is evidence, not a secret or an approval token.

## First Baseline And Intentional Updates

Install Git LFS before recording. On each matching platform runner:

```bash
python3 scripts/visual_fleet.py capture \
  --platform <platform> \
  --allow-missing-baselines \
  --output build/visual-actual/<platform>
python3 scripts/visual_regression.py record \
  --platform <platform> \
  --actual-dir build/visual-actual/<platform>
```

Commit the complete four-platform LFS pointer set on `dev`, then run the normal pre-push and exact-SHA CI loop. Partial platform baselines are not release-ready. Baseline recording is an explicit development operation; the release workflow has no record mode and no approval override.

## Local Verification And Failure Diagnosis

```bash
python3 scripts/check_ui_theme.py
python3 scripts/test_visual_regression.py
python3 scripts/test_visual_fleet.py
python3 scripts/visual_regression.py verify \
  --platform <platform> \
  --actual-dir build/visual-actual/<platform>
```

Read `build/visual-reports/<platform>/report.json` first. Each failed scene includes its diff and a baseline/actual/diff contact sheet. Geometry errors name the clipped, missing, overlapping, undersized, unlabeled, or low-contrast stable element. Do not relax thresholds, mask dynamic regions, or rerecord baselines to hide a product defect; freeze the nondeterminism or fix the UI and add the smallest deterministic regression.

No person is required to inspect or approve screenshots for release. Contact sheets are diagnostic artifacts available when someone chooses to investigate a failure.
