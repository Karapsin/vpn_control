# Product Contracts

This file is the single authoritative source for VPN Control product, platform, UI, state, protocol, localization, artifact, and release invariants. Focused documents describe owners, implementation procedures, troubleshooting, and test commands; they must cite these IDs instead of redefining requirements.

Contract IDs are stable. Update an existing contract when behavior changes, add a new ID for a new invariant, and update affected tests and focused docs in the same change. If another agent document conflicts with this file, this file wins for product behavior while root `AGENTS.md` wins for agent workflow and safety.

## Product And Data Contracts

- **PRODUCT-001 — Empty initial data.** A fresh install has no default subscriptions, routing rules, locations, or demo data.
- **PRODUCT-002 — Cross-platform parity.** Subscription parsing, source selection (including `All`), refresh results, location matching, Find Best candidate selection, secure DNS behavior, SSH Routing truth tables, update states, and user-visible statuses stay aligned across Android and desktop unless a platform contract explicitly diverges.
- **PRODUCT-003 — Additive compatibility.** New protocol or subscription formats do not break supported direct-link, line-based, base64, JSON, Clash, or persisted payloads. Existing serialized names require an explicit migration before they change.
- **PRODUCT-004 — Import/export round trip.** Direct link, clipboard, QR, and file paths preserve a supported configuration's meaning. Custom configurations remain full runtime JSON except for the narrowly allowed runtime transformations in `CONFIG-003`.
- **PRODUCT-005 — Safe updates.** Update checking, downloading, and checksum verification do not stop an active connection. Installation uses platform confirmation/elevation, may briefly disconnect, and preserves the prior reconnect/off intent.
- **PRODUCT-006 — Private data.** Diagnostics and reports do not expose subscription URLs, endpoints, UUIDs, credentials, tokens, or SSH private keys. Private keys never enter `PersistedState`, DataStore, `workspace.json`, generated documentation, or exported diagnostics.
- **PRODUCT-007 — Desktop default mode.** A new desktop workspace starts in VPN mode; macOS capability handling may direct the user to proxy-only without changing the persisted cross-desktop default.

## UI Contracts

- **UI-001 — Fixed appearance.** Android and desktop always use `VpnControlTheme`; light mode, system-derived dynamic colors, and independent platform palettes are unsupported.
- **UI-002 — Palette.** The application background gradient is `#08111F -> #12304B -> #16496B`; base/elevated surfaces are `#141F2D` and `#1D2B3B`; primary/accent are `#4B7BE5` and `#9ED6FF`; primary/secondary/muted text are `#FFFFFF`, `#D3E3EE`, and `#94A9B8`.
- **UI-003 — Semantic hues.** Green is used only for success/active state, amber only for warning/pending state, and red only for error/destructive state. Decorative backgrounds, navigation, ordinary actions, and selection use navy/azure.
- **UI-004 — Shape scale.** Small, medium, and large component shapes use 12, 18, and 24 dp corner radii. Pill controls may use a full radius when their shape conveys selection or state.
- **UI-005 — Accessibility geometry.** Visible content stays within its viewport and remains scroll-reachable. Interactive elements do not overlap, expose a non-empty accessible label, and provide at least a 48 by 48 dp target unless a documented native-control exception applies.
- **UI-006 — Complete surface coverage.** Every tab, submenu, dialog, menu state, enabled/disabled state, progress/error state, and supported OS-owned surface is represented in `visual-tests/scenes.json`. Adding or removing a visible element updates the scene's required-element inventory and its baseline in the same change.
- **UI-007 — Deterministic visual fixtures.** Visual fixtures use synthetic public data, frozen clocks/progress, canonical English, and fixed viewports. They never read the user's workspace or interact with an active VPN/runtime.
- **UI-008 — Localization stress.** The visual suite includes narrow/landscape, 1.3 Android font scale, 960x720 desktop at 125%, long German text, and Arabic RTL stress scenes. Catalog validation still covers every supported language.

## State And Action Ownership Contracts

- **STATE-001 — Shared purity.** Shared model/core owns cross-platform models, validation, draft mutation, selection decisions, state projection, status keys, parsing, refresh, and config-independent logic. Shared code does not directly perform Android APIs, desktop process control, filesystem IO, or OS permission work.
- **STATE-002 — Android side effects.** Android owns Android permissions and activity results, VPN service calls, WorkManager, installed-app catalogs, Android persistence, Android credential storage, and Android update/installer orchestration. Platform services execute effects returned from shared decisions instead of growing the ViewModel.
- **STATE-003 — Desktop side effects.** Desktop owns workspace files, runtime processes, TUN/privilege setup, tray/single-instance behavior, autostart, native dialogs, desktop credentials, direct-probe executables, diagnostics export, and desktop update/installer orchestration. `DesktopAppService` remains a facade/coordinator and delegates focused behavior.
- **STATE-004 — Shared-first decisions.** A decision used on more than one platform is extracted to shared core before platform call sites duplicate it. A genuine divergence is recorded in this file.
- **STATE-005 — Live-setting changes.** Saving runtime-affecting DNS, SSH, routing, mode, or related settings never stops a live connection without an explicit restart action. Pending state remains visible until the user applies it.

## Platform Contracts

- **PLATFORM-001 — Android.** Android provides the shared Compose UI, VPN mode through Android VPN APIs, supported proxy-only flows, app-package routing, in-app diagnostics export, and a direct-install APK. VPN permission is user-granted.
- **PLATFORM-002 — Linux desktop.** Linux provides Compose Desktop proxy-only and VPN modes. VPN requires `/dev/net/tun` and `CAP_NET_ADMIN` on the installed `sing-box`. Packages include DEB and RPM plus the Arch install/update paths.
- **PLATFORM-003 — Windows desktop.** Windows provides Compose Desktop proxy-only and VPN modes. VPN requires Administrator/Wintun; proxy-only remains usable without elevation. Packages include EXE and MSI.
- **PLATFORM-004 — macOS desktop.** macOS provides Compose Desktop proxy-only mode and DMG packaging. Full VPN mode is not advertised or tested as supported until a privileged helper exists.
- **PLATFORM-005 — Desktop app assignment.** Android package assignment rules are not shown as functional desktop routing controls until equivalent OS-specific implementations exist.
- **PLATFORM-006 — Linux tray fallback.** The app auto-detects native AppIndicator/StatusNotifier/GtkStatusIcon support and can use AWT/XEmbed. i3/polybar-style XEmbed sessions prefer AWT; `VPN_CONTROL_LINUX_TRAY_BACKEND=native|awt` remains available for diagnosis. The window stays accessible until a tray icon is confirmed.
- **PLATFORM-007 — Platform update package.** Linux selects DEB, RPM, or Arch bundle from the installed family; Windows uses its installer flow; macOS uses its DMG flow; Android uses the package installer. Stable Android updates use the configured signer identity.

## Desktop Lifecycle Contracts

- **DESKTOP-001 — Single instance.** A second GUI launch activates the existing instance rather than creating an independent app.
- **DESKTOP-002 — Close to tray.** Closing hides the window only after a tray icon is confirmed available. Without a usable tray, the window remains accessible or the app exits instead of becoming invisible.
- **DESKTOP-003 — Autostart visibility.** `--autostart` starts hidden only after tray availability; otherwise the window stays visible. Linux uses the XDG entry and maintains an i3-compatible marked fallback block when enabled from i3.
- **DESKTOP-004 — Reconnect intent.** If VPN/proxy was on before shutdown or reboot, startup reconnects to the remembered selection. If it was off, startup remains disconnected.
- **DESKTOP-005 — Refresh continuity.** Scheduled subscription refresh does not leave VPN/proxy stopped. A short controlled restart is allowed only when a generated config change requires it.
- **DESKTOP-006 — Direct probes.** Desktop Find Best and validation probes use the dedicated direct executable/routing so active VPN/proxy state cannot bias results. Custom profiles are excluded from Find Best candidates.
- **DESKTOP-007 — Scoped elevation.** Windows elevation is requested only for operations that need it; proxy-only remains available without Administrator privileges.
- **DESKTOP-008 — Headless command.** The supported persistent no-GUI entry point is `vpn-control serve`; the internal transient headless-controller argument is not a service interface.

## sing-box And Networking Contracts

- **CONFIG-001 — Supported profiles.** Structured profiles support VLESS, Trojan, Shadowsocks, VMess, and SOCKS. `CUSTOM` stores a complete runtime JSON configuration.
- **CONFIG-002 — Shared config builders.** Non-custom outbound/TLS/transport generation and common DNS/route/rule-set generation are shared. Platform factories own inbounds, Android app assignments, desktop direct-probe rules, and runtime wrappers.
- **CONFIG-003 — Custom transform boundary.** Custom JSON may be transformed only for the loopback management proxy, isolated desktop direct probes, and optional SSH Routing. SSH transforms fail closed on unknown outbound/DNS types, unsupported top-level network features, invalid detour graphs, or reserved-tag collisions.
- **CONFIG-004 — SSH chain.** When enabled, application traffic follows `selected proxy -> remote loopback SOCKS relay -> pinned SSH outbound -> public network`; the SSH leg uses UDP-over-TCP v2. SSH host/bootstrap establishment is the intentional direct exception.
- **CONFIG-005 — SSH direct actions.** `DIRECT` rules, direct-domain suffixes, and remote rule-set downloads use SSH egress while SSH Routing is enabled. Active runtimes expose a loopback-only mixed management inbound for subscription downloads.
- **CONFIG-006 — Secure DNS modes.** `AUTOMATIC` uses `https://1.1.1.1/dns-query`; custom DoH accepts `https://` and supplies `/dns-query` when absent; custom DoT accepts `tls://` and defaults to port 853. Plain UDP/TCP custom DNS is rejected.
- **CONFIG-007 — Secure DNS wiring.** `secure-dns` is final, returns IPv4 answers, and detours through `proxy`. A direct `bootstrap-dns` at `1.1.1.1:53` resolves only proxy/encrypted-DNS establishment hosts. Only the bootstrap address enters direct CIDRs.
- **CONFIG-008 — DNS validation and migration.** Secure endpoints reject credentials, query strings, fragments, invalid ports, wrong schemes, and DoT paths. Legacy enabled raw-IP DNS migrates to automatic secure DNS while retaining the old value only for the migration notice.
- **CONFIG-009 — Routing defaults.** No default rules are added. With `ignoreRules=true`, all eligible traffic uses VPN. With `ignoreRules=false` and no Android app assignments, all apps use VPN. Configured direct-domain suffixes bypass VPN/proxy.
- **CONFIG-010 — Direct probe rule placement.** Desktop VPN config injects direct-probe process rules only in VPN mode and before DNS hijack rules.
- **CONFIG-011 — Find Best parity.** Android and desktop evaluate supported subscription candidates with shared selection logic where possible; results do not depend on whether VPN is currently active.

## Localization Contracts

- **L10N-001 — Catalog ownership.** User-facing labels live in `i18n/*.json`; status, log, benchmark, and freeform runtime translations live in `i18n-status/*.json`. Kotlin does not contain translated `when (AppLanguage...)` branches.
- **L10N-002 — Generated language model.** `languages.json` owns supported languages; `AppLanguage` and lookup tables are generated. UI choices sort by visible display name with System pinned first.
- **L10N-003 — Typed statuses.** Stable runtime events use domain status facades and structured keys. UI/platform code does not concatenate encoded statuses into untranslated compound sentences.
- **L10N-004 — Catalog parity.** Every language has the English key/section shape and preserves all placeholders exactly. Technical commands, paths, URLs, capability names, and protocol identifiers stay recognizable.
- **L10N-005 — Legacy paths.** `dynamic` handles known parameterized legacy patterns, `legacyExact` handles persisted complete messages, and replacement lists are limited to stable fragments. Only `target` text is translated; `source` stays canonical.

## Artifact Contracts

- **ARTIFACT-001 — Tracked runtime inputs.** The Android AAR, Android ARM64 release runtime, Android x86_64 debug runtime, and the four desktop test fixtures named in `native-runtime-artifacts.md` are the only tracked native runtime inputs.
- **ARTIFACT-002 — Generated runtime outputs.** Desktop bundled runtime directories, all `build/`, `dist/`, `.runtime/`, downloaded packages, and prepared `sing-box` binaries remain untracked.
- **ARTIFACT-003 — Runtime provenance.** A tracked runtime refresh records upstream version and checksum, preserves architecture compatibility, and is not mixed with unrelated UI/localization work.
- **ARTIFACT-004 — Visual baselines.** Canonical PNG visual baselines under `visual-tests/baselines/<platform>/` are Git LFS objects. Actual screenshots, diffs, reports, machine fingerprints, and contact sheets are generated artifacts and remain untracked.

## Visual Regression Contracts

- **VISUAL-001 — Supported-platform gate.** A release requires complete automated results and agent screenshot verdicts for every Android, Linux, Windows, and macOS scene at the exact release SHA. A missing capture, result, verdict, receipt, or attestation blocks release.
- **VISUAL-002 — Capture boundary.** App-owned UI uses deterministic Compose/semantics capture; Android and desktop OS-owned consent, picker, chooser, tray/menu-bar, elevation, installer, notification, window-frame, DMG, and Gatekeeper surfaces use full-screen platform automation. Arbitrary third-party target content after a chooser is excluded.
- **VISUAL-003 — Canonical environments.** Android uses Pixel 6/API 35 portrait; desktop uses 1280x800 at 100%. The agent prefers an isolated local emulator, native session, or VM, bootstraps and starts it when absent, and may dispatch a pinned GitHub-hosted ephemeral fallback only for capabilities that environment can faithfully expose. Windows UAC and macOS secure surfaces require a real local client VM/session.
- **VISUAL-004 — Comparison.** Dimensions match exactly. Per-channel deltas up to 8 are ignored; changed pixels above that threshold are at most 0.02%; mean absolute channel error is at most 0.25. Dynamic values are frozen and no masks are allowed.
- **VISUAL-005 — Geometry and contrast.** Every app-owned scene emits viewport, stable-element geometry, and measured text contrast. The gate rejects clipping, off-viewport bounds, overlapping interactive controls, undersized targets, missing labels/elements, and contrast below 4.5:1 for normal text or 3:1 for large text.
- **VISUAL-006 — Evidence.** Every capture subset binds its checked-out SHA, scene-file hashes, manifest, provider, and environment fingerprint. Every run preserves those records plus actual screenshots, baseline/actual/diff contact sheets, per-scene diffs, geometry data, comparison summaries, and scene-level agent verdicts. A release receipt hashes all evidence, the manifest, the environment contract, and the exact SHA.
- **VISUAL-007 — Baseline and failure handling.** Release verification is read-only. A product defect blocks; an infrastructure failure is retried or moved to an eligible provider; an intentional visual change updates reviewed Git LFS baselines on `dev`. Automation failures cannot be waived for the same SHA and require a new validated SHA after a fix or test/baseline correction.
- **VISUAL-008 — Agent-owned execution.** Persistent self-hosted visual runners and externally enrolled runner services are unsupported. The coding agent plans providers, boots only isolated environments it owns, captures or dispatches capability-compatible fallback scenes, combines the evidence, runs comparison, opens every screenshot/contact sheet, records every verdict, and stops only environments it started. Hosted capture never compares or attests independently.
- **VISUAL-009 — Exact-SHA attestation.** A full release review writes an ignored local receipt and posts the `vpn-control/agent-visual` commit status containing its digest. Targeted or partial reviews never create release approval. No human approval substitutes for the agent review.

## Release Contracts

- **RELEASE-001 — Development branch.** Normal work lands on `dev`. The exact pushed SHA passes every required development workflow in `.github/required-workflows.json` before work is reported complete.
- **RELEASE-002 — Explicit authorization.** Building, finishing, shipping development work, or pushing does not authorize `main`, a tag, a GitHub Release, or stable publishing. Only an explicit user release command does.
- **RELEASE-003 — Version source.** `gradle.properties` owns the four-part base-20 version. README, Android code/name, desktop package projections, release metadata, and latest versioned changelog heading agree with it.
- **RELEASE-004 — Changelog roll.** Every non-documentation change adds one concise `Unreleased` bullet. The tenth bullet rolls the version with carry; an early forced roll is allowed only during an explicitly requested release.
- **RELEASE-005 — Exact-SHA release gates.** Release merge fast-forwards `main` from the already verified `origin/dev` SHA, dispatches exhaustive `VPN Integration / all`, and starts a full agent visual review for that SHA. Package workflows, exhaustive integration, the matching visual receipt, and its successful commit status must all succeed.
- **RELEASE-006 — Publisher defense in depth.** The manual publisher independently verifies main/dev SHA equality, version/changelog metadata, exact-SHA package workflows, exhaustive VPN integration, the `vpn-control/agent-visual` status and receipt digest, stable Android signer, package contents, checksums, and update manifest before creating a new immutable tag/release.
- **RELEASE-007 — No same-SHA exception.** The agent reviews all captures and triages failures, but cannot approve an automated failure on the same SHA. There is no human approval override; fixes, baseline corrections, and test corrections return to `dev` and produce a new exact SHA.
