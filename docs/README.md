# VPN Control Developer Docs

This is the authoritative entry point for developer and agent documentation.

| Doc | Purpose |
| --- | --- |
| `development.md` | Workflow guide: source/generated boundaries, dirty worktree policy, and safe patch flow. |
| `architecture.md` | Import/subscription to parser, state, config, runtime, and diagnostics data flow. |
| `state-ownership.md` | Shared, Android, and desktop state/action ownership boundaries. |
| `test-matrix.md` | Which tests to run for each touched area. |
| `platform-matrix.md` | Android, Linux, Windows, and macOS capability/privilege matrix. |
| `runtime-troubleshooting.md` | General runtime safety and read-only diagnostics before interrupting VPN/runtime. |
| `desktop-runtime-troubleshooting.md` | Desktop state, logs, config paths, and platform-specific runtime details. |
| `desktop-lifecycle.md` | Tray, single-instance, autostart, reconnect, refresh, and direct-probe invariants. |
| `sing-box-contract.md` | Supported protocols, config-generation boundaries, routing rules, and benchmark expectations. |
| `native-runtime-artifacts.md` | Which native binaries are tracked, generated, or ignored. |
| `localization.md` | Language catalog architecture, editing rules, validation, and test-update guidance. |
| `developer-release-checklist.md` | Local developer release prerequisites, checks, outputs, and failure modes. |
| `desktop-smoke-testing.md` | Linux/Windows desktop manual smoke checklist. |
| `smoke-android.md` | Android instrumentation commands and manual protocol smoke checklist. |
| `macos-release.md` | macOS signing and notarization setup. |
| `work-in-progress.md` | Optional template for intentional multi-bucket dirty work. |

User-facing install instructions stay in `../README.md`.
