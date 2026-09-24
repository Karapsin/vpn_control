# Development Guide

This guide is the workflow guide for agents and maintainers working on VPN Control. The authoritative docs entry point is `agent_docs/README.md`.

For a complete docs index, start with `agent_docs/README.md`.

## Source And Generated Boundaries

Source files that should be edited and committed:

- Kotlin source under `app/`, `desktopApp/`, and `shared/`.
- Localization catalogs under `shared/ui/src/commonMain/resources/i18n/`.
- Status localization catalogs under `shared/ui/src/commonMain/resources/i18n-status/`.
- Language manifest at `shared/model/src/commonMain/resources/languages.json`.
- Public documentation under `README.md` and `docs/`.
- Agent documentation and tooling under `AGENTS.md`, `agent_docs/`, and `agent_tools/`.
- Scripts under `scripts/`.

Generated or local files that should not be committed:

- `build/`
- `dist/`
- `.runtime/`
- downloaded or extracted `sing-box` runtime binaries
- generated local MCP configuration `.codex/config.toml` (derive it with `agent_tools/configure_codex.py`)
- agent-only environments and indexes under `.agent_venv/` and `.rag_index/`
- Gradle caches and IDE state

Generated Kotlin for languages/catalogs is produced during the Gradle build. Do not patch generated Kotlin directly.

## Dirty Worktree Policy

Treat a dirty worktree as unclassified work, not junk.

Before changing files in a dirty worktree:

```bash
git status --short
git diff --stat
git diff --name-status
```

Classify changes by bucket before staging:

- Public documentation: `README.md`, `docs/`.
- Agent instructions and tooling: `AGENTS.md`, `agent_docs/`, `agent_tools/`, `.codex/config.toml`.
- Android runtime/config/UI: `app/`.
- Desktop runtime/tray/lifecycle: `desktopApp/`.
- Shared model/core behavior: `shared/model/`, `shared/core/`, `shared/storage-api/`.
- Shared UI/localization: `shared/ui/`.
- Packaging/VM/release: `scripts/`, `.github/workflows/`.
- Accidental local files: marker files, caches, downloaded artifacts.

If a large task intentionally spans several buckets, document the current intent in `agent_docs/work-in-progress.md` before handing off to another agent.

Do not use broad cleanup commands such as `git reset --hard` or `git checkout -- .` unless the user explicitly approves it. Preserve unrelated local changes.

## Common Patch Workflow

1. Identify the smallest behavior or documentation unit.
2. Inspect the owner files and existing tests.
3. Patch only that unit.
4. Run the relevant tests from `agent_docs/test-matrix.md`.
5. Report exactly what was changed and what was not tested.

Keep unrelated docs, localization, Android runtime, desktop runtime, and packaging changes in separate staging units or commits.

## Low-Context Patch Workflow

When you enter the repository without fresh context, route the task before editing:

1. Start from the task router in `agent_docs/README.md`.
2. Read only the two or three focused docs named by that route.
3. Check the dirty worktree with `git status --short`, `git diff --stat`, and `git diff --name-status`.
4. Inspect the owner files named by `agent_docs/architecture.md`, `agent_docs/state-ownership.md`, or the focused subsystem doc.
5. Choose the smallest patch unit that does not mix unrelated buckets.
6. Run the minimum validation tier from `agent_docs/test-matrix.md`; expand to a boundary or full tier when the patch crosses subsystem boundaries.
7. Report changed areas, checks run, and checks skipped with the reason.

If the docs disagree, treat `AGENTS.md` as the hard-rule layer and the focused docs as the subsystem detail layer. Fix the contradiction as part of the patch when the answer is clear; otherwise call it out explicitly.

## Resource-Efficient Execution

Optimize tokens per completed, verified change. The acceptance criteria and required
checks remain unchanged; reduced coverage is not an efficiency measure.

- Keep current ownership, blockers, next actions and evidence links in
  `work-in-progress.md`. Replace stale summaries instead of appending contradictory
  updates. Keep historical detail in linked archives and read it only for a specific
  question. Reuse already-read instructions within a continuous task.
- Use one implementation owner per subsystem and concrete, independent worker
  assignments. Default bounded implementation and test execution to **GPT-5.6 Terra
  with medium reasoning**, when available. Reserve stronger-model work for privileged
  code, difficult unresolved failures, shared design decisions and focused independent
  review. Preserve an explicit user model override. Do not restart an effective
  worker merely to change models; transfer at a coherent handoff.
- Give workers a focused brief: outcome, owned/reserved files, applicable contracts,
  interfaces, exact checks, environment/permission boundaries and evidence locations.
  Aim for about 500 words; include additional essential constraints when needed.
  Avoid a full conversation fork for a task that needs only this brief. Reuse a
  worker when its existing context matches the next assignment.
- Keep routine handoffs near 200 words: completed behavior, changed paths, command
  and result counts/skips, source/artifact identity, evidence paths, unresolved cases,
  and cleanup. Send intermediate messages for decisions, completion or actionable
  failures, rather than each setup command. Preserve timely user progress updates.
- On the current macOS host, start shell commands with the shell builtin
  `unset DYLD_INSERT_LIBRARIES` so injected AppleSharpener messages do not multiply
  through child processes. Before displaying captured shell results, remove only
  timestamped AppleSharpener `Windows: Loaded enableSharpener` and `Not in Dock
  process ... skipping setup` lines. Preserve every other diagnostic and the exact
  exit status. Repository MCP command execution applies this narrow filter before
  output truncation. Do not disable host software or suppress stderr wholesale.
- Save full redacted logs and machine-readable receipts outside tracked source.
  Return exit status, counts/skips, artifact identity and evidence paths by default;
  read bounded failure excerpts when needed. Do not trim the evidence needed to
  understand a failure or infer success from a shell wrapper's exit alone.
- Run the mapped focused checks while editing. Batch compatible selections into one
  host Gradle invocation. Repeat passed checks when content, inputs, environment,
  failures or unresolved concerns justify it. Run the complete managed prepush tier
  after each coherent checkpoint's final content/version edit, then push and verify
  every required workflow for that exact SHA. Retain checkpoint pushes.
- Reuse native harnesses and validate the assigned environment, artifact, endpoint
  and trust before product scenarios. Freeze and hash artifacts; reuse evidence only
  for its proven source and scope. Keep every distinct TEST-001 quick regression and
  the original native scenario. Use existing long waits/event notifications and back
  off unchanged remote observations; never restart work because a poll timed out.
- Capture explicitly selected local fixture inputs before remote submission. A script
  sent as `python3 -` cannot locate local inputs through `__file__`; never scan the
  remote working directory to discover them. Validate payload names and hashes
  before acquiring an exclusive guest-agent connection. Generate evidence manifests
  with `scripts/native_fixture_manifest.py` so regeneration excludes the manifest
  itself, then verify the exact frozen inputs before execution.
- Stage the desktop update fixture with `prepare_desktop_update_fixture.py
  stage-entrypoint --source-directory scripts --output <fresh-directory>` before
  transfer; it includes sibling modules and checks an isolated import.
- For trusted Windows fixture files, construct discrete PowerShell arguments with
  `windows_native_fixture.trusted_powershell_file_arguments`; its execution-policy
  option applies only to that process. Never change the guest-wide policy merely
  to run a fixture.
- Before launching a generated native runner, syntax-check the complete script
  and validate its final deployed helper paths, interpreter, package attributes,
  and fixture tools. Reuse `native_fixture_run.sh` for durable child exit/PID
  receipts instead of generating another launcher. For transferred guest helpers,
  use `guest_fixture_input.guest_probe_argv` with the expected nonempty byte count
  and SHA-256. Pass its tuple through the structured guest executor: its verifier
  travels as a fixed argument, so lost stdin cannot turn an empty verifier into
  false success. A zero exit from an empty Python file is not a probe result. A packaged minimal JVM need not include JDK tools such as
  keytool; prepare fixture trust with the verified build JDK. Keep scripts in files
  rather than nesting generated heredocs across shells. Start long commands with
  a short initial tool yield (for example1000ms), retain the returned live session,
  and poll that session. Do not align the inner wait with the outer tool timeout.
  Provider fixtures should durably retain opaque transfer identity before writing
  requests so an interrupted observer can address the exact existing transfer.
- Prepare credential-input helpers before submitting a native operation. Review
  the current prompt immediately before input; use windows_prompt_observation.py
  to reject stale observations, changed screenshots, wrong environment/operation
  identity and terminal operations. The helper does not recognize UI: a human or
  agent must first verify the intended visible credential field. A dismissed
  prompt is not proof of authorization. Preserve the exact terminal receipt.
- Complete installer fixture preparation before submission and keep one durable
  driver responsible for its exact lock handles and cleanup. An asynchronous
  false-ready response requires the later authenticated public ready-status
  acknowledgement; raw receipt polling does not release the controller. Identify
  native process roles explicitly: a live receipt watcher does not establish that
  the installation coordinator is alive. Preserve unknown outcomes when the
  coordinator disappears without a terminal receipt.
- Admit VM starts centrally using host physical memory, current pressure/swap,
  configured memory of running guests, and build/test headroom. A low current VM
  RSS or a favorable memory-pressure percentage alone does not establish capacity:
  guests may consume their full configured allocation later. Record reservations
  before starting guests and recheck pressure before overlapping heavy work. Never
  stop unrelated VMs or uncertain installers to recover capacity.
- For the parity task on the 24GiB macOS host, allow at most one local test VM at a
  time, reserving it for the4GiB macOS fixture; do not overlap local Android
  emulators with that guest. Use authorized owned Arch-host Windows, Android and
  Linux guests for additional native work after checking remote capacity. A stopped
  guest must be inspected on normal restart before replaying any prior operation.

Measure savings from available task usage over comparable accepted changes; do not
invent percentages or treat a cheaper model as proof of fewer total tokens.

## Repository Agent Lifecycle

Use the project MCP lifecycle described in `agent_tools/README.md`. `prepare_start` performs dirty-aware synchronization to the `dev` development branch and routes the task before inspection. `docs` and `change_impact` provide focused repository context from the local documentation index. `workflow_status` makes the current dirty scope and missing actions visible.

After the final non-documentation edit, call `version_bump` once with a concise summary. It adds an `Unreleased` changelog bullet and rolls the three-part version only when the 10-bullet threshold is reached. Then the complete `run_checks(level="prepush")` tier creates a receipt tied to the repository's content fingerprint. Committing the same validated content does not invalidate that receipt, but any content or mode change does. Use managed push/checks to push `dev` and verify the exact commit SHA against `.github/required-workflows.json`.

`main` is not a development branch. Only an explicit user release command authorizes `release_workflow` to fast-forward `main`, require exhaustive VPN integration, and dispatch the manual publisher. Ordinary completion and push requests stop after verified `origin/dev`.

## Changelog And Version Policy

- `gradle.properties` owns the single cross-platform `vpnControlVersion` in `a.b.c` form.
- The major component is in `1..19` and the others are in `0..19`; increment with carry, so `2.0.19` becomes `2.1.0` and `2.19.19` becomes `3.0.0`.
- Each non-documentation change adds exactly one concise bullet under `## Unreleased` through `version_bump`.
- Fewer than 10 bullets do not change the version. At the 10th bullet, `version_bump` moves all notes into a dated version section and updates Gradle and README metadata atomically.
- `force_release` may roll fewer than 10 notes only while carrying out an explicit release command.
- Android version code and the update build number append an internal zero component before base-20 encoding so they remain newer than legacy builds. Every displayed and packaged product version remains exactly canonical; do not restore commit-count or platform-specific versions.

Follow `TEST-001` in `contracts.md` for every distinct failure type found during VM, emulator, native/package, manual, visual, or integration testing. Before fixing the implementation:

1. Reduce the failure to the quickest deterministic unit, component, constrained-heap, or fixture-contract reproducer that exercises the cause.
2. Run it against the unfixed behavior and retain the failing evidence. After the fix, retain the passing result and add the test to the routine suite identified in `test-matrix.md`.
3. Record the failure-to-test mapping and exact commands in the task evidence/WIP, including OS-only gaps. Keep and rerun the original native scenario on the fixed artifact; a host regression does not replace native verification.

Apply the same approach to reproducible harness and infrastructure defects with script or workflow-contract tests. Do not count an opt-in native test skipped by ordinary host checks as the required quick regression.

For native acceptance work, each discovered failure must also improve the related
repository MCP workflow: add a causal preflight, reliable observation, targeted
diagnostic, or recovery guard alongside its quick regression. Preserve the actual
product fix and native scenario. Use named SSH profiles from the private ignored
`.vm-hosts.local.json`; never copy credentials into tool arguments, tracked code,
logs, or evidence. Unknown remote outcomes remain unknown until observed, and must
not trigger an automatic retry of installation or runtime mutations.

The MCP server is agent-only infrastructure. Its environment and index remain ignored in `.agent_venv/` and `.rag_index/`; the application build must not depend on either directory.

## Runtime Safety

Do not stop a running VPN/runtime unless the user explicitly approves it. Stopping VPN can interrupt the active coding session.

Use read-only diagnostics first:

- Inspect `~/.vpn-control-desktop/workspace.json`.
- Inspect `~/.vpn-control-desktop/runtime/runtime-sing-box.log`.
- Inspect generated runtime config JSON under `~/.vpn-control-desktop/runtime/`.
- Use process listing commands before killing anything.

See `agent_docs/runtime-troubleshooting.md` for the safe diagnostic path.

## Where To Look Next

- Platform behavior and limitations: `agent_docs/platform-matrix.md`.
- Authoritative product invariants: `agent_docs/contracts.md`.
- State/action ownership: `agent_docs/state-ownership.md`.
- Test selection: `agent_docs/test-matrix.md`.
- Runtime logs and safe checks: `agent_docs/runtime-troubleshooting.md`.
- Architecture and data flow: `agent_docs/architecture.md`.
- Desktop lifecycle invariants: `agent_docs/desktop-lifecycle.md`.
- sing-box implementation procedure: `agent_docs/sing-box-development.md`.
- Native runtime artifact policy: `agent_docs/native-runtime-artifacts.md`.
- Large dirty-state handoff template: `agent_docs/work-in-progress.md`.
- Localization architecture: `agent_docs/localization.md`.
- Developer release packaging: `agent_docs/developer-release-checklist.md`.
- Android protocol smoke testing: `agent_docs/smoke-android.md`.
- Desktop smoke testing: `agent_docs/desktop-smoke-testing.md`.
