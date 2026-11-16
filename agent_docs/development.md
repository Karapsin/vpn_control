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
- Agent documentation and tooling under `AGENTS.md`, `CLAUDE.md`, `agent_docs/`, `agent_tools/`, and the shared Claude Code configuration `.mcp.json` and `.claude/settings.json`.
- Scripts under `scripts/`.

Generated or local files that should not be committed:

- `build/`
- `dist/`
- `.runtime/`
- downloaded or extracted `sing-box` runtime binaries
- generated local MCP configuration `.codex/config.toml` (derive it with `agent_tools/configure_codex.py`)
- personal Claude Code overrides `.claude/settings.local.json` and a root CLAUDE.local.md file
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
- Agent instructions and tooling: `AGENTS.md`, `CLAUDE.md`, `agent_docs/`, `agent_tools/`, `.codex/config.toml`, `.mcp.json`, `.claude/settings.json`.
- Android runtime/config/UI: `app/`.
- Desktop runtime/tray/lifecycle: `desktopApp/`.
- Shared model/core behavior: `shared/model/`, `shared/core/`, `shared/storage-api/`.
- Shared UI/localization: `shared/ui/`.
- Packaging/VM/release: `scripts/`, `.github/workflows/`.
- Accidental local files: marker files, caches, downloaded artifacts.

If a large task intentionally spans several buckets, document the current intent in `agent_docs/work-in-progress.md` before handing off to another agent.

Do not use broad cleanup commands such as `git reset --hard` or `git checkout -- .` unless the user explicitly approves it. Preserve unrelated local changes.

## Selective checks and native execution optimization

Use `python3 agent_tools/affected_agent_tests.py --run` for agent-tool validation.
Product and prose-only changes select zero agent tests. Tool changes select the
consumers that static imports, literal test/fixture paths, declared scopes and the
CI-recorded footprints connect (`agent_tools/agent_test_footprints.py fetch`
refreshes the local table); unconsumed changed files are listed in
`unconsumedPaths`. CI runs the complete agent suite on any agent-input change, so
local selection trades completeness for precision. Use an
explicit `--audit --baseline HEAD --run` for a complete agent-suite audit. The
managed prepush retains its other gates and binds the selection and result to the
same contents. Per-test timing identifies expensive cases; only reviewed isolated
independent groups run concurrently. See TEST-004 and `test-matrix.md`.

Keep native engineering execution in a qualified immutable clean source worktree,
separate from coordinator tooling edits. Record original source/package/version,
consumed tool hashes, guest generation, operator and server identity. An unrelated
tooling change never relabels old artifacts or grants final current-source acceptance.
A consumed or unknown source change requires new qualification. The initial fixed
engineering route covers only the Linux package builder and requires a new clean
checkpoint containing its gate; it cannot extend an old producer retroactively.
See the concrete operation in `agent_tools/README.md` and TEST-005.

Native dispatch admits only committed, published tool source. Each action's closure
in `readiness_vm_dispatch.json` is computed by `dispatch_source_closure.py`
(`--write` regenerates it; CI requires equality and checks every fixed-host proof
symbol). At dispatch every closure file must be clean in git and equal to the
merge-base with `origin/dev` or to an `origin/ci/*` tip, so push a candidate before
running native work from it. There are no source digests to re-pin.

Collect the complete actual bounded result once before publishing its finite public
summary. Preserve private raw payloads and the original execution receipt; partial
or uncertain collection remains UNKNOWN. Reuse completed collection and compatible
existing batches. Keep source, package, guest, operator and server identities
constant; changing them requires fresh admission. Serialize interfering mutations.
Restrict infrastructure work to demonstrated blockers or explicitly requested
optimizations, with preserved beforeimages and causal RED/GREEN coverage. Direct
native proof and matching MCP retesting remain required under TEST-002.

## CI And Build Environment Pins

Hosted images move on their own: `ubuntu-latest` became ubuntu-26.04 (JDK 25, Rust coreutils) and broke CI with no repository change. Everything the build depends on is pinned and checked by `python3 -m unittest agent_tools.tests.test_ci_environment_pins` (release hygiene):

- Runner images are exact (`ubuntu-24.04`, `windows-2025`, `macos-15`). Only `.github/workflows/environment-canary.yml` follows `-latest`; it runs weekly, is advisory, and is not in `.github/required-workflows.json`. A red canary means the next image bump needs attention, not a revert.
- Every third-party `uses:` is a full commit SHA with a `# vX.Y.Z` comment; resolve a tag with `gh api repos/<owner>/<repo>/git/ref/tags/<tag>` and dereference annotated tags. Dependabot (`.github/dependabot.yml`, weekly, grouped, target `dev`) proposes bumps.
- Linux jobs run in a digest-pinned container (`image: name:tag@sha256:...`) or appear in `UBUNTU_HOST_EXCEPTIONS` in that test with a reason (`host-only`, `privileged`, or `unverified`). Containerize an excepted job only after proving it green in the container, then delete its entry.
- Every Gradle module declares `jvmToolchain(17)`; the wrapper has `distributionSha256Sum`; `gradle/verification-metadata.xml` records sha256 checksums. After changing a dependency, regenerate with `./gradlew --no-configuration-cache --write-verification-metadata sha256 <tasks that resolve Android, desktop and native configurations>` and review the diff. Host-specific configurations (for example the Compose Desktop `skiko` runtimes of the other operating systems) must be resolved explicitly, not only for the current host.
- Python requirements: edit `agent_tools/requirements-mcp.in`, then run `uv pip compile --universal --generate-hashes --python-version 3.12 agent_tools/requirements-mcp.in -o agent_tools/requirements-mcp.txt`. Installs use `pip --require-hashes`.

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
- Give each worker one bounded implementation or native scenario outcome. Retire
  it after a coherent handoff; use a fresh worker when the next task crosses a
  subsystem boundary or accumulated context obscures current facts. Do not stop
  an accepted native operation merely to rotate its worker: transfer its exact
  process/job identities, receipts, ownership and remaining cleanup first. Reject
  incomplete scaffolds and routine tool errors as completion; the owner resolves
  them or explicitly hands off unfinished work before another writer starts.
- Workers may make reversible quick fixes and run assigned checks within explicit
  file and environment ownership without coordinator micro-approval. Preserve
  original failures and relevant unfixed beforeimages first. Once the flow works,
  report encountered failure types, causes and proposed coverage, then complete
  every TEST-001 causal RED/GREEN regression and routine-suite wiring before
  integration, push or completion. Existing scope, runtime authorization, unknown-
  outcome non-replay and source/artifact provenance gates remain binding.
- Run the portable Python capability manifest through release hygiene before a
  push. New platform failures extend executable absent-module/API probes; do not
  add a source-text rule requiring APIs that a test never executes. Keep the real
  platform CI and native scenario as separate gates.
- Freeze an immutable artifact set once per coherent product build. Reuse tools
  must derive changed paths from Git, recheck package/runtime bytes and preserve
  the original source SHA. Documentation/test-only equivalence is an explicit
  attestation, not a new package provenance claim. It does not waive exact-SHA CI
  or signer, architecture, runtime and native admission checks.
- Before an expensive native scenario, use its applicable fixed preflight to
  inspect current identity, credentials/prompt readiness, certificate/endpoint
  behavior and settings. Unknown or stale observations do not establish readiness.
  A durable batch may continue independent nodes after a failure, but blocks their
  dependents and never resubmits an uncertain accepted mutation.
- Versioned VM baselines are immutable snapshots of verified clean, stopped,
  task-owned fixtures. Restore into a fresh disposable clone or overlay; never
  overwrite a live fixture or a pending/unknown installer record. Baseline proof
  records must come from actual preparation checks, not authored success flags.
- Consult the native acceptance matrix for requirement, source/artifact, missing
  scenario and next-action scope. Keep component, historical and partial evidence
  visible without promoting them to current full acceptance. Preserve conflicting
  or unknown outcomes until authoritative evidence resolves them.
- Give workers a focused brief: outcome, owned/reserved files, applicable contracts,
  interfaces, exact checks, environment/permission boundaries and evidence locations.
  Aim for about 500 words; include additional essential constraints when needed.
  Avoid a full conversation fork for a task that needs only this brief. Reuse a
  worker when its existing context matches the next assignment.
- When a reviewer or worker has completed its turn, reactivate it with
  `followup_task` for another assignment. `send_message` only delivers a mailbox
  message and does not start an idle agent. Check `list_agents` before waiting
  for a new review verdict; a queued request alone is not a running review.
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
  failures or unresolved concerns justify it. The complete managed prepush tier is
  optional; after each coherent checkpoint's final content/version edit, gate the
  exact SHA through its `ci/*` branch (`git_workflow`), which runs every required
  workflow there and fast-forwards `dev` only when all succeeded. Retain checkpoint
  pushes (`action="checkpoint"` starts the `ci/*` runs without waiting). Never idle
  on CI while work remains: continue the remaining work while that verification runs
  in the background, fix CI failures in parallel, and rebase work in progress onto
  the fix before its own push. Only reporting completion waits for the final SHA's
  CI and its arrival on `origin/dev` (`AGENTS.md`, Post-Push CI Verification).
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
- Execute generated-carrier regressions with the assembled native namespace
  and imports. Do not inject missing standard-library globals into test harnesses.
  Declare any OS portability seam explicitly; keep real generated function code
  and source guards active. Function hashes alone do not prove that new wrapper
  code has its runtime bindings.
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

After the final non-documentation edit, call `version_bump` once with a concise summary. It adds an `Unreleased` changelog bullet and rolls the three-part version only when the 10-bullet threshold is reached. The optional complete `run_checks(level="prepush")` tier still creates a receipt tied to the repository's content fingerprint, but delivery no longer requires it.

### Pre-merge CI gate

`git_workflow(action="commit"|"push")` is the completeness gate (`RELEASE-001`):

1. It fetches `origin/dev` and refuses with a rebase blocker when `dev` is not an ancestor of the candidate.
2. A candidate whose own exact-SHA runs already succeeded fast-forwards `dev` without new runs. Otherwise, unless `exact=True`, a candidate with no runs of its own at all (any red, pending or partial own run decides by itself) whose difference from the nearest first-parent ancestor with successful exact runs touches only documentation reuses that result after `git diff --check`, `./scripts/check_docs_hygiene.sh` and `scripts/check_source_whitespace.py` pass. The walk stops at the first non-documentation difference or at a red, pending or partially run ancestor.
3. Otherwise it pushes the SHA to `origin/ci/<sha12>`. Every required workflow in `.github/required-workflows.json` triggers on `ci/**`; runs older than a fresh push of the same SHA are ignored.
4. It waits until every required run for that SHA has finished, so a red result carries the complete failure set (`TEST-006`). A workflow that never starts within the discovery window fails the gate. `action="checks"` still returns at the first failure for fast triage.
5. On success it fast-forwards `origin/dev` with a non-force push, which also fails safely if `dev` moved concurrently; a moved `dev` that is no longer an ancestor reports `rebase-needed`.
6. It records the outcome in `.rag_index/ci-gate/<sha>.json`. A merged `ci/<sha12>` is then deleted on origin and locally at once. A red, rebase-needed or pending result keeps the branch: re-run its failed jobs (`gh run rerun <id> --failed`) and resume with `action="push"`, which watches the existing runs instead of pushing again, or stop it with `action="abandon"`, which cancels its unfinished runs and records it but also keeps the branch.

`action="cleanup"` (CLI `git-workflow cleanup --max-age-days N`, default 7) lists every remote `ci/*` branch's runs first and keeps any branch with an unfinished run, even one `dev` contains, because it may be another agent's gate or a re-run. It then deletes a branch that `dev` contains (merged, or superseded by a merged descendant) or whose runs all finished and whose newest run is older than N days. A branch with no runs yet may have just been pushed, so its commit time is not used: it is aged from the first cleanup that saw it unrun (`.rag_index/ci-cleanup-unrun.json`), and kept for at least 15 minutes even with N = 0. Local `ci/*` branches without a remote counterpart are deleted.

The `dev` fast-forward also triggers the `dev` push workflows for the same SHA; each starts with a `Reuse ci/* result` job and skips its other jobs only when the newest exact-SHA `ci/*` push run of the same workflow succeeded; an older green run never hides a newer red, cancelled or unfinished one. The gate does not wait for them. `VPN Integration` has no push trigger and stays an advisory dispatch, and dispatch-only fixture jobs keep their exact `refs/heads/dev` conditions, which a `ci/*` push never satisfies. After each fast-forward the gate dispatches the Gradle cache warm for the new `dev` SHA (`gh workflow run gradle-cache-warm.yml --ref main -f dev_sha=<sha>`). The dispatch is best effort: its result is recorded as `cacheWarm` in the gate ledger and in the tool result, and a failed dispatch never fails the gate. Dispatch runs `main`'s copy of the workflow, which arrives only with a release; until then the gate finds no `.github/workflows/gradle-cache-warm.yml` in `origin/main`, records `cacheWarm.notOnMain: true` without dispatching, and adds nothing to the summary. Because `main`'s frozen copy builds newer `dev` commits, it resolves the commit inline and runs only the stable entry point `scripts/gradle_cache_warm.py` (plus the Windows SDK pin); `scripts/test_gradle_ci_cache.py` refuses any other repository path in it.

`main` is not a development branch. Only an explicit user release command authorizes `release_workflow` to fast-forward `main`, require exhaustive VPN integration, and dispatch the manual publisher. Ordinary completion and push requests stop after verified `origin/dev`.

## Changelog And Version Policy

- `gradle.properties` owns the single cross-platform `vpnControlVersion` in `a.b.c` form.
- The major component is in `1..19` and the others are in `0..19`; increment with carry, so `2.0.19` becomes `2.1.0` and `2.19.19` becomes `3.0.0`.
- Each non-documentation change adds exactly one concise bullet under `## Unreleased` through `version_bump`.
- Fewer than 10 bullets do not change the version. At the 10th bullet, `version_bump` moves all notes into a dated version section and updates Gradle and README metadata atomically.
- `force_release` may roll fewer than 10 notes only while carrying out an explicit release command.
- Android version code and the update build number append an internal zero component before base-20 encoding so they remain newer than legacy builds. Every displayed and packaged product version remains exactly canonical; do not restore commit-count or platform-specific versions.

Follow `TEST-001` in `contracts.md` for every distinct failure type found during VM, emulator, native/package, manual, visual, or integration testing:

1. Before editing, preserve the original failing outcome, exact source/artifacts and action identities, bounded redacted diagnostics, relevant unfixed source/file beforeimages, and cleanup or uncertainty state within authorized ownership.
2. A worker may implement and test a reversible quick fix within explicitly owned files and environments without coordinator micro-approval. After the flow works, report the finite list of encountered failure types, known or unresolved causes, and proposed regression coverage. Scope, runtime-interruption authorization, unknown-outcome non-replay, and source/artifact provenance gates still apply.
3. Implement the quickest deterministic unit, component, constrained-heap, or fixture-contract regression that exercises each distinct cause. Run the same test against the preserved unfixed implementation for actual RED and against the fix for GREEN; if constructed after the fix works, obtain RED in an isolated owned copy without reverting shared or live native state. Retain both outcomes and add the test to the routine suite identified in `test-matrix.md` before integration, push, or completion. Proposed coverage alone does not satisfy the requirement.
4. Record the failure-to-test mapping and exact commands in the task evidence/WIP, including OS-only gaps. Keep and rerun the original native scenario on the fixed artifact; a host regression does not replace native verification.

Apply the same approach to reproducible harness and infrastructure defects with script or workflow-contract tests. Do not count an opt-in native test skipped by ordinary host checks as the required quick regression.

For native acceptance work, each discovered failure must also improve the related
repository MCP workflow: add a causal preflight, reliable observation, targeted
diagnostic, or recovery guard alongside its quick regression. Preserve the actual
product fix and native scenario. Use named SSH profiles from the private ignored
`.vm-hosts.local.json`; never copy credentials into tool arguments, tracked code,
logs, or evidence. Unknown remote outcomes remain unknown until observed, and must
not trigger an automatic retry of installation or runtime mutations.

Apply `TEST-002` to every platform's native acceptance: first prove each complete
scenario directly through SSH, CLI, ADB or native tools, including its applicable
success, failure, recovery and cleanup cases. Integrate that procedure into MCP
only after native success, then repeat the same cases through MCP with matching
source/artifacts. Repeated MCP failures return to direct diagnosis. Keep direct
and MCP evidence separate; a passing local collector or read-only diagnostic
does not close the product scenario. MCP remains the repository startup and
delivery entry point. Ownership, protected data, causal regressions, durable
original handles and unknown-outcome guards apply in both native phases.

Apply `TEST-007` to order that work: give each new or changed row one direct
first-contact run as soon as its tooling exists, on a non-evidence build of the
candidate such as its push-build package, fix what it finds, and land tool
patches between those runs. Run the rows that count as evidence only in one
final sweep, after the candidate package and the scenario tooling are frozen and
`sweep-eligibility` admits the candidate set at HEAD: every row directly, and
through MCP only the representative route shapes `TEST-002` names, with the
others proven by their MCP admission dry run. Land no change while an MCP twin
is in flight; afterwards only changes outside the executed inputs `TEST-007`
names keep the records current.

Apply `TEST-003` to schedule independent native scenarios in parallel. Give every
worker exact file ownership and each guest/emulator one operator. Use separate
verified guests or explicitly isolated state for interfering cases; serialize
installer, machine-wide VPN, reboot and recovery work within the same guest.
The sole operator may batch independent read-only observations. Check resource
capacity and retain each original handle and cleanup owner. Do not clone a live
unverified baseline, share mutable acceptance state, drop cases or restart an
unknown operation to increase concurrency.

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
