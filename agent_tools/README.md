# VPN Control Agent Tools

This directory contains the repository-local MCP workflow server and its documentation RAG indexer. These tools are for coding agents and maintainers; they are not part of the VPN Control application or its user setup.

## Automatic MCP Setup

Codex and Claude Code start the same STDIO server, tools, and safety boundaries.

### Codex

Run `python3 agent_tools/configure_codex.py` once in a new checkout before opening its Codex session. The tracked `agent_tools/codex-config.toml.in` template generates ignored `.codex/config.toml`, deriving absolute launcher and working-directory paths from the checkout. Existing local settings are preserved; `--replace` makes a private ignored backup before regeneration. Rerun after moving the checkout. The generated configuration starts `agent_tools/mcp_server.sh` for trusted checkouts. The launcher:

1. Locates Python 3.
2. Creates the ignored `.agent_venv/` environment when needed.
3. Installs `requirements-mcp.txt` only when the requirements hash changes or `mcp` is missing.
4. Starts the STDIO server with all operational logging on stderr so the protocol on stdout remains clean.

Do not commit `.agent_venv/` or `.rag_index/`. Restart the Codex session after changing project MCP configuration because a running session does not reload its MCP inventory.

### Claude Code

The tracked `.mcp.json` defines the `vpn_control` STDIO server and `CLAUDE.md` imports `AGENTS.md` with a literal `@AGENTS.md` line. Claude Code sets `CLAUDE_PROJECT_DIR` in the server process; the inline guard reads that runtime value, requires an absolute checkout root containing `.mcp.json` and `agent_tools/mcp_server.sh`, and then runs that launcher. It never falls back to the working directory or another checkout, and it fails with a `[vpn-control MCP] CLAUDE_PROJECT_DIR` message on stderr otherwise. Claude does not expand `${CLAUDE_PROJECT_DIR}` in project `args`, so the guard must not use brace syntax.

The tracked `.claude/settings.json` approves only `vpn_control` (`enabledMcpjsonServers`), allows only `mcp__vpn_control__*`, and sets `MCP_TIMEOUT=300000` (300-second startup). `.mcp.json` sets a 3,600,000 ms per-tool `timeout` and `alwaysLoad: true`, so the tools are not deferred behind tool search. Claude waits at most about five seconds for `alwaysLoad` tools before the first turn; a warm launcher answers in under a second, while a cold `.agent_venv/` bootstrap finishes in the background within the startup timeout. Project settings apply only after the workspace trust prompt; no hooks or permission bypass are configured, so startup never fetches, switches branches, or runs checks.

Check the connection with `/mcp` and loaded instructions with `/context` or `/memory`. Restart the session after changing `.mcp.json`, `.claude/settings.json`, or the launcher. Personal overrides belong in ignored `.claude/settings.local.json` and a root CLAUDE.local.md file.

If the desktop app does not export a toolchain path, put it in ignored
`.codex/build-env.local.json`, for example `{"JAVA_HOME":"/absolute/path/to/jdk"}`.
`ANDROID_HOME` is also accepted. The file must be a regular, owner-only file
(mode `0600` on POSIX); values must name existing absolute directories, and
`JAVA_HOME` must contain executable `bin/java`. Managed MCP child commands
read this file for each invocation, so a running server picks up changes
without a restart. The file is parsed as JSON and is never executed as shell
code. On Windows, an existing local file is rejected until an ACL-aware reader
is available. Keep machine-specific paths out of tracked MCP configuration.

## Mandatory Lifecycle

Agent startup, commit and exact SHA CI follow this lifecycle. Its [full procedure](../agent_docs/tools/lifecycle-and-api.md#mandatory-lifecycle)
preserves source custody, check leases and exact-SHA delivery guards.

For implementation, testing, release, or commit work:

1. Call `prepare_start(task, area)` before normal repository inspection, edits, or tests. It fetches `origin/dev` and `origin/main`, selects and safely fast-forwards the `dev` development branch only when the worktree is clean, and rebuilds the local docs index.
2. Read the returned instruction files. Use `docs` and `change_impact` instead of broad exploratory searches when repository documentation can answer the question.
3. Use `workflow_status` while working to re-check routing, dirty paths, index freshness, and validation requirements.
4. Run `version_bump` once after the final non-documentation content change, then run `run_checks(level="prepush")`. A successful check writes a content fingerprint to `.rag_index/prepush_receipt.json`. Every pass runs all independent checks and records any failures beside that receipt; after fixing them, `run_checks(level="failed")` reruns exactly those failures, and the pre-push tier refuses until they pass (`TEST-006`).
5. Use `git_workflow` to push `dev` or to resume checks for a full commit SHA. `action="checkpoint"` is an explicit intermediate option for this parity continuation: it requires the same fresh pre-push receipt, safe explicit commit paths and clean post-commit worktree, then pushes to `origin/dev` and returns the exact SHA with `requiredWorkflowsVerified: false`. Run `action="checks"` for the final pushed SHA; it queries only runs attached to that SHA and requires every development workflow in `.github/required-workflows.json` to succeed.
   Failed-log excerpts select error context and the final summary from the complete
   command output, then enforce an 8,000-character response bound. If more context
   is needed, use the returned exact run ID to inspect its failed log.
   Windows package CI also runs the native check-lease and receipt-fingerprint
   tests; Linux agent-tool discovery alone cannot verify Windows ACL/lock behavior.
6. Use `release_workflow` only after an explicit user release command. It fast-forwards `main` from verified `dev`, starts agent-owned visual review, gates on exhaustive VPN integration plus the exact-SHA visual receipt/status, and dispatches the manual publisher.

Managed checks hold an exclusive checkout lease for execution and receipt
publication. A concurrent caller returns busy before running checks; observe the
existing run rather than deleting the persistent lock file. Dry runs do not
acquire a lease. Direct Gradle commands still require a single coordinator.
If a check runner exits while its child survives, reobserve that child before
starting another build; the lease cannot establish an orphan's terminal outcome.
Pre-push captures source content before and after checks and refuses to publish
a new receipt when content changes during validation. Freeze edits, wait for the
current run to exit, then run a fresh pre-push tier.

The managed agent stage runs the SSH-close gate alone first, then the two halves
of the hosted CI partition without it (each half is the hosted shards of one
index parity), each as its own command with the 50-minute bound; a failed
gate stops what follows. A timed-out command receives SIGTERM, so the agent test
runner stops its worker sessions before the next command starts; SIGKILL follows
only after a 30-second grace, and only the original timeout is reported.
`run_checks(level="failed")` reruns a timed-out, unparsed or import-failed agent
command once without removed modules: the gate alone if recorded, then the rest
by index parity in the sorted union of the current selection and those modules.
For an unchanged selection a recorded half therefore reruns as itself; a
changed selection regroups it, and regrouping runs the selector once per pass.
Recorded failed modules still narrow their rerun.

Managed checks also compare the loaded runner, build-environment, checkout-lease
and output-retention source digests with current files before inspection or a
dry-run plan, between commands and before receipt construction. Changed or
unreadable source refuses the check with a finite `check-source` blocker. Use
`./agent_tools/mcp_tool.sh run-checks --level prepush` or restart MCP. An older
daemon cannot acquire this guard retroactively. The hashes assume trusted fresh
startup; they detect changes and do not make receipt publication atomic.

The actual OpenSSH option-parser unit tests use `openssh_option_probe` for
config-free local `ssh -G` queries only. It keeps the five-second per-attempt
deadline, permits two attempts only on `TimeoutExpired`, retains the original
exceptions/partial streams, and waits for the original owned parser to be reaped
before a successor. Exhausted timeouts and nonzero/semantic failures still fail.
The helper rejects connections, remote payloads and executable configuration
hooks. It is not used to retry SSH transport or native mutations. Qualified
macOS stacks locate one Session parser stall in default service-name lookup
awaiting Directory Services; the host latency trigger remains unknown. Actual
parser fixtures use documentation numeric endpoints before real argv constructors
and explicit original ports, retaining assertions and real `ssh -G` execution.
The declared service-boundary regression does not claim remote SSH/auth repaired.

`prepare_start` deliberately blocks when a fetch fails, branches diverge, a dirty branch other than `dev` would need switching, or a dirty behind-`dev` worktree would need pulling. Resolve the reported condition explicitly and rerun it.

## MCP Tools

The server is fixed to this checkout; there is no root parameter. Use these
lifecycle tools before entering a platform recipe.

| Tool | Purpose |
| --- | --- |
| `prepare_start(task, area=None)` | Safe fetch/sync, branch verification, RAG rebuild and task routing. |
| `docs(query, mode="search", top_k=3)` | Grounded local search with source and line citations. |
| `change_impact(task, area=None, paths=None)` | Focused owners, changed paths, safety and mapped checks. |
| `workflow_status(task=None, area=None, instructions_read=False)` | Worktree, required reading, index freshness and check receipt. |
| `run_checks(area="auto", level="focused", dry_run=False)` | Focused checks, the recorded failed checks (`level="failed"`), or the complete managed pre-push tier. |
| `version_bump(summary=None, change_type="code", dry_run=False, force_release=False, target_version=None)` | Required non-documentation note; unified base-20 metadata roll. |
| `git_workflow(action, message=None, paths=None, sha=None)` | Explicit safe paths, dev push and exact-SHA CI; checkpoint defers CI. |
| `release_workflow(action="status")` | Explicit-release-only main merge, readiness and publisher gate. |
| `visual_workflow(action, target_sha=None, platforms=None, release=False, post_status=False)` | Exact-SHA agent visual review. |
| `visual_review(target_sha, platform, scene_id, verdict, notes=None)` | Verdict after opening the captured scene. |
| `ssh_workflow(action, host=None, identity=None, timeout_seconds=15)` | Strict configured-route observations and owned channel operations. |
| `vm_workflow(action, inputs)` | Strict typed native helpers; evidence scope never implies action authority. |

[Full API, retained-channel schemas and keeper custody](../agent_docs/tools/lifecycle-and-api.md#mcp-tools)
include all action-specific fields, timeout bounds and refusal rules.
Commit paths reject absolute paths, traversal, pathspec magic, globs, generated
output, agent/runtime state and native binaries. Explicit paths must cover every
current change; preserve unrelated work and resolve ownership before delivery.

### Readiness and retained remote work

`ssh_workflow` exposes `readiness-status` and `readiness-ensure` with a configured
`host` and `identity={"operationId": "<canonical UUID>"}`. Status only observes;
ensure admits bounded recovery to that same trusted target. Status includes a
bounded local `recoveryStatus` view of original recovery IDs, operation IDs,
actions, consumed attempts and retained outcomes. An unavailable or uncertain
journal remains explicit and grants no replay authority. Ordinary remote
actions use the shared admission before generating commands and carry its
connection/boot/account identity through dispatch. Local metadata and local
status/collection do not recover a connection. SSH idle persistence is five
hours in production; expiry regressions use short intervals.

`vm_workflow` exposes `readiness-providers` with empty `inputs`, and
`readiness-status`/`readiness-ensure` with
`inputs={"fixtureId": "<registered fixture>", "operationId": "<canonical UUID>"}`.
Clients select a privately registered, directly qualified existing instance;
public inputs cannot assert ownership or supply an executable, VM path or
credential. VM readiness status includes the same local recovery view.
Headless fixtures require their guest agent. Desktop fixtures also
require the intended ordinary session and usable display. Capability inspection
distinguishes a provider's potential from available qualified recovery.
A registration whose pinned sources or lifecycle spec changed since it was
qualified returns `fixture_registration_stale`: re-enroll the fixture against the
current source. Other unclassified failures stay `readiness_admission_unavailable`.

`readiness-reboot` takes the same two inputs and requests one graceful reboot
of an already running, positively idle fixture. It checks reservations, running
and UNKNOWN jobs, installers, lifecycle phases, other operators and protected
processes. Repeating the operation observes its original reboot. This action
does not start or resume a stopped or paused fixture.

The same registered identities admit `readiness-lease-acquire` (also
`ttlSeconds`), `readiness-lease-status` and `readiness-lease-cancel`. Expiry,
cancellation and fresh-client reconciliation observe the original lease owner
and restore its original settings. Restoration and the owner's terminal receipt
are separate facts; continue status until both are proved. Credentials are never
included in these public payloads.

New long-running Python jobs use `ssh_workflow`'s `program-start` with
`transfer={"operationId": "<canonical UUID>", "program": <validated program>}`.
`program-status`, `program-collect` and `program-reconcile` take only that
operation ID in `identity` and the original host. Status and collect are local;
reconcile may restore transport to observe the original remote owner. Legacy
foreground jobs cannot acquire durable ownership retroactively. UNKNOWN never
authorizes a replacement job.

Registered POSIX guest fixtures expose the finite harmless counter through
`guest-program-start`, with `inputs` containing `fixtureId`, `operationId`,
`count` and `intervalSeconds`. `guest-program-status`, `guest-program-reconcile`
and `guest-program-collect` take just the first two fields. Android has the same
four `android-program-*` actions with a fixed counter and those two fields for
every action. These routes accept no source, executable or guest path. Status
and collect use retained local observations; reconcile observes the original
owner and may restore transport without powering or unlocking its VM.

The fresh client `agent_tools/ssh_program_mcp_client.py` follows a start through
same-operation status/reconciliation/collection automatically. Use `--host` for
SSH jobs or `--fixture` for registered guest/Android jobs, with a bounded
`--follow-seconds` budget (default 180; `--no-follow` disables it). Retained RPC
and stream records distinguish a lost response from a proven unsubmitted
operation. Typed `nextAction` responses contain only fixed public routes and
the original identity. See the [infrastructure ledger](../agent_docs/tool-recovery-ledger.md)
for source-bound provider acceptance and remaining blockers.

## Command-Line Fallback

The same operations are available without MCP through `agent_tools/mcp_tool.sh`:

```bash
./agent_tools/mcp_tool.sh prepare-start "update settings copy" --area localization
./agent_tools/mcp_tool.sh docs "which checks cover localization?" --mode ask
./agent_tools/mcp_tool.sh change-impact "update settings copy" --area localization
./agent_tools/mcp_tool.sh workflow-status --task "update settings copy" --instructions-read
./agent_tools/mcp_tool.sh version-bump --summary "Clarified settings copy" --change-type code
./agent_tools/mcp_tool.sh run-checks --level prepush
./agent_tools/mcp_tool.sh git-workflow checks --sha <full-commit-sha>
./agent_tools/mcp_tool.sh release-workflow status
./agent_tools/mcp_tool.sh visual-workflow status --target-sha <full-commit-sha>
./agent_tools/mcp_tool.sh visual-review <sha> <platform> <scene-id> pass
```

Use the CLI fallback only when the MCP transport is unavailable. It returns the same structured JSON and a nonzero status for blockers or failed checks.

## Documentation RAG

Archives under `agent_docs/archive/` and retained `*-history.md` files are classified
as historical. Ordinary queries prefer current guidance; explicit history/archive
queries still retrieve the preserved records. A stale classification-version index
rebuilds automatically. After source edits, use a fresh CLI process for verification
if the existing MCP daemon still has the earlier indexer imported.

`docs_assistant.py` indexes `AGENTS.md`, the public `README.md` and `docs/`, all `agent_docs/`, and this file. Markdown is split under its heading hierarchy and stored with source type, relative path, and line metadata. Search uses a local BM25-style scorer plus small path/source boosts; no document content leaves the machine and no embedding service or API key is needed.

The index is rebuilt when its source hash manifest is missing or stale:

```bash
python3 agent_tools/docs_assistant.py index
python3 agent_tools/docs_assistant.py search "desktop lifecycle"
python3 agent_tools/docs_assistant.py ask "what must happen after push?"
```

The index is a navigation aid. `AGENTS.md` remains the agent hard-rule layer, `agent_docs/contracts.md` owns product invariants, and focused subsystem docs own procedures and implementation maps.

## Tests

Use [Validation Tiers and Quick Mapping](../agent_docs/test-matrix.md) for touched
paths. Prose-only work runs docs hygiene and whitespace checks; it does not run
agent-tool tests or require a version note. Tool or fixture changes use:

```bash
python3 agent_tools/affected_agent_tests.py --run
```

Unknown comparison baselines and dependency mappings refuse. Do not substitute
HEAD, omit consumers, or use an unrequested full-suite fallback. Full selector,
parallelism, output-custody and receipt rules remain in
[the test procedure](../agent_docs/tools/lifecycle-and-api.md#tests).

Fast Checks uses six fresh Ubuntu checkouts (`CI_SHARD_COUNT`) with explicit
`--shard-index 0..5 --shard-count 6` arguments after complete global selection;
each hosted shard's share of the last measured selection must stay within 60%
of its 50-minute phase bound. Its optional `--ci-evidence-dir` records bounded
public progress and requires `--run`, an explicit shard and a new output
directory. Pooled worker evidence requires POSIX; the final coverage job
verifies every successful current-attempt receipt and their exact disjoint
union. Private worker output stays local. Managed checks run the SSH-close gate
alone, then the two halves of the same partition without it; Windows
`--include` retains its existing path, and managed prepush writes its own
content-bound receipt.

## Recipe Index

| Need | Focused procedure |
| --- | --- |
| Startup, API, retained channels, keeper, checks and delivery | [Lifecycle and API](../agent_docs/tools/lifecycle-and-api.md) |
| Native input, source context, private hosts, credentials and fixture preparation | [Platform evidence](../agent_docs/tools/visual-and-platform-evidence.md) |
| Typed acceptance adapters, artifact/matrix custody and fixed historical CP117 recovery | [Parity recipes and historical reconciliation](../agent_docs/tools/parity-worker-recipes.md) |
| Current GUI/CLI parity next action and original operation/lease custody | [Current ledger](../agent_docs/work-in-progress.md), [active brief](../agent_docs/parity-solo-plan.md) |
| Exact full pre-migration tool guide | [Historical snapshot](../agent_docs/archive/parity/2026-10-14/tool-guide-original.md) |

Read the selected recipe's complete admission and cleanup guards before acting.
A stored receipt, source-only/component result or passing test count proves only
its stated scope. Unknown original outcomes retain their original identity and
raw evidence; neither a timeout nor a moved document permits replay or lease
release. Never interrupt a VPN/runtime without explicit user authorization.
Historical commands retain their source/artifact and credential/trust boundaries.
The current brief supplies task scope; contracts remain the global authority.

## Original Section Routes

These short headings preserve inbound anchors from the original tool guide.
Their detailed content moved without dropping schemas, evidence or safety guards.
Historical counts and fixed campaign actions remain source-bounded references.

### Windows retained input observer

[Full procedure](../agent_docs/tools/visual-and-platform-evidence.md#windows-retained-input-observer).

### Native Acceptance Execution

[Full procedure](../agent_docs/tools/visual-and-platform-evidence.md#native-acceptance-execution).

### Fixed Linux engineering source context

[Full procedure](../agent_docs/tools/visual-and-platform-evidence.md#fixed-linux-engineering-source-context).

### Collector uncertainty and local observer loss

[Full procedure](../agent_docs/tools/visual-and-platform-evidence.md#collector-uncertainty-and-local-observer-loss).

### Early SSH close dependency check

[Full procedure](../agent_docs/tools/visual-and-platform-evidence.md#early-ssh-close-dependency-check).

### Selected Arch route for nested guests

[Full procedure](../agent_docs/tools/visual-and-platform-evidence.md#selected-arch-route-for-nested-guests).

### Fixed Linux GUI lifecycle recipe

[Full procedure](../agent_docs/tools/visual-and-platform-evidence.md#fixed-linux-gui-lifecycle-recipe).

### Installer collection diagnostics

[Full procedure](../agent_docs/tools/visual-and-platform-evidence.md#installer-collection-diagnostics).

### Receipt-bound channel keeper

[Full procedure](../agent_docs/tools/lifecycle-and-api.md#receipt-bound-channel-keeper).

### Shared keeper helpers and routine promotion

[Full procedure](../agent_docs/tools/lifecycle-and-api.md#shared-keeper-helpers-and-routine-promotion).

### Other MCP tools

[Full procedure](../agent_docs/tools/lifecycle-and-api.md#other-mcp-tools).

### Private Native Hosts And VM Workflows

[Full procedure](../agent_docs/tools/visual-and-platform-evidence.md#private-native-hosts-and-vm-workflows).

### Fixed Secure Boot firmware prerequisite

[Full procedure](../agent_docs/tools/visual-and-platform-evidence.md#fixed-secure-boot-firmware-prerequisite).

### Fixed swtpm integrity repair for the Windows fixture

[Full procedure](../agent_docs/tools/visual-and-platform-evidence.md#fixed-swtpm-integrity-repair-for-the-windows-fixture).

### Fixed Windows credential-validity probe

[Full procedure](../agent_docs/tools/visual-and-platform-evidence.md#fixed-windows-credential-validity-probe).

### Fixed Windows credential recovery

[Full procedure](../agent_docs/tools/visual-and-platform-evidence.md#fixed-windows-credential-recovery).

### Owned Android stale-proxy recovery

[Full procedure](../agent_docs/tools/visual-and-platform-evidence.md#owned-android-stale-proxy-recovery).

### Configured guest routes

[Full procedure](../agent_docs/tools/visual-and-platform-evidence.md#configured-guest-routes).

### Native artifact, bundle, and environment helpers

[Full procedure](../agent_docs/tools/visual-and-platform-evidence.md#native-artifact-bundle-and-environment-helpers).

### Fixed CP117 loopback forward

[Full procedure](../agent_docs/tools/visual-and-platform-evidence.md#fixed-cp117-loopback-forward).

### Durable fixed-scenario execution

[Full procedure](../agent_docs/tools/visual-and-platform-evidence.md#durable-fixed-scenario-execution).

### Reusable native acceptance orchestration

[Full procedure](../agent_docs/tools/parity-worker-recipes.md#reusable-native-acceptance-orchestration).

### Compact guidance and failure evidence

[Full procedure](../agent_docs/tools/parity-worker-recipes.md#compact-guidance-and-failure-evidence).

### Nested SSH connection recovery

[Full procedure](../agent_docs/tools/parity-worker-recipes.md#nested-ssh-connection-recovery).

### Read-only Android observation

[Full procedure](../agent_docs/tools/parity-worker-recipes.md#read-only-android-observation).

### Verified fixture staging

[Full procedure](../agent_docs/tools/parity-worker-recipes.md#verified-fixture-staging).

### Fixed continuation acceptance adapters

[Full procedure](../agent_docs/tools/parity-worker-recipes.md#fixed-continuation-acceptance-adapters).

### Fixed CP117 retirement recovery

[Full procedure](../agent_docs/tools/parity-worker-recipes.md#fixed-cp117-retirement-recovery).

### Fixed c32 historical baseline admission

[Full procedure](../agent_docs/tools/parity-worker-recipes.md#fixed-c32-historical-baseline-admission).
