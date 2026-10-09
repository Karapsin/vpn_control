# VPN Control Agent Tools

This directory contains the repository-local MCP workflow server and its documentation RAG indexer. These tools are for coding agents and maintainers; they are not part of the VPN Control application or its user setup.

## Automatic MCP Setup

Run `python3 agent_tools/configure_codex.py` once in a new checkout before opening its Codex session. The tracked `agent_tools/codex-config.toml.in` template generates ignored `.codex/config.toml`, deriving absolute launcher and working-directory paths from the checkout. Existing local settings are preserved; `--replace` makes a private ignored backup before regeneration. Rerun after moving the checkout. The generated configuration starts `agent_tools/mcp_server.sh` for trusted checkouts. The launcher:

1. Locates Python 3.
2. Creates the ignored `.agent_venv/` environment when needed.
3. Installs `requirements-mcp.txt` only when the requirements hash changes or `mcp` is missing.
4. Starts the STDIO server with all operational logging on stderr so the protocol on stdout remains clean.

Do not commit `.agent_venv/` or `.rag_index/`. Restart the Codex session after changing project MCP configuration because a running session does not reload its MCP inventory.

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

For implementation, testing, release, or commit work:

1. Call `prepare_start(task, area)` before normal repository inspection, edits, or tests. It fetches `origin/dev` and `origin/main`, selects and safely fast-forwards the `dev` development branch only when the worktree is clean, and rebuilds the local docs index.
2. Read the returned instruction files. Use `docs` and `change_impact` instead of broad exploratory searches when repository documentation can answer the question.
3. Use `workflow_status` while working to re-check routing, dirty paths, index freshness, and validation requirements.
4. Run `version_bump` once after the final non-documentation content change, then run `run_checks(level="prepush")`. A successful check writes a content fingerprint to `.rag_index/prepush_receipt.json`.
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

`prepare_start` deliberately blocks when a fetch fails, branches diverge, a dirty branch other than `dev` would need switching, or a dirty behind-`dev` worktree would need pulling. Resolve the reported condition explicitly and rerun it.

## Native Acceptance Execution

Follow TEST-002 and TEST-003 in `agent_docs/contracts.md` on Windows, Android,
Linux and macOS. Prove each complete native scenario directly with SSH, CLI, ADB
or native tools, including applicable failure, recovery and cleanup cases. After
it passes, integrate the procedure into MCP and rerun those same cases against
matching source/artifacts. Repeated MCP failures return to direct diagnosis.
Local collector tests and successful diagnostics do not close product scenarios.

Parallelize independently owned scenarios within verified resource capacity.
Each guest/emulator has one operator; each file has one writer. Use separate
verified guests or isolated state for interfering operations. Installer,
machine-wide VPN, reboot and recovery work sharing a guest serialize; the sole
operator may batch independent read-only observations. Retain original handles,
raw evidence and cleanup ownership, and preserve unknown outcomes without replay.
MCP remains the repository startup and delivery entry point.

### Installer collection diagnostics

`android_installer_asset_collection` retains bounded schema-2 terminal diagnostics
alongside the original streams. Unobserved process birth and signal facts remain
null; diagnostics confer no admission, replay or native acceptance authority.
The collector attempts both stream publications, stream closes, the exit journal
and directory sync even when an earlier cleanup step fails. Primary failures and
finite secondary cleanup stages remain separate.

`android_installer_direct_transport` preserves the original local process,
stream hashes, EOF and return code when post-collection source checks or result
publication fail. A validated original remote PID is retained where observed.
These UNKNOWN receipts do not authorize another submission. The direct module
and collector primitive are not the MCP `android-installer-dispatch-*` route;
complete direct native proof and explicit route integration remain required.

Focused coverage is in `test_android_installer_asset_collection`,
`test_android_installer_terminal_diagnostic`,
`test_android_installer_collect_closeout` and
`test_android_installer_direct_postcollection`. Ordinary agent-tool discovery,
managed prepush and Fast Checks include these modules. POSIX-only diagnostic
controls retain their platform skips; they do not prove Windows native behavior.

## MCP Tools

`ssh_workflow(action="connection-channel-prepare", host="archlinux", identity={"correlationId":"<canonical UUID>"})` creates one isolated configured two-hop connection channel. `connection-channel-status` accepts the same identity and only observes it. `connection-channel-ensure` accepts the identity plus an optional exact `receiptSha256`; it explicitly renews only after positive channel end. These connection-only actions accept no command, path, transfer or device fields. They preserve unknown correlations, return finite phases, hide private route options and never replay application jobs. Current selection publication integration and native equivalence remain pending. A channel UNKNOWN never authorizes another launch: preserve its correlation and observe or diagnose that same channel. Snapshot refusal is not an authentication failure. Use the fresh `mcp_tool.sh ssh-workflow <action> --host archlinux --identity-file <local JSON>` fallback while the running server has cached predecessor code.

### Receipt-bound channel keeper

The three keeper actions use `host="archlinux"` and reject command, path,
transfer, device and extra identity fields. The correlation is the canonical UUID
of an already admitted channel. They never prepare or renew a channel, start a
new master, or replay an application job.

| Action | Exact identity and timeout | Result |
| --- | --- | --- |
| `connection-channel-keeper-source` | `{correlationId}`; `timeout_seconds` in `1..60` | Create one source manifest for the fixed public keeper dependencies; return `sourceManifestSha256`. This does not admit a channel. |
| `connection-channel-keep` | `{correlationId, receiptSha256, sourceManifestSha256}`; `timeout_seconds=1800` | Start one local keeper bound to that exact existing channel receipt and source manifest. |
| `connection-channel-keep-status` | The same three identity fields; `timeout_seconds` in `1..60` | Observe only the original keeper intent, process identity and protected terminal result; never start or replay it. |

`receiptSha256` is the exact admitted READY receipt, not a branch, artifact or
remaining-time claim. Supply identity through the CLI `--identity-file` when
using `mcp_tool.sh ssh-workflow <action> --host archlinux`; the keep action also
requires `--timeout-seconds 1800`.

The fixed keeper observes the same channel every 15 seconds, for at most 1800
seconds and 120 queries. A gap over 20 seconds stops it, and the final 35 seconds
are reserved rather than starting another query. It retains the original local
PID, birth and session identity, each query's raw evidence before parsing, and
its terminal result. A durably classified nonblocking configuration-lock busy
observation may continue within this same deadline; it remains UNKNOWN until a
later actual READY observation. Other UNKNOWN outcomes stop the keeper.
Borrowers still need their freshest actual READY; keeper completion, a previous
READY or remaining lifetime does not authorize a native action.

The MCP call is synchronous. Its existing child supervision has an 1845-second
timeout around the fixed 1800-second loop. This allowance does not prove survival
of an MCP disconnect or server death, or bound kernel scheduling and I/O. A lost
response, timeout or missing terminal record remains UNKNOWN: preserve the
original identity and use `connection-channel-keep-status`. A consumed keeper
intent cannot launch again. Neither observing nor completed status grants replay,
channel admission or native acceptance authority.

### Shared keeper helpers and routine promotion

The owning child collector, SDK
process/receipt custody, SDK client, byte delivery accounting and stdio relay
use five shared modules: `ssh_keeper_process_owner`, `ssh_keeper_sdk_custody`,
`ssh_keeper_mcp_client`, `ssh_keeper_mcp_delivery` and `ssh_keeper_mcp_relay`.
The owning caller and positive controls must use these same implementations.
These helpers add no MCP action or channel authority.

The routine suite contains 17 controls: three real harmless-child custody
regressions, five SDK accounting/forwarding controls and five controlled SDK
process-topology cases, plus four independent consumer actor checks. Consumer
checks verify each original process separately; they do not require the SDK and
keeper to share a birth or session and do not grant channel admission.
Authenticated historical source specimens preserve the
original REDs; they are test fixtures, never production source or native receipt
adoption. The tests require no ignored source loader or private capture. Missing
SDK or required journal/process capabilities have explicit skips; the three
pure delivery-accounting controls remain portable.

Planned requests, attempted SDK calls, fully forwarded frames and actual server
execution are separate facts. A topology control or source-local GREEN does not
complete direct or MCP app-update acceptance, prove current source/artifact
equivalence, or establish CI success. Retain the original process, raw evidence,
unknown-outcome non-replay and fresh borrower admission requirements above.

### Other MCP tools

`vm_workflow(action="android-api35-remaining-proxy-status", inputs={})` performs
only a fresh read of the fixed completed API35 cleanup0670. It verifies the
original terminal bytes and current stopped owner, settings and Binder state.
Its finite public result grants no installer, replay or product acceptance
authority. Any input field is rejected; full transport evidence stays private.

`vm_workflow(action="android-coldboot-product-api29-observe", inputs={})`
reads the explicitly admitted original API29 emulator generation, installed APK,
full staged CLI manifest, current controller, operations and routing. It requires
stable stopped runtime and preserves old unknown operations. Detailed envelopes
remain in owner-only observation receipts; public output reports bounded fields
and the receipt digest. `productAdmitted` covers these current getters only;
`acceptanceComplete` remains false. It cannot launch, install, reboot, replay or
stop a guest runtime. Source or owner drift yields a diagnostic-only result.

`vm_workflow(action="android-api35-large-routing-observe", inputs={})`
performs two fixed read-only routing reads against the admitted API35 generation.
Each read allows300 seconds publicly,330 seconds for collection and32MiB of
output; the whole transport allows1200 seconds. All routing data must match,
excluding only generated `exported_at`. Owner/revision, stopped runtime,
operations, APK and full CLI-stage generations must remain stable. Private
chunk receipts retain full replies and partial failures. Public success proves
`currentRoutingVerified` only; product and acceptance completion remain false.

The fixed Linux packaging actions `linux-package-tmux-availability`, `-resource-prepare`,
`-preflight`, `-start`, `-status` and `-collect` use a dedicated source-bound tmux worker and
immutable result spool. See [ssh-tmux-sessions.md](../agent_docs/ssh-tmux-sessions.md)
for input schemas, one-submit fences and verified collection. A generic command,
interactive attach or public session release is not exposed. Original86 direct
build/collection and equivalent MCP collection are proven; new-job resource
admission and deliberate disconnect acceptance remain separate gates.


`vm_workflow(action="android-obsolete-consent-denial-collect",
inputs={"denialId": "<denial UUID>"})` verifies and collects one completed,
negative-only obsolete dialog cleanup. It accepts no commands or paths, does
not repeat the Cancel action, and releases only its own proved local claims.
The finite proof retains the original unknown outcome and requires UI absence,
absent VPN permission and stopped runtime. Raw evidence remains private. The
direct native flow is proved before this MCP route is retested.

`vm_workflow(action="android-endpoint-mount-diagnostic-collect", inputs={"correlationId": "<endpoint UUID>", "diagnosticCorrelationId": "<diagnostic UUID>"})`
collects one fixed retained mount diagnostic using8KiB chunks through the
unchanged16KiB transport limit. Original intent, mount plan, stage, failure and
diagnostic generations remain pinned throughout. It preserves private partial
copies without overwriting. The finite result exposes only verified SHA256 and
byte count; it grants no mount, cleanup, installer or replay action. Direct native
collection has succeeded; fresh native MCP collection remains a verification gate.

`vm_workflow(action="android-consent-grant-prompt-collect", inputs={"correlationId": "<original UUID>", "observationId": "<diagnostic UUID>"})`
collects only the four fixed private prompt diagnostic artifacts through8KiB
chunks and the unchanged16KiB transport limit. It pins original record and
artifact generations before/after each chunk, writes create-only local600 files,
and preserves partial copies on unknown outcomes. Its finite MCP result exposes
completion and artifact count, never raw UI, operation payloads or private paths.
It cannot capture a new prompt, tap, replay ON, release claims or overwrite a
previous collection. Native MCP collection verification remains an acceptance
gate; the direct collector's success is recorded separately.

| Tool | Purpose |
| --- | --- |
| `ssh_workflow(action="connection-master-status", host="archlinux")` | Check the configured nested socket through the currently verified outer session, retaining bounded binary output. `socketState` distinguishes ready, absent, refused and unknown; refused leaves `nestedState` unknown and does not imply authentication failure. Finite `failurePhase` identifies an unproved boundary. No launch, replay, configuration change or native acceptance authority is granted. |
| `ssh_workflow(action="gateway-tmux-status-diagnostic", host="archlinux", identity={"correlationId":"…"})` | Read the exact existing gateway status with a finite failure phase. Original source and authority guards remain mandatory; unknown state grants no recovery. Raw errors and control paths stay private. |
| `ssh_workflow(action="connection-session-prepare", host="archlinux")` | Prepare or observe one private, source/config-bound outer gateway master for a configured nested route. A consumed unknown intent cannot launch another master. Existing native commands reuse the admitted socket with network fallback disabled. |
| `ssh_workflow(action="connection-session-status", host="archlinux", identity={"receiptSha256":"…"})` | Revalidate the exact existing master receipt without launching or sending a guest command. Use the digest returned by preparation; arbitrary identity fields are rejected. |
| `ssh_workflow(action="connection-session-close", host="archlinux", identity={"receiptSha256":"…"})` | Send one graceful control exit to the exact owned outer master. A durable intent fences the effect; unknown outcomes cannot replay. No guest command, signal, or VPN action is exposed. |
| `ssh_workflow(action="connection-session-close-status", host="archlinux", identity={"receiptSha256":"…"})` | Observe the original close history and require positive process and socket absence before reporting closed. Retirement remains a separate action. |
| `ssh_workflow(action="tmux-disconnect-probe", host="archlinux", identity={"hop":"gateway", "correlationId":"<new UUID>"})` | Run one fixed20-second inert job in a private tmux server, disconnect only its original local SSH client, and observe the same job from fresh clients. Hop is gateway or archlinux. No commands/paths/credentials, master control, package work, product acceptance or automatic replay. Unknown correlations remain consumed. |
| `ssh_workflow(action="gateway-tmux-reconciliation-status", host="archlinux")` | Read only the fixed original d606 publication and separate adoption records. No inputs, writes or remote queries; finite historical state only. Use the configured probe separately for current connectivity. |
| `ssh_workflow(action="gateway-tmux-availability", host="archlinux")` | Read tmux availability on the configured gateway. Availability does not grant launch or product acceptance authority. |
| `ssh_workflow(action="gateway-tmux-prepare" | "gateway-tmux-release" | "gateway-tmux-status", host="archlinux", identity={"correlationId":"…"})` | Prepare one dedicated foreground nested master, release its original anchored gate once, or observe it. Require a canonical UUID. Source/config/profile/process/socket authority is retained; unknown outcomes cannot replay. No command, credential or path overrides are exposed. Canonical recovery publication and inventory adoption remain separate coordinator steps. |
| `ssh_workflow(action="connection-session-retire", host="archlinux", identity={"receiptSha256":"…"})` | Archive the exact previously completed outer session only after positive process and socket absence. Preserve its full history; consumed retirement is status-only. Live, ambiguous and unknown startup sessions cannot retire. No signals or guest commands are sent. |
| `ssh_workflow(action="connection-session-retirement-status", host="archlinux", identity={"receiptSha256":"…"})` | Read the exact archived retirement receipt without probing a reused PID or modifying a new session. |
| `ssh_workflow(action="connection-nested-orphan-archive-status", host="archlinux", identity={"observationId":"0fb841fc-2f24-4eca-ae2b-6cc16f772f28","observationSha256":"522ffc5f5f1a9cb6160ffe5b1989c86837b5662ba6fed3fa869b4d9dd1f27069"})` | Read the immutable owned orphan archive receipt. This historical result does not revalidate current remote state. The corresponding archive action uses the same fixed proof and preserves the consumed one-shot fence; no signals or replay. |
| `ssh_workflow(action="android-availability", host="archlinux", device="api29")` | Classify configured ADB visibility, including a positively missing or offline device. `api35` is also supported. Optional identity `{"expectedBootId":"…"}` compares an explicitly known host boot. Availability never grants product or lifecycle admission. |
| `ssh_workflow(action="inventory", host=None, timeout_seconds=15)` | List private host aliases or run a bounded authenticated connectivity probe. |
| `ssh_workflow(action="forward-open" | "forward-status" | "forward-close", host="archlinux", identity=None)` | Open, observe, or close the one fixed CP117 loopback VNC forward. |
| `vm_workflow(action, inputs)` | Verify fixture bytes/preflight, maintain native artifact evidence, create fixed scenario bundles, or manage non-authorizing environment reservations. |
| `prepare_start(task, area=None)` | Safe fetch/sync, branch verification, RAG rebuild, and task routing. |
| `docs(query, mode="search", top_k=3)` | Search or produce a grounded extractive answer with file-and-line citations. |
| `change_impact(task, area=None, paths=None)` | Combine task routing, changed paths, RAG references, safety constraints, and checks. |
| `workflow_status(task=None, area=None, instructions_read=False)` | Show worktree state, required reading, RAG freshness, and check receipt state. |
| `run_checks(area="auto", level="focused", dry_run=False)` | Run focused checks or the repository's complete pre-push tier. |
| `version_bump(summary=None, change_type="code", dry_run=False, force_release=False, target_version=None)` | Add the required changelog note and atomically roll unified three-part version metadata at 10 notes or an explicit forced/targeted release. |
| `git_workflow(action, message=None, paths=None, sha=None)` | Commit explicit safe paths and push `dev`; `checkpoint` defers required CI until the final exact-SHA check. |
| `release_workflow(action="status")` | Explicit-release-only `merge-dev`, readiness, and publisher dispatch gate. |
| `visual_workflow(action, target_sha=None, platforms=None, release=False, post_status=False)` | Start, inspect, or complete an exact-SHA agent visual review. |
| `visual_review(target_sha, platform, scene_id, verdict, notes=None)` | Record the agent's verdict after opening a captured scene. |

The MCP server has no root parameter: all operations are fixed to this checkout. Commit paths reject absolute paths, traversal, pathspec magic, globs, generated output, agent state, runtime state, and native runtime binaries. A commit path list must cover every current change, preventing accidental partial staging of unknown work.

For the CP117 Windows update fixture, call
`vm_workflow(action="windows-fixture-server-acl-preflight", inputs=<exact server-start request>)`
before a fresh server start. It compares the staged fixture script hash with the
frozen Git source and requires the Windows-safe probe-directory creation and
exact ACL verifier. `blocked` or `unknown` prevents server reservation, lease
claim, and task creation. The fixed
`windows-fixture-server-probe-events-acl-diagnostic` observes the failed
`316e6189-5be0-4ea0-bca1-a3905816d815` attempt without returning raw SIDs.
The isolated `windows-fixture-acl-preflight` scratch exercise is scoped to QGA
SYSTEM and cannot establish original-user acceptance; use the source-bound
server gate for admission.

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

`docs_assistant.py` indexes `AGENTS.md`, the public `README.md` and `docs/`, all `agent_docs/`, and this file. Markdown is split under its heading hierarchy and stored with source type, relative path, and line metadata. Search uses a local BM25-style scorer plus small path/source boosts; no document content leaves the machine and no embedding service or API key is needed.

The index is rebuilt when its source hash manifest is missing or stale:

```bash
python3 agent_tools/docs_assistant.py index
python3 agent_tools/docs_assistant.py search "desktop lifecycle"
python3 agent_tools/docs_assistant.py ask "what must happen after push?"
```

The index is a navigation aid. `AGENTS.md` remains the agent hard-rule layer, `agent_docs/contracts.md` owns product invariants, and focused subsystem docs own procedures and implementation maps.

## Tests

Run the stdlib-only unit suite with:

```bash
python3 -m unittest discover -s agent_tools/tests -t .
```

The complete local pre-push tier is documented in `agent_docs/test-matrix.md` and is also encoded by `run_checks(level="prepush")`.

On supported POSIX hosts, each completed managed check retains exact stdout and
stderr under ignored `.rag_index/check-runs/<runId>/` before displaying bounded
excerpts. `completionOutput` reports byte counts, SHA256, receipt identity and
finite unittest failure identities; it does not expose raw bodies. Capsules are
private, create-once files with descriptor and named-generation custody. Retention
failure blocks check success even when the child exits0. Unsupported platforms
refuse private retention; there is no weak ACL fallback. Timeout/incomplete-child
results remain outside this completed-output guarantee. Focused capsules identify
the runner source; prepush capsules identify the complete repository fingerprint,
which is rechecked before the validation receipt is written.


## Private Native Hosts And VM Workflows

The staged Windows fixture-retirement routes and Android consent-grant,
permission-reset and runtime-acceptance routes use explicit public response
schemas in `native_parity_response_projection.py`. Correlations, fixed receipt
bindings, nested proof fields, state/boolean consistency and non-replay flags
must match. Malformed helper output or exceptions return a finite unknown
response without private fields or exception text. A valid tool response still
proves only its stated evidence scope; it does not promote an inert or historical
receipt into current native acceptance.

Store machine-specific connection details in `.vm-hosts.local.json` at the checkout
root. This file is ignored and rejected by managed staging. On POSIX it must be an
ordinary non-symlink file owned by the current user with mode0600. Native inventory
access on Windows fails closed pending ACL-safe handling; Windows guests remain
reachable from the supported POSIX coordinator. Never pass
passwords through MCP arguments or command-line flags. `identityFile` points to
existing private key material; optional `password` stays in this local file.

The version1 schema is `{ "schemaVersion": 1, "hosts": { "alias": { ... } } }`.
Each host has `host`, integer `port`, `user`, absolute `identityFile` and absolute
`knownHostsFile`. Host-key checking is strict; establish trusted keys separately.
A nested route additionally declares `transport: "nested"`, `gateway` (a direct
host alias), `remoteHostAlias` and an absolute `remoteControlPath`. Its known-hosts
path refers to the gateway filesystem. Connection details are not an authorization
to install, elevate, stop a VM, or affect a host VPN.

`ssh_workflow("inventory")` returns aliases only. `ssh_workflow("probe", host=...)`
executes a bounded read-only check and distinguishes authentication, host-key,
connection and timeout failures. It never retries a mutation. `job-status` observes an existing Linux job using
`identity: {jobId, pid, startTicks, receiptPath?}`; only a matching terminal receipt
establishes completion, and PID reuse or lost observation remains unknown. The CLI
accepts this mapping through `--identity-file`. No job-status action starts, stops
or retries remote work.

### Fixed Secure Boot firmware prerequisite

`vm_workflow("windows-vm-virt-firmware-install-start", inputs=...)` is the
single remote installer for the Windows Secure Boot VM prerequisite. It accepts
only `{host: "archlinux", correlationId: "<canonical lowercase UUID>",
timeoutSeconds: 10..300}` and installs only `virt-firmware=26.9-1`. Its status
counterpart accepts the same exact fields and only observes the durable local
intent plus the fixed package identity and integrity checks.

Before any start, call `windows-vm-virt-firmware-install-preflight` with a new
canonical correlation and the same fixed host/timeout fields. It performs no
credential read and returns only `ready`, `intent-existing`,
`signature-policy-rejected`, `credential-metadata-invalid`, or
`signature-policy-unavailable`, or `transport-unavailable`. The categorical
transport diagnostic identifies the local SSH, gateway SSH, nested SSH, remote
Python, and `pacman-conf` hop without exposing raw stderr. A status call with no durable intent returns
`intent-absent`; it does not contact the host or manufacture a remote `unknown`.

The start route reads the local ignored `.codex/arch-sudo.local` file. It must
be a nonempty regular non-symlink file owned by the current POSIX user with mode
`0600` and at most 512 bytes. The credential never enters MCP fields, SSH/shell
arguments, environment variables, journals, stdout, stderr, or public results;
it is supplied only over SSH stdin to the fixed remote `sudo -S pacman` command.
The `.codex` parent is opened as a non-symlink directory descriptor before the
credential is opened. Before the credential is read or sent, the fixed remote
`/usr/bin/pacman-conf --repo extra SigLevel` check requires a package signature
token (`Required` or `PackageRequired`) and trusted-key token (`TrustedOnly` or
`PackageTrustedOnly`), rejecting `Never`/`PackageNever`, optional signatures,
and `TrustAll`.
The remote transaction uses pacman's configured signature verification, then
checks `pacman -Q virt-firmware`, `pacman -Qkk virt-firmware`, and executable
`/usr/bin/virt-fw-vars` before it can report `verified`.
The fixed transaction does not use `--needed`, so an already installed matching
version is reinstalled through pacman's signature verification.

Sudo and pacman diagnostics stay suppressed so credential bytes cannot enter
public logs. A nonzero fixed transaction therefore reports only
`transaction-failed`; it does not claim whether sudo authentication or pacman
caused the failure.

Start validates the local credential, then writes one owner-private intent before
SSH submission. An invalid local credential writes no intent. A duplicate start,
timeout, response loss, or `unknown` result is never replayed. Call
`windows-vm-virt-firmware-install-status` with the exact correlation instead;
its `replayAllowed: false` remains authoritative. This route does not copy a
live VM disk, open CP117, or start, stop, reset, or modify any VM.

The installer pins both the local and each configured nested SSH hop to
`/usr/bin/ssh`; remote Python is `/usr/bin/python3`. Its one fixed pacman target
is `extra/virt-firmware=26.9-1`.

### Fixed swtpm integrity repair for the Windows fixture

`vm_workflow("windows-vm-swtpm-repair-preflight", inputs=...)` and its one-shot
start/status counterparts accept only `{host: "archlinux", correlationId:
"<canonical lowercase UUID>", timeoutSeconds: 10..300}`. They can repair only
the observed `extra/swtpm=0.10.2-1` condition where `pacman -Q swtpm` returns
that exact installed version and `pacman -Qkk swtpm` fails. This route does not
install a missing or different package, update another package, or inspect,
start, stop, reset, copy, or otherwise change a VM.

Preflight is read-only and does not read `.codex/arch-sudo.local`. It uses the
fixed nested `/usr/bin/ssh` path and checks package identity, `Qkk`, and a
bounded `pgrep -x swtpm` census. Any active swtpm process, census failure,
transport loss, matching/unknown package state, unsafe signature policy, or
invalid credential metadata blocks the repair. No process is killed. The
configured `extra` policy uses the same bounded `pacman-conf` evaluation as the
firmware repair: when `extra` inherits the global policy it checks that global
effective value; an explicit unreadable override, optional signatures, `Never`,
or `TrustAll` fails closed before start can read the owner-only credential.

Start reads the ignored `0600`, current-user, non-symlink credential only after
the repeated read-only integrity and process admission. It records one private
durable intent, then supplies the secret only through SSH stdin to the fixed
remote `sudo -S pacman -S --noconfirm extra/swtpm=0.10.2-1` transaction. The
command deliberately omits `--needed`: an installed same-version package must
be reinstalled through pacman's signature verification. Remote stderr and
transaction diagnostics are discarded. The postcondition requires the exact
installed version and a passing `pacman -Qkk swtpm` with no active swtpm process.
The raw remote start rechecks exact package identity and `Qkk` before it reads
stdin; if another actor already repaired the package, it returns
`already-healthy` and makes no sudo or pacman transaction.

An accepted intent, timeout, response loss, or `unknown` result is never
replayed; use status with the same correlation. Results, SSH arguments,
environment, and journals never include the credential or raw remote stderr.

When repair preflight reports `active-swtpm-processes`,
`vm_workflow("windows-vm-swtpm-owner-observe", inputs={host: "archlinux",
timeoutSeconds: 10..60})` provides a separate fixed read-only census. It returns
only each visible swtpm process's PID, start ticks, UID, and a categorical
relationship: `task-owned-swtpm-socket`,
`unattributed-vm-or-socket-path`, or `no-visible-socket-path`. The task-owned
category requires both the exact secure-boot fixture TPM socket and matching
owner-private `swtpm-started` plus `qemu-started` receipts. The QEMU PID and
start ticks must still identify a stable `qemu-system-x86_64` process; a stale
receipt or known path prefix alone never establishes ownership. No path, command line, descriptor target,
credential, or raw process data is returned.
An incomplete `/proc` census returns `unknown` with one bounded categorical
reason: `proc-visibility-incomplete`, `process-read-unavailable`,
`fd-census-incomplete`, `census-capacity`, or `census-unavailable`; it is not
evidence of process absence. The observer does not kill, park, signal, modify, or otherwise affect
any process, socket, or VM. Its result always has `nativeActionAllowed: false`.

`vm_workflow("arch-ai-loop-observe", inputs={"host":"archlinux",
"timeoutSeconds":15})` is a fixed read-only inventory for the Arch host's
`ai_loop` tool. It accepts no executable, command, path, prompt, credential, or
job identifier and never runs `ai_loop`. It reports bounded package/executable
presence, service/process state, and a version from package metadata only. An
optional owner-private `~/.local/state/ai_loop/observer-v1.json` may expose a
strict safe projection of provider/model, budgets, and aggregate token counts;
unknown fields, malformed data, and secret-like values are rejected. Absence of
that projection means token-saving behavior remains unverified.

`vm_workflow("inspect-input", inputs={"input": {"path": "...", "size": 123,
"sha256": "..."}})` verifies exact nonempty Python input bytes. Optional
`preflight: "desktop-update-entrypoint"` checks canonical staged siblings and
performs the approved isolated import. A hash-only result is not execution proof.
`admit-plan` accepts explicit memory observations and reservations; its result is
planning arithmetic, not fresh host observation or permission to start a VM.

`vm_workflow("macos-installer-recovery-status", inputs=...)` accepts one exact,
redacted unknown-job envelope: `jobId`, its nonfinal `publicStatus`,
`protectedReceiptObservation`, optional `bootSessionToken`, and
`currentBootSessionUuid`. It is read-only and always reports the job as unknown.
A missing launch token preserves a legacy job such as one created before
boot-session recovery existed. A different valid boot token plus caller-reported
receipt absence only identifies a product-maintenance candidate; the product must
reopen its private token and protected receipt before it may publish cancellation.
The MCP action never starts a VM or product owner, replays or cancels an installer,
or accepts credential fields.

### Fixed Windows credential-validity probe

The separate `scripts/windows_msi_fixture_preflight.py` two-phase UAC CLI requires
independent `--compact-observation` and `--expanded-observation` JSON records.
Each contains exactly `version: 1`, `phase`, `frameSha256`, `qemuIdentity`,
`operationId` and `promptId`, recorded with the corresponding capture. The CLI
binds both frames to the expected prompt; it never supplies expected identity as
observed evidence. The credential-input driver must separately use the existing
prompt freshness guard immediately before input. This metadata/pixel check never
types a credential or establishes installer success.

`vm_workflow("windows-credential-probe-start", inputs=...)` and
`vm_workflow("windows-credential-probe-status", inputs=...)` are the only
credential-probe actions. Both accept exactly `host`, `correlationId`, and the
optional `timeoutSeconds`; the first two are nonempty strings, `correlationId`
must be a UUID, and `timeoutSeconds` is an integer from 1 through 60 (15 by
default). They do not accept a password, account, SID, QGA command, executable,
arguments, script, or guest path.

The configured host must have both an absolute `fixtureTransferRoot` and the
following private `windowsCredentialProbe` object. Its field set is exact; keep
the inventory mode0600, ignored, and outside version control.

```json
{
  "schemaVersion": 1,
  "hosts": {
    "<host-alias>": {
      "host": "<ssh-host>",
      "port": 22,
      "user": "<ssh-user>",
      "identityFile": "/absolute/private/key",
      "knownHostsFile": "/absolute/private/known_hosts",
      "fixtureTransferRoot": "/absolute/private/fixture-root",
      "windowsCredentialProbe": {
        "environment": "<windows-environment-id>",
        "qgaSocketPath": "/absolute/qemu-guest-agent.socket",
        "qemuPid": 12345,
        "qemuStartTicks": 123456789,
        "accountName": "<windows-account-name>",
        "expectedSid": "S-1-5-21-<domain>-<domain>-<domain>-<rid>",
        "credentialPath": "/absolute/private/credential-bytes"
      }
    }
  }
}
```

`credentialPath` names an existing, nonempty owner-only regular file (maximum
512 bytes); it is never returned or placed in an MCP argument. The probe admits
the credential, the exact Windows account and expected SID, the live QGA socket,
and the QEMU process generation before it submits one fixed operation:
`windows-credential-validity-v1`. It freezes and hashes the approved Python and
PowerShell helpers, stages them and the credential in exclusive owner-only remote
directories, and invokes only the fixed PowerShell guest-exec program. The public
terminal receipt contains only the correlation, boolean success, and one of
`none`, `invalid-credentials`, `account-restricted`, or `unavailable`.

Start durably records the correlation before SSH submission. Reuse the same
correlation only to observe its existing operation: use `status` after an
interruption, timeout, missing receipt, or `unknown` result. Never replay a
probe with an unknown outcome or create a second operation from the same intent.
`status` checks the durable binding and observes the existing QGA PID; it does
not read current helpers or submit guest execution. A terminal receipt is the
only completion evidence. This interface and its static/unit coverage do not
establish native Windows/QGA acceptance; native verification remains pending.

```text
vm_workflow("windows-credential-probe-start", {
  "host": "<host-alias>",
  "correlationId": "<new UUID>",
  "timeoutSeconds": 15
})
vm_workflow("windows-credential-probe-status", {
  "host": "<host-alias>",
  "correlationId": "<same UUID>",
  "timeoutSeconds": 15
})
```

### Fixed Windows credential recovery

Credential recovery uses owner-only opaque handles from `NativeCredentialStore`.
Every handle is bound to the exact `environment`, `accountName`, `expectedSid`,
purpose `account-login`, and one attempt `correlationId`; a handle cannot be read,
observed, or made active under another binding. The secret is generated and kept
under ignored `.runtime/native-credentials`; no secret is accepted in tool
arguments or returned in stdout/results. Earlier handles remain private audit
records after a later credential becomes active.

The optional `recoveryAdmission` field belongs inside the private
`windowsCredentialProbe` object shown above. When present, its field set is exact:

```json
"recoveryAdmission": {
  "taskName": "<owned-task-name>",
  "taskPath": "\\",
  "expectedLastResult": 0,
  "expectedTaskState": "Disabled",
  "expectedTaskExecute": "<approved-task-executable>",
  "expectedTaskPrincipal": "<approved-task-principal>",
  "expectedTaskArgumentsSha256": "<64 lowercase hex argument digest>"
}
```

These values admit one configured owned task only. The argument digest is stored
only in ignored private inventory; callers cannot provide task fields, an
executable, script, arguments, account data, or a credential. The durable recovery
intent retains the prior private credential reference and refuses publication if
that reference or the VM/account binding has changed.

`vm_workflow("windows-credential-recover-start", inputs=...)` and
`vm_workflow("windows-credential-recover-status", inputs=...)` accept exactly
`host`, `correlationId`, and optional integer `timeoutSeconds` from 1 through 60
(15 by default). `vm_workflow("credential-status", inputs=...)` accepts exactly
`host`, `correlationId`, and opaque `handle`; it reports availability plus the
bound environment, account name, SID, purpose, and correlation, never credential
bytes. `correlationId` must be a UUID.

```text
vm_workflow("windows-credential-recover-start", {
  "host": "<host-alias>", "correlationId": "<new UUID>", "timeoutSeconds": 15
})
vm_workflow("windows-credential-recover-status", {
  "host": "<host-alias>", "correlationId": "<same UUID>", "timeoutSeconds": 15
})
vm_workflow("credential-status", {
  "host": "<host-alias>", "correlationId": "<same UUID>", "handle": "<opaque nc-... handle>"
})
```

Start records durable intent before its single fixed reset submission. For a lost
response, timeout, or `unknown` result, call recovery status with the same
correlation; never replay the reset. Once reset reaches a successful terminal
receipt, status may advance the authorized recovery by running the fixed
credential-validity verification. It observes an existing verification attempt
when present and does not reissue the password reset. Only successful fixed
verification updates the private inventory reference and publishes the active
handle. Inactive task state must match exactly (`Disabled` or `Ready`); queued or
running tasks are never admitted. A terminal `verified: true` response establishes
recovery; credential-file existence alone does not. Rejections report a bounded
admission stage without disclosing raw exceptions or secret values.

### Owned Android stale-proxy recovery

`vm_workflow("android-proxy-recover", inputs=...)` accepts exactly `host`, `device`,
`expectedPort` (1–65535), and a UUID `correlationId`. It uses the configured owned
API29 profile and fixed loopback host, requires an OFF owner with no active
operations, absent stored proxy fields, and fresh independent NetworkMonitor
refusal at the expected task port. It records private intent before the single
Android proxy-observer clear. Merely deleting stored settings does not establish
that Android's cached proxy has cleared.

Completion requires a clear broadcast and successful fresh network validation,
then restores absent fields only while they still equal the values written by
the clear operation. `vm_workflow("android-proxy-recovery-status", inputs=...)`
accepts exactly `host`, `device`, and the returned `identity`. Reused correlations
only observe; unknown results never trigger another clear. Full command streams
stay in private evidence; public output contains categorical results and identity.

### Configured guest routes

Nested host profiles may reference another nested gateway, up to four hosts in
one declared route. Each hop preserves quoted argument boundaries and strict
known-host checks; cycles, missing gateways and excessive routes are rejected.
`remoteConfigFile` is an optional absolute path to an agent-owned SSH config on
the preceding host. A nested hop requires that field or `remoteControlPath`.
For example, the private guest profile can use the configured Arch host as its
`gateway` and the disposable guest alias as `remoteHostAlias`, with its dedicated
remote config and known-host file. Keep all concrete paths in the ignored
inventory. This does not modify the remote user's normal SSH configuration.

Password/askpass handling resolves the first local connection host, even through
multiple hops; intermediate credentials are never substituted for that host.
Use a fresh MCP process or `mcp_tool.sh` after changing the inventory schema if
an existing server still has the older module loaded. Probe the exact guest and
verify its OS/package identity before assigning it a native scenario.

### Native artifact, bundle, and environment helpers

The helpers below are local coordination and evidence tools. They never search a
host, download an artifact, start a VM, submit a native scenario, or turn a
historical record into a current observation. A successful response is evidence
only in the scope stated by that action.

`vm_workflow("source-review-close", inputs={"manifestPath": absolute_path,
"manifestSha256": full_sha256})` authenticates explicit local review inputs.
Supported manifests use source/archive rows in `files`, relative pinned `files`,
absolute pinned `pins`/`inputs`, or a direct map of absolute paths to pins.
Mixed schemas are rejected. Archive-only reviews require an explicit
`packetManifestPath` and `packetManifestSha256`, or an authenticated listed
`proofPath` and `proofSha256` carrying current `sourcePins`. Do not combine those
options. The helper retains file and ancestor descriptors, verifies full hashes
and generations, and closes every identity after all reads. Actual credential and
private-binding files are excluded. It writes no evidence and returns
`SOURCE_ONLY` with native permission and product acceptance both false. A source
closure receipt does not grant native execution.

`vm_workflow("artifact-register", inputs=record)` stores immutable, content-derived
artifact evidence under the checkout's private agent state. A local record must
name one existing regular file with its exact `sha256` and `size`, and use
`evidenceClass: "local-verified"`; registration streams those local bytes once.
Remote metadata uses `evidenceClass: "unverified-remote"` plus a configured host
alias, an absolute remote POSIX path, and a receipt. It is never contacted or
verified by this API. Artifact IDs have the form `sha256-<digest>`.

`artifact-find` returns at most 100 historical index matches (20 by default) and
does not reread artifact bytes. Filter only by registered identity fields such as
`artifactId`, `platform`, `artifactKind`, `sha256`, `sourceSha`,
`sourceFingerprint`, or location evidence. Treat every result as historical until
`artifact-verify` reports `verification: "verified"` for local bytes. Verification
can instead report `mismatch`, `missing-or-unsafe`, or `unverified-remote`; none
of those states establishes usable bytes. An artifact may have more than one
registered location; when no unique local location exists, supply the returned
`locationId` to verify the intended evidence location.

```text
vm_workflow("artifact-register", {
  "platform": "linux", "artifactKind": "desktop-package",
  "localPath": "/staging/package.tar.gz", "sha256": "<64 lowercase hex>",
  "size": 123456, "evidenceClass": "local-verified", "sourceSha": "<git sha>"
})
vm_workflow("artifact-find", {"platform": "linux", "artifactKind": "desktop-package"})
vm_workflow("artifact-verify", {"artifactId": "sha256-<64 lowercase hex>"})
```

`vm_workflow("bundle-prepare", inputs={"scenarioId":
"linux-public-update-driver", "outputDirectory": "<fresh directory>"})`
creates an exclusive mode-0700 snapshot of the allowlisted scenario source,
writes a canonical manifest, and imports the staged entrypoint in isolation. The
output directory must not already exist. `bundle-verify` rereads a frozen bundle
against its exact manifest digest and rejects changed, unexpected, symlinked, or
non-allowlisted files. It does not run the scenario.

```text
vm_workflow("bundle-prepare", {
  "scenarioId": "linux-public-update-driver",
  "outputDirectory": "<fresh-private-bundle-directory>"
})
vm_workflow("bundle-verify", {
  "path": "<prepared-bundle-directory>", "manifestSha256": "<returned digest>"
})
```

Without `hostAlias`, `environment-status` summarizes caller-supplied receipts,
marks them fresh, stale or unknown, and never claims readiness. With a configured
`hostAlias`, it performs bounded SSH observation; optional `device`, `jobIdentity`
and `artifactId`/`locationId` add configured Android, existing-job and local-byte
checks. `requestedProbesReady` applies only to those probes. Use `observeHost: true` for a fixed Linux `/proc` memory and QEMU inventory
probe; optional `vmIdentity: {pid, startTicks}` verifies a selected live guest.
Unparseable allocations or incomplete process visibility withhold the admission
measurement. Caller-supplied facts remain separately labelled and never establish
readiness. The host receipt feeds `admit-plan` or reservation accounting; observation
alone does not allocate memory or start a VM.
`timeoutSeconds` is bounded at30 seconds; unknown outcomes do not cancel jobs.
`environment-reserve` atomically records capacity for a host/environment/operator
request, beginning in `pending`; pending reservations count against the host
budget. An idempotent retry returns the same opaque identity. A reservation may
move to `running` only with that exact identity and a complete mapping of running
allocations. Neither state starts a VM or authorizes a native action.
`environment-release` requires that exact opaque identity and refuses release
while its correlated active-job evidence is active, unavailable, stale, or
unknown. A lost observation must remain unknown; do not retry execution to clear
it.

`linux-vm-readonly-inventory` takes only `{host: "archlinux",
timeoutSeconds: 1..30}`. It inventories the two fixed historical Ubuntu/Arch
package-test VM trees, their exact QEMU/disk/port/QMP identity, host disk and
bounded guest process/job facts when reachable. Incomplete or ambiguous facts
remain unknown. The result always has `nativeActionAllowed: false`; it neither
boots a guest nor reserves capacity or admits an installer.
For a running guest, completeness requires the observed QEMU PID generation to
remain stable after the guest probe and its open socket FDs to own both the
loopback SSH listener and QMP socket. Matching command-line claims alone are
insufficient. An unreadable live guest PID also makes its process census
incomplete.

```text
vm_workflow("environment-status", {"observations": []})
vm_workflow("environment-reserve", {
  "hostAlias": "build-host", "environment": "windows-vm", "operator": "agent-a",
  "requestedMemoryBytes": 8589934592, "headroomBytes": 4294967296,
  "measurement": {"physicalMemoryBytes": 34359738368,
    "runningConfiguredMemoryBytes": 0, "pressure": "normal", "swapUsedBytes": 0}
})
vm_workflow("environment-release", {"reservationId": "<returned id>",
  "token": "<returned token>", "hostAlias": "build-host",
  "environment": "windows-vm", "operator": "agent-a"})
```

### Fixed CP117 loopback forward

`ssh_workflow("forward-open", host="archlinux")` is intentionally not a general
forwarding API. It can only use the configured nested `archlinux` route to expose
the owned Windows VM's loopback VNC service through the fixed local loopback port
`45909`; it accepts no destination, port, command, or arbitrary SSH option.
Opening writes a durable intent before network effects. If the result is pending
or unavailable, use `forward-status` with the same host; never replay an uncertain
open. `forward-status` is observation-only and reports `ready` only when the
recorded local SSH process/control state match and the endpoint returns a valid
VNC protocol banner. This checks connectivity without entering credentials. `forward-close` requires
an identity object containing the `correlationId` returned by open and only closes
a forward owned by this tool. It can return `close_pending` or `owner_unknown`; those are not
permission to remove sockets or issue ad-hoc SSH commands.

```text
ssh_workflow("forward-open", host="archlinux")
ssh_workflow("forward-status", host="archlinux")
ssh_workflow("forward-close", host="archlinux", identity={"correlationId": "<open result>"})
```

The corresponding fallback forms are `mcp_tool.sh vm-workflow <action>
--inputs-file <private-json>` and `mcp_tool.sh ssh-workflow forward-open|forward-status|forward-close
--host archlinux` (pass `{"correlationId": "<open result>"}` to close through
`--identity-file`).
The input and identity files are private operational data; keep them outside
version control and do not put passwords or secret material in them.

### Durable fixed-scenario execution

`scenario-start`, `scenario-status`, `scenario-resume` and `scenario-collect` are
registered `vm_workflow` actions. The component execution scenario
`linux-public-update-preflight`: it transfers and imports the verified Linux
public-update driver bundle. It performs no product installation or VPN action;
its receipt is explicitly component evidence.

Register the prepared `native-scenario-manifest.json` as a local artifact first.
Start takes exactly `scenarioId`, configured `host`, `environment`, `bundleHash`,
`artifactIds: {"bundleManifest": "sha256-<manifest digest>"}`, and a unique
`correlationId`. The other three actions take exactly `{correlationId}`. The
private adapter resolves the registered manifest rather than accepting command,
script, executable or remote-directory arguments.

The journal precedes submission. A repeated start never launches a second job;
resume only observes its existing correlation. Terminal receipt verification binds
the plan, artifacts and actual process generation. Local bundle removal does not
prevent observation of an already submitted remote job. Missing or uncertain
receipts remain unknown. The installed-package recipe below has its own fixed
adapter; new scenarios require an explicit adapter and native evidence.

### Reusable native acceptance orchestration

All actions below use `vm_workflow(action, inputs)`. Private journals remain under
`.rag_index`; source packages and evidence retain their original source identity.
A successful tooling operation does not mean the product acceptance gate passed.

**Fixed CP117 old-stage retirement.** `windows-cp117-staged-fixture-retire-`
actions `preflight`, `parser`, `diagnose`, `guard-diagnostic`, `start`, and `status`
take exactly `{}` and bind the historical e848 stage and e59 campaign. The parser
examines the exact generated observer and deletion scripts without invoking them;
the guard diagnostic executes only their read-only checks and returns a fixed
rejection code. Preflight requires the cleaned server/credential receipts, idle
installed base, exact protected ACLs, manifest hashes, known failed-server tree,
privileged creator ownership, and no reparses. Start reserves once, rechecks those
guards immediately before deleting the guest stage, removes only its bound host
payload and local ZIP, retains historical journals, and closes the old campaign.
`windows-cp117-staged-fixture-retire-tree` observes actual fixed guest tree
presence and exclusive result-file access. `...-locks` uses read-only Windows
Restart Manager to classify the fixed result.json holders and HRESULT; it never
stops a process or service. Its exact LocalSystem qemu-ga claim requires a sole
holder with matching process and service identity. Historical stage receipts do
not establish that the live immutable stage remains present.

Private step receipts distinguish completed guest removal, host submission/removal,
and campaign close. An unknown result never permits replaying start; use status
and the read-only diagnostics to identify the unresolved step.

**Artifact sets.** `artifact-set-freeze` takes `sourceSha` (current clean product
HEAD), `packages` (registered `{artifactId, locationId}` entries), `runtimePaths`
(explicit repository-relative runtime files), and `provenance` containing
`architecture` and `signer: {kind: "unsigned"}` or
`{kind: "certificate", path: "<certificate file>"}`. It derives the build-input
manifest and version, streams package/runtime bytes and stores an immutable set.
`artifact-set-verify` and `artifact-reuse-check` take only `{artifactSetId}`.
Reuse derives changed paths from Git: narrowly allowed docs/test-only changes may
reuse bytes, while product/build/runtime/unknown changes require rebuilding.
Original source SHA is never relabelled, and current exact-SHA CI remains required.
Signer/architecture provenance is an attestation until a trusted native inspector
verifies it; `nativeAdmissionReady: false` must not be treated as package admission.

**Preflight and batches.** `fixture-preflight` takes a fixed `scenarioId` and its
strict typed inputs. `linux-scheduled-refresh` requires configured `host`,
`environment`, `bundleManifestArtifactId`, `scenarioInputArtifactId`, and unique
UUID `scenarioCorrelationId` (optional `timeoutSeconds`). It checks frozen inputs,
live access and the exact installed RPM/JAR/protected OFF owner. Endpoint,
certificate and settings checks occur inside the runner after fixture creation
and before ON. The separate `linux-scheduled-refresh-fixture-ready` profile checks
an existing fixture using `expectedTestUrl` and optional `certificateRelativePath`.
The Windows `windows-credential-validity-v1` profile admits an owned environment
and opaque private credential; its batch then uses the existing real credential
probe. A stored credential alone never establishes a working login.

**Fedora RPM HTTPS fixture server.** `linux-rpm-fixture-server-start` takes the
same exact public RPM intent fields as `rpm-public-install-start`, plus
`sourceSha` bound to the current checkout. It requires the owner-only public
authorization record, registered same-source RPM-only fixture and package,
then writes a private server journal before sending any guest bytes. A lost
response is unknown and the start correlation must never be replayed.
`linux-rpm-fixture-server-status` and `linux-rpm-fixture-server-collect` take
only `{correlationId}`. They report `ready` only after a fresh guest Java HTTPS
manifest probe, certificate/trust check and exact journal identity. The public
RPM launcher independently requires that protected server state and live
endpoint for the same intent before submission. This is fixture readiness, not
evidence that the RPM update installed successfully.
If an unknown correlation leaves only its exact loopback fixture server alive,
`linux-rpm-fixture-server-stop` takes only `{correlationId}`. It requires a fresh
matching boot/PID-start/UID/argv observation, an absent worker and a private
one-shot stop journal, then sends one pidfd-bound SIGTERM to that fixture server.
An uncertain stop result remains unknown and never authorizes a second signal.
It does not stop the product VPN or promote the old fixture job to success.
`linux-rpm-workspace-recovery-status` takes only the canonical UUID
`{correlationId}` of the existing fixture server campaign. Its pinned,
read-only scanner reports whether the protected workspace is still referenced;
uncertain scanner evidence stays `unknown`. This route cannot delete a
workspace or start a guest. Cleanup remains a separately reviewed action.

**Windows interpreter preflight.** `windows-fixture-python-preflight` takes
exact `host`, `leaseId`, `stageCorrelationId`, `serverCorrelationId`,
`sourceSha`, `fixtureReceiptArtifactId`, `baseMsiArtifactId`, and
`targetMsiArtifactId`. Run it after `windows-fixture-stage-collect` has proved
the exact stage. It performs bounded read-only CP117 QGA inspection of the
fixed signed Python interpreter and reports only its hash/version. This
does not provision credentials, start a server, or admit an MSI update; those
routes remain gated by their full lifecycle and original-owner network proof.

**Windows read-only recovery views.** `windows-fixture-stage-diagnostic` takes
only `{correlationId}` after an uncertain fixture stage. It binds the local
intent, registered artifacts, campaign and VM generation before reporting a
bounded phase. Every result keeps replay and native action disallowed; use the
phase to select a separately reviewed cleanup or recovery action.
The one-correlation `windows-fixture-stage-recover-7f27` accepts only
`{"host":"archlinux"}`. It closes the diagnosed pre-dispatch stage only after
confirming the original host submitter is gone, the guest create task and leaf
are absent, the campaign and VM generation still match, and the base install is
idle. It retains the original intent and an exact cleanup receipt. Ambiguous
or partial cleanup remains unknown until its guarded reconciliation proves the
same absence facts.
`windows-cp117-campaign-rebase` opens one new source-bound campaign after that
fixed recovery, using a new canonical lease ID and the exact prior lease,
source SHA and registered fixture/base/target artifact IDs. It requires the
closed old campaign, bound base terminal receipt, unchanged VM generation and
fresh idle 2.1.19 install. A lost response is not replay permission.
`windows-cp117-campaign-status` accepts only `{"host":"archlinux"}` and
reports the verified current or closed campaign with a read-only next action.
`windows-cp117-campaign-diagnostic` uses the same fixed input and returns only
a bounded failed proof phase when campaign status is unknown.
`windows-update-fixture-phase-status` accepts only `{correlationId}` and reads
the durable HTTP fixture transfer and guest phase evidence. Its finite phase
and next missing fact never authorize replay, extraction, or campaign changes.
`windows-update-fixture-http-transfer` uses an exact `phase` plus the normal
source-bound fixture-stage request for `prepare`; later phases accept only the
frozen `correlationId`. It transfers the ZIP over a one-use host listener and
uses the existing stage receipt for extraction and campaign completion. Each
native phase reserves an intent before dispatch; a lost response is checked
with read-only phase status rather than replayed.
After an unknown host `stage-start`, its read-only `host-stage-probe` accepts
only `{correlationId}` and hashes the exact remote bundle and binding. Only
`host-stage-complete` permits the separately correlated listener start;
partial, absent and uncertain host stages remain blocked without replay.
After the current guest download submission, `guest-download-diagnostic`
accepts only its fixed correlation. It reads the already scheduled task,
downloaded file metadata, and one-use listener completion state, returning
only finite task, file, and listener facts. It never submits a task, starts a
listener, downloads bytes, extracts the bundle, or updates the app. Keep the
correlation after an unknown result; this diagnostic is evidence for a later
separately reviewed recovery action, never retry permission.
The fresh-process fallback remains `mcp_tool.sh vm-workflow
windows-update-fixture-http-transfer --inputs-file <private-json>` with
`{"phase":"guest-download-diagnostic","correlationId":"e848bed2-5bea-47bc-a85a-6cf17b1fcc6a"}`.
`windows-update-fixture-http-stage-extract-diagnostic` accepts only that
current transfer correlation. It is a read-only observer of the uncertain
guest extraction, returning only a bounded binding result and extraction
phase, including finite remote-layout, guest-probe, dispatch-status,
result-read, and receipt-invalid classifications. It never submits extraction, writes a guest file, changes a receipt, or
retries the transfer.
Its `e66-pre-effect-recovery` phase is a one-correlation repair for the recorded
local source-open failure. It requires the ignored, owner-only Codex command
transcript export, writes an immutable import receipt, and checks fresh remote
absence before closing the consumed stage phase. It does not replay the stage.
Its fixed `e66-retire-aborted-stage-status` and `e66-retire-aborted-stage`
phases verify the aborted transfer and fresh host absence before retiring the
held CP117 stage role as `failed-cleaned`. The status phase is read-only;
the action preserves the original failed transfer and never resends bytes.
`windows-cp117-e66-successor-start` takes the fixed retired e66 lease as
`oldLeaseId`, one fresh canonical `newLeaseId`, `host=archlinux`, the exact
source SHA and registered fixture/base/target artifact IDs. It verifies the
immutable e66 retirement, fresh idle 2.1.19 installation and absent owner,
then closes that idle campaign and begins the distinct successor. It never
replays e66 or transfers fixture bytes. Its separate `-status` action is
read-only; `-reconcile` reads back a durable pending campaign transition
without repeating close or begin. A distinct `-resume-begin` action can reserve
the new lease once if the old close is proven terminal while the new lease is
conclusively absent; it writes a one-shot marker before reservation. Keep the supplied successor input after an
unknown result and inspect status before any next action.
`windows-update-fixture-guest-create-abort-status` accepts only the fixed
guest-create correlation and reports whether the recorded, unserved download
attempt can be retired. It is read-only. `windows-update-fixture-guest-create-abort`
uses the same exact input to remove only that stopped, unserved host staging
area and close its held stage role as failed-cleaned. It never retries guest
creation, downloads, extraction, or the application update. An unknown result
does not authorize a retry; inspect the status action first.
`windows-cp117-guest-abort-successor-start` consumes only that terminal abort
receipt and opens one new campaign with a fresh canonical lease ID, the same
source SHA, and the registered fixture, base, and target artifact IDs. It first
proves the old campaign is idle, the guest is still at 2.1.19 with no owner or
runtime, and the remote cleanup marker is present. It never recreates the
abandoned guest operation. Its `-status` action is read-only; `-reconcile`
reads a durable partial close or open without repeating it; `-resume-begin`
can reserve the new lease once only after the old close is terminal and the new
lease is absent. Preserve the exact input after an unknown result and inspect
status before a later reviewed action.
`windows-fixture-credentials-diagnostic` accepts only its fixed CP117
correlation and reports a bounded credentials phase and next read-only action.
It includes finite host journal, binding, layout, and guest-observer outcomes,
without exposing paths or credential material; it cannot create, clean up, or alter
credentials, tasks, servers, or the application.
`windows-fixture-credentials-failure-detail` accepts the current exact credentials
correlation and reduces a fully bound terminal task failure to finite task-result,
directory, ACL, file, provenance, and safe-stage values. It is read-only and never
returns credential bytes, paths, or filenames.
`windows-fixture-credentials-provenance-acl-shape` accepts that exact correlation
only after a terminal provenance-ACL failure. It exposes seven finite ACL category
labels and no paths, SIDs, filenames, or credential material.
`windows-fixture-python-inventory-diagnostic` takes the exact eight CP117 server
campaign fields and reports only finite signed-interpreter identities. It classifies
an empty or ambiguous candidate set without selecting an interpreter or changing the
existing unique-interpreter preflight rule.
`windows-fixture-python-download-preflight` uses those same eight fields to observe
the fixed Python endpoint from the admitted guest before any download. The separate
`windows-fixture-python-host-source-observe` also requires the current campaign
binding, then observes only a finite category for the fixed Arch source. Neither
route transfers, installs, or exposes the source path or bytes.
`windows-fixture-python-acquire-start` takes the exact nine CP117 campaign,
artifact and fresh correlation fields. After a durable one-use intent, a limited
original-user task downloads the fixed Python 3.13.15 AMD64 installer directly
from python.org and verifies its exact length, SHA-256 and signer before placing
it at the private fixed guest path. `windows-fixture-python-acquire-status`,
`-collect` and `-reconcile` take only that correlation and never retry a submit.
`windows-fixture-python-install-start` takes the same nine fields and requires
the exact verified acquisition. It submits one limited original-user per-user
installer task. `windows-fixture-python-install-status` and `-collect` take only
the correlation and report finite task, registry and interpreter proof. An
unknown submission is never replayed; a fresh correlation requires a separate
exact cleanup and admission review.
`windows-fixture-credentials-pre-effect-guard-probe` is a separate exact
read-only check of the remote role guard and durable command metadata. It does
not read or generate credential bytes, write a journal, dispatch QGA, or change
credentials.
`windows-update-fixture-download-abort-status` accepts only the fixed failed
download correlation and reports whether its listener is stopped and unserved,
the guest download tree remains empty, and no task, installer, or runtime is
present. It is read-only. `windows-update-fixture-download-abort` uses the
same exact input to retire only that unserved host stage and mark its stage
role `failed-cleaned`. It never retries the scheduled download, deletes the
guest evidence tree, extracts a bundle, or updates the application. An unknown
result requires a fresh status read before any separately reviewed action.
`windows-update-fixture-download-task-cleanup-status` accepts that same fixed
correlation and reads whether the recorded download task is terminal, has the
expected original-user action, and the empty guest evidence tree is safe. Its
separate `windows-update-fixture-download-task-cleanup` action unregisters
only that exact failed task after writing a durable cleanup receipt. It cannot
start, repeat, or alter the download; an unknown result does not authorize a
second cleanup submission.
`windows-update-fixture-download-abort-current-...` is the separate action
family for the current frozen download correlation. Its `task-cleanup-status`
and `task-cleanup` actions first read, then unregister only the exact failed
scheduled task. Its `status` and terminal action read, then retire only the
stopped unserved host stage after the task cleanup receipt is durable. The
family is bound to the current source, lease, and correlation; it cannot touch
the completed historical download recovery or repeat a download.
`windows-cp117-download-abort-successor-start` consumes only that terminal
download-abort receipt. Given the fixed old lease, a fresh canonical new lease,
the current source SHA, and the registered fixture/base/target artifacts, it
closes the retired idle campaign and opens one distinct campaign. Its `-status`
action is read-only; `-reconcile` reads durable partial close or open state;
`-resume-close` can finish only a close already recorded in its durable intent,
and `-resume-begin` can reserve the new lease once only after a terminal old
close and proved absence of the new lease. It never recreates the download,
serves bytes, or runs an installer.
`windows-cp117-download-abort-current-successor-{start,status,reconcile,resume-begin}`
is the isolated handoff for the current download retirement. It requires its
fixed old lease, current source SHA, registered artifact IDs, and a fresh
canonical new lease. Status is read-only; reconcile reads a durable partial
close or open; resume-close finishes only a previously recorded close;
resume-begin reserves the new lease only after terminal old-close proof and
new-lease absence. It cannot touch historical successor
state or repeat the failed download.
Native unknown receipts for the fixed Windows stage, owner census, and stage
diagnostic carry bounded phase/type and causal regression references in their
failure fingerprint; the private raw receipt remains separate.
`windows-msi-owner-census-preflight` and `windows-msi-owner-census` take only
`{"host":"archlinux"}`. The former checks the fixed PowerShell probe; the
latter reports a source-bound installed CLI and exact app owner process chain
only when the disposable CP117 guest proves it. Neither route quits the app,
stops a runtime, or admits an update.
If the census is unknown, `windows-msi-owner-diagnostic` accepts the same fixed
host input and reports only a bounded failed proof phase. It does not return
raw guest output or authorize an owner action.
`windows-msi-stale-lock-recover` accepts only `{"host":"archlinux"}`. It
removes the fixed original-user stale lock once, after matching the base
installation, VM generation, CLI hash, owner SID, runtime-off process census,
and a durable pre-effect intent. An unresolved intent never authorizes replay.
`windows-msi-stale-lock-diagnose` and
`windows-msi-stale-lock-reconciliation-status` read the armed recovery only;
they expose bounded proof failures and cannot delete or rearm the lock.
`windows-msi-owner-relaunch-{launch,status,collect}` admits one fixed,
original-user limited-session owner launch after proved stale-lock recovery
and preserves unknown launch intent. `windows-msi-owner-public-status-{start,status,collect}`
runs one fixed original-user limited scheduled task to validate the private
controller endpoint and exact owner process pair, then invokes the installed
public CLI `status`. It projects only a bounded runtime-off result; QGA never
reads the private endpoint value. An unknown start is not replayable.
`windows-msi-owner-public-status-diagnose` reports only a finite bootstrap
phase and fixed task-state category for an already armed intent. It never
resubmits the scheduled task or exposes controller credentials.
`windows-msi-owner-public-status-retry-{preflight,start,status,collect}` is a
second fixed one-shot with a distinct correlation after the original task is
proved absent. Its read-only preflight checks the Scheduler, original-user
account and Session 1. The retry stores a durable intent before submitting a
limited original-user task and preserves the original unknown attempt.
`windows-msi-owner-public-status-retry-diagnose` reads only the armed retry
intent and the fixed scheduled task, projecting a finite bootstrap phase and
task status without replay or private endpoint values.
`windows-msi-owner-public-status-retry-observe` also accepts the fixed host;
it reads the retry task after a lost response using the durable retry intent
and VM generation, even if the current owner census has changed. It reports
only a finite failed binding stage or task category.
`windows-msi-owner-public-status-third-{start,status,collect}` is a separate
fixed read-only one-shot. Start requires the first two task names to be absent,
no active matching task process, and a fresh exact owner and runtime-off check.
It writes a durable intent before submitting its own limited original-user
task. Status and collect inspect that intent without replaying any submission.
`windows-msi-owner-public-status-third-observe` reads the armed third task with
the durable intent and exact VM generation, even if the live owner census has
changed. It returns only finite task status or a binding blocker.
`windows-msi-owner-relaunch-quit-{start,status,collect,diagnose}` is a fixed
public CLI quit for the current relaunched CP117 owner. Start requires exact
source, VM generation, owner pair, expected private-endpoint redaction and
runtime-off proof. Its limited original-user task validates the endpoint,
binds `quit` to that controller and verifies
owner exit. A durable intent prevents replay after an unknown response. The
other actions inspect only the fixed task and expose bounded results.
`windows-msi-owner-relaunch-quit-v2-{start,status,collect,diagnose}` is a
separate fixed one-shot for the long-running relaunch task. Its bootstrap
verifies the relaunch task's exact action and principal, absence of the first
quit and status tasks, and absence of a matching or ambiguous original-user
encoded PowerShell task before registering its own limited-user public quit.
It keeps its own durable intent and never resubmits an unknown attempt.
`windows-msi-owner-relaunch-quit-v2-bootstrap-diagnostic` checks the fixed
armed attempt's exact pre-registration gates read-only and returns one finite
gate without submitting or replaying a task.
`windows-msi-owner-relaunch-quit-v3-{start,status,collect,diagnose,bootstrap-diagnostic}`
uses a separately correlated one-shot and a bounded, hash-verified compact
outer PowerShell bootstrap. Its causal regression measures the final command
below Windows' command-line limit. Prior unknown quit intents remain untouched.
`windows-msi-owner-relaunch-quit-v3-task-result` reads only the armed v3 task,
verifies its principal and exact action hash, and reports a finite
pending/exited/failed result without replaying the public quit.
`windows-msi-owner-quit-phase-{start,status,collect}` is a separate fixed
original-user read-only diagnostic for a verified failed v3 quit. It checks
the same identity, owner, endpoint and controller-bound public `status` gates
and projects only the first finite failure phase from its task exit code.
`windows-msi-owner-relaunch-quit-v4-{start,status,collect,diagnose}` is a
new one-shot tied to the exact failed v3 task and its `owner-before` phase
receipt. It accepts the two command forms proved for the relaunched owner,
uses the bounded compact bootstrap, and preserves all earlier quit intents.

`batch-plan` takes `batchId`, `recipe`, and recipe inputs. For
`linux-scheduled-refresh`, use the preflight fields above without `scenarioId` or
`timeoutSeconds`. Prepare a `linux-scheduled-refresh-driver` bundle and register
its manifest and versioned scenario-input JSON as local artifacts first. Input
schema is defined in `scripts/integration/linux_scheduled_refresh_scenario.py`;
it binds the expected RPM/JAR, protected controller, owned root, observation
window and refresh mode. The fixed runner performs fixture setup, admission,
benchmark/Find Best, scheduled observation, actual HTTPS traffic and scoped cleanup.
For `windows-credential-validity-v1`, use `host`, `environment`, and UUID
`probeCorrelationId`. The component-only `linux-public-update-preflight` recipe
uses `host`, `environment`, `bundleManifestArtifactId`, `scenarioCorrelationId`.

`batch-start`, `batch-status`, `batch-resume`, and `batch-collect` accept only
`{batchId}`. Durable node intent precedes submission. Failed prerequisites stop
dependent work while independent checks continue. Resume observes an accepted or
uncertain operation; it cannot replace its plan or repeat the mutation. Collection
preserves failure evidence. Cleanup is recipe-scoped; uncertain runtime ownership
is preserved for recovery rather than stopped to make a batch appear complete.

**Versioned VM baselines.** Optional `nativeBaselines` in private mode-0600
`.vm-hosts.local.json` contains `{schemaVersion: 1, sources: {<id>: <entry>}}`.
Source IDs and `generation` are public configuration labels. Never put
credentials, account secrets, tokens, or private paths in either label. A
metadata projection may expose these two labels and provider kind; all other
inventory fields stay private. Listing labels is not proof of VM readiness.

Each entry contains `provider` (`tart` or `qemu`), `sourceRoot`, `sourcePath`,
`generation`, `providerName`, `preparationReceiptPath`, `accessReceiptPath`,
`dependencyReceiptPath`, and `installerJobReceiptPath`. No credentials or absolute
host paths belong in tracked configuration.

A trusted preparation run must write private proofs binding source ID, generation
and exact source digest to actual access/dependency evidence and terminal/no-job
state. The preparation receipt also binds hashes of those proofs. The adapter
validates evidence bytes and reobserves provider stopped state; arbitrary JSON
claiming readiness is not a substitute for a verified preparation run. See
`native_vm_baseline_config.py` for the strict versioned proof schemas.

`baseline-source-inventory` takes exactly `{}`. It returns only the public
source ID, provider kind and generation labels with scope
`CONFIGURATION_METADATA_ONLY`, `nativeActionAllowed=false` and
`readinessVerified=false`. The trusted provider reads private configuration;
reviewers do not open the inventory. Missing, empty or malformed baseline
sections report `baselines_not_configured`; invalid inventory, unsafe source
configuration and other unavailable metadata have separate finite reasons.
Private errors and paths are suppressed. This read writes no native failure
receipt. Use the fresh-process MCP CLI fallback if the live server predates the
new action; do not restart retained native operations to reload its inventory.

`baseline-preflight` takes `{provider, sourceId}`; `baseline-capture` adds
`baseline` and `generation`. `baseline-verify` takes `{manifest}`;
`baseline-restore` takes `{manifest, destination}`. Capture seals an immutable
baseline; restore creates a fresh disposable clone and never overwrites a guest.
Tart and QEMU use fixed provider operations. Active disks, backing-chain inputs,
changed proofs, unknown installer outcomes and unsafe paths fail closed. Preserve
pending/unknown operations instead of capturing or restoring over them. Provider
unit tests are not native snapshot/restore evidence.

**Acceptance matrix.** `matrix-record` accepts a reviewed observation binding
`requirementId`, `platform`, `originalSourceSHA`, `immutableArtifactIDs`,
`evidencePath` (checkout-relative), `evidenceHash`, `environment`, `result`,
`scenarioResults`, `missingEvidence`, `nextFixedCommand`, `reviewerAttestation`,
and `evidenceScope`. Hashes and registered local artifact bytes are verified;
semantic interpretation remains an explicit reviewer responsibility. The tracked
requirements are in `native_acceptance_requirements.json`. `matrix-status` takes
optional `sourceSha` (must match current HEAD) and reports remaining scenarios.
Partial current receipts aggregate; historical/component receipts remain visible,
conflicts and unknowns remain open, and evidence changes invalidate a pass.
`matrix-record` returns the observation's immutable `originalSourceSHA`; a
record is classified as current or historical only by a subsequent
`matrix-status` for the checked-out HEAD.
If a reviewer overstates a scenario, `matrix-retract` accepts exactly
`receiptId`, a nonempty `reason`, and `reviewer`. It writes an immutable private
correction bound to the original receipt bytes; `matrix-status` reports the
retracted ID and excludes that claim while leaving its original file auditable.
Record a corrected observation separately with the original source/artifact
identity. Do not edit or delete the original receipt.

`matrix-equivalence-record` accepts exactly `receiptId`, `artifactSetId`,
`targetSourceSHA`, and a nonempty `reviewerAttestation` (at most 240 characters).
It creates an immutable link only for a complete passed full-native receipt and
a clean committed target with verified eligible docs/tests/noncritical-tool
changes. Product, build, runtime, fixture, MCP and matrix changes require new
evidence. Original source and artifact identities remain intact. The response
contains `linkId`, `receiptId`, `originalSourceSHA`, `targetSourceSHA` and
`requiredCurrentChecks`; `currentChecksCompleted` and `nativeActionPerformed`
remain false. Exact-SHA CI and any changed-tool checks must still run. An unknown
response grants no replay: inspect `matrix-status` for the checked-out target to
recover an existing link before deciding on further work. Use the fresh-process
`mcp_tool.sh vm-workflow matrix-equivalence-record --inputs-file <private-file>`
route when the running MCP implementation is stale.

**Read-only acceptance and prebuild views.** `acceptance-status` accepts
`{}` or `{sourceSha: "<current full SHA>", correlations: [{platform,
correlationId, statusAction}], ownerProbes: [{platform, action, inputs}]}`.
The fixed correlation status actions are Android consent status, Linux RPM
workspace recovery/cleanup status, and Windows MSI public status. Fixed owner
probes are Android observe, Fedora owner observe/public quit status, and a
Windows configured environment status with exact VM identity. macOS remains
unknown until a read-only owner/correlation adapter exists. It combines the
current reviewed matrix rows into one
Android/Linux/Windows/macOS view with the exact source SHA, hashes from
reviewed current receipts and the exact-source artifact index, unmet gate
counts and next fixed command. Registry-only hashes are labelled
`registered-unverified`. The view rehashes current-source local package/APK/DMG
bytes within a 1 GiB total read limit and labels matches
`verified-local-bytes`; this verifies local files, not their installed state
or matrix review. Large inputs beyond the limit remain registered only.
`sourceSha` names the HEAD commit. `checkoutExact` is true only when a bounded
read-only Git status sees a clean checkout; `worktreeDirty` is true when any
tracked or untracked work is present. An unavailable status makes the whole
view unknown, with `checkoutExact: false`.
Caller correlation IDs and owner probe parameters are never promoted by
themselves: the route verifies a correlated status, its source binding and a
fresh owner/guest observation. A stale source, foreign owner/device, omitted
probe or uncertain status remains `unknown`. Terminal correlations are
reported as `observedCorrelationId`; `activeCorrelationId` appears only
for verified submitted/running work. The route also discovers bounded private
Android consent and Fedora cleanup intents that bind to the current source,
then checks their fixed read-only status routes. Each verified result appears
in `correlationObservations` and `observedCorrelationIds`; when several results
exist, the singular `observedCorrelationId` remains unset unless exactly one
active result is unambiguous. `knownCorrelations` are source-bound local lookup
keys, not proof that a native operation completed. A fixed macOS machine-denial
summary appears under `localNativeSummaries` only after its source and artifact
IDs match the index; it is labelled `local-summary-not-matrix-reviewed` and
does not establish a live owner, installed state or full matrix coverage.
The matrix and artifact index are read
without creating, migrating, cleaning or chmodding local evidence. A legacy
or incomplete index returns unknown. A live owner/guest probe alone does not
prove its installed package came from the current source; that separate
`ownerSourceBinding` remains unknown unless the Android owner matches a
verified current-source correlation. This view never authorizes a native action.

`artifact-cache-check` takes exactly `{sourceSha, artifactSetId}` before a
package rebuild. It rechecks frozen package bytes, product inputs and Git
changes through `artifact-reuse-check`; `cacheEligible` is true only for a
verified same-source set with no reasons. A different source, dirty product
inputs, missing bytes or provenance uncertainty requires rebuilding. Cache
eligibility does not establish native installer admission or exact-SHA CI.

`vm-preflight-batch` takes `{reads: [{id, action, inputs}, ...]}` with one to
four distinct IDs. Only `environment-status` (configured host and bounded
observer inputs) and `linux-vm-readonly-inventory` (fixed `archlinux` host
and 1–30 second timeout) are accepted. Independent reads run concurrently.
`observationsComplete` requires a live `READY` environment observation or
a complete Linux inventory for every entry. Unknown, supplied-only,
malformed and failed observations remain unknown. The result always has
`nativeActionAllowed: false`; a subsequent native start must run its own
fresh owner, reservation and artifact admission.

`android-consent-acceptance-preflight` takes only `{host, device,
cliStageCorrelationId}` and reports fixed read-only admission categories for
the staged Android consent-denial fixture. It performs no consent action and
does not create a journal or reservation.

`windows-vm-baseline-inventory` takes only `{host: "archlinux",
timeoutSeconds: 1..30}` and returns a bounded read-only census of Windows
qcow2 candidates, QEMU descriptors and image metadata. Each candidate's
`sourceState` is `stopped-observed` only after a complete all-process file
descriptor census and QEMU generation recheck; otherwise it is `unknown`.
`noQemuObserved` alone does not prove a source is stopped. The census never
admits cloning, capture, shutdown or package testing.

`arch-qemu-holder-census` takes exactly `{host: "archlinux",
timeoutSeconds: 1..30}`. It reports a bounded read-only census of Arch QEMU
process generations, allocated memory, and file and socket holders. A
Windows baseline role is assigned only when the fixed source receipts and
live descriptors agree; incomplete observations return `unknown`. It never
admits parking, shutdown, or another native action.

`windows-vm-media-fingerprint` takes exactly `{host: "archlinux",
timeoutSeconds: 30..240}` and rehashes only two fixed existing Windows media
paths through a stable read-only file observation. It reports SHA256 and size
as byte identity; it does not establish publisher trust or admit installation.

`windows-vm-driver-fetch-start` and `windows-vm-driver-fetch-status` take
exactly `{host: "archlinux", correlationId: "<canonical lowercase UUID>",
timeoutSeconds: 30..300}`. Start creates one local intent before the fixed
VirtIO ISO download; status observes that same intent and remote destination.
The URL, SHA256, size and private destination are fixed in the reviewed adapter.
Unknown or partial outcomes are never replayable. A verified download is
fixture preparation only and does not admit a Windows clone or install.

`windows-vm-disk-probe-start/status` take exactly `{host: "archlinux",
correlationId: "<canonical lowercase UUID>", timeoutSeconds: 30..300}`. The
reviewed start makes one task-owned 8 MiB qcow2 probe after an exact local
intent; status observes that same probe. `partial` or unknown is never
replayed. A verified probe establishes only this fixed disk operation, not
capacity or admission for the planned 96 GiB Windows VM. Fresh VM start and
installer work require separate review and resource checks.

`windows-vm-secureboot-fresh-preflight` takes the same fixed Arch host,
canonical correlation and 30..300 second timeout. It reads only the reviewed
blank-guest prerequisites and returns `nativeActionAllowed: false`. When it
returns `host-components-unavailable`, its nonempty
`missingHostComponents` list identifies the fixed missing executable or package
admission fact: `qemu-system-x86_64-binary`, `qemu-img-binary`,
`swtpm-binary`, `swtpm_setup-binary`, `edk2-ovmf-package`, `swtpm-package`,
`qemu-system-x86-package`, or `qemu-img-package`. The receipt never includes a
host path, command output, or log data. For a missing package label,
`hostComponentAdmission` reports only `absent`, `version-mismatch`,
`integrity-failed`, or `query-unavailable`, derived from the fixed bounded
`pacman -Q` and `pacman -Qkk` checks. The same safe fields are preserved when a
start reaches a deterministic blocked prerequisite; the caller must not relabel
that receipt as an unknown outcome. This gate runs before firmware/media hashing
and memory/disk sampling, so null resource fields and returned pinned input
identities are not evidence that later gates passed. Repair a named host component
only through its separately reviewed host workflow, then run a new read-only
preflight correlation; never replay a start or mutation from an older correlation.

`windows-vm-fresh-preflight` takes exactly `{host: "archlinux",
correlationId: "<canonical lowercase UUID>", timeoutSeconds: 30..300}` and
observes the fixed Windows media, OVMF/KVM support, memory, disk and port
requirements. Its `ready` result remains read-only with
`nativeActionAllowed: false`; it does not create a VM, reserve resources or
authorize a later start.

`windows-vm-fresh-start/status` use the same fixed Arch host, canonical UUID
and 30..300 second timeout. Start additionally requires `reservationRequest`
with fixed `hostAlias: archlinux`, `environment:
windows-vm-baseline-20260929`, `operator: windows-baseline`,
`requestedMemoryBytes: 6442450944`, `allocationState: pending`,
`headroomBytes: 8589934592`, and the exact native-environment
`reservationIdentity` and `measurement` objects. It creates a one-shot VM
intent and consumes only the reviewed reservation transition. Status takes no
reservation request. Unknown or unrecorded-running outcomes require exact
status observation and never authorize a repeated start.

`windows-vm-fresh-screen-start/status` take exactly `{host: "archlinux",
correlationId: "<canonical lowercase UUID>", timeoutSeconds: 30..300}`.
The reviewed one-shot screen capture and status adapter returns only a bounded
frame path, SHA256 and dimensions; it never returns image bytes. Unknown
capture outcomes require exact status, without a repeated capture start.

`windows-vm-optical-boot-preflight/start/status` each take exactly
`{host: "archlinux", correlationId: "<new canonical lowercase UUID>",
timeoutSeconds: 30..300}`. Preflight checks the fixed running VM, reservation,
blank disk, and Microsoft ISO. Start writes one-shot intents before one QMP
reset and timed space key, then records before and after frame hashes. It does
not enter Windows setup. Unknown outcomes require exact status and cannot be
replayed; the route accepts no arbitrary key or VM command.

`windows-vm-optical-close-preflight/start/status` each take exactly
`{host: "archlinux", closureCorrelationId: "<new canonical lowercase UUID>",
timeoutSeconds: 30..300}`. Preflight checks that the first optical attempt
has no observed VM effect. Start writes one durable closure intent and exact
pre-effect receipt after two bounded idle samples; it sends no QMP reset or
key. Unknown closure outcomes require exact close status and cannot be
replayed.

`windows-vm-optical-attempt2-preflight/start/status` take exactly
`{host: "archlinux", correlationId: "<new canonical lowercase UUID>",
closureCorrelationId: "<verified first-attempt closure UUID>",
timeoutSeconds: 30..300}`. The closure correlation is fixed to the reviewed
pre-effect closure, and the action correlation must be new. Start has a
separate one-shot journal and permits one reset and space key only after the
first attempt's terminal closure is reverified. Unknown outcomes require
exact attempt-2 status and never authorize replay.

`windows-vm-optical-attempt2-phase-probe` takes only the fixed Arch host, the
exact existing attempt-2 and closure correlations, and `timeoutSeconds:
30..300`. It reads the current owner and typed QMP phase without a frame,
reset, or key. `phase-probed` with a `ready` probe is diagnostic evidence;
unknown phases never authorize another attempt.

`windows-vm-optical-attempt2-close-preflight/start/status` take exactly
`{host: "archlinux", closureCorrelationId: "<new canonical lowercase UUID>",
timeoutSeconds: 30..300}`. The adapter binds the fixed second attempt and
first closure, then proves no observed guest effect before recording a
second pre-effect closure. Unknown outcomes require exact closure status;
the one-shot start cannot be replayed.

`windows-vm-optical-attempt3-preflight/start/status` take exactly
`{host: "archlinux", correlationId: "<new canonical lowercase UUID>",
closureCorrelationId: "<verified second-closure UUID>", timeoutSeconds:
30..300}`. The two IDs must be distinct and cannot reuse earlier optical
correlations. The adapter verifies the exact second closure before a
third one-shot optical attempt. Unknown outcomes require exact attempt-3
status and never authorize replay.

`windows-vm-optical-attempt3-frame-collect` takes the fixed Arch host,
existing attempt-3 correlation `e80d5b29-d44f-4b22-a821-5612304564b5`,
second closure `7cbc014c-3890-422a-891a-a114d7cb779e`, and
`timeoutSeconds: 30..300`. It verifies the sealed post-frame state and saves
a private local PNG under ignored runtime evidence, returning its path and
hash. It accepts no caller image path or VM input; uncertain collection is
`unknown` with no replay authorization.

`windows-vm-optical-current-screen-preflight/start/status/collect` take
exactly `{host: "archlinux", observationCorrelationId: "<new canonical
lowercase UUID>", timeoutSeconds: 30..300}`. The adapter fixes the same
attempt-3 and second-closure correlations and verifies the sealed previous
frame and live QEMU owner. Start makes one QMP screen observation without a
reset or key; status reads its bound journal, and collect saves a private
PNG under ignored runtime evidence. An unknown start requires exact status
and cannot be replayed; callers cannot choose an image path or VM action.

`windows-msi-owner-quit-preflight` takes only `{host: "archlinux"}`. The
reviewed `windows-msi-owner-quit-start` requires the fixed Arch host, a new
canonical `correlationId`, exact source/controller/installed CLI identities,
parent and child PID generations, and a prior cleaned `statusCorrelationId`.
`windows-msi-owner-quit-status/collect` take only the quit correlation. The
one-shot public quit concerns only the identified CP117 owner; unknown status
is not replay authorization.

`windows-msi-base-pre-effect-status` takes only `{host: "archlinux"}`. It
observes the fixed failed pre-dispatch base correlation and reports `absent`
only after the owned remote stage, scheduled task, and guest leaf are absent.
It does not close a lease or run an installer.
The one-off `windows-msi-base-pre-effect-close` also takes only
`{host: "archlinux"}`; it requires repeated absence and idle proofs before
closing that exact failed campaign while retaining its original intent.

`android-fixture-tls-mint` takes exactly `{campaignId, sourceSha,
baseArtifactId, targetArtifactId}`, with optional absolute `sourceRoot` for a
clean linked worktree. It rechecks actual source and registered APK bytes,
versions and signer before creating a private disposable CA and endpoint leaf.
The create-only campaign retains source, plan, all five certificate-material
file pins and the original nested directory identity. Output contains validated
metadata and evidence locations; it never contains private key bytes or grants
guest trust, network, installer or release authority. A consumed campaign is
not replayed. Use the fresh-process `mcp_tool.sh vm-workflow
android-fixture-tls-mint --inputs-file <private-request.json>` if the running
MCP server predates this adapter.

`android-native-fixture-start` takes exactly `{host, device, campaignId,
planPath, certificatePath, privateKeyPath}`, with optional absolute `sourceRoot`
for a clean linked worktree of the same Git repository. Source validation uses
that checkout; host configuration, journals, leases, artifacts and fixture bytes
remain owned by the coordinator root. The aliases are configured,
the campaign is a canonical UUID, and the three file paths are absolute local
paths checked by the reviewed adapter. Only a host HTTPS/SOCKS endpoint is
started; the receipt explicitly leaves device mutation and installer target
admission false. `android-native-fixture-status/stop/collect` take only
`{campaignId}`. Unknown outcomes are not replay authorization. No certificate
or private key bytes are accepted or returned by these routes.

`android-endpoint-admission-start` takes exactly `{host, device,
correlationId, campaignId, sourceSha, targetArtifactId, caArtifactId,
backupCorrelationId, expectedOwner, expectedRevision,
expectedBackupSha256}`, with the same optional clean linked `sourceRoot` for
planning and target validation only. Both start routes require a NUL-free source
path of at most4096 characters; status, stop, collect and cleanup reject it.
It binds the configured disposable emulator, running
host fixture, exact package and CA artifacts, and fresh guarded OFF/backup
readback before its one-shot CA mount and two fixed ADB reverses. It neither
installs the package nor admits an installer target. `status/cleanup` take
only `{correlationId}`; uncertain outcomes require exact status and never
authorize replay. Cleanup removes only the bound temporary endpoint effects.

`android-runtime-acceptance-start` takes exactly `{correlationId,
endpointCorrelationId, cliStageCorrelationId}`. The fixed API29 adapter binds
a ready endpoint, source-matched published CLI and an empty stopped baseline.
It preserves settings/source/routing, performs guarded public ON/Find Best/OFF,
and requires fixture SOCKS plus HTTPS traffic observations. This proves selected
proxy outbound traffic, not TUN ingress. Status/collect take only `correlationId`;
unknown attempts retain their child claim. Endpoint cleanup blocks active or
uncertain children and requires the exact terminal closing owner/revision and
fresh stopped restoration proof. No arbitrary command, path or host is accepted.

`android-installer-dispatch-start` takes exact configured `host`/`device`, a
new `correlationId`, `sourceSha`, base and target package artifact IDs,
backup and public inspect correlations, expected owner/revision/backup hash,
`expectedTerminal` (`installed` or `cancelled`), CLI-stage correlation, and
three fixture CA/leaf/key artifact IDs. It owns one source-bound device lease
and a single detached installer job. `status/collect` take only
`{correlationId}` and never authorize replay. Fixed
`android-installer-callback-handoff-ready/continue` and their
`callback-status-handoff-ready/continue` observations also take only
`{correlationId}`; each callback checks its exact UI phase and operation
session before signaling once. `android-installer-abort-prelaunch` takes
`{correlationId, closingReadbackCorrelationId}`; `android-installer-reconcile`
also requires `expectedClosingOwner` and `expectedClosingRevision`. These
closure routes release only the exact lease after their respective fresh
prelaunch or terminal proofs. No route accepts an arbitrary guest command.

`linux-package-fixture-build-preflight/start` take exactly `{sourceSha,
baseVersion, targetVersion, correlationId}`, with optional absolute `sourceRoot`
for a clean worktree of the same Git repository. It applies only to source
validation: exact HEAD/origin/dev, clean tracked and untracked inventory, and
target version must match. Direct symlink roots are rejected. The coordinator
root still owns private host configuration, journals, the existing Arch claim,
artifact registration and collection. `sourceRoot` is not part of the immutable
build request and is rejected by status/collect. Preflight verifies a clean
exact `origin/dev` source and the fixed Arch build host. Start writes a
one-shot source-bound intent and host claim before dispatching the fixed
builder. `linux-package-fixture-build-status/collect` take only
`{correlationId}`; collect registers verified Linux package and fixture
receipts plus bound timing receipts only after a `ready` build. Unknown
submission or worker status is never replay authorization.
After collection, `linux-package-fixture-build-terminal-ready-status` takes
only `{correlationId}` and gives a read-only proof digest for an ended worker,
registered package bytes, timing receipts and its exact host claim.
`linux-package-fixture-build-terminal-ready-close` takes that correlation and
`closureDigest`; it preserves the build intent and releases only the matching
claim after writing a durable marker. Foreign, changed or uncertain claims stay
held. This releases a build slot, not a guest or package installer.

`linux-guest-park-preflight/start` take exactly `{correlationId,
preparationCorrelationId, guestRole, sourceSha}` for one of the four fixed
Ubuntu/Arch guest roles. The reviewed adapter loads the owner-private guest
manifest and preparation receipt itself, verifies registered source-bound
artifacts, and runs the fixed privileged idle/process census. Start writes a
one-shot intent before a graceful, exact-generation QEMU park. Status takes
only `{correlationId}`; only `parked` proves terminal absence. Unknown or
blocked outcomes never authorize replay or guest restart.

`linux-deb-arch-guest-prepare-preflight/start` take exactly `{profile,
distribution, correlationId, sourceSha, artifactIds}`. The four fixed
profile/distribution pairs map to ports 2330–2333; `artifactIds` contains only
`fixtureReceipt`, `basePackage`, `targetPackage`, and `bundleManifest`.
Preflight verifies a clean exact source and frozen package inputs. Start uses
the reviewed fixed remote driver with a one-shot local intent. Status takes
only `{correlationId}` and reports `ready` only with bound guest-manifest and
preparation-receipt artifact IDs. Unknown status forbids replay.

`linux-deb-arch-acceptance-preflight/start` take the same source-bound request
with the two preparation artifact IDs added as `guestManifest` and
`preparationReceipt`. The fixed live observer rechecks guest generation,
package/process state and the prepared source before admission. Status takes
only `{correlationId}` and reports only verified terminal `dependencies-installed`,
`installed`, or `rollback-restored` outcomes. A blocked or unknown start is not
replayed.

`linux-rpm-workspace-cleanup-start` takes exactly `{correlationId,
cleanupCorrelationId}`; `linux-rpm-workspace-cleanup-status` takes only
`{cleanupCorrelationId}`. The separately reviewed Fedora adapter permits a
single exact failed-public-job workspace deletion only after the public quit
receipt, absent process/workspace references, installed target RPM, clean
package verification and credential recovery are rechecked. An existing intent,
transport loss or missing terminal receipt remains unknown and forbids replay.
The MCP route returns success only with terminal removal proof.

**Failure grouping and safe next read.** Failed or unknown native MCP responses
now include `failureSignature` and `admissionGap`. The signature hashes only
the fixed tool/action, normalized state class, typed phase and bounded reason;
it excludes correlation IDs, paths and secrets so repeated causes group without
rewriting their separate immutable failure receipts. `sourceReceiptId` links
the signature to that response's original private receipt. A known
`causalRegression` points to the relevant quick test; otherwise
`regressionRequired` remains true. The admission gap names the missing fact
and, only when the original adapter returned a canonical correlation, an
existing read-only status call. It never authorizes a start or cleanup.

**Build phase timing.** `build-timing-report` reads immutable private phase
receipts and takes exactly `{sourceSha, pipelineId, runId, receipts:
[{path, sha256}]}`. `sourceSha` must equal checked-out HEAD; `runId` is a
canonical UUID. Each path must be a regular owner-only mode-0600 JSON file
directly under the owner-only mode-0700
`.rag_index/build-timings/` directory. The file's SHA-256 must match the
request. Each JSON record has exactly `schemaVersion: 1`, `sourceSha`,
`pipelineId`, `runId`, `hostAlias`, `phase`,
`startedMonotonicNs`, and `finishedMonotonicNs`. Phase is one of
`gradle`, `runtime-prep`, `packaging`, `upload`, or `guest-staging`.
Build and staging owners emit those timestamps from their own monotonic clock
and copy the receipt into the private index; the report itself never creates
or changes one. It verifies source, run, owner, hash and bounded duration,
sums repeated phase samples, reports the largest measured phase, and labels
every missing phase `unmeasured`. A partial report is not a completed
five-phase timing study.

**Continuation native adapters.** `vm_workflow` exposes narrow, journaled
`android-package-install-start/status/collect`, `linux-rpm-base-prepare-start/status`,
and `windows-msi-base-start/status` actions. Each start binds an owned device or
guest, registered exact package bytes, the opening owner/package state, and a
correlation before submission. An unknown outcome is not replayable; status and
collect observe only the same correlation. Read-only admission actions are
`android-public-inspect`, `linux-rpm-base-prepare-preflight`,
`linux-rpm-owner-observe`, and `windows-msi-base-preflight`. The Android install
collect result is package evidence only until a fresh post-install mutation
guard succeeds. Use the exact input schemas enforced by the fixed adapters and
the CLI fallback when a long-running MCP server has an older action inventory.
The MCP dispatcher rejects a directly selected native adapter whose source
file changed after that server process started and points to the fresh-process
fallback, so that adapter cannot silently apply pre-edit admission rules.
`android-package-install-reconcile` accepts only `installCorrelationId`,
`currentReadbackCorrelationId`, `expectedCurrentOwner` and
`expectedCurrentRevision`. It releases a historical device lease only after
the exact install is terminal, a detached current readback matches its target
package and owner, and a fresh public inspection confirms runtime off and no
operations. Unknown or changed state retains the lease; it never repeats an
install.

`windows-msi-base-reconcile` accepts only the exact existing base
`correlationId`. It performs a fixed, bounded read of the already recorded
intent, matching QGA generation, bootstrap result, and durable guest result.
It classifies a generic bootstrap `triggered:false` record as
`failurePhase: "bootstrap"` and
`failureType: "task_trigger_outcome_ambiguous"`. The bootstrap may have
registered or started the task before its broad catch, so this remains unknown;
it never infers a no-effect failure or success from that record or a missing
receipt. The route does not stage bytes, start or
replay an installer, alter a guest, close a campaign, or clean up. Unknown
results retain `replayAllowed: false` and require preserving the correlation.

`windows-msi-base-diagnostic` accepts the same sole exact existing
`correlationId`. It is a separate read-only observer for an unresolved base
attempt. It returns only the correlation, a bounded binding state
(`exact`, `mismatch`, or `unverified`), and one checkpoint:
`local-intent`, `descriptor`, `remote-stage`, `remote-binding`,
`remote-dispatch-absent`, `remote-dispatch-malformed`, `qga-protocol`, or
`bootstrap-result-proof`. For an exactly bound absent dispatch record only, its
fixed read-only QGA census also returns bounded task, correlation leaf/result,
correlation-bearing PowerShell, product/version, and installer states. Those
fields are observations, not proof that the bootstrap had no effect or that a
closure is safe. It does not return guest output, paths, task data, credentials,
or installer details. Its `guestProofFailure` is one of `none`,
`qga-exec-rpc-or-protocol`, `qga-status-rpc-or-protocol`,
`qga-status-exited-malformed`, `qga-status-terminal-fields-malformed`,
`qga-status-running-timeout`, `qga-truncated`, `powershell-nonzero`,
`powershell-empty-or-malformed-output`, or `projection`; every non-`none`
code forces the proof fields to `unknown`. QGA's optional truncation fields are
accepted only when absent or literal `false`; `true` or a non-boolean is rejected.
For a `powershell-nonzero` census result, `guestProofFailurePhase` reports only
one fixed phase: `task`, `leaf`, `process`, `product`, `installer`, or `output`.
Other proof failures report `unavailable`, and a complete proof reports `none`.
When the failure is `projection`, `guestProofProjectionReason` is only one of
`missing-or-extra-fields`, `version-or-phase-invalid`,
`nonzero-failure-envelope-invalid`, `success-enum-invalid`,
`product-version-invalid`, or `internal-error`; it never exposes the rejected value. For only
`missing-or-extra-fields`, `guestProofProjectionSchema` adds a fixed-order
nine-bit `presenceMask` for `version`, `phase`, `task`, `leaf`, `result`,
`correlationPowerShell`, `product`, `installedVersion`, and `installer`, plus
an `extraFieldCount` capped at 9. It never includes field names beyond that
published order or values. The projection reason is `none` for a complete proof
and `unavailable` for every other proof failure.
Every checkpoint preserves `state: "unknown"`,
`replayAllowed: false`, and `nativeActionAllowed: false`; a missing stage or
result proof does not establish that the accepted bootstrap had no effect. The fresh-process CLI fallback is
`mcp_tool.sh vm-workflow windows-msi-base-diagnostic --inputs-file <private-json>`.

`windows-msi-base-stage-diagnostic` accepts only the same existing
`correlationId`. It validates the recorded source-bound base artifact locally,
then performs a fixed read-only QGA query of that correlation's guest
`base.msi`. It returns only `guestStage` (`absent`, `partial`, or `full`), the
bounded observed byte count, and booleans for the registered size and SHA-256
matches. The digest is calculated inside the guest; MSI bytes, raw hashes,
paths, task output, and credentials never leave it. `full` only proves the
staged file matches the immutable registered artifact; it does not prove a task
or installer ran. Missing, malformed, truncated, changed-generation, or
artifact evidence remains `unknown` with `replayAllowed: false` and
`nativeActionAllowed: false`. The fresh-process CLI fallback is
`mcp_tool.sh vm-workflow windows-msi-base-stage-diagnostic --inputs-file <private-json>`.

`windows-msi-base-unknown-close` accepts only the two reviewed correlations
`2ace6a48-ba60-4705-9200-4ff857f2aba6` and
`45e4514a-c629-4f3b-99bc-aad599640d29`, each bound to source
`19be9df22cbab8086c26e5ca907d9569a5a28a08` and its recorded command hash. It
is recovery for those lost base submissions only. Before cleanup it requires two independent exact
diagnostics with absent remote dispatch, a present correlation leaf, absent
task/result/process/msiexec, the single `2.1.17` product, two fresh QGA
censuses, and a normal idle readiness readback. It then fsyncs an immutable
local close intent. The remote action is status-first and idempotently handles
each leaf/stage partial state; it deletes only the exact correlation leaf and
an exactly bound stage containing only `binding.json`. Two subsequent censuses
must prove both are absent before the base role is recorded as
`unknown-cleaned` and the CP117 campaign is closed. Lost, truncated, malformed,
or changed evidence leaves the correlation unknown and non-replayable.

`windows-msi-base-unknown-close-status` has the same reviewed fixed correlations
and is read-only. It reports only a bounded phase/reason: local intent,
descriptor, dual diagnostic, cleanup-status guard or parse, readiness, or
lease. When a cleanup census is valid it includes only its bounded task, leaf,
result, correlation-PowerShell, product/version, installer, remote-stage and
mutation fields. It does not write the close marker, delete the guest leaf or
stage, alter a campaign, expose raw guest output, or retry an installer.

`windows-msi-base-transfer-preflight` accepts only one of those already
recorded correlations. It validates the source-bound local MSI registry record,
the exact CP117 generation, bounded QGA execution, and whether `C:` has room
for two copies of that immutable MSI. It returns only QGA health and the
`enough` or `insufficient` disk category. It creates no guest leaf, file, task,
endpoint, server, credential, or installer action. A malformed or truncated
reply remains `unknown` and non-replayable.

`windows-msi-base-transfer-network-admission` accepts only the separately
recorded partial-transfer correlation. It reads the exact CP117 QEMU
generation, bounded metadata from that QEMU binary for every unbound device,
and a bounded QGA PowerShell projection of the active guest adapter and IPv4
default gateway. Only one QEMU user-mode NIC plus the exact SLIRP gateway
(`10.0.2.2`) produces `eligible`, with a future host service bound to
`127.0.0.1` and reached by the guest at that gateway. It neither binds a port
nor creates a server, changes QEMU networking, connects from the guest, or
touches the existing loopback fixture server. Any alternate or ambiguous NIC,
gateway, QGA reply, or truncation stays `unknown` and non-replayable.

`windows-msi-base-transfer-endpoint-probe` accepts only that same reviewed
partial-transfer correlation. After a fresh network admission, it creates one
short-lived Python HTTP listener on Arch `127.0.0.1` with a random port and
one-time path/body nonce. A bounded QGA PowerShell request rechecks the QEMU
user-network topology, disables the guest HTTP proxy for this request, and
accepts only the exact nonce digest. The MCP result contains only
`reachable`, `blocked`, or `unknown`; it never returns the endpoint, nonce,
guest output, or MSI bytes. It always stops the listener and proves the port
is no longer bound before returning. Lost replies, QGA truncation, spoofed
proof, topology changes, and uncertain cleanup remain `unknown`, with no
product action or replay authority. Use the fresh process fallback
`mcp_tool.sh vm-workflow windows-msi-base-transfer-endpoint-probe --inputs-file <private-json>`.

`windows-msi-base-transfer-endpoint-status` accepts only that same correlation
after an uncertain endpoint cleanup. It reads the private persisted worker
PID/generation, port, and nonce-digest record and returns only bounded worker
(`running` or `stopped`), listener (`owned`, `absent`, or `unattributed`), and
port (`bound` or `free`) facts, plus `startup` (`ready`, `missing`, or
`unknown`) and `receipt` (`seen`, `not-seen`, or `unknown`) when its private `ready.json` and terminal
worker receipt match the persisted identity. It never returns the port, URL,
nonce, digest, or guest output. PID reuse, malformed records, changing CP117
binding, and any unrecognized listener state remain `unknown`.

`windows-msi-base-transfer-endpoint-reconcile` first runs that status check.
It stops a listener only when the exact persisted worker generation owns the
exact recorded bound port. It then performs a fresh status read; a lost stop
response can complete only when that read proves the worker stopped and port
free. An unattributed listener, PID reuse, or unknown observation never causes
a kill. This action has no installer, MSI, guest product, or replay behavior.

`windows-msi-http-transfer` is the fixed CP117 fallback for a verified base MSI
after the QGA byte stream stopped early. Its `inputs` contain a fixed `phase`:
`ps5-preflight` takes only `host: "archlinux"`; `prepare` takes the same exact
source-bound request as `windows-msi-base-start`; later phases take only the
private transfer `correlationId`. The workflow derives the registered MSI,
current QEMU generation, owner SID, paths and one-use endpoint from verified
state. Run the parser preflight, then prepare, stage-start/status,
listener-start/status, guest-download/status, guest-task-cleanup/status,
listener-stop and ready-for-base. Only a fully verified `ready-for-base` result
admits `windows-msi-base-start-from-transfer` with the same base request and
correlation. That base action independently checks the guest file owner,
reparse points, size and SHA-256, then uses the existing lease and installer
bootstrap without repeating QGA byte writes. Failed transfer states use the
explicit guest-abort/abort-cleanup and status phases; successful base terminal
readback uses guest-file-cleanup/terminal-cleanup and status phases. Unknown or
running states never authorize replay or cleanup. The public result never
exposes the one-use endpoint, token, port or guest task command.
If `guest-status` stays `unknown`, use the read-only `guest-diagnostic` phase
with the same correlation before any cleanup decision. It reports only bounded
task state, principal/action/SID matches, guest leaf class, and a fixed reason
enum; it never returns task arguments, paths, raw output, or credentials.
For a principal or guest-leaf mismatch, `guest-diagnostic-detail` adds only
finite subreason codes for the task account/logon/run level and the failing
path component, fault kind and owner class. It remains read-only and does not
authorize retry or cleanup.
`guest-owner-census` reads the seven fixed CP117 transfer path components in
one bounded QGA observation and returns only kind, reparse and owner classes
for each. It exposes no path, ACL, SID, or raw guest output and cannot mutate
the existing correlation.
If `listener-status` is `unknown` after a guest download, use read-only
`listener-diagnostic` with the same correlation. It reports finite binding,
stage-file, intent, worker, receipt, and port-owner classes plus a bounded
reason. It does not return a path, process ID, port, endpoint, or payload hash,
and it never stops or cleans up the listener.

The recovered CP117 generation currently uses the fixed internal
`windows_cp117_base_source_refresh` direct procedure while the complete native
flow is being established under TEST-002. Its source-refresh baseline is setup
for a source-matched update test. General public update admission still requires
a newer version and matching source; an older installed JAR/helper lineage does
not grant equal-version public update authority. Host upload checks the actual
file-size limit before its attempt and immediately before writing, and retains
raw streams, exit status and EOF before parsing. Listener and ordinary-user task
submission are separate one-shot stages. Submission does not prove downloaded
bytes, installer metadata, cleanup or installed-package acceptance. The next
read-only stage must verify the held guest MSI and exact task/principal before
selecting a baseline setup command. Preserve each consumed correlation and
original unknown; do not change older fixed VM descriptors to make a public
route accept this recovered generation. Integrate and retest the complete proven
flow through MCP after direct native success and applicable recovery cases.

`windows-msiexec-service-diagnostic` is a fixed CP117 read-only observation for
the post-base-install Windows Installer process. Inputs are exactly
`{"action":"preflight"|"status","host":"archlinux"}`. It binds the current
guest and terminal base receipt before inspecting the one recorded process
generation, `msiserver` service, and bounded transaction indicators. The result
contains finite classes only and always sets `readinessAdmitted: false`; an idle
candidate does not clear the separate `windows-msi-base-readiness` gate.

When the QGA bootstrap process record expires after a successful base install,
`windows-msi-base-preflight` with `profile: "terminal-reconcile"` parses the
fixed PowerShell 5 proof, and `windows-msi-base-terminal-reconcile` with the
exact correlation reads the durable result. It independently checks current
guest/source binding, the fixed task identity and action, the staged MSI, and
installed CLI/JAR/helper hashes. A terminal result is read-only; the base role
still requires a separate idle-readiness check before it can be finished.
`windows-msi-base-finish-observed` takes only that correlation and rereads both
proofs before the one-use base campaign role transition. An unknown transition
must be reconciled from its campaign receipt rather than replayed.

`vm_workflow("rpm-proc-observe", inputs={"host":"fedora2328","environment":"fedora2328"})`
is a fixed read-only process-visibility check for the disposable RPM guest. It
returns bounded same-UID PID generations and the phase of any unreadable process
entry without exposing command lines, descriptors or paths. `procState=unknown`
and `ok=false` require investigation; unreadable entries are never treated as
absent or as permission to start the installer. A running MCP server may retain
the old action inventory after a source edit; the equivalent fresh-process route
is `mcp_tool.sh vm-workflow rpm-proc-observe --inputs-file <private-input-json>`.
`rpm-proc-observe-privileged` accepts the same exact keys and runs only a fixed
read-only `sudo -n` observer on that positively identified disposable guest.
It filters to the fixture UID and returns bounded visibility without command
lines or filesystem targets. A clear visibility result does not itself prove
installer cleanup; the workspace-reference criterion still needs an exact
owned-process check.

`linux-rpm-fixture-dispatch` accepts exact `sourceSha` (current `origin/dev`),
`baseVersion` and a new UUID `correlationId`. It journals a private no-replay
intent before dispatching only the Linux Desktop Package fixture job on `dev`.
`linux-rpm-fixture-status` accepts only that correlation and binds the run's
display title, exact head SHA and one unexpired artifact name/ID. Unknown
dispatch remains unknown and must not be repeated with the same intent.
Download the exact artifact ID and independently verify the contained snapshot,
receipt, base/target RPM bytes and package headers before admitting either RPM
to a native guest; workflow success alone is build evidence.

`vm_workflow("android-admission-readback", inputs={"host":"archlinux",
"device":"api35","correlationId":"<new-uuid>"})` performs fixed read-only
package, owner, operation-history and routing inspection on a configured AVD.
Optional `expectedBaseSha256` binds the installed base APK to separately verified
signed artifact bytes; optional `timeoutSeconds` is 1..60. It requires shell
UID 2000 and a non-debuggable package, creates an exclusive private routing
backup under the configured fixture root, and returns only its path/hash/size
plus a redacted controller/revision guard. Unknown transport or owner changes
preserve the correlation and any partial backup; they do not authorize mutation
or retry. A new correlation is required for a genuinely new read-only snapshot.
`vm_workflow("android-admission-status", inputs={"host":"archlinux",
"device":"api35","correlationId":"<original-uuid>"})` observes that exact
private backup stage and the current public owner after response loss. A backup
alone is not admission; inspect its result before a new snapshot or any write.
`android-admission-preflight` uses the same configured host/device and a new
UUID correlation, with optional `timeoutSeconds` 1..60. It emits ordered
bounded stage evidence for identity, package bytes, reverse mappings and public
read-only commands. Timeout preserves completed stages and the last stage;
its result never authorizes a product mutation or substitutes for the full
private routing backup.
For large routing exports, `android-readback-start` accepts exactly configured
`host`, `device`, a new UUID `correlationId`, and `expectedBaseSha256`. It writes
a private local no-replay intent before one detached, fixed read-only device
job. `android-readback-status` and `android-readback-collect` accept only that
correlation; they inspect the durable remote result without resubmission.
A submitted or running job is not mutation admission. Only a complete private
backup with its hash and same-owner/revision guard can support a later action.
Timeout or unknown keeps the original correlation and `replayAllowed=false`.
The wrapper may report `ok=true` for a correctly observed running job; only
`android-readback-collect` with `admissionReady=true` certifies its completed
readback, and a later write still requires a fresh owner/revision check.

`vm_workflow("windows-msi-preinstall-status", inputs={"host":"archlinux",
"jobId":"<exact-protected-job-uuid>"})` observes one configured CP117 guest's
protected installer status and fixed enum-only preinstall diagnostic through
QGA file reads. Optional `timeoutSeconds` is 1..30. It binds the guest socket
to its running QEMU generation and the status to the exact job ID. Missing or
unreadable diagnostic leaves remain explicit; the action never starts,
cancels, replays or infers an MSI installation. Use a fresh-process MCP CLI
fallback after server source changes until the MCP session is reloaded.
`windows-msi-powershell-preflight` accepts only `host="archlinux"` and runs a
fixed inert PowerShell 5 compatibility self-test through the positively bound
CP117 QGA guest. It checks compressed bootstrap parsing and UTF-8 JSON file
round-tripping in a unique temporary leaf, then removes that leaf. It does not
submit the app CLI, UAC, MSI or VPN action; only `state=passed` clears this
fixture transport preflight.

`windows-msi-public-start` accepts exactly `host="archlinux"`, a new UUID
`correlationId`, `sourceSha`, registered `fixtureReceiptArtifactId`,
`baseMsiArtifactId`, `targetMsiArtifactId`, and optional `timeoutSeconds`
(1..30). It checks the configured CP117 guest and a same-source complete MSI
pair, writes a private no-replay intent, then submits one fixed original-user
public update request. `windows-msi-public-status` and
`windows-msi-public-collect` accept the exact `host` and `correlationId`, plus
optional timeout, and observe that durable intent without submission. Unknown
submission is not permission to retry. A collected protected terminal result
does not assert installation, target bytes, relaunch or cleanup; those need
independent native proof before an acceptance receipt.

Darwin `admit-plan` accepts historical nonzero swap only with a caller-supplied
`measurement.platform="darwin"` and exactly two `samples`. Each sample has
`observedAtUnixMs`, `freePercent`, `pressure="normal"`, `pageouts` and
`swapUsedBytes`; timestamps must be recent, ordered and at most 30 seconds
apart. Both samples must retain guest memory plus host headroom, with unchanged
pageouts and non-growing swap. The latest swap value must match the top-level
measurement. This is conservative planning arithmetic, not a VM-start permit;
`environment-reserve` records the separate owned allocation.

### Compact guidance and failure evidence

Native tool responses include `nextAction` with a safe existing observation or
verification route where known. `replayAllowed: false` forbids treating a timeout
as permission to repeat a mutation. Unknown states default to evidence inspection.
At the MCP response boundary, a canonical UUID `correlationId` from the request
or adapter identity is returned when the adapter omits it. An `unknown` or
`submitting` result always receives `replayAllowed: false`, even if a lower
adapter accidentally allows replay. The boundary does not infer success from
these fields.
When an adapter supplies bounded lowercase `failurePhase` and `failureType`
tokens, an uncertain response also includes `uncertainty: {phase,
failureType}`. Transport text and free-form exception messages are never
converted into typed failure values.

Failures and uncertain results automatically record allowlisted private evidence
under `.rag_index/native-failures`. Responses return its ID/path, classification
and counts. Receipts preserve correlation, available artifact identities and a
fingerprint of current agent-tool Python modules (including dirty modules), not a
claim that a product package matches that source. Raw configuration, credentials,
commands and exception messages are excluded. Failure to save evidence never
changes the original result. Repeated identical evidence is deduplicated.

Public contract tests start the actual FastMCP stdio server with a temporary root,
exercise registered actions and validate serialization, verification failures and
guidance. They run when the optional MCP dependency is installed; ordinary unit
and native acceptance checks remain required.

New MCP registrations require a server/session reload to appear in an existing
client inventory. Until then, use the same implementation via `mcp_tool.sh
ssh-workflow inventory`, `ssh-workflow probe --host <alias>`, or `vm-workflow
<action> --inputs-file <private-json>`. Do not fall back to ad-hoc SSH routes.
Agent-tool discovery tests and focused native-tool tests run in the ordinary
`agent_tools/tests` suite and managed prepush.

### Nested SSH connection recovery

`ssh_workflow("connection-recover", host=...)` checks the configured nested
control socket before creating an isolated replacement connection. It is limited
to configured nested hosts. A nested profile's optional `password` supplies the
authorized key passphrase through SSH stdin and a temporary private askpass file;
the value is never a command argument or ordinary tool result.

A private local intent records the exact new socket before submission. A repeated
call observes that socket and does not create another connection after an uncertain
result. Existing sockets are never removed or replaced. Recovery intents are keyed by the configured route identity, so adopting a ready recovered socket does not make its later expiry collide with the previous intent. Completed legacy receipts remain preserved; unknown or foreign legacy receipts fail closed. Recovery does not restart
any VM, installer, VPN or product process. A ready recovery receipt identifies the
socket for the coordinator to adopt in its private host inventory after verification.

Use `ssh_workflow("connection-adopt", host=...)` (or the equivalent CLI action)
to perform that adoption. It verifies the immutable ready recovery intent and
socket, pins the private inventory and route, and holds the shared inventory
writer lock. A durable create-only fence precedes replacement; unknown attempts
cannot replay. Only `remoteControlPath` changes. Both inventory publishers use
the same lock; arbitrary external writers are outside its cooperative guarantee.
After a ready result, run the fixed connectivity probe. Adoption never starts a
new master or changes a VM, installer, VPN or product process.

### Read-only Android observation

A private host entry may include `androidDevices`, mapping a device alias to
exactly `adb`, `cli`, `serial`, `expectedAvd`, and `api`. Executable paths are
absolute remote POSIX paths; serial names an owned emulator and API is 29 or 35.
Use `ssh_workflow("android-observe", host=..., device=...)` or CLI
`ssh-workflow android-observe --host <alias> --device <alias>`.
The observer verifies shell UID 2000, API and AVD identity before public CLI reads,
captures all five global proxy settings, and pins the configured ADB environment
for status and operation-list reads. It rejects owner replacement. It cannot
start, stop, install, refresh or modify the device. Transport loss remains unknown.

### Verified fixture staging

A host may declare `fixtureTransferRoot`, an existing private remote POSIX directory
owned by the SSH user with mode0700. `ssh_workflow("fixture-publish", host=...,
transfer={sourceDirectory, owner, environment, correlationId})` stages only the
canonical desktop update entrypoint and its two required sibling modules. Prepare
these with `prepare_desktop_update_fixture.py stage-entrypoint`, then generate
`SHA256SUMS.txt` with `native_fixture_manifest.py`. This first scenario does not
transfer arbitrary packages or execute the received scripts.

The tool reserves a private local intent before submission and binds it to the
host, transfer root and unique correlation. The remote destination is exclusive;
receipt publication follows complete byte/hash verification. After interruption,
use `fixture-status` with the returned identity. Never resubmit the same correlation
or create another transfer merely because an observation timed out. Existing
partial transfers remain evidence. The CLI accepts publication fields through
`--transfer-file` and recovered identities through `--identity-file`.

`ssh_workflow("apk-publish", host=..., transfer={apkPath, manifestPath,
receiptPath, owner, environment, correlationId})` stages one frozen Android APK
as `app-nativeFixture.apk`. The source must match its artifact receipt and exact
manifest bytes. Publication snapshots and streams verified bytes into an exclusive
private destination; the receipt is written last. It does not install the APK or
replace Android package/signer admission. Use `apk-status` with the returned
identity after interruption; a timeout never authorizes another publication.

Job and transfer observation currently require key/agent profiles on a POSIX
coordinator. Password-backed connectivity probes remain separate from these actions.

### Fixed continuation acceptance adapters

`android-recovered-endpoint-stage-collect` takes exactly `correlationId`,
`historicalCorrelationId`, `recoveryCorrelationId` and `stageCorrelationId`,
as four distinct canonical UUIDs. It revalidates the separate stage cleanup's
immutable terminal, stopped public baseline and normal API29 ADB principal.
Its component reconciliation result preserves the original unknown outcome;
it grants no installer or runtime admission and accepts no paths or commands.

`windows-cp117-cp95-task-retire-tail-close-pre-effect` takes `{}` and closes
only verified pre-effect old tail `60c5d5da-1d80-492b-90b5-7a4a9ad48b34`.
Separate fixed `windows-cp117-cp95-task-retire-successor-start` and
`windows-cp117-cp95-task-retire-successor-status` take `{}` and bind fresh child
`7cc61627-2881-4cc3-887d-a5bf545ed2ca` to original retirement
`9a5d3d6a-5f43-4a3f-9e4e-f90b9cc86e86`. Start requires the exact closure marker,
absence of an old child reservation, current guest generation and owned task
proof, then creates its separate intent before its single scoped task action.
Unknown results retain the child intent; observe status rather than resubmitting.
Only `retired/complete` proves linked child and parent retirement.

`android-endpoint-cleanup-readmission` and `android-endpoint-cleanup-readmitted`
accept exactly distinct `correlationId` and `readmissionCorrelationId` UUIDs.
The first retains cleanup-only replacement-owner proof for an exact failed API29
mount attempt; it never modifies the original intent. A shell receipt explicitly
leaves mount and namespace observations unverified. Cleanup guards temporary root,
then verifies the current namespace, stage, CA, package, owner, revision, full
rules, stopped runtime and final operations before removing only the owned stage
and unrooting. Unknown cleanup retains its lease and evidence.
`android-endpoint-cleanup-readmission-status` observes the original request;
`android-endpoint-cleanup-mount-diagnostic` observes a retained admitted receipt.
Both use the same two UUIDs, return finite observations, and authorize no cleanup.
`android-endpoint-cleanup-readmitted-status` observes a completed cleanup using
those same immutable original/request/readmission records. It verifies current
public state and full routing twice, absent local/remote leases and children,
and exact stage/CA absence in the unchanged namespace. Fixed verified `su 0,0`
reads establish namespace evidence after unrooting; public requests remain
UID2000. The observer performs no writes, root/unroot, mount, removal or claim
release. Its outer3130-second bound derives from the serial subprocess ceilings.
The ordinary original-owner status route remains unchanged. A terminal
observation grants no installer or runtime admission.
The mount diagnostic does not invent an opening mount baseline. On command failure,
its optional `commandDiagnostic` contains only finite `phase`, `outcome` and
`stderrClass` values; it never returns command text, paths or raw stderr.

`android-consent-grant-acceptance-start` accepts exactly `host`, `device`,
`correlationId`, `artifactId`, `cliStageCorrelationId`,
`openingReadbackCorrelationId`, `expectedBackupSha256`, `expectedOwner`, and
`expectedRevision`, with fixed Arch/API35 profiles. It saves source/settings
before checking an empty stopped VPN baseline, then requests and observes visible
consent through the public app boundary. Status, collect, diagnose, and reconcile
accept only the original `correlationId`. Read-only `reconcile-status` and
`reconcile-diagnose` use that same correlation to inspect claim/lock state and
current guard failures; neither closes claims nor proves consent. Diagnosis reports current finite facts,
not historical reconstruction. Reconciliation closes only verified owned claims
of a terminal pre-ON baseline rejection; it preserves the original unknown
outcome and explicitly reports no observed grant. An actual grant and successful
traffic require their separate native proofs.

Fixed no-input `windows-cp117-cp95-task-retire-*` observations and recovery actions
retain original retirement `9a5d3d6a-5f43-4a3f-9e4e-f90b9cc86e86`.
`diagnose` and `finish-diagnose` are read-only. `finish` can create only a missing
completion marker after complete archive, absence and idle proofs; it never
unregisters tasks. The separately journaled `tail-start` successor
`60c5d5da-1d80-492b-90b5-7a4a9ad48b34` can retire only the exact fifth archived
task after proving the first four absent. `tail-status` verifies both linked
journals; `tail-diagnose` reads bounded child-journal state. All remain specific to
this preserved fixture history. Unknown results never authorize replay.

`android-vpn-permission-reset-start` accepts exactly `correlationId`, `artifactId`,
`cliStageCorrelationId`, `openingReadbackCorrelationId`, `expectedBackupSha256`,
`expectedOwner`, and `expectedRevision`. The fixed disposable API29 scenario
sets only the identified package's `ACTIVATE_VPN` mode to `ignore` after fresh
source, package, stopped owner and full backup admission. It requires no active
endpoint lease. Status and collect accept only the original `correlationId`;
unknown results retain the lease. Collection verifies permission absence,
stopped runtime, unchanged rules and the complete staged CLI hashes before
closing the exact lease. This prepares a fresh visible consent test; it does
not grant permission or prove runtime traffic.

`vm_workflow("android-cli-stage-start", inputs={host, correlationId, artifactId})`
publishes one verified, current-source Linux x86_64 RPM's complete desktop CLI
tree into a private Android fixture host stage. `android-cli-stage-status` and
`android-cli-stage-collect` accept only `correlationId`; they rehash the staged
RPM and tree. An unknown transfer is not replayable. This stage does not install
the Android APK or start a runtime.

`vm_workflow("android-document-acceptance-start", inputs={host, device,
correlationId, artifactId, cliStageCorrelationId, expectedOwner,
expectedRevision})` runs the fixed API29 48 MiB routing-document scenario only
after the exact APK and current CLI stage are admitted. Status and collect accept
only `correlationId`. Its receipt reports full and cold reads, export, restore,
retained wait and same-request retry separately; false fields must not be
promoted as passed scenarios. Unknown outcomes retain their device lease.

`android-action-acceptance-start` is a separate fixed API29 small-frame
same-request scenario. It requires `{host, device, correlationId, artifactId,
backupCorrelationId, expectedBackupSha256, expectedOwner, expectedRevision}`
and uses the public provider with one explicit UUID for import and retry. It
checks one operation/revision, rejects changed-payload reuse, restores the
verified opening routing and keeps the runtime off. Status and collect take only
`{correlationId}`. Uncertain transport retains the journal and device lease;
this receipt does not claim a large-document retry or API35 acceptance.

`android-consent-acceptance-start` is the fixed Android VPN consent **denial**
scenario on an owned English API35 fixture. It requires exact `host`, `device`,
`correlationId`, `artifactId`, `cliStageCorrelationId`,
`openingReadbackCorrelationId`, `expectedBackupSha256`, `expectedOwner`, and
`expectedRevision`. `openingReadbackCorrelationId` must identify a completed
`android-readback-collect` receipt; the synchronous admission readback is not
accepted. It captures the visible system denial, checks the public
result and restores the opening state. Status and collect take only
`{correlationId}`. The MCP route has no grant option; an uncertain result keeps
the device lease and is not replayable.

`android-document-recovery-start` is a separate one-shot API29 restore for an
exact unknown document correlation. It requires `host`, `device`,
`recoveryCorrelationId`, `unknownDocumentCorrelationId`,
`openingReadbackCorrelationId`, `currentReadbackCorrelationId`, `artifactId`,
`cliStageCorrelationId`, `expectedOwner`, and `expectedRevision`. Admission
checks the original worker's exact terminal failure and stopped PID generation,
the preserved 239-byte opening export, current larger routing readback, exact
package/CLI bytes and runtime-off owner. `status` and `collect` accept only
`recoveryCorrelationId`; they never resubmit. `android-document-recovery-finalize`
takes that correlation plus `closingReadbackCorrelationId`, `expectedOwner`,
and `expectedRevision`. It releases the original document lease only after a
fresh live readback and public inspection prove the opening rules returned.
Unknown recovery keeps both journals and the lease for inspection.

`vm_workflow("macos-fixture-guest-stage-start", inputs={correlationId,
sourceSha, guestRoot, baseSha256, baseSizeBytes, targetSha256,
targetSizeBytes})` verifies registered same-source DMGs and repairs only the
mode of exact task-owned copies in the disposable Tart guest after hashing both.
Status and collect accept only `correlationId`. It neither starts a fixture
server nor submits an installer. An uncertain mutation cannot be resubmitted.

`macos-machine-server-stop-start` takes the exact accepted machine campaign
and HTTPS server identity: schema version, source SHA, correlation, scenario,
job/operation/boot/reservation IDs, fixture receipt artifact ID, server
instance/PID/start identity, and ready-receipt SHA256. The reviewed adapter
checks the trusted campaign, writes a durable stop intent, then sends one
generation-bound server signal; its start state remains unknown and cannot
be replayed. `macos-machine-server-stop-status/collect` take only
`{correlationId}`. Only fresh status `complete` proves current server absence;
collect labels its receipt historical with `currentState: unverified`.

### Fixed CP117 retirement recovery

`windows-cp117-guest-agent-recovery-successor-{preflight,parser,start,status}`
is the fixed successor to the preserved8dbe unknown service attempt. It admits
only an unchanged old service generation, absent old journal/task, repeated
exact QGA lock evidence, idle product state and the fixed separately correlated
SYSTEM journal/task. Start consumes a create-only intent once; status must prove
its exact protected terminal, task action and fresh restarted service. These
actions take `{}`. They cannot replay the original attempt or stop the product.

`windows-cp117-retirement-recovery-{preflight,parser,start,status,finish}` takes
`{}` and removes only the fixed result-only e848 remnant after fresh protected
service recovery and remaining-tree admission. It parses the exact prospective
PowerShell before dispatch, journals the action before deletion, confirms root
absence before writing the guest terminal, and gates host cleanup and lease
closure on that terminal. An after-delete state without a terminal remains
observation-only. Historical attempts and receipts are retained.

### Fixed c32 historical baseline admission

`windows-cp117-c32-archive-diagnose` and `windows-cp117-c32-archive-preflight`
take exactly `{leaseId: "<new canonical UUID>"}`. The diagnostic reads local
historical terminal/cleanup bindings. Preflight additionally checks the old
closed campaign remotely, original-source transfer cleanup, fixed host staging
metadata, and fresh guest task/file/process observations. It preserves original
source and artifact identities after HEAD changes; ordinary mutation admission
still requires current source. Outputs expose finite phases and guard codes only.

A completed task and result directory may remain historical evidence. Their
presence alone cannot admit another installation: the verifier must bind the
exact original task action/principal, successful terminal payload and absence of
correlated work. `windows-cp117-c32-host-archive-self-test` takes exactly `{}`
and runs two inert temporary Linux filesystem cases on configured Arch: exclusive
rename and destination-race rejection. Its component result proves no VM behavior.

`windows-cp117-c32-host-archive-start` and `-status` also take exactly `{}`.
Start verifies fixed historical admission and fresh retained-terminal evidence,
persists an exclusive private intent, normalizes the two metadata files to0600,
and atomically moves their exact directory into host history without overwriting
a destination. Guest task/results remain preserved. Start is one-shot; an unknown
response permits status only. Status checks original source/artifacts/generation
and exact archived metadata read-only. Subsequent admission requires fresh archive
proof whenever the local archive journal exists. Unknown observations never
authorize replay.

The source campaign `reservation-diagnose` also performs read-only historical
admission checks. Its finite `blockers` identify c32, pre-effect, transfer-recovery
or unknown-closure categories and phases. It preserves all original records and
does not create a new base intent or permit an installer replay.

Source campaign `diagnose` binds an existing source-specific intent and returns
the finite pre-dispatch gate (`legacy-job`, `legacy-idle`, `legacy-tasks`, or
`legacy-history`) without writing the legacy attestation or claiming a lease.
At `legacy-tasks`, a verified read-only census may add bounded counts for the
fixed historical names and all other MCP tasks. Counts do not prove task action,
principal, terminal state or installation admission. Preserve an uncertain intent
and never replay start based on this diagnostic.

`windows-cp117-historical-base-archives` takes exactly `{}` and reads the fixed
45e transfer-recovery and2ace unknown-closure history. It verifies the original
terminal closure hashes separately from fresh current-version absence, under
shared locks with active-campaign exclusion. It preserves original source and
records, returns finite phases, and cannot replay work or perform product actions.
Installation reservation consumes this proof only when both profiles are archived.
