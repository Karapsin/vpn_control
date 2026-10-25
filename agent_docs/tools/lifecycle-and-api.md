# Lifecycle and API reference

This focused reference retains the full startup, validation, transport and API
procedures from the 2026-10-14 tool-guide source. Start at
[the tool entry point](../../agent_tools/README.md) and [the task router](../README.md).
Current delivery and custody facts belong in
[work-in-progress.md](../work-in-progress.md); source-bounded counts,
predecessor pins and acceptance statements below describe their recorded scope.
They do not certify current native acceptance or authorize original-job replay.

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

New work takes its environment and connection context explicitly. An original
operation identity can address its own status, diagnostics or closure; it cannot
select a default guest, account, home, boot session or source for new work.
Retired attempt-specific starts fail before dispatch. The current repair's closed
VMs and connections must stay closed; a status query never restores them.

`macos-fixture-stage-start` prepares only the modes of an already supplied,
verified fixture pair in an already running Tart guest. It takes schema version 1,
canonical `correlationId`, full `sourceSha`, `fixtureReceiptArtifactId`, `guestRoot`,
`baseVersion`, `targetVersion`, and each package's `Sha256` and `SizeBytes` fields
prefixed with `base` or `target`. Its exact `environmentContext` is
`provider: "tart"`, `vmName`, `guestUser`, `guestUid`, `guestHome` and
`guestBootSessionUuid`. There are no previous-guest or account defaults.
The registered fixture receipt supplies authoritative versions and package
metadata; both registered DMGs and the receipt remain held through closing.
The saved helper reobserves the account, home and boot session before accessing
the owned root, verifies both files before changing either mode, and retains a
create-only effect intent. `macos-fixture-stage-status` and
`macos-fixture-stage-collect` take only the original `correlationId`; status may
inspect the original intent but never repeats the mutation. The historical
`macos-fixture-guest-stage-start` is retired and its original status/collection
routes remain. No stage action starts or restores a VM or establishes product
acceptance. Programme transfer uses stdin in bounded chunks and executes a saved,
hash-checked filename; the outer command stays within 60,000 bytes.

`vm_workflow` provides argument-driven Windows VM actions:

| Action | Exact inputs | Result scope |
| --- | --- | --- |
| `windows-vm-deploy-preflight` | `spec` | Read-only media, dependency, port, disk and KVM checks; no reservation or VM. |
| `windows-vm-deploy-media` | `spec` | Read the exact ISO's image names, editions, architectures and languages; no VM required. |
| `windows-vm-deploy-resources` | `spec`, `credentialFile` | Explicit privileged host resource census; no VM effect. |
| `windows-vm-deploy-start` | `spec`, `setup`, `credentialFile` | Create-only blank VM with capacity reservation and immutable original intent. |
| `windows-vm-deploy-status` | `deploymentId`, `credentialFile` | Observe the original instance or positive original-actor absence after stop. |
| `windows-vm-deploy-stop` | `deploymentId`, `credentialFile` | Consume one stop intent after exact original actor reidentification; never replay. |
| `windows-vm-deploy-qualify` | `deploymentId`, `operationId`, `credentialFile` | One fixed read-only guest setup/account query, with a retained guest PID. |
| `windows-vm-deploy-qualify-status` | Same qualification inputs | Collect that original PID/terminal; never submit another query. |
| `windows-vm-deploy-secure` | `deploymentId`, `operationId`, `credentialFile` | After qualification, rotate the setup administrator secret, disable automatic logon/task and remove credential-bearing setup media/caches. |
| `windows-vm-deploy-secure-status` | Same secure-operation inputs | Collect the original guest operation and finish only its proven post-success media cleanup; never change the password again. |
| `windows-vm-deploy-frame` | `deploymentId`, `operationId` | Capture one owned console PNG and return a verified private coordinator file. |
| `windows-vm-deploy-frame-collect` | Same frame inputs | Return that exact saved frame again, without another capture. |

`spec` contains `deploymentId`, configured `host`, absolute new `root`,
`memoryMiB`, `cpus`, `diskGiB`, `vncPort`, `headroomMiB` and `assets`.
Assets are exactly `installer`, `drivers`, `firmwareCode`, `firmwareVars`, each
with an absolute host `path`, exact `bytes` and lowercase `sha256`.
`setup` contains exact `imageName`, `locale`, ordinary `user` and a distinct
`administrator`. `credentialFile` is an explicit absolute coordinator path to
an owner-only single-link credential file; its contents are not MCP arguments.
Host alias, principal, media paths and VM identity have no prior-attempt defaults.
Image name and language must both exist in the installer. Start checks them
before credentials/reservations and again on the held installer before creating
the root. The coordinator captures all 16 verified source files of pinned
`pycdlib` 1.14.0 in the saved programme. The Arch host needs no reader package
installation. The ISO/WIM read uses seeks, with bounded uncompressed XML metadata;
unsupported or ambiguous formats refuse. A single-image ISO cannot silently
override the requested edition.
The host must provide the qualified Arch/KVM dependency profile. Root paths must
fit Unix socket limits and cannot contain QEMU's comma delimiter.

Complete source is saved before transport, transferred as bounded chunks and
invoked by its hash-checked filename. Pending/unknown claims remain counted,
including positively bound host aliases. Reservation consumers of an MCP result
use `windows_vm_resources.mcp_measurement(value, deploymentId)` to validate the
explicit envelope and strict native facts separately. That conversion grants no
freshness or host-action authority. Source beforeimages and original start
custody are retained before VM effects. A duplicate or uncertain start is never
replayed. `booted-observed` reports host process facts, not completed Windows
installation or product acceptance; `productReady` remains false. Native VM
and product qualification are recorded separately in the current WIP.

Qualification reports actual OS, setup, account groups, profile and service
facts. `setupReady` also requires the requested image/locale and an observed
ordinary session. The fixed noninteractive PowerShell source suppresses progress
records; other stderr and truncated/failed output still refuse. Security setup
passes the final generated administrator credential through guest stdin, verifies
it with a native logon, and retains acknowledgement before waiting. Its original
intent fences all password/media effects. Missing acknowledgement never permits
replay. It preserves the current ordinary session; a later sign-in uses the
private generated user credential. These facts do not attest a product token,
package, GUI/CLI scenario or visual scene.

Frame return has a separate bounded output budget. The command limit stays
60,000 bytes: only a short filename/hash invocation crosses the command boundary.
PNG length/hash and source custody must close before the coordinator returns its
file path. Frame operation IDs are create-only; collection reads the original
receipt. No arbitrary guest command, source body, remote file path or readiness
override is accepted by these actions.

`stopped-observed` requires positive absence of both original actor identities.
Stop preserves the VM root, disk, evidence and reservation. Release the exact own
reservation only after fresh closure evidence; archive/purge is separate. A lost
quit response stays recorded as such. Status never repeats quit or a signal.
UNKNOWN diagnostics contain bounded phase/class/check identifiers, with no raw
exception text. Reservation admission refusal reports BLOCKED with
`vmSubmitted=false`, retains preparation evidence and never discards claims.
Specialize stages a protected SYSTEM task; guest-agent MSI waits for completed
Windows setup. Installed-OS locale and ordinary autologon are explicit answer-file
settings; a running QEMU alone does not establish that they completed.

The 36 old Windows VM setup/preflight actions listed in
`agent_tools/windows_vm_setup_policy.py` return
`historical_windows_vm_setup_retired`; their original status/collection routes
remain available. CP117-only `forward-open` and the old boot-pinned
`environment-status(privilegedHost=true)` shortcut are also retired. Use the
new resource API with explicit inputs. Fixed historical diagnostics retain their
original scope and cannot supply admission for a fresh deployment. Fixed historical
CP117/MSI/fixture new-start and rebase actions also refuse, including
`windows-msi-base-start-from-transfer`. The two historical HTTP transfer
multiplexers reject their prepare/stage/listener/download/create/extract submission
phases; their original status, collection, diagnostics and cleanup remain available.
A phase argument cannot bypass the new-work fence.
The hosted `windows-msi-fixture-dispatch` builds packages solely from explicit source,
base version and correlation inputs. It does not inspect a guest; installation
admission separately verifies the selected deployment and installed version.

Named Windows input profiles take an explicit validated profile root and
session ID (1..16383); installed/task roots stay beneath that profile. The
supported token policies are explicit: `ordinaryFilteredAdmin` requires elevation0,
elevationType3, administrator membership present but disabled;
`ordinaryStandardUser` requires elevation0, elevationType1 and no administrator
membership. All fields retain strict types; mixed or elevated tokens refuse.
The renderer and every role/console/impersonation check use the selected policy.
Connected QMP/QGA sockets must have the expected kernel PID/UID and full current
process identity before any send. Choosing a profile proves neither native
admission nor completion of a UAC/product operation.

Native adapters now compile captured source bytes into a private package per
request, including local script dependencies. They bypass cached modules and
`.pyc` files, keep imported source under physical custody through calls, and
isolate import-path changes. A changed server requires the fresh-process route;
ordinary dotted stdlib imports load their requested submodule before the scoped
`importlib` view is refreshed, while repository imports keep their source custody.
The custody primitive itself is authenticated before its top-level code executes:
POSIX holds bounded nofollow file and ancestor descriptors; Windows holds native
source handles. The bootstrap remains held until the full request takes custody.
No current file hash is treated as proof of an old executing implementation.
New v2 nested channel intents retain source capsules for read-only verification
of positively ended records across revisions. Their authenticated peer identity
is observed at first readiness and must remain identical; old unknowns never
become launch authority. Original v1 readers remain scoped to their old evidence.

`ssh_workflow(action="windows-caller-file-stage", host="archlinux",
timeout_seconds=60, transfer={"sourceFile":"<absolute .runtime file>",
"sourceSha256":"<SHA256>", "correlationId":"<32 lowercase hex>"})` saves
and compiles the complete caller and stage-only gateway programme locally before
submission. It streams bounded chunks through stdin into an exclusive private
file on Arch, then checks the physical file's size, hash, ownership and generation.
Both outer commands remain below 60,000 bytes. The existing 8 MiB file ceiling
also bounds the rendered gateway programme; escaping can make a large caller
refuse locally. Each phase has a fixed 60-second observation budget. No supplied
caller is executed and no timed server, application operation or VM is started.
Partial transfers and unknown outcomes remain under their original correlations;
no overwrite, replay or selected-channel adoption is offered.

`windows-caller-file-receipt` takes its original configured host alias and only
`identity={"correlationId":"<original 32 lowercase hex>"}`. It reads preserved
local custody without connecting. An authentic closing record is required;
missing closure or retained UNKNOWN cannot become a successful stage. Even a
recorded stage returns `remoteReadiness: false` and `nativeActionAllowed: false`.
A separately reviewed short filename invocation must freshly verify the saved
source, hold it through the original child, retain both complete streams, and
close its scenario and scoped cleanup before native acceptance is claimed.
While MCP caches predecessor code, use the fresh-process `mcp_tool.sh
ssh-workflow` adapter with `--transfer-file` or `--identity-file`. These are two
narrow actions on the existing SSH tool, not a general remote executor.

Existing operation owners also handle oversized generated Python carriers
automatically. The SSH builder measures the fully quoted configured route before
submission. Up to 60,000 bytes uses the existing command path; a larger supported
`python3 -c` carrier becomes an immutable transfer plan. At the actual submission
boundary, the owner saves the complete source locally, streams it in chunks of
at most 65,536 bytes to an exclusive private remote file, and invokes a short
filename/hash loader. Source size remains limited to 8 MiB. Original arguments,
stdin, streams, exit status and operation admission remain with the same owner.
The transfer binds the current configured principal and observed account/home/boot
session, and revalidates the saved source and connection context through closing.
Local and remote execution intents are create-only. A partial transfer, timeout,
disconnect or uncertain execution is retained under the original identity and
cannot trigger another submission. No stderr phrase, including a command-size
error, authorizes retry of a possibly submitted operation. Unsupported oversized
shell, module or privilege forms refuse before transport. This automatic path
adds no public command executor and starts no VM or historical connection.

`ssh_workflow(action="connection-channel-prepare", host="<configured alias>",
identity={"correlationId":"<canonical UUID>"})` creates one isolated configured
two-hop connection channel. `connection-channel-status` accepts the same host and
identity and only observes it. `connection-channel-ensure` accepts that identity
plus an optional exact `receiptSha256` and selects only an admitted route.
The direct prepare/status actions use the same host and correlation schema;
`connection-direct-channel-select` additionally requires the actual returned
`receiptSha256`. Timeout is an exact integer in `1..60`. These connection-only
actions accept no command, path, transfer, device or extra identity fields.
Host aliases match `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}` and must resolve to a valid
exactly-two-hop nested peer in the captured configuration. Account, UID and boot
identity are observed from that authenticated peer. No literal host alias or
historical UID/boot selects the new operation.

New prepares, including `archlinux`, use host-scoped journals under
`.rag_index/ssh-fresh-nested-channel/hosts/<host>` or
`.rag_index/ssh-direct-nested-channel/hosts/<host>`. Selections are also host-scoped
under `.rag_index/ssh-channel-selection/hosts/<host>`. Correlations must remain
unique across both providers, hosts and legacy journals. Cross-host/provider
collisions and duplicate legacy/scoped records refuse. Exact original identifiers
can read their legacy records only without a scoped conflict; new work never
adopts or rewrites them. UNKNOWN remains observation-only and cannot authorize
another launch. Explicit unavailable or malformed selections refuse without a
fallback connection. Snapshot refusal is not an authentication failure. Use the
fresh `mcp_tool.sh ssh-workflow <action> --host <configured-alias>
--identity-file <local JSON>` fallback while the server has cached predecessor
code. Native connection acceptance remains separate from local fixture tests.

`connection-direct-channel-prepare` explicitly creates a fresh configured gateway
connection and one owned inner channel when historical outer-session authority
cannot be reused. It uses a separate create-only journal and never adopts or
rewrites old session history. Its identity is the same canonical UUID shape;
`connection-direct-channel-status` observes that original correlation, and
`connection-direct-channel-select` additionally requires the actual returned
`receiptSha256`. Selection binds current complete inventory, credentials, keys
and source, then lets normal managed workflows reuse only that owned inner socket.
These POSIX coordinator actions accept no arbitrary command, transfer or device.
Unsupported coordinators return finite UNKNOWN before private admission.

The following historical bridges are original-record compatibility only; they do
not migrate global history into new host-scoped admission. Completed DIRECT
history retains its original source and receipts. A finite
reviewed predecessor bridge permits the known provider/MCP transition only after
authentic terminal intent and READY custody checks; all other source pins and
typed intent fields must match. Missing, live, unknown or altered history refuses
before a new intent or SSH child. A terminal record cannot erase its READY receipt
reference. Historical files are never rewritten. Other future source transitions
remain refused pending separately reviewed coverage; this is not a general
source migration or native connection acceptance result.

The closure-source bridge permits only the reviewed2a384a to0fac47 bounds
extension, with the actual current closure image hash checked. Its b1a provider
predecessor may change only provider self-source plus that closure pin; it cannot
combine the older MCP transition. The prior b957/f569 bridges retain their existing
reviewed deltas. All other source, typed intent and terminal/READY custody checks
remain required. Public historical source fixtures and complete private-TempFS
provider regressions run through ordinary agent-tool discovery.

Set final source-leaf modes before any retained reader opens them. Finish full
hash, descriptor generation and named-path closure and close all readers before
immutable handoff. Changing permissions while readers remain held is source
drift even when bytes and SHA are unchanged. Fresh owned output directories
must retain the writable mode required by their schema; do not seal them early.

DIRECT status forwards the existing private inventory diagnostic callback without
changing the public result, raw capture or route options. Retained consumers may
record the bounded sanitized inventory classification separately; publication
failure does not promote UNKNOWN to readiness. An observed local inventory refusal
does not establish an SSH authentication or network fault. Historical91655 retains
its unobserved underlying cause even though later local acquisition succeeded.
The finite reviewed predecessor bridge covers the exact callback-only DIRECT
source transition and preceding provider; all other pins and terminal/READY custody
checks remain required. New routine tests guard POSIX fixture imports before Windows
discovery skips and retain the actual unsupported-module discovery regression.

Prepare, select and the admitted workflow must execute promptly: the existing
inner master expires after60 idle seconds. Preauthor the complete flow before
preparing it. A lost or UNKNOWN observation requires status on the same original
correlation; it does not authorize a second producer. After positively observed
end, a new explicit correlation may create a new channel. Selection and builders
refuse expired channels without automatic fallback. Native MCP equivalence remains
a separate acceptance gate; local fixture and Windows-like import checks do not
prove actual Windows installation or connection recovery.

### Receipt-bound channel keeper

The historical keeper actions use `host="archlinux"` and reject command, path,
transfer, device and extra identity fields. New `connection-channel-keeper-source`
and `connection-channel-keep` requests are blocked with
`historical_channel_keeper_new_work_retired`. Their fixed historical peer is not
reusable construction input. `connection-channel-keep-status` retains only the
original reader described below; it never prepares or renews a channel, starts a
master, or replays an application job.

| Action | Exact identity and timeout | Result |
| --- | --- | --- |
| `connection-channel-keeper-source` | `{correlationId}`; `timeout_seconds` in `1..60` | Retired new-work refusal before dispatch. |
| `connection-channel-keep` | `{correlationId, receiptSha256, sourceManifestSha256}`; `timeout_seconds=1800` | Retired new-work refusal before dispatch. |
| `connection-channel-keep-status` | The same three identity fields; `timeout_seconds` in `1..60` | Observe only the original keeper intent, process identity and protected terminal result; never start or replay it. |

`receiptSha256` is the exact admitted READY receipt, not a branch, artifact or
remaining-time claim. Supply identity through the CLI `--identity-file` when
using `mcp_tool.sh ssh-workflow <action> --host archlinux`; the keep action also
requires `--timeout-seconds 1800`.

The historical fixed keeper observed the same channel every 15 seconds, for at most 1800
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
immutable result spool. See [ssh-tmux-sessions.md](../ssh-tmux-sessions.md)
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
| `ssh_workflow(action="forward-open" | "forward-status" | "forward-close", host="archlinux", identity=None)` | Opening is retired; observe or close only the original fixed CP117 forward. |
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

Run affected agent-tool tests with:

```bash
python3 agent_tools/affected_agent_tests.py --run
```

The selector compares Git changes with the applicable baseline and includes actual
transitive consumers from both previous and current source. Product or prose-only
changes run no agent tests. A changed tool, runtime fixture or dependency selects
its affected consumers; unknown dependencies refuse selection with an explanation.
Shared dependencies can legitimately select a broad set. CI uses the push's
previous SHA or PR merge base; a missing comparison baseline is a failure.
Use `--baseline <commit>` for an explicit comparison and `--audit --baseline HEAD
--run` only for an intentional complete agent-suite audit.

When selection refuses a dynamic source reader or loader, inspect that exact
consumer and preserve its source beforeimage. Add a finite reviewed dependency
scope in `affected_agent_test_dependencies.json` bound to the actual consumer's
source hash, or teach the static resolver the demonstrated bounded expression
with causal coverage. A changed opaque consumer invalidates its declaration.
Do not use a whole-suite fallback, imported test execution or a caller-supplied
consumer list to make an unknown mapping appear qualified.

The runner retains each test's duration and outcome privately, with aggregate
counts in its result. Only reviewed source-bound independent groups run concurrently,
with at most two local workers and separate immutable fixture copies. All other
modules of one runner command run in one serialized group. Fixture/import errors,
skips, subtests and incomplete children remain visible. Windows named checks use
serial stdout timing. This bounds local test execution; it does not change remote
agent concurrency.

Managed `run_checks` (prepush, and focused `agent_tools`) plans the selected
modules as separately bounded commands: the SSH-close gate alone first as plain
`unittest`, then the two halves of the `shard_selection` partition (sorted and
alternating over the whole selection, duplicates refused) without the gate, each
half in its own runner. Hosted Fast Checks runs the same partition as six shard
jobs, so each half is exactly the hosted shards of its index parity. Every
command has the 50-minute managed bound, and a failed gate stops the commands
planned after it. On timeout `_run` sends SIGTERM,
so the runner's cancellation handler stops its worker sessions before the next
command starts; `_run` keeps draining output and sends SIGKILL only after a
30-second grace (or the command's shorter bound). The result still reports no
return code and only the original timeout, even when drained text output does
not decode. A timed-out, unparsed or import-failed command
(`unittest.loader._FailedTest`) records no failed modules;
`run_checks(level="failed")` reruns it once without removed modules and never
splits it recursively: the gate alone when it was recorded, then the remaining
modules by index parity in the sorted union of the current selection and those
modules. While every remaining module is still selected, each group is the
row's part of one current half, so for an unchanged selection a recorded
half reruns as itself; a changed selection regroups it. A row whose modules
were all removed, including a single-module row, is skipped. Regrouping two or
more non-gate modules runs the selector once per pass, so a selector refusal
blocks that pass with the `agent-test-selection` blocker.

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


Return to [the tool entry point](../../agent_tools/README.md) for current task routing.
