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

## MCP Tools

| Tool | Purpose |
| --- | --- |
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
python3 -m unittest discover -s agent_tools/tests
```

The complete local pre-push tier is documented in `agent_docs/test-matrix.md` and is also encoded by `run_checks(level="prepush")`.

## Private Native Hosts And VM Workflows

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
`targetMsiArtifactId`. It performs bounded read-only CP117 QGA inspection of
the fixed signed Python interpreter and reports only its hash/version. This
does not provision credentials, start a server, or admit an MSI update; those
routes remain gated by their full lifecycle and original-owner network proof.

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

`android-native-fixture-start` takes exactly `{host, device, campaignId,
planPath, certificatePath, privateKeyPath}`. The aliases are configured,
the campaign is a canonical UUID, and the three file paths are absolute local
paths checked by the reviewed adapter. Only a host HTTPS/SOCKS endpoint is
started; the receipt explicitly leaves device mutation and installer target
admission false. `android-native-fixture-status/stop/collect` take only
`{campaignId}`. Unknown outcomes are not replay authorization. No certificate
or private key bytes are accepted or returned by these routes.

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
