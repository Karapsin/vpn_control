# VPN Control Agent Tools

This directory contains the repository-local MCP workflow server and its documentation RAG indexer. These tools are for coding agents and maintainers; they are not part of the VPN Control application or its user setup.

## Automatic MCP Setup

Run `python3 agent_tools/configure_codex.py` once in a new checkout before opening its Codex session. The tracked `agent_tools/codex-config.toml.in` template generates ignored `.codex/config.toml`, deriving absolute launcher and working-directory paths from the checkout. Existing local settings are preserved; `--replace` makes a private ignored backup before regeneration. Rerun after moving the checkout. The generated configuration starts `agent_tools/mcp_server.sh` for trusted checkouts. The launcher:

1. Locates Python 3.
2. Creates the ignored `.agent_venv/` environment when needed.
3. Installs `requirements-mcp.txt` only when the requirements hash changes or `mcp` is missing.
4. Starts the STDIO server with all operational logging on stderr so the protocol on stdout remains clean.

Do not commit `.agent_venv/` or `.rag_index/`. Restart the Codex session after changing project MCP configuration because a running session does not reload its MCP inventory.

## Mandatory Lifecycle

For implementation, testing, release, or commit work:

1. Call `prepare_start(task, area)` before normal repository inspection, edits, or tests. It fetches `origin/dev` and `origin/main`, selects and safely fast-forwards the `dev` development branch only when the worktree is clean, and rebuilds the local docs index.
2. Read the returned instruction files. Use `docs` and `change_impact` instead of broad exploratory searches when repository documentation can answer the question.
3. Use `workflow_status` while working to re-check routing, dirty paths, index freshness, and validation requirements.
4. Run `version_bump` once after the final non-documentation content change, then run `run_checks(level="prepush")`. A successful check writes a content fingerprint to `.rag_index/prepush_receipt.json`.
5. Use `git_workflow` to push `dev` or to resume checks for a full commit SHA. It queries only runs attached to that exact SHA and requires every development workflow in `.github/required-workflows.json` to succeed.
6. Use `release_workflow` only after an explicit user release command. It fast-forwards `main` from verified `dev`, starts agent-owned visual review, gates on exhaustive VPN integration plus the exact-SHA visual receipt/status, and dispatches the manual publisher.

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
| `git_workflow(action, message=None, paths=None, sha=None)` | Commit explicit safe paths, push `dev`, and/or watch exact-SHA CI. |
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

### Fixed Windows credential-validity probe

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
registered `vm_workflow` actions. The currently supported execution scenario is
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
receipts remain unknown. Other execution scenarios are unsupported until they
have an explicit adapter and native evidence.

### Compact guidance and failure evidence

Native tool responses include `nextAction` with a safe existing observation or
verification route where known. `replayAllowed: false` forbids treating a timeout
as permission to repeat a mutation. Unknown states default to evidence inspection.

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
result. Existing sockets are never removed or replaced. Recovery does not restart
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
