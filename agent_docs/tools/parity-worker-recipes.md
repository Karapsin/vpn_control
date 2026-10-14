# Parity recipes and historical incident reconciliation

This is the detailed recipe reference reached from [the tool entry point](../../agent_tools/README.md).
Use [the current ledger](../work-in-progress.md) and
[active parity brief](../parity-solo-plan.md) for present scope and
custody; the recorded procedures below do not replace either.

Fixed CP117 old-stage retirement, original base/transfer/credential recoveries,
optical attempts and c32 archive admission are **historical incident references**.
Their fixed correlations, source/artifact pins, unknown outcomes and one-shot
fences remain intact. Descriptions of a historically current campaign or proof
refer to that original source, not the current checkout. Never replay a consumed
start or infer terminal success, absence, cleanup or lease closure from this text.
A named status/diagnostic remains limited to the exact original identity and its
stated evidence scope. No native action, VM/VPN interruption, credential/trust
change or replay is authorized by this documentation cleanup.

Reusable schemas retain every native gate, source/artifact custody bracket,
resource limit, prompt guard, credential boundary and cleanup restriction.
Historical commands are preserved to explain and safely reconcile original
custody only when a later task explicitly authorizes that action.

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
`registered-unverified`. Top-level `sharedGates` projects every cross-platform
requirement, including passed gates, with its matrix status, missing scenarios
and next fixed command. `requirementCount`, `unmetGateCount` and
`missingScenarioCount` include both platform and shared rows; scenario counts
are occurrences across requirements. `sharedUnmetGateCount` and
`sharedMissingScenarioCount` expose the shared subset without assigning package,
owner or correlation evidence to a platform. Unknown requirement platforms are
rejected before observer calls. The view rehashes current-source local package/APK/DMG
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
canonical UUID. Each repository-relative path must name a regular owner-only mode-0600 JSON file
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
An authenticated `Succeeded/OK` receipt includes `remainingVerification` for
installed target files, original-user return and input cleanup, with a read-only
`nextAction` to verify those facts on the same job. It does not diagnose a return
failure or authorize manual relaunch, cleanup or another install request.

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

For the retained API35 engineering image, the same action accepts exactly
`identity={"cliArtifact":"qualified-d32-fae-2.2.2"}`, with host `archlinux`,
device `api35` and timeout15. The fixed source selects the directly qualified
155-file fae image; callers cannot supply a path, command or admission flag.
The configured CLI and device profile stay unchanged. Without identity, the
existing configured observer remains the default.

The qualified observer runs the full status/operations read with app/device and
source/image brackets, then uses the canonical result parser. It retains initial
streams unchanged, naturally drains that same child and appends terminal streams
before its final source/profile/HEAD check. Late terminal success does not replace
an original timeout/UNKNOWN; failed final closing also returns UNKNOWN without
replay. This engineering observation provides no installation, lease, retirement,
new-owner or final-product acceptance authority. Use a fresh MCP/CLI process after
integration; a running server can retain the older dispatcher.

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
sourceSha, guestRoot, baseVersion, targetVersion, baseSha256, baseSizeBytes,
targetSha256, targetSizeBytes})` requires canonical three-part base-20 versions
with a numerically newer target. It verifies registered same-source DMG bytes and
derives only fixed guest basenames `vpn-control-<version>.dmg`, repairing only the
mode of exact task-owned copies in the disposable Tart guest after hashing both.
Versions are fixed argv data and remain bound to the original source, source-bound
guest root, artifact hashes/sizes and correlation in the durable request. These
caller-declared versions do not prove embedded app version, architecture or signature; native
admission verifies those separately. Status and collect accept only `correlationId`.
Authentic historical seven-field requests retain their original records and can
only inspect the original fixed pair; new legacy mutation is rejected. It neither starts a fixture
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

Return to [the tool entry point](../../agent_tools/README.md) for current task routing.
