# GUI/CLI Control Development

Authoritative requirements: `CLI-001` through `CLI-008`, `STATE-001` through
`STATE-005`, and `DESKTOP-001` through `DESKTOP-008` in `contracts.md`.
Read `state-ownership.md` before moving actions and `desktop-lifecycle.md` before
moving process ownership. Implementation progress is in `work-in-progress.md`;
this implementation specification is not a claim of packaged availability.

## Command Inventory

The target executable is `vpn-control` on Linux/macOS and
`vpn-control-cli.exe` on Windows. Android is selected with `--android`; optional
`--serial SERIAL` chooses an authorized ADB device. A sole authorized device is
selected automatically; multiple devices require an explicit serial.

```text
on
off
status [--watch]
restart
select <name|visible-index>
find-best
source show
source set current-locations
source set subscription <id>
source set all
subscriptions list
subscriptions show <id>
subscriptions add --source URL [--name NAME]
subscriptions add --input PATH|- [--name NAME]
subscriptions add --qr-image PATH [--name NAME]
subscriptions update <id> [--source URL | --input PATH|-] [--name NAME]
subscriptions delete <id>
subscriptions refresh <id|active|all>
locations list
locations show <selector>
locations add --input PATH|-
locations add --qr-image PATH
locations update <selector> --input PATH|-
locations delete <selector>
locations select <selector>
locations benchmark <selector>
locations import --input PATH|-
locations import --qr-image PATH
locations export --output PATH|- [--format json|qr-png]
routing show
routing set ignore-rules true|false
routing set direct-domains JSON_ARRAY
routing set block-quic-udp443 true|false
routing import --input PATH|-
routing import --qr-image PATH
routing export --output PATH|- [--format json|qr-png]
routing apps list [--search TEXT]
routing apps set --input PATH|-
routing apps add <package>
routing apps remove <package>
routing apps select-all [--search TEXT]
routing apps clear [--search TEXT]
settings show [key]
settings set <key> <value>
settings apply --input PATH|-
settings languages
ssh key status
ssh key import --input PATH|-
stats [--watch]
logs [--follow] [--limit N]
diagnostics export --output PATH|-
operations list
operations status <id>
operations wait <id>
operations cancel <id>
updates status
updates check
updates download
updates install
updates cancel
updates dismiss
serve
gui show
gui hide
quit
capabilities
```

Global options: `--help`, `--version`, `--json`, desktop-only `--state-dir PATH`,
`--android`, Android-only `--serial SERIAL`, `--interactive`, `--async`,
`--timeout-seconds N` (default 600, zero unlimited), `--controller-id ID`, `--if-revision N`.
Revision guards require the `controllerId` from the same observed JSON snapshot:
`--controller-id ID --if-revision N`. A bare numeric revision is rejected before
dispatch because the same number can recur after owner replacement. Desktop pinned
requests never bootstrap a missing owner. The authenticated transport preserves an
explicit epoch rather than replacing it with the newly discovered owner's identity.
Desktop `revisionGuardOperations` lists the currently supported guarded writes:
settings, SSH-key import, subscription/location edits and selection, source changes,
routing set/import, bulk location import, and quit. Runtime/job guards outside that
list remain unsupported. Android forwards both guards to its implemented owner
handlers; this does not make its remaining domain commands implemented.
The timeout is currently wired for supported desktop JSON commands. It bounds
waiting for the response frame after sending the command; bounded connection,
authentication and owner startup have their own limits. The timeout is client
metadata, not part of the owner's request or deduplication identity. A timed-out
operation wait reports exit 2, `TIMEOUT`, `final=false` and the known operation ID;
it does not cancel the owner operation. Non-JSON synchronous timeout options still
need migration.
Preserve existing GUI-only `--autostart`, `--tray`, and `--minimized`. Unknown
flags fail before startup rather than falling through to GUI initialization.
Resolve file paths relative to the invoking client's working directory.

The registry must describe actual command argument schemas, aliases,
mutability, required capabilities, asynchronous support, contract/coverage IDs,
and actual GUI bindings (or explicit service/presentation classification).
Registry presence alone is not evidence that an action is implemented.

Desktop `capabilities [--json]` is static and does not contact/start an owner or
create a workspace. Its `jsonOperations` covers the full registry but marks only
implemented JSON handlers as supported; this is not an inventory of legacy CLI
support. It reports async/cancellation support and platform-level capabilities
separately. `runtimeReadinessChecked=false` means it has not checked binaries,
privileges, connectivity, installation state or consent. Public revision guards
list supported operations separately; acknowledged GUI show/hide is now reported
as implemented, but native packaged coverage is pending. A typed capabilities
request sent directly to an owner returns the same implementation inventory with
that owner's metadata, not a runtime readiness probe.

## Settings Schema

Writable keys and input types:

| Key | Value |
| --- | --- |
| `mode` | `vpn` or `proxy-only` |
| `language` | generated catalog code or `system` |
| `dns.mode` | `automatic`, `custom-doh`, `custom-dot` |
| `dns.endpoint` | string, validated with proposed DNS mode |
| `ssh.enabled` | boolean |
| `ssh.host`, `ssh.user` | string |
| `ssh.port`, `ssh.relay-port` | integer |
| `ssh.host-keys` | JSON string array |
| `refresh.policy` | `off`, `every-hour`, `custom` |
| `refresh.custom-hours` | number, existing shared normalization |
| `refresh.find-best-after-refresh` | boolean |
| `validation.test-url` | string |
| `validation.batch-size` | integer |
| `validation.subscription-refresh-concurrency` | integer |
| `validation.retry-count` | integer |
| `validation.active-verification-window-size` | integer |
| `autostart` | boolean; Linux/Windows only, separate OS transaction |

`settings apply` accepts a partial flat JSON object using those dotted keys.
Reject unknown keys and wrong types; validate the complete proposed state before
persisting atomically and return normalized values. Do not include autostart in
a mixed configuration patch. Private-key import is separate; key bytes and
credential internals never become readable settings. Persisted legacy/internal
fields and dormant UI setters are not automatically public writable settings.

Current desktop JSON entry points: `--json settings show [key]`, `--json settings
set <key> <value>` and `--json settings apply --input PATH|-`. Show returns the
settings in `data` with metadata captured under the same commit monitor. Settings
writes return the normalized public patch in `data`, with their own commit
metadata captured before releasing that monitor. Retried accepted requests retain
the original result even after subsequent commits. Other mutation result data is
still incomplete. JSON also
supports on/off/restart, Find Best, location benchmark, subscription refresh, update check/download
and operation list/status/wait/cancel. Long commands accept `--async` with `--json`;
operation inspection does not create a replacement owner. Its `data` contains the
observed operation summary, or `data.operations` for list. The outer envelope
describes the inspection request; wait propagates the observed terminal exit code.
Remaining JSON commands are reported by capabilities; guarded writes use the
explicit owner/revision pair described above. Local errors without an
owner snapshot have null `controllerId` and warning `OWNER_METADATA_UNAVAILABLE`;
their required numeric revision field is zero and must not be used as a snapshot.

Desktop JSON also supports `stats`, `logs [--limit N]`, `source show`, and
`settings languages`. Shared pure projections produce the data; the owner captures
the read and revision metadata under its commit monitor. Logs return an `entries`
array of timestamps and redacted messages, including an empty array for limit zero.
Stats retain null for unavailable timing and do not invent traffic counters. Source
returns `mode` and nullable `subscriptionId`; languages returns code/name records.
Desktop `status --watch`, `stats --watch` and `logs --follow` now poll an existing
authenticated owner without startup or rebinding. JSON emits NDJSON; human stream
output goes to stderr. Timeout bounds each read, not the entire stream lifetime.
Log records have owner-scoped cursors, including an empty-history/tail cursor for
`--limit 0`; subsequent reads use positive batches and report `LOG_HISTORY_GAP`
when bounded history was lost. Same-timestamp messages remain distinct. Closing or
interrupting the client stops observation, not owner operations. Disconnected
macOS and Linux ARM64 app-image checks cover native Ctrl-C and streams; Windows,
final exact-commit packages, VPN traffic and Android streaming remain outstanding. These reads do
not add operations or change configuration.

JSON inspection also covers `locations list/show`, `subscriptions list/show`,
`routing show`, `ssh key status` and `updates status`. Lists return `locations` or
`subscriptions` arrays without raw profiles/source URLs. Location rows have the
same one-based visible indices and names as legacy CLI; show uses the shared
name/index resolver and preserves ambiguous/not-found errors. Location show puts
the existing usable configuration text in `data.configuration`. Subscription show
explicitly returns its source URL; this is intentional configuration inspection.
Routing show returns the existing v7 transfer object in `data.routing` (including
its per-read export timestamp). SSH status returns only `data.present`; private
key bytes and paths are never returned. Update status uses the existing checked
manifest/download state and does not start a check or download.

Android currently shares subscription and routing inspection and exposes location
list/show in the exact localized GUI order. Its owner also accepts SSH key import:
payloads are immutable versions selected by the atomic configuration commit, and
GUI imports use the same guarded operation as ADB. Routine results contain presence,
not key bytes or file paths. Android SSH status resolves only the captured committed
key version. Update status reads the same immutable state as its GUI, without starting
a check/download; unknown availability/compatibility and failed-check verdicts remain
explicitly null. Version-pinned native SSH loading still requires isolated device
verification.

Without `--json`, Android responses use a readable result summary with owner,
request, revision, completion, operation, pending restart, warnings and nested data.
Unavailable metadata is explicitly unknown rather than a false zero/no verdict;
async acceptance remains pending. Terminal control characters are escaped. JSON
envelopes and raw stdout exports retain their existing formats.

Android also accepts guarded `source set current-locations|subscription ID|all`.
It preserves a running selection and atomically invalidates an out-of-scope stopped
selection's legacy cache, with strict IDs rather than fallback selection. Location,
routing and diagnostics exports use invoking-client destinations (file or raw stdout),
never device-side paths. JSON export envelopes omit report/configuration content and
report success only after the local write. JSON/QR files are created privately without
overwriting existing destinations; raw stdout has no envelope or success suffix.

Android subscription add/update/delete now use guarded atomic commits and return
the exact affected ID. Add/update support async completion; source changes clear
subscription caches while preserving active or unknown runtime selections. Android
routing set/import and apps list/set/add/remove/select-all/clear share GUI domain
normalization and visible-app search semantics. Bulk app changes preserve assignments
outside the filtered catalog; explicit unknown package targets return NOT_FOUND.
Imported routing assignments retain the GUI import behavior for uninstalled apps.
These commands have focused regressions; native release verification of this latest
subscription/routing batch remains outstanding.

Android location add/update/select now use the same guarded owner path as GUI
editing/selection. Selectors resolve against localized visible order; GUI drafts
pin owner/revision and opaque target identity. Subscription locations remain
read-only but their editor still permits configuration inspection/copy. Manual
selection and selected-row updates stage configuration without reapplying a live
runtime; the GUI distinguishes actual active rows and displays pending restart.
Definite failed clicks may capture fresh state on the next explicit click, while
unknown-outcome retries retain their request identity. Location delete/import and
their actual-active-aware stop/rollback flow are not implemented in this adapter.

Android update check/download/cancel/dismiss now share application-owned commands
between GUI and ADB. Check fetches only a manifest; download uses its captured
compatible asset and verifies size/checksum/APK identity/version/signature. Safe
update actions remain available with unknown VPN runtime, with truthful warnings.
Async operation status/list expose transfer progress, and both update cancellation
and cancellation by operation ID await cleanup. Cancellation reserves its target
before asynchronous waiting, so a later transfer cannot be cancelled by mistake.
Terminal code/data are captured before releasing the transfer and survive later
dismissal. CLI installation remains unsupported pending explicit OS handoff.

JSON writes now also cover source/location selection, subscription add/update/delete,
location add/update/delete/import, routing set/import, SSH-key import and update
dismissal. Typed requests reuse `ControlCommandArguments` and the shared grammar;
option keys omit `--`, and `input` contains client-read content rather than a path.
These dispatch the existing domain actions with owner operation tracking and
request deduplication. Subscription add/update and location delete/import support
async; acceptance is not completion. Routing set/import returns committed public
controls; bulk location import returns the committed manual-location count. Routing
import warns about desktop-unsupported app assignments without retaining package
names in the operation result. JSON-array domain input uses the same normalization
as GUI/plain text. Some other non-settings normalized result data,
runtime/job revision guards, large chunk transfers and other remaining adapter gaps are still
open. Desktop QR image imports and PNG exports are implemented, as are JSON file
exports for locations/routing/diagnostics; content is not echoed in the final
envelope and success follows client file writing. CLI stdout is
explicit UTF-8 on every OS, independent of the JVM/console default encoding.

## Action Semantics And Existing Owners

- `on` while live reports actual active state and pending next state without
  restarting. `off` is idempotent and clears reconnect intent. `restart` requires
  a live connection and applies committed state, not an open routing/DNS draft.
- Selection uses exact names first, then positive one-based indices in the same
  visible ordering as GUI; duplicate exact names are ambiguous. Do not use
  `DesktopLocationRecord.index` as a displayed position. Selecting the same
  identity is a no-op. Selecting another location while live only stages it.
- Source selection changes visible/search scope, not the running profile.
  Reuse `SubscriptionSourceLogic`, including `__all_subscriptions__` eligibility.
- Keep `DesktopFindBestService` and `AndroidFindBestActionsService` explicit
  evaluate/verify/connect/rollback semantics. Desktop direct probes and CUSTOM
  exclusion remain. Individual benchmarks do not replace the connection.
- Use `LocationMutationLogic` and `LocationConfigs` for real add/edit/import,
  preserving subscription-owned read-only records. Replace desktop sample-node
  and append-`(edited)` callbacks with genuine shared editor actions. Removal and
  remapping distinguish actual active identity from pending selected identity.
- Subscription CRUD/refresh reuse validation, cache invalidation, remapping and
  concurrency limits. Report per-source partial failures, not generic success.
- Routing uses current `RoutingRulesTransfer` v7 controls: ignore rules, direct
  domains, QUIC UDP443 block, Android proxy-package assignments. Do not revive
  dormant rule-set or bypass-app editors. Do not strip full CUSTOM JSON's own
  `rule_set` configuration. Warn about compatible imported fields that are not
  functional on the target instead of advertising desktop app routing.
- Session stats/logs match the current `StatsScreen` and session counters;
  unavailable traffic telemetry is not a fabricated zero.
- QR uses a deterministic barcode library and the existing 1600 UTF-8-byte
  export policy extracted from Android UI into shared validation. Bulk imports
  retain their existing supported formats rather than silently reinterpreting
  arbitrary text as a different format.
- Update check and download become separate domain steps; GUI may compose them.
  Preserve manifest trust, size/hash, APK ID/version/signers. Obtain installer
  authorization before stopping runtime. Handoff coordinates GUI, controller,
  and Windows CLI executable replacement. Report installer-started, preserve a
  receipt for next-launch reconciliation, and do not claim installation complete.

## Session And Protocol Ownership

Current desktop `status --json` reports `runtimeRunning`, selected/active opaque
configuration IDs, configured/active mode, runtime ID/start time and pending
restart. Configuration IDs are owner-local, not persistent location row IDs or
selectors; they do not expose profile content. Status does not start an owner.
Normal GUI startup now registers a separate frontend, discovers or starts a
headless owner, and attaches through an authenticated owner-pinned lease. Production
Main no longer constructs a service/controller graph. Heartbeats preserve an idle
owner while the GUI is attached; runtime/jobs survive detach or lease expiry.
First GUI attach initializes reconnect once in owner scope, independent of client
cancellation. Navigation/drafts/pickers stay frontend-local. Complete installer,
Windows privilege and native GUI traffic evidence remain unfinished.
GUI/tray connection toggles, explicit restart, Find Best, per-location benchmark
and subscription refresh now submit through that session. On/off/restart support
JSON and async CLI submission and appear in operation history; they are not yet
cancellable. GUI benchmark callbacks capture the rendered configuration's
owner-local opaque ID, so numeric names and reordered lists do not retarget them.
Gone/replaced/ambiguous references conflict; public CLI name/index semantics remain
unchanged. Full atomic commit proposals, stable references for other GUI actions,
and GUI feedback for pre-admission rejection still need implementation.

Shared transport DTOs live in `shared/model/.../model/ControlModels.kt`; manual
JSON codec and `ControlSession` live in `shared/core/.../control/`. Do not serialize
the complete `MainUiState`/persisted model graph. Platform adapters own IO.

Separate four concerns: committed configuration, active runtime configuration,
operation state, and frontend-local drafts/navigation. Configuration revisions
change only for successful committed changes, not telemetry. A GUI draft captures
its opening revision. Save conflicts rather than overwriting newer config. Bind
optimistic revisions and deduplication to a controller epoch, not a bare counter.

Typed settings arguments use `key` and `value` text for `settings.set` (the same
value grammar as the terminal), and `input` text containing the JSON document for
`settings.apply`. `input` is transferred content, never a controller-side path.
The desktop headless adapter now dispatches these requests with epoch validation,
atomic expected-revision checks and retained request deduplication. Public guarded
writes carry `--controller-id` and `--if-revision` from one observed snapshot.
DNS, refresh, validation, language, mode and SSH GUI
settings now use frontend-local drafts and typed guarded saves. Opening reads
coherent owner/revision/settings; conflicts retain input and require explicit
reopen to rebase. Identical retries within one opening recover the original
result. SSH key import captures owner/revision before its frontend picker opens,
then uses a dedicated typed guarded credential commit. A transient redacted action
supports same-request Retry after response loss; closing/reopening or success
discards its content. Key import never silently rebases the open SSH settings draft.
Credential writes check revision before IO and capture their own completion metadata;
rollback tests cover metadata persistence failure. Two-file crash atomicity remains
open and is not implied by these guards.
Subscription add/rename uses local guarded drafts too, opened with stable-ID
explicit reads. Dedicated owner ADD/UPDATE guards precede domain mutation and
return only normalized saved ID plus exact commit metadata; existing async CLI
support is preserved. Tab navigation is frontend-local. Location editor reads and
updates accept internal opaque `id` rather than positional selectors. ADD/UPDATE
save resolves the target and checks revision inside the commit monitor, retains
only normalized location identity and captures its own result metadata. GUI uses
opening owner/revision and stable retry identity. Public CLI selector/async behavior
is unchanged. SELECT/DELETE also use rendered opaque IDs, owner/revision checks and
stable retries. Active deletion rechecks admission after native stop and restores
the prior runtime on failure without restoring an obsolete configuration snapshot.
Success returns the normalized ID and captured commit metadata; failed durable
rollback is not reported as successful deletion. Source selection/subscription
delete, routing set/import and bulk location import now have guarded owner paths.
Bulk import rechecks before effects and commit and uses runtime-only restoration.

`DesktopRemoteControlSession` also supports explicit authenticated presentation
reads and opt-in polling, with last-known data separate from connection failure.
Location rows have a strict typed decoder and shared UI mapping without raw
profiles. Explicit owner-selected/active flags replace profile-content matching;
invalid or unexpected row fields cannot replace the last good remote view.
The presentation projection whitelists routine fields and omits credentials,
private configuration and drafts. Editors require explicit configuration reads;
unstructured legacy details have unavailable flags. Runtime/presentation reads
reject owner replacement and revision rollback. Production Main consumes the typed
frontend presentation/client, uses explicit reads for editors and bounded logs,
and disables mutation when the retained view is unavailable. A separate fixture-only
adapter preserves visual test setup. Deterministic lifecycle/client tests pass;
native GUI crash/detach with uninterrupted traffic still needs evidence.
Source labels/references and mismatch are explicit safe display data rather than
URL-derived frontend logic. Shared location rows can render explicit selected and
active flags; Desktop uses the actual owner IDs so a pending selection is not
mistaken for the running location. Android legacy fallback remains until migrated.

Mutations await durable persistence. Make every desktop failure observable while
preserving a successfully written recovery file as
durable success. If effects changed runtime before persistence fails, restore
the prior runtime where possible and report rollback failures separately.
Use a mutation lane, not a global socket lock: status, progress, and cancel remain
responsive. Do blocking IO away from state dispatch.

Retain active operations and at most 256 recently completed operations for 30
minutes in memory. Track queued/running/succeeded/failed/cancelling/cancelled/
awaiting-user states. Do not turn this into a persistent generic job queue.
Wait timeout never cancels the job; include its known ID. After connection loss,
look up the original request/operation; do not blindly replay against a new owner.

JSON envelope fields: `schemaVersion`, `controllerId`, `requestId`, `ok`, `code`,
`message`, optional `messageKey`, `messageArgs`, `final`, `operationId`,
`configurationRevision`, `restartRequired`, `data`, `warnings`. Accepted async
results have `code=ACCEPTED`, `final=false`, and an operation ID. Synchronous JSON
emits one envelope; watch/follow emits NDJSON. Human progress belongs on stderr.
Reject `--json` combined with `--output -`; raw exported bytes cannot share stdout
with envelopes. Private keys never leave credential storage. Explicit config
inspection/export is privileged by user intent, not by default log verbosity.

## Desktop Adapter Work

Split controller lock and frontend registration. Only the owner constructs the
default service graph, owns shutdown hooks, persists state, runs reconnect and
scheduled refresh, starts/stops sing-box, and prepares updates. GUI projects
snapshots and owns Compose/tray/pickers/clipboard/local drafts. Remove Swing
dependence and indefinite future waits from command execution.

Use loopback TCP with an ephemeral endpoint descriptor containing protocol,
controller identity, port and a random 256-bit per-owner token. Apply POSIX owner
permissions or Windows owner ACL. Authenticate before any command including
legacy activation. Bound connection, handshake and idle transfer waits. Use
length-prefixed UTF-8 JSON frames up to 1 MiB; larger documents use chunk streams,
not new CLI-only import limits. Authenticate each connection, validate opaque
transfer IDs, clean partial transfers, and never permit arbitrary server paths.
Protocol incompatibility is not a missing controller and does not authorize
killing it or launching a competing owner.

Concurrent startup connects to the winning owner. Do not blindly use
`ProcessHandle.command()` as a packaged launcher (it is Java in development).
Propagate resolved state directory through owner, locks, runtime and updates.
Automatic CLI owners have no implicit reconnect and idle out after 30 seconds
only without a GUI, connection, operation or scheduled work. `serve` stays in the
foreground while disconnected and restores intent once; an existing owner
returns exit 2, not a fake supervisor wrapper. `status` with no owner returns 2
without startup. Other config queries may start a transient owner without GUI or
connection; help/version/static capabilities do not mutate a workspace.

GUI startup may restore intent once even if a prior query started the owner.
Detach/GUI crash preserves runtime. Retain tray-confirmed visibility fallback.
Explicit off clears intent; quit/supervisor shutdown stops cleanly but preserves
the previous reconnect setting. Autostart inspection must be pure: existing
`isEnabled` also migrates/writes and needs separation from explicit migration.

Windows packaging adds a jpackage console launcher while keeping GUI and owner
windowless. Remove unconditional GUI elevation; a narrow authenticated helper
performs fixed owned VPN runtime/setup operations, never arbitrary shell commands.
Proxy-only runs in the standard-user owner; UAC denial preserves prior state.
Autostart targets the actual GUI launcher, not Java or the console launcher.
macOS CLI runs the bundled binary directly, not `open`, with no Dock/window for
headless commands; preserve signing and runtime lookup. Linux must run without
DISPLAY/WAYLAND, retaining installed TUN/capability and direct-probe behavior.

## Android Adapter Work

Move authoritative coordination to an application-scoped session shared by GUI,
provider, and refresh work. `MainViewModel` must not own command jobs or create an
independent authoritative repository per caller. Keep Android-specific effects
in focused services with existing `VpnManager`, storage and WorkManager owners.

Current implementation has `AndroidApplicationOwner` for the shared dependency
graph, update state and `AndroidCommandJobs` lifetime/tracked admission. GUI
factories and refresh workers reuse it, while GUI drafts/navigation stay local.
Focused actions still capture frontend state and some writes bypass tracked
admission. Protected provider reads now use strict committed metadata. Settings
SET/APPLY use application-owned jobs, atomic epoch/revision guards, bounded retry
deduplication and confirmed refresh scheduling. ADB binds an omitted settings
owner to the authenticated transfer-creation response, never replaces an explicit
owner, and never replays writes against a replacement process. Runtime-unknown
admission is refused; runtime uncertainty discovered at the atomic guard reports
an explicit not-committed failure. Failures after durable commit report that
configuration was committed rather than implying rollback.
Settings and tracked GUI/worker jobs share atomic mutation admission; duplicate
requests join existing work, and waiter cancellation does not release an accepted
job's lease. Manual subscription refresh and location save/delete/select/import
also use admission through their persistence/lifecycle completion, without adding
unsafe mid-commit cancellation. Controller-effect settings/source/subscription
writes now execute as sequential awaited batches under that admission, with mode
stop-to-save retaining its original lease. The six legacy statistics/logging/test
preference setters are dormant, not reachable Android GUI controls, and remain
outside configuration revision identity. Direct repository APIs still permit
unguarded calls, but the current reachable configuration caller audit found no
additional bypass. Optimistic frontend state on persistence failure remains to be
hardened, and callback-level admission regressions are still required.
Routing save/import and SSH settings/key-import also
use non-cancellable admission; rejected attempts report BUSY through the existing
status path. Credential-file/settings crash/rollback atomicity is separate work.

Prepared runtime descriptors have expiring one-use handoffs tied to actual
generated configuration. Unknown legacy/mismatched handoffs and mutable SSH
credentials do not claim a known active configuration. Application initialization
can establish STOPPED because all native service construction is in the same
process and follows owner creation. Standalone observers remain unknown by
default. Other provider actions, consent interaction and complete GUI admission
remain unfinished. Instrumentation is compiled but still needs device execution.

The runtime adapter now correlates start/stop acknowledgments by application-owned
command IDs, action and generated-config digest. Native action plus required
persistence—not status text changes—completes a receipt. Prepared input is checked
before resetting the old runtime; unknown cleanup blocks replacement. Claimed
receipts survive waiter cancellation until actual completion or bounded expiry,
which reports unknown outcome. Protected OFF is now exposed through provider/ADB
using the same application-owned lease and deduplication ledger. Known STOPPED is
an idempotent no-op without dispatch; known RUNNING awaits correlated cleanup,
even if its prepared configuration is unavailable. Unknown runtime, stale guards
and busy admission fail before native effects. Caller disconnect does not cancel
the owner wait. Receipt expiry retains a failed result with an explicit
RUNTIME_OUTCOME_UNKNOWN warning, never redispatching the same request. ON/RESTART
now share that admission and validate configuration before replacement. The protected
interaction Activity uses expiring owner-bound tokens, resumed/unlocked foreground
checks and normal VPN consent; denial/revocation never starts a runtime. ADB explicitly
launches the Activity then polls the original operation status/wait without replay.
Unit/compilation/fake-ADB checks pass. Disconnected non-debuggable API29/35 shell
and unauthorized-caller checks pass; actual consent grant/FGS/traffic evidence
remains open. STATUS now projects actual runtime and opaque selected/active IDs,
with explicit unavailable state when runtime/prepared inputs are unknown. This
STATUS addition postdates the tested release APK and needs a new native run.
Provider operation list and safe consent-wait cancellation are now implemented;
listing explicitly excludes existing GUI/worker jobs. Cancellation competes with
approval before preparation and waits for token/lease cleanup; native and persistence
effects remain uncancellable. GUI/worker ledger migration and immutable known SSH
descriptors remain open.

Add exported `${applicationId}.control` provider protected by
`android.permission.DUMP` plus explicit Binder shell/app UID checks on every call
and stream. Authenticate before clearing Binder identity or launching async work;
disable grants and path traversal. ADB `content read/write` transports content,
requests/results and exports, with only opaque identifiers in extras. Never put
private keys in shell arguments. No TCP listener, root, run-as, or debuggable-only
command interface.

Use a protected interaction activity for foreground/consent/installer requests.
Without `--interactive`, return interaction-required before forbidden effects;
with it, ADB launches an opaque validated request. Always use `VpnService.prepare`
and normal user consent. Handle denial/revocation, locked devices, background FGS
restrictions, process recreation, and disconnected ADB explicitly. Desktop-only
serve/gui/quit operations remain unsupported instead of simulating an Android
background daemon.

## Android Location Removal Implementation Gap

DELETE/IMPORT need a dedicated destructive-action executor outside the current
DataStore ADD/UPDATE/SELECT transaction. Capture committed owner/revision and a
canonical replacement/removal plan under the mutation lease; resolve selectors
against visible localized rows and distinguish source ownership. Compare removed
identities with actual active A separately from pending selected B.

If A must stop, first capture a private exact runtime restore point (actual JSON,
prepared inputs, mode and runtime ID), then await a runtime-pinned stop outside
DataStore. The current observer stores only inputs/digest, not enough to restore
exact A. Existing stop tickets also need expected-runtime identity validation at
service claim time so a delayed stop cannot affect a replacement runtime.

Revalidate and commit the original captured revision even when no explicit public
guard was supplied. Atomically update saved rows, benchmark metadata, selected
fields and permanent cache invalidation without deleting active runtime artifacts.
On post-stop commit failure, recover only the captured runtime, never a stale full
workspace. Existing restoreSnapshot/rehydrateSelection(previousCommitted) and
startForControl are unsafe substitutes: pending B/settings may differ from A and
startForControl writes selected/last-profile state. Recovery must respect current
consent/foreground eligibility and distinguish restored, stopped and unknown results.

GUI and ADB must enter the same owner executor with async DELETE/IMPORT support;
GUI imports pin revision before opening the picker. Regressions must cover deleting
pending B versus active A, import preserving/removing each independently, unrelated
source identity, stop failure, runtime replacement, concurrent settings during stop,
failed commit/runtime-only recovery, exact retries, picker cancellation and cache
restart safety. No native stop/rollback is authorized merely by this design note.

## Android Installer Implementation Gap

`AndroidUpdateActionsService.buildInstallIntent` is not a completed control action:
it currently checks file existence, sets INSTALLING before dispatch and has no
unknown-sources permission continuation. Do not expose it as installed success.
The remaining adapter work is to pin/revalidate a unique private verified APK with
its manifest/hash/package/version/signers, admit installation through the owner
ledger and prevent download/dismiss from replacing the pinned artifact.

Without interactive opt-in, return INTERACTION_REQUIRED before launching any OS
surface. Extend the protected interaction registry/activity with authenticated
install-action stages for unknown-sources permission and installer dispatch; never
route installation through VPN consent. Recheck permission after returning from
settings. Preserve action/owner/expiry and recreation binding, foreground/unlocked
gates and one-shot dispatch/cancellation. ADB transfers only opaque tokens, not paths.
GUI Install must enter the same owner operation instead of direct startActivity.

Only acknowledged successful dispatch can publish INSTALLING and an explicit
installer-started/not-installed outcome. Actual installation or process replacement
requires separate confirmation/reconciliation; owner death is not success and must
never trigger automatic replay against a new owner. The current service's verified
download alone is not evidence that the file is still unchanged at installation.

Regressions must cover missing/changed/wrong-signer artifacts, noninteractive no-op,
permission denial/revocation/return, locked/unfocused activity, recreation, duplicate
requests, cancel-versus-dispatch, pinned artifact replacement, dispatch failure and
truthful handoff. These tests must precede any disposable-device installer exercise.

## Large-Content Transfer Implementation Gap

This section is an implementation plan, not a claim of supported transfers.
`ControlProtocolCodec` bounds the complete JSON document at1MiB. Desktop additionally
base64-encodes that JSON inside `DesktopCliProtocol` and frames the string in
`DesktopControlEndpoint`, making the effective content ceiling lower than768KiB
before escaping/envelope overhead. Android has independent limits in the CLI input
reader, protocol codec, ADB stdout capture, provider transfer buffers and result
reader. Its existing offset-based file descriptor API does not remove these limits.
GUI import has no corresponding1MiB product limit; increasing one constant is not
a complete fix.

The planned adapter extension keeps bounded authenticated frames and introduces
owner/principal/purpose-bound opaque blob references:

1. Begin an upload without changing configuration; negotiate bounded chunk size.
2. Append offset-addressed chunks (64KiB raw fits existing framing). Exact duplicate
   retries succeed; conflicting or noncontiguous writes fail.
3. Finish with byte count and SHA256, validate strict incremental UTF8, then seal
   immutable content in private owner/app spool storage.
4. Submit the existing domain operation with the typed blob reference. Apply owner
   and revision guards at serialized commit, not at upload time. Fingerprints use
   immutable content identity, not a temporary path; retained operation retries must
   work after blob cleanup.
5. Capture exports once and return an immutable download manifest with length,
   digest and existing revision metadata. Read bounded offset-addressed chunks.
6. Discard idempotently; inactivity expiry/disconnect never deletes an active
   consumer's blob. Active transfers retain transient desktop owners. Bound transfer
   count, not document size with a new CLI-only cap; report resource failures safely.

Desktop GUI remote import/export must use the same mechanism. Android can carry
small chunk envelopes through its existing authorized ADB provider. No server paths
or private content enter argv. Stream client file exports to private task-owned
partials, verify digest/count, then publish without overwriting existing targets;
raw stdout failure is necessarily partial and must end nonzero with stderr only.
Existing QR/SSH-specific safety limits remain separate. Current domain parsers are
String-based: chunked transport does not establish constant-memory domain parsing.

Required regressions include valid1MiB+/10MiB+ documents, Unicode splits and escaping
overhead, duplicate/conflicting chunks, bad hashes/offset overflow, wrong principal,
owner replacement, revision changes during upload, retry after commit/cleanup,
spool permissions/symlinks, disk failure, expiry with active consumers, interrupted
export/no-overwrite and public desktop/fake/native ADB end-to-end cases.

## Validation And Handoff

Start with `ControlModelsTest` and `ControlProtocolCodecTest`; then add registry,
parser, shared action, persistence-failure/rollback, revision/draft, operation,
transport authentication/framing, and lifecycle regressions. Actual GUI callbacks
and CLI adapters must exercise the same fixture/effects; two wrappers invoking
the same mock are not parity evidence.

Packaged E2E uses an empty temporary workspace and a local proxy fixture: help /
version / invalid options; serve readiness; configure and add; select/on; prove
traffic; stage selection/DNS with unchanged runtime; restart; attach GUI; mutate
from both clients; detach with uninterrupted traffic; query/cancel operations;
export diagnostics; off with serve still alive; quit. Add native Linux package
families, Windows console/UAC/Unicode, macOS proxy/unsupported VPN, and Android
ADB authorized/unauthorized and consent/lifecycle cases on API 29 and 35.

Real TUN, installer and autostart tests require disposable environments; a temp
state directory is insufficient. Add CLI checks to the five existing required
development workflows and path filters, plus disposable integration coverage.
Changed UI requires localization catalogs, scene inventory, deterministic
captures, reviewed baselines and targeted visual evidence. Finish with the
repository's version-bump/prepush/managed-push/exact-SHA CI loop, not a release.

The disconnected `scripts/test_packaged_cli.py` harness is invoked by native
DEB/RPM/Arch/MSI/macOS package smoke scripts. It verifies public launcher streams,
exit codes, Unicode workspaces, serve/read/settings isolation and async operation
inspection without connecting. Native macOS app-image execution has passed;
the other native package paths still require execution. This is an additional
safe tier, not a substitute for the traffic/GUI/consent cases above.
