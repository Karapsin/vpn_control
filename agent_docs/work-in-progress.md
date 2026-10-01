# Work In Progress

## Objective And Boundaries

Finish the full GUI/CLI parity plan on Android, Linux, Windows and macOS,
including matching public behavior, persistence, runtime effects, progress,
cancellation, packaged native acceptance, visual review, reviewed dev pushes and
all five required workflows for the exact delivered SHA. The goal is incomplete.
No release, main merge, tag, publisher, runtime upgrade or TUI implementation is
part of this task.

Product authority: [contracts.md](contracts.md), especially CLI-001..008,
STATE-001..005, DESKTOP-001..008 and TEST-001. Command authority: [cli.md](cli.md).
Failure/prevention index: [parity-failure-regressions.md](parity-failure-regressions.md).
Historical checkpoint descriptions remain in Git at
`fc82b28eab7b42dadbb9bdd04443e2c66e8b3dec:agent_docs/work-in-progress.md`.
The pre-consolidation working copy is preserved in ignored
`checkpoint51/work-in-progress-before-consolidation.md`. Evidence paths below are
relative to `.runtime/parity-evidence/` unless explicitly absolute.

Only positively identified owned VMs/emulators may run VPN, elevation, installation
or fixture trust operations. Preserve the host VPN, personal workspaces, unrelated
VMs and AVDs5580/5582/5584/5590/5592, and excluded `agent_docs/.Rhistory`.
A timeout is not cancellation, termination, or permission to replay. Retain unknown
job correlations and inputs. One operator per environment and one writer per file;
root owns host Gradle, shared integration, metadata, commits, push and exact-SHA CI.

## Current handoff review — 2026-09-28

### Live Windows gate — 2026-10-01

The Windows-first campaign remains the sole active native slice. Source HEAD is
`19be9df22cbab8086c26e5ca907d9569a5a28a08`, product version 2.2.2, with
no target update installer run yet. The CP117 guest still has the original-user
2.1.19 app and runtime OFF. The frozen target MSI SHA-256 is
`5ac252557106a2bae56583253a70ea037bb300827df6b5c36b2dc502e1e01234`.
The active campaign lease is `e59a7483-4e38-4e7b-b8fa-0d8b2356916a`, stage
`e848bed2-5bea-47bc-a85a-6cf17b1fcc6a`, and current server correlation
`316e6189-5be0-4ea0-bca1-a3905816d815`. The server task is Ready with
LastTaskResult 1, `ready.json` absent, and only `probe-events` in server state.
Do not replay server start or resume. TLS certificate load, resource import,
digest recheck and loopback bind pass in a separate read-only SYSTEM diagnostic.
The `probe-events` DACL has three protected full-control ACEs for SYSTEM,
Administrators and `OWNER RIGHTS` (`S-1-3-4`); it omits the configured
original-user SID. Python 3.13 documents special Windows ACL handling for
`mkdir(mode=0o700)`, which exactly matches the staged fixture code and native
ACL. A portable regression failed on the old mode and passes after a local
uncommitted source fix that uses inherited private-parent ACL creation on
Windows, then retains exact ACL establishment and verification. The full
fixture unit suite passes (75 tests). This product source change invalidates
the frozen stage and package source receipts; no rebuilt package or update
installer action has run. A source-bound static server preflight is being added
before any future server role/task. Retire the failed server task only through
fresh task/process proof and the reviewed one-shot cleanup path.
An isolated QGA SYSTEM ACL exercise yielded unknown before bounded phase
handling was added, then `guest-output-truncation` because omitted QGA flags
were treated as true, and finally a blocked all-unknown exercise under SYSTEM.
Its read-only scratch census reported zero between attempts. It never claimed
a server role or touched the failed server state; it does not prove the
limited original-user behavior and is not acceptance evidence.

Windows native acceptance, Android, Linux, macOS, visual review, pre-push,
coherent dev push and the final exact-SHA five-workflow CI gate remain open.
The user requested sparse checkpoints, one CI check at final delivery, platform
order Windows → Android → Linux → macOS, and no release. The detailed
2026-09-30 entries below are historical attempts; they do not supersede this
gate.

### Windows-first continuation — 2026-09-30

Current source is `19be9df22cbab8086c26e5ca907d9569a5a28a08` on `dev` at
product version 2.2.2. Tool, route, regression and visual-support edits remain
dirty. The user requested platform order Windows, Android, Linux, macOS, sparse
checkpoint pushes, and one required exact-SHA CI check at final delivery. No
release is authorized. Windows CP117 remains the sole active native owner;
Android/Linux/macOS mutations remain paused.

Latest Windows gate (2026-09-30): the corrected v4 current-owner public quit
exited the exact CLI owner pair; fresh owner liveness found no owner, installer,
consent or runtime process, with runtime OFF. Fresh target fixture correlation
`1a92ea8f-dd8e-4a8f-b891-9804b902d366` returned unknown at prepare with no
new local stage/HTTP intent. Its read-only prepare and bundle diagnostics passed;
reserve reported prior-stage confirmation required. The read-only
`prior-stage-confirmation` returned `history-invalid`. Local causal audit found
the retired e66 stage intent still bound to the current active idle campaign
lease `94238e9e-4296-4a70-9b0a-0762f82aaf07` while stage-history admission
requires each earlier stage lease to differ from the current lease. The older
7f stage has a closed c32 lease. Do not replay the unknown prepare. A narrowly
scoped successor campaign must prove the exact e66 retirement and close the
current campaign before staging under a new lease; do not bypass general stage
history admission. No target MSI action has started.

Follow-on (2026-09-30): reviewed successor tool, CAS close and causal tests
closed e66 lease 94238 and opened fresh lease
`68393b94-144c-405c-bc8d-bc61afa38d65`; read-only successor status was
active and prior-stage confirmation for 1a92 became `confirmed`. Fresh fixture
correlation `727a4097-e57c-46f6-ba42-5492cd4af4da` prepared the exact
131,218,059-byte bundle with SHA-256
`95a0f90171185110a636d678c4517f35954a3c1f9aa99a248137c210d9f28de4`.
Its one `stage-start` returned unknown after 18 seconds. Shared phase status
reported `transfer-unobserved`, stage-start diagnostic `phase-ineligible`, and
host-staged pre-effect diagnostic `host-stage-present`. Do not repeat stage
start or launch the listener until a read-only host-stage integrity probe proves
complete exact bytes and binding. The probe is under code-only development;
no guest-create, listener or target installer action has started.

Subsequent fixed host probe proved the full 131,218,059-byte remote bundle,
authority binding, mode and SHA, so the earlier stage-start response loss did
not require a transfer replay. After reviewed listener admission changes, the
one-use host listener started. The first QGA `guest-create` attempt returned
unknown; read-only phase status twice observed the guest leaf absent and the
listener transitioned from listening to stopped without serving bytes. The
shared phase remains `guest-created` intent, with campaign stage role active.
Do not replay guest-create or listener-start. A read-only guest-create cause
diagnostic and a guarded closure path are needed before a fresh attempt. The
target installer has still not run.

The fixed read-only QGA diagnostic now reports
`guest-create-not-confirmed-leaf-absent` with the matching PowerShell child
absent. The generated guest directory script had followed a PowerShell
`.Parent` object without reloading its provider attributes, causing a false
ancestor-type rejection before the guest leaf was created. A causal regression
and script fix are in place. The consumed guest-create, listener, and stage
actions remain non-replayable; a fixed-correlation abort is under review to
prove the unserved listener, remove only the terminal HTTP stage, and retire
the campaign role. A distinct source-bound successor lease will then be
required before any fresh update attempt. No target MSI has run.

The reviewed fixed abort admitted fresh `guest-created` host bytes, the stopped
unserved listener, absent guest leaf and absent matching child. Its sole native
action returned `retired` with cleanup receipt SHA-256
`c2a9fb2beff7a193b90894f4bab2a4d5e8627fff96dcd7f399b7e888eafa01de`.
The first post-abort status could not admit the idle campaign through its
pre-abort reader. A fixed retired-only reader now verifies the original
artifact/source/VM binding, immutable local receipt, remote cleaned marker,
and a fresh guest census. A real-signature regression caught a missing
argument in that census builder. The corrected read-only MCP status reports
`retired`. The abort is not replayable; the next stage needs a distinct
source-bound campaign lease. No target MSI has run.

One reviewed fixed successor action closed the retired lease 68393 and opened
new lease `67cb7008-f9e4-436a-bfa8-683e79bbe21d`. Its exact read-only
successor status reports active. The generic campaign status initially reported
unknown because its binding compared the six-field persisted stage request
against a five-field campaign projection that omits `host`. A causal test and
exact request-shape fix are in place; fresh read-only MCP campaign status now
reports active on the same lease, with remote cleanup and predecessor close
proof intact. Preserve the one-shot successor intent; do not call successor
start again. The next step is a fresh correlation for the target update
package. No target MSI has run.

Fresh correlation `af3360e5-a53b-4cd2-b91a-4c6abfd6b118` prepared the
131,218,059-byte package with bundle SHA-256
`91358792bbbf173f1e74e159529cc8bb119d53794404eebc6ff47ba805efc6c3`.
Its single host transfer returned unknown, but a read-only exact host hash and
binding probe proved complete bytes. The one-use listener started, and the
corrected guest-create action returned `created`. The limited-user
`guest-download` action returned `submitted`; subsequent listener status moved
from listening to stopped (unserved), while phase status still observed only
the created guest leaf and no download receipt. Do not resubmit guest-download
or start extraction. A bounded read-only task/file diagnostic is under
development to distinguish timeout, task failure, and partial download before
selecting the next safe action. The server has a 120-second deadline; elapsed
orchestration time is a suspected cause, not yet a proved cause. A reviewed
read-only download diagnostic now proves the stopped host listener recorded
`served:false`, the exact scheduled task is absent, and the expected guest
bundle file is absent. The accepted download request is not replayable; a
fixed-correlation retirement of this empty attempt must precede a distinct
lease and fresh correlation. No installer has run.
The one-use listener's fixed waiting window is now 600 seconds (previously
120), with a regression that executes a successful single request and proves
immediate terminal closure; this affects only future listeners. Whether the
shorter window caused this attempt remains an inference, not a native proof.
The download diagnostic initially misread the Task Scheduler root path and
the account name, producing a false task-absent/principal-mismatch sequence.
Causal regressions corrected both. Fresh native read-only evidence now proves
the exact scheduled task is terminal `failed`, the expected bundle file is
absent, and the listener stopped unserved. The abort tool therefore must first
remove only this bound failed task, then prove it absent before host cleanup
and stage-role retirement. That one-shot task cleanup remains under independent
safety review; no cleanup or target installation has run.

Follow-on (2026-09-30): the bound Task Scheduler result was `1` for the
af3360 attempt; an earlier `task-absent` diagnostic was false and is superseded
by the corrected task probe. The reviewed one-shot task deletion returned
unknown, but its read-only status proved `cleaned`; no deletion was replayed.
The reviewed host abort then returned `retired` with cleanup receipt SHA-256
`792bc3a4c46c87f5474a5c46765b015c51ddb760af5c7174d3f59915a6aa7b47`.
A campaign projection bug in that abort was fixed with causal tests and a
lock-protected full lease read. One successor action closed lease 67cb7 and
opened `9b4cf4c7-791a-4e51-93ac-0b8db4ac4409`, now read-only active and
idle. The next correlation `07708dc7-6884-40a5-9a78-c75dbb391dbd`
prepared the exact 131,218,059-byte package (SHA-256
`aabec9e1d7b705ab04555e4eb74a3c25119c984bf9b590cb56d0d0f047f686d3`).
Its host transfer returned unknown but the exact host hash probe proved
complete bytes. Listener start, guest-create and guest-download submission
returned success. The download task nevertheless ended `failed` with result
`1` before the listener served bytes; no bundle or installer ran. A likely
cause is the download PowerShell script's missing `System.Net.Http` assembly
load, now fixed with a regression matching the established Windows transfer
path. This cause is not yet proven by a successful native retry. Do not replay
the consumed guest download. The 600-second listener must first stop unserved,
then the exact failed task and stage must be retired before a fresh correlation.

Further follow-on (2026-09-30): the 07708 listener stopped unserved and the
bound failed task result was again `1`, with no download file. A fixed
historical-script fingerprint recognized that exact pre-fix task after the
`System.Net.Http` change. One task deletion again returned unknown but
read-only status proved `cleaned`; the cause was a post-deletion PowerShell
result-formatting syntax error, now covered and fixed. Host abort returned
`retired` (receipt SHA-256
`571701f7f9c0fffdc5d14e0cae2fe43b4be91cc14f93c866d645bb94100388ab`).
One reviewed successor opened idle lease
`e59a7483-4e38-4e7b-b8fa-0d8b2356916a`. Its recovery route includes a
durable-intent `resume-close` path with a causal crash-window test. Fresh
correlation `e848bed2-5bea-47bc-a85a-6cf17b1fcc6a` prepared an exact
131,218,059-byte package (SHA-256
`634aa7a97ef77399ace35bc82fb0dae31ae6e00560a7815b2868f2793d555870`),
staged exact host bytes after an unknown transfer response, and downloaded in
the guest with listener served, scheduled task result `0`, and complete hash.
The first extraction response was unknown. Read-only diagnosis proved exact
binding, dispatch, and a present receipt; its initial protocol error came
from treating QGA's already-consumed process status as required. Receipt-first
validation now checks the full file hashes, bundle hash, and three ACL
receipts. Native `windows-fixture-stage-status` and HTTP `collect` both return
`staged-not-server-ready` with the expected target MSI SHA-256
`5ac252557106a2bae56583253a70ea037bb300827df6b5c36b2dc502e1e01234`.
The installer has not run. Next is credential/server admission, then one
public update and its real install/GUI/CLI evidence.

Credential provision correlation `6161b4ae-3634-4312-ac85-1bacd0001dfa`
returned `unknown` after a durable intent and held the `credentials` role.
Read-only diagnosis proved the exact remote credential work group absent;
the exact remote role guard still matched. A code audit established the
pre-effect cause: credential dispatch requested a 120-second SSH timeout,
while the shared SSH transport admits at most 60 seconds and returned no
remote command. The accepted provision was not replayed. Its one guarded
abort returned `submitted`; read-only abort status proved `aborted-cleaned`
with cleanup receipt SHA-256
`02377ac3321c1afae18c6a392c7546e5944be9f79f2a546f4f3ecd7b70084738`.
The timeout regression and fix are in progress. A fresh correlation is needed
for certificate provision after the fix; no server or installer has run.

The 60-second timeout fix passed 24 focused tests and independent review.
Fresh campaign status was active with no held role, and the exact e848 stage
still returned `staged-not-server-ready` with matching target MSI hash. Fresh
credential correlation `486932f6-6370-46b3-b42c-490183fa8364` was rejected
before a local intent or VM effect: the provision journal currently requires
every prior credential campaign to be closed, while the verified aborted
attempt belongs to this active campaign and its staged MSI. Preserve the
rejected request and old abort receipt. A narrowly scoped admission fix with
a causal regression is in progress; use a new correlation afterward.

The exact aborted-cleaned admission fix passed 41 focused credential/lease
tests and independent review. Fresh provision correlation
`791b5235-9ca7-409c-96bc-c341047c7fb4` returned `submitted` on the intact
stage. Its first status was `unknown`; a separately reviewed current-correlation
read-only diagnostic found exact binding and `terminal-failed` guest task.
No provision replay or server/installer action occurred. Preserve the task and
host receipts while a bounded, secret-free failure detail is developed; abort
only after the cause is classified or no further safe readback is possible.

The reviewed, read-only credential failure detail now proves Task Scheduler
result `1`, exact certificate/key/trust-store hashes, a verified credential
directory ACL, and a present provenance receipt whose ACL is `mismatch`.
This is a real terminal guest task failure, not SSH response loss; no server
or installer has run. The task is preserved while a more specific,
secret-free ACL-shape diagnostic is prepared. Do not infer whether `Set-Acl`
failed or a later check disagreed until that readback is available.

The reviewed ACL-shape readback found exactly three expected principals with
full-control rights, but the provenance file's ACL is unprotected and its
rules remain inherited. This proves the required protected ACL was not
established; it does not prove which attempted ACL write failed. The first
guarded abort request for correlation `791b5235` was rejected pre-intent:
the existing abort journal for `6161b4ae` is still on this active campaign,
although its exact abort is verified cleaned. No second cleanup or installer
effect occurred. A narrow abort-history admission fix is required before
retiring the failed task; then repair protected provenance creation and use
a fresh provision correlation.

The abort-group-only history fix passed 48 focused tests and independent
review. One `791b5235` abort submission and exact read-only status returned
`aborted-cleaned`, receipt SHA-256
`02377ac3321c1afae18c6a392c7546e5944be9f79f2a546f4f3ecd7b70084738`.
The old and new abort records remain preserved; the credential task and
temporary files are absent, the stage remains. The protected-provenance
creation repair is code-only work in progress before any fresh provision.

The provenance ACL repair passed 33 focused tests and independent review.
Fresh stage and campaign readbacks verified the exact staged MSI and idle
active lease (an initial campaign status transport unknown was transient;
the repeated read-only status returned active). Fresh provision correlation
`75ed6f9c-ebe6-4f70-ba1a-ab64b8507d16` returned `submitted`, then
`ready` in native CP117. Its peer certificate SHA-256 is
`18ef6ba14a327f487c6ce060b7851d1eb790c8be7a8ca56223608bf78e475d21`
and trust-store SHA-256 is
`a2dcd0980c1770def0ac12d58abd5ccd512abcc1d8848f8e92d8b3c124e27b24`.
This proves the corrected protected-file and original-user provenance path
in the guest. No server or installer has run; next is exact server admission.

Server-start correlation `9f47d8f2-bfe1-4164-aa8b-2f617abaa482`
rejected before a server intent or VM effect because the guest Python inventory
did not contain exactly one signed fixed-location interpreter. A new reviewed
read-only MCP inventory diagnostic, with 26 focused server/route tests, returned
`candidateCount: 0` for that exact CP117 campaign and QEMU generation; the
original error wording `not unique` had conflated zero with multiple. The
strict server admission remains unchanged. The official Python 3.13.15 AMD64
installer has SHA-256
`edec09c4853aeae9ac36efb8c9f95b6b8e2fee65eee56d9767a8b7c69c574403`;
CP95 historical evidence names a staged Arch copy but does not prove current
availability or CP117 installation. The current campaign's read-only Arch
source probe returned `absent-or-mismatch`; it does not authorize reuse of the
historical copy. The first guest HEAD probe was unknown because its MCP helper
passed a Mac workspace path to an Arch command. A causal regression now checks
the configured Arch transfer root, and the corrected native CP117 HEAD returned
HTTP 200 with normal TLS validation and exact expected length `29452944` for
the fixed official URL. The full installer still needs a digest-verified guest
download and a one-shot original-user install; these tools are being reviewed.
No server or product installer has run.

CP117 has installed base 2.1.19, original runtime OFF, and a running exact
original-user CLI owner pair. The owner stale-lock one-shot failed unknown,
then a separate reviewed reconciliation proved the lock recovered. The owner
relaunch one-shot remained unknown, while bounded native detail proved the
exact quoted/unquoted CLI serve pair and no installer, consent or sing-box
runtime. QGA SYSTEM cannot read the owner-private activation endpoint, which
is expected ACL behavior. The original limited-user public-status task and a
separately correlated retry both retained unknown intents; read-only task
diagnostics observed each task absent. The retry's generated Python remote had
a causal quoting syntax error, now fixed and covered by a compile regression.
Neither unknown status attempt has been reclassified or replayed. A further
public-status probe, if admitted, is an independent read-only task and must
retain both earlier unknowns.

A third, separately correlated read-only public-status task
`3a7b048d-aec4-4f07-845c-86677dd90f9` passed independent code review,
compiled generated programs and strict owner/runtime/task admission. Its one
start returned unknown after a durable intent; its normal status was also
unknown. A separately reviewed no-replay observer bound the exact intent and
VM generation and found the third task absent. All three unknown starts remain
unknown and none was resubmitted. The existing Windows public owner-quit tool
requires a successful status receipt for the same exact owner generation; the
historical receipt cannot be used for the current relaunched owner. A fixed
current-owner public quit adapter is under code-only development, gated on
runtime OFF and exact relaunch evidence. No Windows owner exit has run.
An independent emitted-program audit proved why the retry and third tasks
were absent: their generated Python bootstrap decoded the account separator
in `VPNMSIX64\vpncp117` as a vertical tab before task registration. A causal
RED/GREEN regression now examines the parsed emitted bootstrap and the builder
escapes that separator. The original task has no corresponding injected
account and its unknown cause remains unclassified.

The first fixed current-owner quit attempt
`44ac1ea9-b18b-4203-9cef-9e38c5d45970` first blocked locally before
intent because its admission expected a terminal relaunch receipt and a
SYSTEM-readable private endpoint. Its corrected actual-state admission wrote
one durable quit intent, but the native start returned unknown. Read-only
diagnosis reported `owner-task-running`: the relaunch scheduled task runs the
long-lived CLI server and is expected to remain Running, while this quit
bootstrap is coded to reject that state before registering its own task. The original
quit intent remains unknown and has not been replayed. A separate fixed
correlation is required after proving the first quit task absent and covering
the expected running relaunch task in a causal regression. Runtime remains OFF
and no owner exit is proved.

A second fixed quit correlation
`d4edbb13-6a97-4a1e-8c28-3dd623f6f7f9` passed independent source and
route review, including the expected long-running relaunch task and an
encoded-command census for any still-running first-quit PowerShell. Its sole
start also returned unknown after a durable intent; read-only task diagnosis
found the second task absent. It has not been replayed. A finite read-only
bootstrap gate diagnostic is being added to identify the failed pre-registration
condition before any new native quit action.

A no-VM emitted-command audit then measured the actual nested
`powershell.exe -EncodedCommand` lengths: 37,642 characters for the first
public-status start, 40,086/41,434 for its retry/third, 37,654 for the second
quit start, and 37,050 for its bootstrap diagnostic. Each exceeds Windows'
32,767-character process command-line limit, explaining why the fixed tasks
were absent and why the second quit diagnostic fell through to unknown. The
retry/third account separator also had the independently fixed vertical-tab
defect; both causes remain documented. A bounded verified compression helper
and a new separately correlated one-shot are code-only work in progress. All
earlier unknown intents remain preserved; none has been replayed.

The compact third quit correlation `38daf3a3-a661-495e-a001-b2b0bdaa9a66`
passed independent review and its emitted guest command measured 19,127
characters. Its one native start was `submitted` and the task is present.
A read-only exact-task-result probe verified `failed`; subsequent liveness
still showed the original owner pair and runtime OFF. No quit was replayed,
and owner exit is not proved. A separately correlated original-user read-only
phase diagnostic is being built to identify the failure before any further
owner mutation.

The fixed read-only original-user phase diagnostic
`7c35c962-3fd3-42ce-914f-05f6e4a48a42` then ran once and returned
`owner-before`. A source comparison found a deterministic mismatch: the quit
task's owner check expected the state path quoted for both CLI processes,
whereas the exact relaunched pair has one quoted and one unquoted state path.
The third quit task body and its failed receipt remain immutable. A fourth,
separately correlated quit helper is code-only work in progress with a causal
command-form regression and fresh admission.

The source-bound 2.1.19→2.2.2 MSI pair and 131,218,059-byte target fixture
bundle remain registered. Fixture correlation
`e66d02a7-a40c-41e0-8f8b-674624f98a54` failed locally after reserving
`host-staged` because a buffered stream was passed where the remote helper
expected a Path. The exact failed Codex command transcript was imported from
the app into ignored owner-only evidence, reviewed against its input/source,
and used once with fresh remote absence to durably close the consumed transfer
as `aborted`. A separate fixed retirement finished only the held `stage` role
as `failed-cleaned` under campaign lease
`94238e9e-4296-4a70-9b0a-0762f82aaf07`. Read-only status now proves the
transfer `aborted`, role `retired`, and campaign `active` with no role. The
original e66 failed command and receipts remain preserved; no package bytes
were staged in that attempt. A new admitted correlation is required for target
fixture staging.

The next Windows gates are a proven original-user public status or another
source-bound owner proof, public owner exit while runtime remains OFF, a fresh
target fixture stage, installed 2.2.2 update/recovery, and remaining Windows
broker/lifecycle/visual cases. The final-source package and four-platform
evidence gates remain open.

### Windows-first continuation — 2026-09-29

The user set the native acceptance order to Windows, Android, Linux, then
macOS. Subagents for new slices use GPT-5.6 Terra at medium effort. Android,
Linux guest and macOS native mutations are paused; already submitted hosted
builds and captures retain their exact correlations and historical evidence.
`97f63af670a0b68f266e1fa3a0bdf7c4af429739` is the latest clean pushed
`dev` checkpoint. Its full prepush tier passed, and the user requested one
required exact-SHA CI check only at final delivery. The Secure Boot preflight
diagnostic and fixed swtpm repair are in this checkpoint. A read-only swtpm
owner census is reviewed and currently dirty for the next coherent checkpoint.

CP117 remains at installed 2.1.17 with runtime and active product process count
zero, one owned Explorer, passed read-only PowerShell/base/owner preflights and a
successful credential probe. Exact-dd10 hosted MSI pair run `36620110827` is
historical after later source checkpoints. Correlation
`3ff2a91c-2e1e-4775-8d84-b0cc5b2e8b30` was collected, byte
verified and registered with base 2.1.19 and target 2.2.1. No CP117 installer
or VPN action has run. The separate blank Windows Setup VM is blocked before
start because its Arch host lacks `virt-firmware 26.9-1`; it cannot copy the
live source disk. A fixed MCP installer for the signed Arch package and private
ignored `.codex/arch-sudo.local` input is in place. Its first start returned
unknown before any durable intent, credential read, or transaction. The
read-only preflight identified an inherited global signature policy that the
original repo-specific query misclassified. The original correlation remains
retired. At the clean `00e8897` checkpoint, a fresh correlation
`0751a22c-e242-4dc9-89db-fa2b98300b87` passed admission and the fixed
signed `virt-firmware 26.9-1` transaction, package integrity and executable
checks. A new Secure Boot preflight then blocked on `host-components-unavailable`
before resource/digest sampling; its corrected read-only diagnostic, correlation
`37604a3d-a215-460f-962c-e80f0b0b75b5`, names `swtpm-package`. A later
read-only correlation `4c625eba-2441-4dd2-a4bf-4e7f44e2d8f3` classified
the exact installed `swtpm 0.10.2-1` as `integrity-failed` by `pacman -Qkk`.
A fixed signed same-version repair tool passed focused/full agent-tool tests
and independent security review. Its fresh preflight
`3c10ed24-d542-431f-b858-bf20a7155fbd` blocked on an active swtpm process.
The new fixed read-only owner census sees PID `589341`, start ticks `520739`,
UID `1000`, but classifies the socket relationship as unattributed and `/proc`
visibility as incomplete. CP117 QEMU PID `589342` has adjacent start ticks,
which is not ownership proof. No repair, process stop or VM start has run. CP117
remains running for its public MSI acceptance. The credential value is never
documented or committed.

Exact-dd10 hosted visual captures were collected with source provenance:
Linux 59/59 and Windows 57/57 hosted scenes. Linux has 17 automated passes,
40 reviewed expected pixel differences and two missing add/edit baselines;
Windows has 15 passes, 40 pixel differences, two missing add/edit baselines,
and one local-only UAC scene still absent. No geometry or contrast defect was
found. The user also requested a read-only Arch `ai_loop` token-efficiency
review; the configured SSH route had no fixed observer, so a narrow redacting
MCP observer was added and independently reviewed. Its first remote read-only
result found no system package or standard-path executable, inactive service
units, a running `ai_loop` process, and no safe model/budget/token projection.
The actual entrypoint and token savings are unverified; the user was asked for
its path. No `ai_loop` job was started.

### Eleventh continuation checkpoint pushed — 2026-09-29

`f7c09aa3c02f486d3e93b38c7684a25dba36c0d4` is on `origin/dev` at
product version 2.2.1 with a clean managed prepush receipt. It delivered the
reviewed Android unknown-install/retry recovery, Linux/Windows/macOS fixture
portability, Secure Boot/TPM read-only/fresh admission tools and visual capture
guards. Its required exact-SHA CI is deferred by user request until the final
delivery SHA; this is a source checkpoint, not native/visual completion.

Verified f414 artifacts could not be relabelled f7: no f414 frozen artifact set
exists, and the source-bound CLI/retry adapters require artifact source SHA equal
to HEAD. An exact-f7 nondebuggable Android APK was built, registered and
published for API29 staging: SHA256
`08836f869c4cb404ae0922b3c8fe1c55b4dd8afcd4a0140a4c737e90651389f0`,
45,027,012 bytes, package 2.2.1/code16820, nondebuggable x86_64 and original
signer. No API29 install or product action ran. Exact-f7 hosted Windows MSI,
Mac DMG, Linux RPM and Linux/Windows visual jobs were dispatched once and
retain their own f7 evidence.

The first exact-f7 Linux builder start `989f435d...` was refused before journal
or worker because the earlier collected f414 build retained `archlinux.claim`.
A causal terminal-ready closure route was implemented and independently
reviewed. It closed only the f414 claim under digest `1f4d2923...`, preserving
the f414 intent, verified artifacts, timings and a durable closure marker.
That tool repair is currently dirty and needs the next clean source checkpoint
before a new builder correlation and native Linux preparation. Hosted f7
package/visual jobs already running remain component evidence for their exact
SHA; do not treat them as final-source after the tool repair commits.

The exact-f7 hosted RPM pair completed and passed byte, receipt, NEVRA and
source-fingerprint verification. Fedora2328's guarded base preflight is ready:
installed 2.2.0, pinned current RPM header `3ef23bc...`, clear privileged
app/runtime/package process census, and no pending protected job. The f7 base
RPM has a different header, so a same-version source-bound base replacement is
needed before its target-update scenario. No installer has run.

The exact-f7 hosted Windows MSI pair and Mac DMG pair passed package and signing
verification. The Windows pair used base 2.1.17, equal to CP117's installed
version, and was refused before transfer or install. A reviewed read-only
pre-dispatch version gate now catches that mismatch; the next clean source needs
a 2.1.19 base and 2.2.1 target pair. The Mac guest remains stopped because host
free-memory pressure has not met its admission threshold; no install ran.

Linux visual capture completed with 59/59 source-provenance scenes and no
geometry or contrast failures. Forty pixel differences and two absent add/edit
dialog baselines were individually reviewed as expected changes from older
baselines, including owner-state projection and chooser decoration. The exact
final-SHA baseline/review gate remains open. Windows visual capture and the
other platform reviews are separate outstanding work.

### f414 native component review (historical) — 2026-09-29

`f414471de3bac3a4cda3161ea2b5cd47b2b10caf` was the preceding pushed
`origin/dev` checkpoint at product version 2.2.1. Its managed prepush tier
passed; the user requested one required exact-SHA CI check at the final source
freeze, so this checkpoint was not final delivery. Subsequent source work included
Android unknown-install recovery, two hosted Windows test portability repairs,
and visual fixture/capture guards. Preserve `f414` native evidence as historical
when the next source checkpoint is made.

The exact-`f414` API29 nondebuggable APK SHA256
`4398ac2659a1fe7d9bfabf8545793c0b9b73d353c9ed957f9263a541dd75ab06`
was installed by the guarded public path. The original owner wait stayed
`unknown/postinstall_owner_unknown` and was never replayed. A separate fresh
readback and public inspect proved owner
`a16efca1-d742-411b-9fa7-20b4826cf830`, revision 0, runtime stopped, no
operations, and unchanged canonical routing rules across the private backups.
Reviewed proof digest `c0fff5a275ade6e607d434dd36d737122690191411379b8e1ab054d4c45200da`
recomputed successfully before only the exact held install lease was released.
The original unknown receipt remains. API29 action/document acceptance is in
progress; API35 has not been updated.

The exact-`f414` Linux package builder correlation
`07d961ae-3189-4e6e-b4bc-3f8c8d1e0ee5` collected `ready` with verified
2.2.0/2.2.1 DEB, RPM and Arch packages and source-bound receipts. The target
RPM artifact ID is
`sha256-a57667e362d4447d1f5d66735f79f57f92908df8642a6bc8f1a33828d7c0ffc9`;
fresh byte verification passed. This enables same-source Android CLI staging,
subject to that adapter's admission. The first API29 stage correlation
`fbd6b8ea-06d1-456c-89d7-6f82d0795dd1` failed locally before remote
intent: macOS `bsdtar` could not list the newer zstd RPM with stripped CPIO.
A bounded RPM-aware `rpm2archive` fallback passed real-format local/remote
regressions and independent review. New correlation
`8b671747-b4ca-4ce7-9db4-f01ddd30f4c6` published and collected the exact
`f414` RPM CLI companion; the old partial state remains. API29's small-frame
same-request action `b1586f83...` passed: idempotent retry, conflicting
payload rejection, restored routing rules at revision 2 and runtime OFF.
Its large-document job `3db8fd9c...` collected complete under UID2000/API29
with a 48 MiB Dalvik heap limit and 11,536,164-byte/56,000-domain fixture:
full and cold reads, retained wait, new-request no-op, private
export and opening-rule restoration passed; runtime remains OFF. The receipt
reported `sameRequestRetry=false`, which remains an acceptance gap. Fresh
post-scenario readback admitted the exact APK with new owner
`66ce5143-2e32-4cd6-ba20-c8c88de9df93`, revision 1 and 239-byte backup.
The first dedicated same-request retry correlation `a2fbb6f0...` returned
`unknown/command_failed` with no phase and was never replayed. Fresh readback,
public inspect and reviewed categorical proof established exact terminal
PID/start ticks, `before_first_upload`, no transfer/product effect, unchanged
owner/rev, operation history 1→1, canonical routing and stopped runtime. The
packaged CLI `status` returned rc0 with nonempty stderr, which the retry worker
had misclassified as command failure; a causal regression and narrow adapter
fix are in progress. Exact MCP no-effect close recomputed proof, wrote a durable
marker and released only the held a2f lease (`state=closed`, `replayAllowed=false`).
The original unknown receipt and prior successful document receipt remain.
No Linux guest was booted or installed. Ubuntu2307 and Arch2317 are
stopped and lack current source-bound bundle/preparation receipts; one 6 GiB
host reservation is pending. Fedora2328 has ready read-only base preflight at
installed 2.2.0-1 with pinned header `3ef23bc...` and clear privileged process
census. Guest preparation waits for a clean final source checkpoint and
matching package/bundle manifest rather than reusing historical `f414` bytes.
The exact-`f414` hosted Mac DMG pair run `36603278497` succeeded. Both DMGs,
fixture receipt and signing metadata were byte verified and registered through
MCP; mounted apps passed strict expected ad-hoc codesign and JAR hash checks.
Reviewed ignored evidence is at
`continuation-macos/fixture-f414471/reviewed-package-summary.json`. Tart remains
stopped under host memory pressure; fresh read-only sample found 42% free,
pressure level 2 and 3,582 MiB swap used, below the 50%/normal admission gate.
No Mac reservation or monitor is active. This is package component evidence only.

The exact-`f414` hosted MSI fixture run `36602892567` failed before packaging
on two test-only Windows portability cases: strict Android installer admission
used POSIX private-file APIs, and Mac rollback test patching assumed
`os.getuid` existed. Causal RED/GREEN platform tests and independent review
now pass; CP117 remains installed at 2.1.17 with runtime OFF. The separate
blank Windows Setup guest is still paused at its TPM 2.0/Secure Boot blocker;
the reviewed read-only MCP inventory bound QEMU PID 3369984/start ticks
45177745 to its held disk/QMP and confirmed no linked TPM and ordinary
`OVMF_CODE.4m.fd`. Arch has `swtpm`, `swtpm_setup` and
`OVMF_CODE.secboot.4m.fd`; key-enrolled variable firmware still needs
identification. Prepare a stopped separate secure guest clone rather than
altering the current running VM. A reviewed read-only clone preflight
`windows-vm-secureboot-clone-preflight` returned
`unknown/failurePhase=source-holders`: complete `/proc` holder visibility is
not established for the Arch account. It remains `nativeActionAllowed=false`;
no new input or VM lifecycle action ran. A fresh independent blank disk and
the already verified ISO avoids copying the live source disk. Its source-only
one-shot preflight/start/status adapter passed focused review and a read-only
native preflight returned `blocked/virt-fw-vars-unavailable`. A separate
reviewed noninteractive `sudo -n -l` MCP privilege probe returned
`sudo-unavailable-or-auth-required` with `noninteractivePacmanEligible=false`.
No package, disk or VM mutation ran. A task-private pinned `virt-firmware`
install or user-provided Arch package installation is needed before fresh
secure guest admission; CP117's installed-VM update path is separate.

Hosted `f414` Linux/Windows visual captures passed provenance and have zero
geometry/contrast failures. Linux's synthetic refresh-policy scene had draft
state without persisted policy; a focused fixture regression corrected it.
Windows tray frames were contaminated by a native `System Properties` paging
warning. A causal per-frame and pre-provenance guard now rejects visible exact
or suffixed `System Properties` windows; focused tests and independent review
pass. The common missing `Desktop VPN capability: ready` row is an intended
owner-presentation change: the old fixtures injected an unverified healthy
message through a legacy path. Two causal fixture/owner projection regressions
passed after removing that synthetic claim from app and native scenes; old
baselines predate the presentation change and require review rather than an
invented ready status. The contaminated captures remain as failure evidence. Current-source
four-platform visual review and missing baselines are still open.

### Tenth continuation checkpoint pushed — 2026-09-29

`df05f3fec37d1d12de492592bcc118c4b8babd0f` is on `origin/dev` at
product version 2.2.1. The fresh managed prepush tier passed before its
checkpoint commit; GitHub CLI credential setup allowed the interrupted push to
resume without another commit. Required exact-SHA CI remains deferred until the
final delivered SHA by user request. The managed MCP transport stayed stale, so
fresh `agent_tools/mcp_tool.sh` processes supplied current routes and receipts.
This checkpoint is not native or visual acceptance completion.

The exact-`df05f3f` nondebuggable Android APK SHA256 `3f4c1e11...` was built,
verified and staged for API29/API35. Fresh readbacks preserved the original
2.2.0 installations, OFF runtimes and private routing backups (239 and
11,872,243 bytes); no APK replacement or AVD product action ran. The Mac
2.1.19→2.2.1 hosted DMG pair and receipt passed artifact verification under
run `36592834172`; they are component evidence at this SHA. Tart remains
stopped because host memory pressure fails admission, and the old unknown
installer job `465a954f...` is unchanged.

The blank disposable Windows VM booted the official evaluation ISO into
Windows 11 Setup. Exact-owner one-shot navigation selected English-US language
and US keyboard. A read-only provenance proof bound its originally blank
task-owned qcow2 by device/inode to live QMP topology and excluded foreign
writable disks. Separate reviewed one-shot actions focused and checked the
disposable-disk deletion acknowledgment, then selected Next once. The sealed
result says Windows 11 cannot install because this guest lacks TPM 2.0 and
Secure Boot. No bypass or further input ran; inventory for a standard virtual
TPM/Secure Boot remedy is read-only. Sealed optical, setup and screen receipts
live under `optical-boot-20260929/attempt3-current-frame/`. CP117 is separate
and remains installed at 2.1.17, runtime OFF, with no new MSI attempt. Two
`df05f3f` hosted MSI fixture runs failed in Windows release hygiene before
packaging because POSIX-only Python APIs were exercised; a causal portability
fix is dirty below.

The Arch Linux package builder's first one-shot correlation
`5c1c217f-3eb3-45e0-a499-96ae0a409883` failed before SSH launch on a
multiline bootstrap command. A reviewed pre-effect closure preserved its old
unknown intent and released only its exact local claim; the causal SSH fix is
dirty below. A hosted exact-`df05f3f` RPM fixture run `36593094225` is pending.
Six QEMUs remain live; no new Linux guest was booted or parked. Fedora2327
lacks a configured SSH alias; Fedora2328 has read-only connectivity but no fresh
installed-package admission.

The exact-`df05f3f` hosted Linux and Windows visual captures passed provenance
for all 59 and 57 hosted scenes respectively. Old-baseline comparisons were
17/59 and 15/58 passing; Windows UAC requires an owned local guest. A filtered
synthetic location-error fixture and sub-4.5 dialog button contrast have focused
causal fixes and a three-scene Linux recapture in dirty source. Most pixel
differences require reviewed baseline classification. All four-platform
current-source visual receipts remain open.

Current dirty work intentionally spans guarded Windows Setup, CP117 fixture
dispatch/MCP routes, Linux builder recovery, Windows Python portability, Mac
rollback portability and focused visual fixes. Each has an exclusive file and
environment owner; root owns their integration, metadata, next coherent
checkpoint, source-matched artifact rebuild, native matrix and final CI. Do not
label `df05f3f` component artifacts as final-source after this dirty work commits.

### Ninth continuation checkpoint pushed — 2026-09-29

`096804e8228540d4f7b59aeb6f7e56a58a11e245` is on `origin/dev` at
product version 2.2.1. Two managed prepush runs passed before its reviewed
checkpoint push. Its five required workflows are deliberately deferred until
the final exact SHA, as the user requested. This is a source and tool checkpoint,
not completion of native acceptance. Later source edits are dirty and require
a new clean checkpoint before source-matched packages are admitted.

The `096804e` nondebuggable Android x86_64 fixture APK was verified at SHA256
`19f7df032c95e2caa8d26ec9b523a124b427c9e288b9b6d1a59a6ad78c0b200b`,
registered and staged on the host for API29 and API35. Neither guest installed
it. Both still have installed 2.2.0, runtime off and preserved routing backups
(239 and 11,872,243 bytes respectively). Rebuild and reverify at the next
source freeze before guarded native update, action and endpoint acceptance.

CP117's old pre-dispatch MSI start was closed `failed-cleaned` with its original
intent retained; no MSI effect was inferred. A new exact-`096804e` hosted MSI
fixture run `36564027924` failed in release hygiene before package creation:
one opt-in build timer rejected equal monotonic ticks, and a visual platform
test called an unselected `bash` on Windows. Both failures have deterministic
RED/GREEN regressions and narrow fixes in the current dirty source; the MSI
pair must be built anew after the next checkpoint. CP117 is idle with installed
2.1.17, original-user CLI exited and runtime off. The fresh Windows baseline
VM is separate: its exact one-shot 6 GiB start is observed running but booted
past an optical `Press any key` prompt to PXE. Read-only ISO/OVMF/QMP/owner
diagnostics support the missed prompt. A minimal, guarded one-shot optical
reset/key action is being implemented; no reset or key has been sent.

The Linux same-source DEB/RPM/Arch package builder passed independent code
review and ten focused tests; MCP route wiring and a clean source checkpoint
remain before its first native use. No new guest was booted. The hosted
exact-`096804e` RPM fixture run
`36564346563` completed successfully, and its downloaded base/target pair
passed hosted verification (SHA256 `222e8452...` / `7e73ab93...`, fingerprint
`667f5778...`). The pair is historical at this source and is not registered
for the final native update after later edits.
Ubuntu and Arch final-source native replacement/rollback remain open. The Mac
Tart guest is stopped. Current host memory pressure did not admit its 4 GiB
boot, and candidate machine rollback/server-stop receipts remain untrusted;
no new machine installer ran. A host-only `096804e` source snapshot is retained
as historical preparation, not a signed final-source DMG pair.

Current work is limited to the timing/visual harness fixes, Linux package
builder, Windows boot diagnostic/recovery and their MCP routes. Root owns the
next metadata/prepush/checkpoint and final exact-SHA CI loop. No release action
is authorized.

Subsequent code-only reviews passed for the Linux same-source package builder
and an exact-owner guest park adapter; the latter requires a fresh privileged
read-only holder census before QMP powerdown and cannot accept caller-supplied
guest safety claims. Both have MCP route work, but neither has built packages
or parked a guest. Windows optical-boot recovery now has independently reviewed
ISO-FD, positive OCR and durable receipt guards, and a separately reviewed
post-key capture; read-only preflight found `ocr-unavailable` on the Arch host.
A user-local, signed two-phase OCR source/provision tool is under review. It has
not downloaded packages, reset the VM or sent a key. Mac's rollback worker,
fixture driver and observer now have an independently reviewed five-transition
root trace plus owner-bound cleanup receipt. A one-shot fixture-server stop
controller passed independent review after full campaign and fresh dual-stack
status binding. A prospective baseline for the old unknown Mac job is still
being developed; it must not claim historical preservation since CP174.

The Mac prospective baseline subsequently passed independent review after
causal pre-effect phase and short-write fixes. It records two matching
read-only input/worker/unknown-status samples under the current boot and
reservation, then requires the same baseline ID and fresh equality after a
new campaign. It does not change the CP174 outcome or prove its input was
unchanged before this new baseline. Mac rollback/fixture focused checks and
native worker compile passed; no Tart action occurred. Mac server-stop,
Linux guest-park and two-phase Windows OCR MCP routes passed 93 focused route
tests; full agent-tool discovery passed 1,142 tests with four skips. OCR source
preflight found the fixed Arch tools/keyring and 64 MiB headroom, but no fetch
or extraction ran. Root review found unchecked short writes in the pre-effect
source-stage intent; its owner added a causal fix and requested re-review.
Windows VM still shows the preserved PXE frame.

After full-write re-review passed, one guarded OCR source-stage fetch under
`3e8ef3d0-fe71-4e11-878d-9b452e6dd0d0` stopped as `partial-unknown`.
The first Tesseract package and signature are retained at SHA256
`75e96e4f...` and `4db444af...`; the English-data pair was not downloaded.
Read-only signature diagnostics found the selected Arch package-export
keyring returned `NO_PUBKEY`, while pacman's populated root-owned trust store
verified the exact signer subkey and primary. A separate v2 source root and
new correlation are being developed; the original partial intent will not
be replayed. No OCR extraction or Windows VM reset/key/capture ran.

The separately reviewed v2 stage used pacman's populated trust store under
new correlation `96ac7b5e-5159-4848-a38f-e78c50439a87`. All four package
and signature files were downloaded, but the stage remained `partial-unknown`:
the English-data package was validly signed by Christian Heusel's primary
fingerprint `F00B96D15228013FFC9C9D0393B11DAA4C197E3D`, while the v2
policy expected a different subkey. V1 and v2 roots/journals remain intact
and neither start will be replayed. A separate adopt-only verification of
those frozen v2 bytes is being developed under a new correlation; no OCR
extraction or Windows VM reset/key/capture has occurred.

The v3 adopt-only source verification was independently reviewed and admitted
under new correlation `b142de63-ad87-4258-afb3-de030c44d1be`. It copied no
network bytes and returned `verified` for all four frozen v2 package/signature
hashes. A local tuple/list JSON status mismatch initially hid readback; a
causal status-after-start fix passed independent review, and exact MCP status
now reports the same verified pins. V1/V2 partial intents remain unchanged.
OCR provision preflight exposed a separate source-correlation versus action-
correlation ABI gap; it is being fixed before any extraction. The Windows VM
has still received no reset, key or new capture.

One reviewed OCR provision preflight against the verified v3 stage admitted
three signed archive members and a fixed private runtime path. The single
provision start under `76e47261-f262-4887-94ab-d9513509e293` ended
`partial-unknown`; exact read-only status found all three extracted files
with matching signed hashes, but `--list-langs` exited 127 because the Arch
host lacks `libleptonica.so.6`. The intent remains non-replayable. A bounded
dependency inventory is underway before a separately signed remedy; no
Windows VM reset, key or capture has occurred. Android endpoint routes are
wired but native start is held until its shared device lease integrates with
the public installer and package-install paths.

The signed Leptonica package was later verified, but the OCR runtime
finalizer did not yield a verified receipt. Its partial journal and all
fetched bytes remain historical evidence. The user questioned the dependency
chain; work has pivoted to a single exact-owner QMP optical reset/key action
for this disposable blank Windows guest. The OCR/Leptonica path is stopped.
Independent code review and MCP route admission are required before that
native action. Windows CP117 and its installed 2.1.17 remain separate.

The minimal optical adapter subsequently passed independent review after
causal QMP peer, actual 6 GiB allocation and orphan-receipt corrections.
Read-only preflight for new correlation
`ca76aff1-b67b-47cf-9e82-e61b1fe76ebb` matched QEMU PID 3369984/start
45177745, the 7,092,807,680-byte Microsoft ISO at SHA256 `a61adeab...`,
zero allocated guest clusters and the fixed reservation. Its single native
start returned UNKNOWN; fresh exact status is `intent-only`, with no
before-screen, reset or key receipt. The attempt is non-replayable. A narrow
read-only phase diagnostic and pre-effect closure proof are in development;
no new reset/key is authorized from this attempt. Evidence is in ignored
`optical-boot-20260929/`.

Android installer dispatch teardown/lease and visible PackageInstaller
callback gates passed independent code review after causal orphan-listener
and foreign-focused-package fixes. The callback binds an exact UI snapshot,
public operation/session, owner/revision/runtime and source/artifact before a
one-shot handoff or continuation; it never taps a dialog. MCP route wiring
is complete; current-source native acceptance remains open. The Mac Tart guest is still
stopped: fresh host reclaimable memory was about 6.95 GiB, below the 8 GiB
observer gate for a 4 GiB boot.

Windows optical attempt 1 was closed pre-effect under
`b76bfd72-2d7b-459a-91da-a063e35c8007` after two matching read-only
samples. Attempt 2 `98b4f1e0-968c-455b-a85b-d87490f5b256` also stopped
at intent-only: a read-only phase probe proved a second closure/QMP handshake
ran while the action QMP socket was open, before any screenshot, reset or key.
It was separately closed pre-effect under
`7cbc014c-3890-422a-891a-a114d7cb779e`. Causal socket-census,
single-QMP-client and post-reset status regressions passed independent
review. Attempt 3 `e80d5b29-d44f-4b22-a821-5612304564b5` then completed
one reset and one space key: exact status is `post-screen-observed`, with
before/after PPM SHA256 `85410c93...` / `37488297...`, the same QEMU
PID 3369984/start 45177745, and no replay. A reviewed one-shot current-screen
observer/collector under `0dea2405-6b21-43b6-8629-38f77fa05e31` then
captured PNG SHA256 `db09c43c...`: it visibly shows Windows 11 Setup at
`Select language settings`. No installer option was selected or VM setup input
sent after the boot key. All raw MCP outputs and sealed images are retained in
ignored `optical-boot-20260929/`.

A reviewed read-only Arch QEMU census reached six live PID generations. Its
evidence remains incomplete for two unknown memory arguments and all older
role ownership, so it authorizes no parking. Six live guests alone block the
Linux new-guest preparation gate requiring fewer than four. The exact Windows
baseline is the only receipt-claimed role in this census. Source and MCP tool
edits are now quiescent for version metadata, full prepush and the next dev
checkpoint. Required workflows remain deferred to the final exact SHA per the
user's instruction.

### Eighth continuation checkpoint in progress — 2026-09-29

`a876f46fa4582e6218d341ac7012fd31bc919758` is pushed on `origin/dev`
after the full prepush tier. The user requested one required-workflow review at
the **final delivered SHA**, so intermediate CI was not watched. Current dirty
work includes Android native-document harness fixes, Fedora fixture diagnostics,
Windows owner/probe tools, hosted visual workflow and reviewed Android baselines.
No release is authorized; do not move HEAD while the Fedora source-bound native
fixture is active.

The exact `a876f46` Android native-fixture APK is 45,027,012 bytes, SHA256
`e36e54a218c8e4191abe28977147155d5bdf0f34e4a76bd055fd310d84cf2ec9`;
the exact Linux x86_64 target RPM is SHA256
`7c662bece800a761032f0c20fa6b4aa46d941afdfa1475d91834b6da7373c83b`.
Both are independently verified and MCP registered. API29 installed the APK,
and its fresh readback/public inspection proved retained opening rules and
runtime off. Two 48 MiB document correlations remain historical unknowns after
their imports committed; each was separately restored with a guarded one-shot
recovery and lease finalize. The later corrected API29 document correlation
`32390627-3429-44b9-a07d-08d70136d6f2` completed full/cold reads, retained
wait, new-request no-op, private export and restoration. Fresh closing readback
`1b7e90e5-584c-4b88-aaf1-82f6d3b779ca` and public inspection proved the
239-byte restored routing, exact APK, new owner and runtime off. Same-request
retry was not exercised. API35 has a fresh 11,872,243-byte opening backup and
completed one guarded `a876f46` replacement under
`54df1051-2ed2-4d3c-b174-7db67e6364c4`; fresh readback
`0e8dbb7c-8f51-475e-ad28-ef02a45c8671` and public inspection confirm exact
APK, preserved 56,000-domain routing, new owner and runtime off. Its install
lease was reconciled after that proof. API29 then completed a separate
small-frame explicit-UUID provider retry under
`214b85ef-eb8c-4efb-9d78-91d9a62be784`: identical request returned the
same operation/revision, changed-payload reuse was rejected, and fresh closing
readback `684a8ada-dc52-4216-879a-ab3f146c8630` proved 239-byte restored
routing/runtime off. This does not claim a large-document transport retry.
Current-source consent denial is preparing a fixed requestor-bound UI route;
grant and cancellation remain open.

Fedora installed the exact-source `2.1.19` base RPM by guarded same-version
replacement and verified its header and `rpm -V`. The old unknown HTTPS fixture
server correlation `0c2265fc` and fresh diagnostic correlation `e5cb22c8`
each left a live loopback fixture server after Java probe failure; each server
was stopped once through reviewed exact pidfd/identity MCP and absence verified.
Both jobs remain UNKNOWN and unreplayed; product VPN/runtime was untouched.
Subsequent guarded attempts exposed and causally fixed Java CONNECT Host,
certificate-stream lifetime and a missing protected-intent JAR hash. The fifth
server reached exact READY and the public update ran, but its terminal scenario
failed on protected workspace cleanup. Fresh read-only state proves the target
`2.2.0` RPM installed, `rpm -V` clean, protected job succeeded, replacement
owner present with runtime off and credential restored. Preserve the failed
correlation `944447ff` and retained workspace; do not replay the RPM update.
A bounded read-only workspace recovery route is under final review before a
separate one-shot cleanup. The historical
Ubuntu DEB and Arch package cases were reviewed, but their older source does
not close final-source package acceptance; the owned guest/resource map is
being checked before fresh reruns. A new fixed read-only inventory found both
old guest disks stopped and safe with no listeners or reservations, but its
`nativeActionAllowed` is false; a fresh clone, source-matched package pairs and
new guest/job admission remain required.

The workspace route has since passed independent review and observed the
retained workspace as `referenced` by replacement owner PID 84498, start ticks
42693938, controller `4da9288d-dd73-4312-92d8-c7d96f046040`. Fresh public
observation reports runtime off and no active or selected location. The Linux
owner added a generation-bound public quit with a causal test and independent
review. One exact public quit correlation `bf57271c` completed; fresh observation
proves that owner generation exited and the retained workspace is no longer
referenced. A separate one-shot cleanup remains under review. The update
correlation remains failed and unreplayed. The read-only VM inventory received
final independent review
after socket-inode and process-generation corrections. It does not admit a
native action.

Fedora subsequently completed the separate exact cleanup correlation
`5eac659d-a6d4-4005-b97a-40063b10d8bf`; read-only status verified workspace
absence. The original public `944447ff` terminal failure remains unchanged.
The exact loopback fixture server was then stopped once after target/header and
cleanup proof; pidfd exit was observed, fresh server/worker process readback is
absent, and the target RPM remains ready with no app runtime. This is recovered
native evidence for `a876f46`, not a retroactive passing public receipt.

Windows CP117 still has no guest mutation. Reviewed stage/server/base/target,
owner-network and probe code retains fail-closed public starts; private intent,
closed-campaign, ACL and scheduled-task cleanup regressions passed focused
checks. Fresh read-only CP117 preflight found installed 2.1.17 and two
original-user CLI processes, so this guest is not idle; both were preserved.
There is no trusted stopped baseline disk for a fresh clone yet. One exact
`a876f46` hosted MSI fixture build correlation `5c7f5da3` is submitted, not
native acceptance. Native PowerShell 5.1/QGA behavior and actual owner-JVM
HTTPS proof are still needed. The exact `a876f46` hosted Windows visual run failed before
capture because its workflow omitted pinned .NET SDK setup; the workflow now
reads the lockfile and installs the SDK, with a causal RED/GREEN check. It needs
a new pushed SHA rerun.

The exact `a876f46` Mac 2.1.19-to-2.2.0 hosted DMG pair is signed, hashed and
MCP verified (review summary
`continuation-macos/fixture-a876f46/reviewed-package-summary.json`). Native
Tart had remained stopped while host GUI unlock was unverified; Finder AX now
proves an unlocked Desktop and a fresh resource check passed. The Mac owner is
reserving a graphical native Tart slot; no machine installer has been submitted
yet. Android visual capture completed 74/74;
69 pass and five independently reviewed expected changes were recorded, with
five Git LFS baselines updated. A repeat-start AVD ownership defect was fixed
with a causal test and the owned AVD was scoped-stopped. Desktop final-source
visual capture/review remains open.

The exact `a876f46` Mac machine install reached a visible SecurityAgent password
prompt. One Escape dismissal yielded public `CANCELLED`, installed=false; a new
owner reported `cleanupCode=OK`, the signed 2.1.19 base inode and JAR were
unchanged, and runtime stayed off. The reviewed denial summary is
`continuation-macos/fixture-a876f46/native-machine-denial/reviewed-denial-summary.json`
(SHA256 `e300e7f6cd6541410ce56c43c5ea6276786bb87f7dbcc8cee3ef5d14eb544a3b`).
Both owned app processes quit, fixture server stopped, and Tart/reservation were
released. Machine grant, installed update, rollback and GUI return remain open.

The separate MCP worker finished narrow route and boundary improvements:
canonical correlation IDs, conservative retry flags for uncertain states,
typed uncertainty only from allowlisted domain observations, reviewed Android
consent-denial and Fedora workspace-status routes, and the read-only Linux VM
inventory. Full agent-tool discovery passed 832 tests with four skips and docs
hygiene passed. One lease test fixture was corrected for restrictive process
umasks. Android consent preflight then exposed a 120-second SSH request against
a 60-second transport limit; a causal 15-test fix passed independent review.
Its next fresh denial attempt rejected before submission because permission was
not freshly absent. The Android owner added a bounded read-only preflight
classifier with a missing-mode causal correction; 18 focused tests and root
review passed. Its MCP route and native category observation are pending; no
grant or VPN start occurred.

API35 then completed exact-current-source consent denial under correlation
`06705397-240c-4729-b6cb-721f9286cf78`: the public operation returned
`PERMISSION_DENIED`, permission remained absent, runtime stayed off, and its
lease was released. Fresh closing readback preserved package, owner/revision
and 11,872,243-byte routing export size; independent export hashes differ due
to generated timestamps, so semantic rule identity is not claimed here. API29
read-only preflight classified permission already granted; no reset was made.

The user authorized additional development-speed work. A separate MCP owner
implemented a source-bound read-only acceptance overview, verified artifact
cache check, parallel read-only VM preflights, failure fingerprints and admission
gaps, and a strict build timing report; 854 agent-tool tests passed with four
skips. Root review requested live verification for caller-supplied correlation
and owner fields before claiming the overview complete. A Gradle cache probe
found two generator tasks incompatible with configuration cache; a separate
worker recorded the causal RED and is validating the fix. A Windows baseline
worker is inventorying stopped trusted sources without touching live CP117.
The next package matrix will freeze source after current fixes; required CI is
still reserved for one final exact SHA.

The Gradle worker fixed both JSON generator configuration-cache captures and
proved the real desktop task graph reuses cached configuration (1.42s cold,
0.31s warm after the final edit). Both generators restored byte-identical
outputs FROM-CACHE; a real task-graph regression is now in release hygiene.
The Windows baseline read-only census found a flat historical disk with no
observed QEMU holder, but its source state remains **unknown** until all-process
holders, provenance and job state are verified. Live CP117 was not copied or
stopped. The Linux timing helper emits opt-in, source-bound private receipts
for runtime/native-helper preparation, Gradle, packaging, upload and staging;
76 focused tests passed, while actual durations await a source-frozen build.

Further current-source Android API35 acceptance correlation
`266b647a-1504-4e2a-b3b6-604f06852819` completed a public noninteractive ON
rejection (`INTERACTION_REQUIRED`, no VPN dialog), then an interactive consent
Cancel (`PERMISSION_DENIED`). Fresh closing readback retained the exact APK,
owner/revision and 11,872,243-byte routing export size; permission remained
absent and runtime off, and the lease was released. Raw export hashes differ
because `exported_at` is generated. API29's granted permission was preserved.
This proves only these action slices, not actual VPN traffic or installer grant.

The exact `a876f46` hosted Windows MSI fixture run `36551205532` completed and
its pair was MCP collected and verified: base 2.1.19 MSI SHA256 `9a63e408...`,
target 2.2.0 MSI SHA256 `dff5b596...`, receipt `086cf410...` and source
fingerprint `424cb779...` (full values remain in the immutable receipt). CP117
base readiness remains blocked by original-user CLI PIDs 3640/5520; runtime and
selection facts require a fresh public owner snapshot before any public quit.
The first owner observation `c9f7bd65` stayed UNKNOWN because its remote start
used the MSI parser instead of the owner-specific empty-artifact payload. The
corrected parser has causal RED/GREEN tests; bounded fresh status reports
`preEffectAbsent=true` with no exact stage/task/result leaf, while the old
correlation remains preserved and unreplayed. No CP117 installer was submitted.

The fresh Windows baseline remains separate from CP117. Read-only all-process
holder census is incomplete, so no historical qcow2 was cloned. The existing
official Windows evaluation ISO was matched to Microsoft's published hash;
the original small `virtio-win.iso` remains unverified. A pinned Microsoft
VirtIO ISO download under correlation `414697b9` had an uncertain CLI start
response and first status `partial`; a later read-only status verified the
*original* completed 789,645,312-byte transfer at SHA256
`e14cf2b94492c3e925f0070ba7fdfedeb2048c91eea9c5a5afb30232a3976331`.
It was never resubmitted. The exact start-response traceback was not retained;
the MCP boundary now has defensive unknown/status coverage, not a claimed
causal diagnosis. No new Windows VM has been created. Vendor-controlled
evaluation setup/account sign-in remains ahead.

The new MCP acceptance overview performs bounded, read-only source-bound
local verification: exact APK/RPM/DMG/MSI bytes and both Android consent
correlations plus Fedora cleanup are visible; live owners remain unknown unless
freshly observed, and the matrix gate remains open. The Gradle configuration
cache fix is ready; measured package phases await a clean source checkpoint.
Ubuntu/Arch fresh guest admission, package/fixture receipt binding and native
worker code are under development, with no guest boot or package action. A
Mac-only one-shot gate and diagnostic Tart observer are also code-only; fresh
resource, owner, secure UI and terminal adapters remain required before a
machine grant/rollback run.

Subsequent reviewed `a876f46` Android API35 denial/cancel evidence is complete
under both consent correlations above. The new Android host-only fixture
lifecycle passed independent review and 18 focused tests after causal journal,
lease, process-identity and terminal-read fixes; its scope explicitly excludes
installer-target admission and no AVD fixture was started. CP117's fresh
original-user public status correlation
`5119871d-9df6-4205-b315-af24a9040fbc` completed and cleaned. It observed
controller `d1040a53-ccaf-4f26-9a1b-76d910d4255f`, configured VPN mode,
runtime off and no active or selected location. The one-shot public quit adapter
passed 30 focused tests and root review; MCP wiring and a fresh native check
remain before the approved quit. The fresh Windows baseline's Windows and
Microsoft VirtIO media hashes, OVMF, KVM, QEMU, free VNC port, memory and disk
passed read-only preflight. A separate 8 MiB qemu-img probe completed; the
proposed 6 GiB VM reservation and one-shot start remain pending route review.
No Windows installer or new VM has run.

CP117 subsequently completed one reviewed public quit under correlation
`46dc2dd5-d8ba-4e31-b607-8ac572128a3f`. Fresh guest admission checked the
exact original-user CLI PID generations and runtime-off status before the
single public command. Terminal status and cleanup report `quit-complete`:
both PIDs exited, the endpoint and runtime process are absent, runtime remains
off, and no location is selected or active. The response wrapper initially
classified that successful new state as `ok:false`; a causal MCP regression
corrected it without changing the immutable native receipt. Fresh base readiness
and MSI installation remain open.

The next CP117 base MSI start reserved its local campaign under correlation
`30a6f33b-3ea2-42d0-8818-3d6711b34169` but rejected an 1800-second SSH
connect timeout before remote dispatch. The original intent was not replayed.
A causal transport-bound regression now validates the command before any
reservation. One-off read-only MCP proof twice found no remote stage, guest
task or installer leaf; fresh readiness still showed one installed 2.1.17
product and zero active installers. The exact campaign was then journaled
`failed-cleaned` and closed with receipt SHA256
`dd6b954cef91496807fbf5d07057c6665f1a3dace787e3f81368c453bc905dc6`.
The original intent remains archived and a new MSI campaign awaits the clean
source checkpoint.

The managed repository workflow now has an explicit intermediate `checkpoint`
action. It keeps pre-push receipt, explicit-path, version and clean-worktree
guards, then returns the pushed SHA with required CI marked deferred; the
ordinary commit/push paths still watch exact-SHA CI. This follows the user's
request for one required-workflow review at the final delivered SHA. Its causal
RED/GREEN tests passed, and the quiescent agent-tool suite passed 1,047 tests
with four skips. Full managed pre-push passed before the checkpoint action was
added, so it must be rerun after that final tool change.

Ubuntu/Arch fixed guest preparation and native acceptance remain blocked from
guest action by independent review findings: process census could count its
own probe or miss unreadable PIDs; final package effect needs fresh owner and
runtime admission; rollback owner cleanup must cover activation timeout; and
launcher version checks must match an exact displayed version. Owners are
adding causal tests. Mac's source-bound machine boundary and observer passed
21 focused tests, but historical unknown preservation, fixture-server stop and
rollback trace lack fresh trusted evidence, so machine grant remains closed.
No Tart boot or guest action was run in this code-only phase.

The DEB/Arch source-level admission adapters subsequently passed independent
review with 67 focused tests. Six narrow MCP guest-preparation/native-acceptance
routes are available, but dirty-source preflight still denies native starts.
The Mac machine boundary, receipt validators and dual-stack kernel observer
passed separate independent reviews and 29 focused tests. Candidate validators
still lack trusted server-stop/rollback producers and fresh proof that the
legacy unknown job is unchanged; terminal acceptance flags stay false. Mac
source edits are paused for the next checkpoint, with Tart stopped.

### Seventh continuation checkpoint in progress — 2026-09-29

`fa05e690fad16a01675c223f1d9825ac257a6a65` is the current pushed
`origin/dev` checkpoint, version `2.2.0`. Its full prepush tier passed before
push. Per the user's delivery preference, required development CI is reserved
for the **final delivered SHA**; the exact-source hosted package/visual runs
below are component evidence. No release is authorized.

The exact `fa05e69` Android native-fixture APK is frozen at SHA256
`0657316f2d8d9ac8f6a4677ddc70c476282ea3b3c2ed80adde4b2d60cc7c6b41`.
API29 and API35 each had a fresh backup and runtime-off owner admission.
Independent review cleared the Android-only artifact-kind alias, equal-version
different-byte signer guard and per-device lease lock. The historical API29
terminal lease was reconciled through MCP after current package/owner/backup
proof, then one `fa05e69` API29 install completed under correlation
`e506c6ec-36fd-4338-95a3-503240ff6957`: target bytes, new controller,
239-byte routing and runtime-off state passed terminal and fresh public
inspection (`fa05e69-android/install29-terminal.json` and
`install29-public-inspect.json`). The historical API35 terminal install lease
was separately reconciled against its old receipt and fresh admission; no new
guest action occurred on the rejected pre-submit correlation. One guarded
API35 install `9ef0ce38-5c06-4d31-87af-3c7cf7dfe050` replaced old APK
bytes with the exact `fa05e69` APK and retained the 11,872,243-byte routing
document with runtime off. Fresh public inspection `29fd22f2` and detached
readback `d1877484` confirmed the new owner, exact APK and zero operations.
The verified APK's immutable `native-fixture-apk` registry record remains
intact. The exact `fa05e69` Linux RPM target is registered at SHA256
`777083fadda70257498d8026a16b89c995eef4e49358a9ccb16f79a1a372451b`;
Android CLI stage `3a60c550-6f62-4fb8-a72f-c6fd6f2012e9` is published and
rehash-verified. The first API29 48 MiB document scenario correlation
`2d74c7fb-11f8-4a2b-8b98-4a195875a7b1` ended `unknown/command_failed`
after its 56,000-domain import committed. Fresh readback shows unchanged
`fa05e69` package, runtime off, owner revision 1 and 11,872,243-byte routing.
Its opening 239-byte export and unknown result are preserved. A separate
journaled guarded restore completed under fresh correlation
`cb114417-209f-4063-85d6-27c0b508f64a` with exactly one public restore
operation. The independent closing readback
`368c2fa3-f621-428c-ab02-1cc76592bded` verified the same `fa05e69`
package and controller, runtime off, a 239-byte routing backup and all
persistent fields from the opening export (ignoring only the export timestamp).
The original unknown document lease was then released through the guarded
finalize route. Preserve the unknown scenario and its evidence; do not replay
it. A full new-source Android document, cancellation, consent and resource
matrix has not passed on either emulator.
The next guarded document run will use a durable, fixed-token command-phase
marker added after a causal RED/GREEN test; no phase is inferred for the old
unknown correlation.

The `fa05e69` hosted Linux RPM, Windows MSI and Mac DMG pairs were verified
and MCP registered without relabelling old source artifacts. Fedora still has
the verified `2.1.19` base, runtime off and no public target update. A separate
journaled HTTPS server lifecycle and protected public launcher binding passed
independent review; the fixed MCP route is wired with causal tests and a new
pushed source is the next native gate.
Windows CP117 remains untouched: shared lease, stage, credential and server
code is dirty and fail closed. Independent credential path ancestor review
passed, but server stop/abort failure-order fixes and original-owner JVM
proxy/trust plus actual HTTPS probe still need review before server start can
be exposed to native use. The historical CP176 cleanup proof has a guarded
adapter under review and remains a base-install gate.

Mac's `fa05e69` user-local native update completed `SUCCEEDED/OK`, with strict
target signature/bytes and a new app controller while runtime stayed off
(`continuation-macos/fixture-fa05e69/native-user-local-summary.json`). Tart
was stopped and released. The machine authorization/visible GUI return case is
still open because the host Mac locked before SecurityAgent submission; its
READY machine fixture was left untouched. The prior unknown job remains
historical and unreplayed.

Android visual capture at `fa05e69` has 74/74 scenes; comparison is 71 pass
and three independently reviewed intended-change candidates (`locations-qr`,
`routing-qr`, `routing-error`). All three desktop hosted captures exposed one
`settings-refresh-custom-hours` fixture defect; a causal fix is dirty and
requires a new-SHA rerun. The Android `locations-empty` stale selection and
Android/desktop hidden DNS validation feedback were reproduced with focused
RED tests, corrected and passed focused GREEN tests plus diagnostic captures.
No baseline has been changed. Full native document, four-platform visual and final exact-SHA
required-workflow acceptance remain open.

### Sixth continuation checkpoint and next dirty source — 2026-09-29

`2a7b6a4cbbca75a8a3e9740f6be33f9ed1bac6bf` is pushed on `origin/dev`.
The user requested **one required-workflow CI review at the final delivered
SHA**. The following are exact-source component results, not completed
four-platform parity rows or final artifact and visual acceptance. No release
is authorized.

Android API35 and API29 installed and publicly inspected the same frozen
native-fixture APK, SHA256
`75e0e9fc2804373b174e16e82310d62e9815c9cf51aa7ed603466cf64ca9c4eb`
(`2a7b6a4-android/frozen-apk-receipt.json`). Both terminal install receipts
report the expected package hash, verified post-install routing and stopped
runtime; the fresh public inspections bind the package, controller and revision
(`install35-terminal.json`, `install35-public-inspect.json`,
`install29-terminal.json`, `install29-public-inspect.json`). Their backup SHA256s
are `0322057579803ce36cc6eb94765c2d74c66c674d7fda00ee12d8532bd963b8fa`
and `13398ce608ccfb1d56f1d81ab51b57b89d1bf82d3cd3d437af2dfdd79a5a97f2`;
post-install routing SHA256s are
`5eafd50d15ef1fc2db6a2069bcf42ad086367a71748ad752e15edc41e6bf9b7b`
and `86e573cb513090daead226040e5ace7ab9a22a32f56f645f4b384c0cb96e37e3`.
The native document row and Android visual comparator remain open.

Fedora's exact-source base RPM `2.1.19` install passed with clean RPM verify
(`continuation-linux-2a7b6a4/base-install/status-1.json`); the independently
verified `2.1.19`/`2.2.0` pair is in
`continuation-linux-2a7b6a4/hosted-rpm-fixture/local-verification.json`.
Reviewed RPM-only fixture derivation succeeded locally, but the public HTTPS
fixture endpoint, proxy and trust are still unready. No target start was
submitted. Windows' exact-source hosted MSI pair (run
`36447907765`, artifact `10982156646`) is locally verified as package input:
the receipt SHA256 is
`aa87705abb113ef845a71012a07304c3e1859a4dcac3a2fa926ae8ff7da47911`,
with base/target MSI SHA256s
`adb11ce963880e3b103f9b4987bc5950114a0e3bb3535988e4c3139280db19be`
and `4b389187c35095009fa6ffe3030672fd4937e8eb4bf74d6c5682df68b5bbc976`
(`../windows-msi-fixture-collect/b05b8679-02fa-40a6-8805-8faa128d3bcc/`
`extracted/fixture-receipt.json`). CP117 owner observation ended
`TASK_UNKNOWN_ENDPOINT_AUTH` and its correlation was cleaned without replay
(`continuation-windows-owner-2a7b6a4/owner-observation.json`). Windows
staging and lease tools remain dirty; there is no target install result.

Mac's exact-source signed arm64 `2.1.19`/`2.2.0` DMG pair is recorded in
`continuation-macos/fixture-2a7b6a4/pair/fixture-receipt.json`. The owned
Tart guest disk grew from 50 to 60 GB. The fixture DMGs are already staged in
the guest with verified bytes but mode `0644`; fixture serving requires
read-only mode `0444`. Installation is held for the fixed MCP mode repair in
the next checkpoint. Hosted desktop visual capture on `2a7b6a4` exposed a
cursor fixture failure; its causal fix is dirty and needs a new-source
recapture. Preserve all component
receipts and historical captures; document-native and remaining GUI/CLI matrix
rows still require their own packaged actions and effect comparisons.

### Fifth continuation checkpoint and next dirty source — 2026-09-28

`31b3c1145e0d33be473f5a88debc881e3a816498` is the current pushed
`origin/dev` checkpoint. Its frozen Android native-fixture APK has SHA256
`83a9aea9eb52681bc49197be0ba5d5c36a6232321656bc1768edc9046b00009c`
(`31b3c11-android/frozen-apk-receipt.json`); capture is pending comparator
review. Package and native receipts below prove only their stated components.
The user requested **one required-workflow CI review at the final delivered
SHA**. Full four-platform parity, final artifact and visual gates remain open;
no release is authorized.

Mac's one visible SecurityAgent Escape denial ended with protected installation
`CANCELLED`/`NOT_STARTED` and `cleanupCode OK`
(`continuation-macos/fixture-31b3c11/denial-not-started.json` and
`denial-recovered-status.json`). The input and protected paths are absent, the
base inode and signature are unchanged, and Tart is stopped and released. Keep
this as bounded denial and cleanup evidence, not an installed target result.

Fedora's explicitly approved guest-only public quit of PID `18367`/startTicks
`2078693`, controller `1780cc81-65a6-4284-a424-2178b94e2690`, is terminal:
the exact owner generation is gone and the correlation cannot be replayed
(`continuation-linux-owner-quit-31b3c11/quit-collect.json`). The guarded
protected-job scan observed the expected jobs terminal `SUCCEEDED`
(`continuation-linux-protected-job-31b3c11/observe.json`), and a read-only
base RPM preflight is ready (`base-preflight-after-fix.json`). RPM installation
is still held while the new reservation-lock fix receives its next source
checkpoint and admission; the scan itself did not mark admission ready.

The Windows hosted fixture at `31b3c11` failed in a Windows test portability
path. Its bounded failure log led to a test-only fix in the next dirty batch;
no target install or owner acceptance follows. The owner-observer correlation
ended `TASK_UNKNOWN_TRANSPORT` and was cleaned without replay. New stage
diagnostics are also dirty and require fresh source-bound verification. The
desktop visual benchmark fixture fix is in this same next checkpoint; prior
captures remain historical until recaptured and reviewed on that source.

### Fourth continuation checkpoint and next source work — 2026-09-28

`1b0cc06d0964763fadba5137652498355501eeb5` is pushed on `origin/dev`.
The user requested one required-workflow CI review at the **final delivered
SHA**; intermediate pushes and fixture workflows supply source-scoped evidence,
not final acceptance. Full parity and every platform's native/visual matrix
remain open. No release is authorized.

The exact-`1b0cc06` Android native-fixture APK is frozen with SHA256
`a16a91ecb7034dd4a6520475849979c1a9344bdf9573e802e7707d0051007a8e`
(`1b0cc06-android/frozen-apk-receipt.json`); install remains held. Independently
verified Linux 2.1.19/2.2.0 RPMs are recorded in
`continuation-linux-1b0cc06/hosted-rpm-fixture/local-verification.json`, and
strictly signed Mac arm64 2.1.19/2.2.0 DMGs in
`continuation-macos/fixture-1b0cc06/reviewed-package-summary.json`. These are
**component package receipts only**. Windows still has the earlier verified
`58b5695` MSI pair; no current-source Windows install or owner-lifecycle proof
follows from package bytes.

Windows owner observation on the `1b0cc06` route stopped at a pre-submission
guard; the QGA closed-receipt causal fix is in the next dirty batch and awaits a
new SHA. The exact older `c8351cb2-162e-489e-91a1-3a75d7b49fb5` UNKNOWN
observation remains cleaned up and unreplayed. Target preparation still requires
an admitted live CP117 fixture HTTPS server/proxy and an exclusive shared lease;
the legacy CP176 job remains terminal historical failure evidence. No Windows
target install has been submitted. Android and Linux installs also remain held,
and Mac native installation awaits host GUI unlock and fresh resource admission.

The user explicitly approved a **guest-only public quit** of Fedora2328's
task-owned `vpn-control` controller
`1780cc81-65a6-4284-a424-2178b94e2690`, PID `18367`/startTicks
`2078693`. A fresh MCP observation found `runtimeRunning=false` and no active
location. Approval is scoped to that identified guest owner; the quit has **not**
been sent. A narrow public-quit adapter, tests and MCP route are awaiting
independent review and the next source push. Base RPM installation remains held
until the exact quit and cleanup are authoritatively observed on that source.

Android visual comparison reached 71/74 on this source. Three remaining diffs
are intentional baseline candidates requiring individual screenshot review and
a next-SHA recapture after any approved baseline change; they are not accepted
yet. Hosted desktop capture exposed a selected-row fixture failure; its causal
fix is dirty and likewise needs the next source capture. The dirty next
checkpoint also includes a product transport probe plus fixture event and a
correlated Windows fixture workflow. None is native acceptance until its
source-bound tests, package inputs and protected guest outcomes are reviewed.
Preserve previous captures, package receipts and unknown correlations.

### Third continuation checkpoint and pending acceptance — 2026-09-28

`58b569559184cfbb24f588d5ac46aa4884690dc3` is the latest pushed
`origin/dev` checkpoint, version `2.2.0`. It delivered native admission and
visual-fixture repairs; full parity remains open. The user's requested delivery
policy is larger coherent checkpoint pushes with **one required-workflow CI
review at the final delivered SHA**. Intermediate workflow and package results
remain evidence for their own source and scope, not final CI acceptance. No
release is authorized.

Current uncommitted work spans Android installer admission, Linux RPM preparation,
Windows MSI owner observation/readiness and target preparation, desktop update
fixture hashing, and desktop/Android visual fixtures. The writers own their respective
tool/test files; root owns shared MCP registration, host checks, metadata and
delivery. These changes need a reviewed coherent checkpoint and a fresh
content-bound prepush receipt. Do not relabel the `58b5695` artifacts as built
from the later dirty source.

Exact-`58b5695` **component** package inputs are preserved: Android's frozen
native-fixture APK SHA256
`7dfc10891a14dd1747a580bbeef4133728d13d280a569c21b463f53575646bdd`
(`58b5695-android/frozen-apk-receipt.json`); independently verified Linux
2.1.19/2.2.0 RPM pair (`continuation-linux-58b5695/hosted-rpm-fixture/`
`local-verification.json`); verified Windows AMD64 2.1.19/2.2.0 MSI pair
(`checkpoint-current/windows-msi-fixture-58b/fixture-receipt.json`); and
strictly signed Mac arm64 2.1.19/2.2.0 DMG pair
(`continuation-macos/fixture-58b5695/reviewed-package-summary.json`). These
receipts establish bytes/provenance and relevant packaging checks, not installed
native behavior or current-source matrix completion after another code change.

| Native slice | Current gate and preserved uncertainty |
| --- | --- |
| Android API29/API35 | The first guarded install attempt failed in its pre-lease parser/admission path; it is not an installer success or a reason to replay an uncertain accepted action. Preserve both readback backups and inspect the corrected parser/route regression before one newly admitted install. Neither API has a new `58b5695` installed-package acceptance result. |
| Linux | Fedora2328 still has a live task-owned controller. A guest-only stop needed for base RPM installation awaits explicit approval under the runtime rule; no RPM replacement or owner-lifecycle batch is admitted. Preserve the existing owner and exact-source RPM pair. |
| Windows | The exact-source MSI pair is staged. Owner observation `c8351cb2-162e-489e-91a1-3a75d7b49fb5` ended `UNKNOWN`; its exact task cleanup is complete, and the observation must not be replayed. A causal QGA one-shot read fix awaits the next source SHA. Target preparation fails closed as `FIXTURE_ADMISSION_UNAVAILABLE` without a live CP117 HTTPS proxy/TLS receipt; a separate read-only owner probe and base-install readiness remain under design/review. No public MSI replacement has run for this SHA. Preserve the terminal CP176 failure. |
| macOS | The exact-source DMG pair is staged and the Tart guest is stopped. Host GUI unlock is required to observe the protected authorization surface before a new native case; legacy job `465a954f-cd70-45c4-896d-67e4508bae49` remains unknown. |

Desktop visual fixture corrections and the remaining five Android comparator
diffs require capture and review on the next source SHA. The earlier 25aa Android
74/74 capture, desktop hosted single-scene failures, and six missing desktop
add/edit-location baselines remain historical/partial evidence. No four-platform
visual row is closed. The desktop owner-lifecycle matrix is likewise open on
Linux, Windows and macOS; a fixed route is under preparation and does not itself
prove installed GUI attachment or uninterrupted traffic.

A causal desktop update fixture-manifest hash correction is in the dirty tool
batch; it does not retroactively validate a failed manifest or admit an install.
At this checkpoint no new Windows, Android, Linux or macOS native installation
has been submitted. Preserve all exact correlations and await the scoped
preflights, source checkpoint and required environment approval/GUI readiness.

### Second continuation checkpoint and active native admission — 2026-09-28

`25aa22e1cdefe0417dc1f56ce159c4fe8a7b592f` is the second reviewed
continuation checkpoint on `origin/dev`, version `2.2.0`. Managed prepush passed.
The user requested one required-workflow CI review on the final delivered SHA,
so checkpoint pushes are not being treated as final CI acceptance. The matrix
currently has zero complete current-source rows, 20 open groups and two
historical groups. The corrected Mac receipt and its immutable retraction
remain preserved. No release is authorized.

The checkpoint fixed bare subscription source selection for GUI/CLI parity,
added Android durable admission, and supplied guarded Linux/Windows native
fixture routes. Exact-source `25aa22e` Android APK and Linux RPM, Windows MSI,
and Mac DMG pairs were built or registered with byte, version, signer, helper
and source checks as applicable. Later tool and visual-fixture edits are dirty,
so these pairs remain source-scoped component evidence; the conservative
artifact-reuse policy requires fresh final-source builds after the next push.

Android API35's third detached readback correlation
`45a4066c-265a-40ea-8a44-731f0c44ad4e` completed admission with owner
`d51f6046`/revision 2, no operations, and a private 11,872,243-byte backup
SHA256 `9f67f574e40c5623d24b038d687aed4e96675a51b014b578887fc486f2bf1160`.
API29 later completed a separate read-only admission and 239-byte private
backup under correlation `952b9ba6-4f4c-409b-aebc-70b581a2ab58`; its
installed 2.1.17 APK was located by exact bytes and registered. Neither API
has undergone a new install or VPN interruption. New guarded Android installer
and bounded public-inspection adapters have causal tests; the installer start
waits for the next source checkpoint so the older installed baseline remains
available for one monotonic replacement.

Linux's exact 25aa 2.1.19-to-2.2.0 RPM pair was independently verified and
registered. Fedora2328's guarded base-install preflight blocks on live
`vpn-control` PID 18367/startTicks 2078693. Read-only public status reports
configured VPN mode but runtime OFF, no selected or active location, and no
runtime ID. The owner has not been stopped; guest-only stop approval was
requested under AGENTS.md. No separate owned Fedora guest was identified.
Windows's 25aa 2.1.19-to-2.2.0 MSI pair was verified and registered; CP117's
inert PowerShell 5 preflight passed. A reviewed durable base-preparation route
is ready, but the single native base install is deferred until final-source
fixture selection. CP117 has not been mutated in this continuation.

Mac's 25aa DMG pair passed strict signing/embedded-worker checks. A native
user-local fault rollback restored the exact base; reviewed component summary
SHA256 is `3a94dcc8ec1098fd44fc31505b9f4011b9ed2f75cb5a4ad1880b0050388bd05a`.
Machine authorization denial was not submitted because the host Mac is locked
and the approved GUI surface cannot observe SecurityAgent. The Tart VM and
monitor are stopped/released; the old unknown job remains untouched.

Visual capture at 25aa completed Android 74/74 scenes. Comparator found 62
passes and 12 diffs, including an ordinary location fixture with inconsistent
selected references; causal host RED/GREEN fixed that fixture for next-source
recapture. Three hosted desktop runs reached one scene, then failed on a
synthetic runtime/presentation mismatch; a visual-only desktop preview fix has
causal RED/GREEN and full desktop-test pass. The six desktop add/edit location
baselines remain missing. Notification OS-header mask drift, QR symbols and a
routing-error scroll difference remain under review. No new baselines have been
accepted, and all four visual matrix rows remain open.

### Active continuation after first delivery — 2026-09-28

The first continuation checkpoint is `4aa0658bdc69ffd12b4f30d66988b7ccb4720dd6`
on `origin/dev`, version `2.2.0`. Its managed prepush tier passed. The user
requested larger, less frequent checkpoints and a single required-workflow CI
review at the final pushed SHA; intermediate fixture workflow results are still
artifact evidence and do not close final CI. No release is authorized.

The acceptance matrix currently has one reviewed **historical** Android API35
document-response recovery receipt from source `5cebf153` and 21 open groups.
The Mac component summary has a corrected partial receipt
`native-acceptance-2ec39b0a0d04914d6d0f7dceb92e2bd6` on source `4aa0658`.
An earlier receipt `native-acceptance-7648c94fca43aaadf8583e089c53e731`
overmarked explicit authorization denial and was immutably retracted; the
original bytes remain auditable. Matrix status confirms one retraction and
keeps the Mac row open without a conflict.
No native operation has been replayed to turn historical evidence into current
evidence. The Mac base `2.1.19` and target `2.2.0` DMGs are verified as one
`4aa0658`-source arm64 pair; the old missing-token installer job remains unknown.
On its admitted task VM, the public user-local `2.1.19`→`2.2.0` update
completed: operation `779be669-2f61-4d4e-a185-2415438e30ed`, new protected
job `5992b278-0232-4dab-9047-d0aae9d45099`, receipt sequence 4
`SUCCEEDED/OK`. The installed target's signed app and original-user Aqua GUI
returned with a live controller in OFF/proxy-only mode. This is a successful
component scenario for original source `4aa0658`, not the full Mac lifecycle or
final-source matrix row; subsequent machine cases are described below.
The separate machine-owned preauthorization job
`2f1ec654-c5ad-41c1-9af5-b4437ec85299` then crossed a distinct guest boot.
The packaged original-user owner recovered it as final `CANCELLED`,
`cleanupCode=OK`, `installed=false`; base `2.1.19` remained intact and only
that new job's input/stage were removed. Legacy job `465a954f` remains unknown.
The next monitored graphical boot completed a real machine-owned authorized
replacement: protected job `e8227d0d-c599-452d-bedb-62ace8fe2538` returned
`SUCCEEDED/OK`, installed signed `2.2.0`, and the original-user GUI/controller
returned. A separate fault-injected machine rollback job
`c0208907-4b5c-45e3-a200-75e7300f9d65` ended
`FAILED/PERSISTENCE_FAILED`; the exact signed `2.1.19` base identity was
restored, owner maintenance reported cleanup `OK`, and the candidate stage was
retained as evidence. Explicit authorization denial, user-local rollback,
first-gate races and final-source package reruns remain open. The sole Tart VM
was stopped and its reservation released after these scenarios.

Android API35 preflight retained package/owner/operation facts, but
`routing show` exceeded even a 30-second bounded step. The Android owner
replaced the redundant read with guarded private `routing export` and a
durable detached readback job. Its first run, correlation
`c5299b5f-402b-447e-945b-070902ddbc03`, retained an exact 11,872,243-byte
private export (SHA256 `f6242fa695c4a264e3db0a0abd58d3775063fb9dc4ba4ce95464b27656c49ca8`)
but ended `unknown/readback_or_backup_unknown`; no mutation is admitted. The
second correlation `d4c6e8f9` also preserved a complete private export but
ended `unknown/readback_export_stdout_unknown`. The cause was a valid JSON
success envelope that the adapter had incorrectly required to be empty; a
causal regression now validates its owner/revision/byte count. A third exact
read-only correlation is running. The same audit found Android's public CLI
still rejected bare subscription source mode;
causal Android RED (2/6 failures) and GREEN (6/6 pass) now cover remembered and
empty selections, with packaged acceptance still open.

The Linux privileged read-only process probe can inspect all nine fixture-UID
processes, while full workspace cleanup and RPM batch remain unproven. A
disposable same-source RPM fixture workflow and correlated MCP dispatch/status
route are ready, but no fixture has been dispatched because the next source
checkpoint is not frozen. Windows CP117 still has no new public MSI operation;
its durable original-user route is under final source review. An inert fixed
CP117 PowerShell 5 preflight passed parser, gzip and UTF-8 pipeline checks
without submitting an installer. A complete same-source MSI pair is still
needed after the next source freeze.

One additional GUI/CLI parity defect was reproduced and fixed in the dirty
working tree: the GUI could enter subscription source mode without an explicit
ID, whereas CLI rejected that form. Real-owner desktop and shared parser tests
passed after the narrow command change. This change and all active MCP/native
tool changes require a later metadata bump, full prepush receipt and delivery.

Current exclusive writers are Android for the admission/readback adapter and
fixture script, Linux for RPM cleanup/harness and Linux fixture workflow,
Windows for MSI scenario adapter, and macOS for installer/recovery. The
coordinator owns shared MCP registration, matrix accounting, docs, metadata,
Gradle scheduling, checkpoint delivery and final CI. The desktop parity audit
is complete and its writer has stopped. The sole local Mac VM is reserved for
the Mac operator while admitted; host Gradle waits for its release.

### Continuation ownership and live gates — 2026-09-28

Startup on `dev` found clean HEAD `24ec90d70ac58029068561fc434692a268ce0714`
at version `2.1.19`; the five required workflows and advisory VPN Integration
passed for that SHA. `matrix-status` still reports 22 open groups and zero
registered reviewed receipts. The prior source-specific native evidence remains
historical until its artifacts and scenario coverage are reconciled.

| Slice | Owner and exclusive files | Environment and preserved identity | Next gate |
| --- | --- | --- | --- |
| Windows MSI | Windows worker: install helper/installer/broker files and focused tests; coordinator owns MCP route | CP117 AMD64 guest; CP176 request `99126312-977f-4a61-a9ef-fb6884d2d26f`, operation `a021aae5-2235-4646-b750-01dca01441d0`, job `9107428f-9c80-4284-9f4e-926350105a59` terminal and never replayed | Freeze same-source complete MSI pair, use a new admitted public operation and diagnose protected pre-MSI stage |
| Android | Android worker: Android owner/fixture files and focused tests; coordinator owns MCP route | Arch-host API35 `5682` and API29 `5684`, one AVD at a time; UID2000 read-only observation, no new mutation | Fixed package/owner/routing admission and backup, then native action and installer scenarios |
| Linux RPM | Linux worker: RPM native adapter, batch/harness and tests; coordinator owns MCP route | Fedora2328 installed base and pending state preserved; CP173 correlation `a1f33191-4f6d-41dc-aa1e-cbc4c6029282` rejected and never replayed | Strict process observation and separate base-RPM build guest, then same-source batch |
| macOS | Mac worker: boot recovery/installer/worker and focused tests; sole local Tart VM | Legacy job `465a954f-cd70-45c4-896d-67e4508bae49` remains unknown; VM stopped, no reservation | Prove safe Darwin memory admission, then future-job reboot recovery, rollback and GUI return |
| Documents | Document worker: focused desktop export boundary and tests | Read-only historical audit; no native environment | Causal GUI export parity fix and remaining document scenario mapping |
| Visuals | Visual worker read-only inventory, coordinator controls later capture/review | 249 required scene-platform pairs, six desktop add/edit-location baselines missing; no current-SHA review | Capture in platform-owned environments after native operators release them |
| Integration | Coordinator: shared protocol, MCP server, docs, metadata, Gradle, commit/push | Host checkout and exact-SHA CI | Register narrow native MCP routes, validate coherent checkpoints, reconcile reviewed receipts |

Each worker owns cleanup of its admitted environment and must hand off exact
correlation, artifact IDs, terminal status and residual uncertainty. No host VPN,
installer, trust or runtime interruption is authorized by this ledger.

First-checkpoint observations: the Android API35 readback correlation
`a4a2f73c-6c99-4028-a846-a4c63f21f6d6` is unknown after a bounded timeout;
fixed status found no backup, the same controller and zero operations. Do not
use it as mutation admission. Fedora2328's fixed process probe found unreadable
same-UID user-manager processes (`EACCES`); cleanup remains unknown and no RPM
batch started. The macOS local VM was admitted with stable historical swap,
observed, then stopped and its reservation released. Legacy Mac job `465a954f`
still has no launch boot token or protected receipt. The 24ec90d arm64 DMG was
registered under `sha256-eb672e633c659e0c9db8d247aafc6c01ffa474d9d914b01ce4a1329f7b3f39c4`
as component evidence, not final native acceptance. The GUI text-export helper
now uses the same private no-overwrite publication as CLI; its two real-filesystem
tests failed before the fix and passed afterward.
The fixed Windows preinstall observer re-read CP176's exact protected status as
`Failed/RUNTIME_FAILED` sequence 3; its diagnostic is absent on the old image.
The 24ec90d Windows fixture workflow `36412798220` produced a verified
same-source 2.1.17→2.1.19 AMD64 MSI pair and receipt under
`checkpoint178/windows-msi-fixture/`, registered through MCP. The pair is
component/historical evidence once this checkpoint changes product source;
there is still no new public MSI operation or durable MCP submission route.

The user stopped the old `Finish GUI CLI parity` task and requested review and
delivery of its inherited dirty batch before passing the remaining work to a fresh
GPT-6 Sol medium coordinator. Use [parity-continuation-plan.md](parity-continuation-plan.md)
for the detailed continuation sequence and native acceptance gates. The old task
and its previous workers no longer own implementation or environments.

This review began on `5aa882412b4a1dea614303946640351111c8ad3c` with36 dirty
paths. Four independent reviews cover Mac recovery, Windows diagnostics/fixtures,
RPM batch/harness, and MCP environment/SSH recovery. A separate read-only audit
checked remaining acceptance against current source and saved evidence. Findings
and causal RED/GREEN records are under `handoff-review/`.

Review corrections include descriptor-bound private build-environment and Mac
boot-token reads; independent Windows UAC frame/identity admission and portable
tests; private SSH-config preservation and unresolved-intent guards; integer-zero
RPM terminal success, durable failure journals, strict proc observation and
descriptor cleanup. Current-source packaged acceptance is still required.

The old task had retained a prepush child after being paused. A focused regression
run briefly overlapped it, causing shared Gradle report failures. The user then
confirmed the old task was stopped; root rechecked active build processes before
continuing. Managed checks now take an exclusive checkout lease and verify a
pre/post content fingerprint. Direct Gradle calls still require coordinator scheduling.
Preserve `checkpoint177/prepush-final.json` as the failed overlap evidence;
never reuse its receipt. Final metadata, current prepush and exact-SHA dev CI are
the delivery gates for this review batch.

The first review push `03fc7d8` passed local prepush but exposed RPM harness
fixture assumptions in Linux and Windows CI. Linux's descriptor-specific test
encountered unrelated unreadable runner processes; Windows synthetic tests used
POSIX paths/APIs. Preserve the original CI logs in `handoff-review/`; fixture
repairs must keep strict unknown-process rejection. MCP failed-log selection now
retains causal error context and the final summary within its response bound.
Windows package CI now explicitly runs the lease and fingerprint suites, closing
the earlier coverage gap where only Linux ran agent-tool discovery.

No VM, installer or VPN mutation was performed by this review. The native matrix
reported22 open requirements with zero registered reviewed observations at the
starting SHA; reconcile historical receipts before treating every row as new work.

## Previous integration follow-up — checkpoint176

Checkpoint177 delivery follow-up: managed pre-push validation exposed a missing
`JAVA_HOME` in the desktop MCP process even though the interactive shell has a
working JDK. A causal quick test and owner-only ignored local build-environment
loader now supply the path to each managed child command; the full pre-push tier
must still pass before this dirty batch is pushed. The source-matched Linux RPM
target is verified, but the base RPM still needs a separately admitted build
guest; Fedora2328's installed base and pending installer state remain preserved.
The strict RPM cleanup check currently fails closed on uninspectable same-UID
`/proc` entries; Arch observation is blocked rather than a native GREEN.
The first full managed pre-push tier passed after the local JDK fix. A repeated
run exposed two newly added macOS boot-token tests failing under a symlinked
input parent and a permission-granting Darwin ACL. The product reader now
rejects both; its focused 10-test suite passed. The complete pre-push tier
must be rerun for the final content snapshot before any commit.

The full parity goal remains incomplete. The seven requested optimization areas
are implemented, and current native adoption continues to expose gaps that need
causal quick regressions. Pushed `dev` HEAD
`5aa882412b4a1dea614303946640351111c8ad3c` is clean at the start of this
checkpoint; all five required exact-SHA workflows and advisory VPN Integration
passed. Version is 2.1.19. This verifies delivery of that checkpoint, not the
remaining native acceptance matrix.

Checkpoint173 repaired package-qualified MCP imports, Linux owned-workspace
admission and bounded actionlint download retry. The rejected Linux correlation
`a1f33191-4f6d-41dc-aa1e-cbc4c6029282` remains terminal and must not be replayed.
Checkpoint174's fresh Fedora Find Best plus scheduled refresh completed with a
51.1 ms benchmark and scoped cleanup. Its old listener had 224/226 successful
traffic probes and two brief connection-refused gaps; new-listener traffic
recovered in about 0.265 seconds. This is mixed-artifact evidence using an
installed 2.1.17 RPM, not uninterrupted traffic or final-package acceptance.
Read-only contract review found this is the permitted short controlled restart
when scheduled Find Best applies a changed generated configuration; the public
operation completed with the runtime running on B. `DESKTOP-005` requires the
refresh not leave the runtime stopped. The existing auto-refresh lifecycle test
guards against stopping A before the post-refresh selection.
See `checkpoint174/linux-refresh/` for the protected native receipt and review.

Windows CP117 recovered its exact earlier installer cancellation under the
corrected complete 2.1.18 image: public operation status exited 130, update
status was CANCELLED with `cleanupCode=OK` and `installed=false`, and the old
2.1.15 installation stayed intact. The subsequent public MSI success scenario
is still open. Fresh admission exposed a nested SSH recovery path of 86
bytes against an 85-byte cap. A causal quick regression and bounded path repair
are in the current dirty work; the new recovery master is verified and adopted
in the ignored host inventory. A second regression guards renewal after that
adopted socket expires. The next public install reached real UAC once, but the
fixture driver rejected the expanded dialog's re-rasterized title after it had
already matched the selected administrator account. That exact operation later
ended `CANCELLED`/130 without installer execution; no replay occurred. CP175
evidence is under `checkpoint175/windows-msi/`. The separate fixed credential
probe correctly rejected a secret under a world-writable ancestor; root moved
the same bytes to an owner-only home directory, updated the ignored inventory,
and a new exact probe completed successfully. The corrected two-phase preflight
passed eight quick tests and a fresh CP176 public attempt passed real UAC. Exact
request `99126312-977f-4a61-a9ef-fb6884d2d26f`, operation
`a021aae5-2235-4646-b750-01dca01441d0`, and protected job
`9107428f-9c80-4284-9f4e-926350105a59` ended `Failed/RUNTIME_FAILED` after
`WaitingForExit`, before `Installing` or any `msiexec`. Base 2.1.17 is intact,
helpers exited, and owned fixture cleanup completed without replay. Read-only
forensics narrow the failure to `TryExclusiveAdmission` or
`TryInstallationReady`; the protected receipt does not distinguish them. A
causal quick role regression and fixed enum-only protected diagnostic are now
implemented. Isolated CP117 role fixtures showed both old-code RED branches and
current-code GREEN, including strict ACL/readback for the protected diagnostic
leaf; they ran no installer. The first inert QGA test command exceeded the
guest-exec command size before launch, so a portable size/chunking regression
was added to routine hygiene. Another packaged native MSI attempt must inspect
the new fixed stage/kind to establish the underlying cause. Evidence is under
`checkpoint176/windows-msi/`.

macOS machine update job `465a954f-cd70-45c4-896d-67e4508bae49` was accepted
on the frozen 2.1.17→2.1.18 pair and awaited OS authorization. After the owned
VM was stopped and booted again, the original prompt/coordinator was absent,
there was no protected receipt, and the public operation remained
`OUTCOME_UNKNOWN`. The job, target, worker and legacy unknown job remain
preserved; no install was replayed. A future-job boot-session recovery guard is
implemented in the current dirty work for both machine and user-local receipt
authorities. It requires a private exact-job kernel boot token from before the
coordinator attempt, a different current boot and a second authoritative
receipt-absence check before marking not-started. The exact old job predates that
token and cannot be labelled terminal from a newly inferred outcome. Focused
Mac tests pass; packaged reboot/process-loss verification remains open.

Android API35's 11,872,243-byte, 56,000-domain baseline is preserved. A
matching complete Linux CLI image from frozen source `5cebf15` is now verified
on Arch: archive SHA-256
`826b597754bf422de67566bead66d8640720847d35073dc09c302af92772a504`,
full tree manifest SHA-256
`d045410fd7351eb097057177b04ba3280b7af40cd488b63044c7ec28984ab60f`.
The nondebuggable 2.1.18 APK has the expected signer. Fresh device admission and
the single response-loss scenario remain open. The signed APK installed under
API35, creating a new controller epoch. The first guarded response-loss request
mistakenly used the pre-install owner/revision and correctly returned `CONFLICT`
before a document operation existed. An exact cleanup import succeeded and a
fresh full export matched the pre-install backup byte-for-byte at the canonical
rules hash; no persisted-data loss occurred. A reusable post-install rebind
helper with ten passing quick tests is in the current dirty work. The fresh
API35 nondebuggable APK scenario passed: one guarded request
`29be994c-6cd1-4e43-956d-568c1506bc03` committed at operation
`2fe094a8-a29c-4603-8088-07ce68a71c35`/revision1; first response loss
returned `OUTCOME_UNKNOWN` while retaining the exact identity. Pinned status
was final OK, same-request replay returned byte-identical committed results
without a second effect, and guarded restoration reached revision2. Final
56,000-domain content and canonical rules hash matched the backup; runtime
remained OFF and the shim was removed. Raw exports differ only in generated
`exported_at`. See `checkpoint174/android35-document-response-loss-rerun/`.

| Task | Owner | Files/environment | Current check / handoff |
| --- | --- | --- | --- |
| SSH recovery path | ssh_socket_regression handoff; root integration | `ssh_connection_recovery.py` and test | Causal RED/GREEN, 13 focused tests; native master recovered, Windows admission pending |
| Windows public MSI | windows_msi_retry176/diagnostic handoffs complete; root integration | CP117 guest terminal, native role code/tests | CP176 pre-MSI failure retained; enum-only diagnostic passed inert native test, fresh packaged retry required |
| Windows UAC fixture | windows_fixture_preflight handoff complete | Reusable scripts/tests, no VM | Eight quick tests and CP176 two-phase UAC admission passed; current MSI failure is later |
| macOS recovery | macos_unknown_recovery handoff complete; root review | Mac installer classes/tests; no VM mutation | Machine/user-local boot guard and read-only MCP diagnostic pass focused tests; native reboot scenario open |
| Android document response loss | android35_response_loss175/177 handoffs complete | API35 AVD5682 now clean | Fresh owner guard, one committed response-loss operation, exact retry and full content restoration passed; remaining Android lifecycle gates separate |
| Linux continuity review | linux_findbest_continuity handoff complete | Read-only CP174 receipt review | Controlled A→B restart allowed by DESKTOP-005; final package proof remains open |
| Linux RPM recovery batch | rpm_transport_implementation handoff; linux_rpm_harness_cleanup | New fixed MCP adapter/tests and synthetic workspace cleanup; no Fedora VM mutation | Agent suite 366 passed/6 skips; truthful cleanup must become achievable before native RPM retry |
| CLI coverage audit | cli_public_coverage_audit handoff complete | Read-only registry/adapter review | No concrete handler gap; `cli.md` corrected for Android-only apps and desktop update revision guard |
| Visual gate audit | visual_gate_audit handoff complete | Read-only scene/baseline inventory | Android API35 is canonical; desktop location add/edit baselines missing, current-SHA review and Windows secure capture open |
| Delivery | root | Shared docs/metadata, host checks, dev push/CI | Final content freeze and full native matrix still outstanding |

The visual audit found desktop `locations-add-dialog` and
`locations-edit-dialog` baseline PNGs missing on Linux, Windows and macOS, plus
no current-SHA four-platform review receipt. `VISUAL-003` specifies Pixel 6/API35
as the canonical Android visual environment; API29 remains a native product
acceptance gate, not a second canonical visual baseline set. The local Windows
visual VM was retired during the user-authorized storage cleanup, so its secure
UAC capture needs a fresh owned environment before review.

Frozen Windows/macOS pairs use source5cebf15, base2.1.17 and target2.1.18; their
identity must not be relabelled as2.1.19. Current-source Android APK under
checkpoint172/android-current likewise retains5cebf15 provenance. Final package
acceptance and exact-SHA CI remain separate gates. The Android API35 full backup
contains56000 domains, original ignorefalse; preserve it before any device mutation.

Earlier user-authorized storage cleanup temporarily reached112.5GiB free on the
Mac. A fresh Data-volume check at checkpoint176 found80.15GiB free; current
Tart/AVD/evidence state has grown since that receipt. The exact proven disposable
repo build/dist set is only about5.51GiB and would not reach the requested
100GiB. Automatic command review rejected its permanent deletion as an unsafe
`rm -f` style action; no workaround or deletion was performed. The obsolete
stopped local Windows ARM visual/component
VM and its READY marker were retired; recreate explicitly before any future local
Windows visual run. The active remote Windows CP117 and every unknown installer
input remain preserved. Arch cleanup reclaimed112.27GB from Trash/build caches
plus2.23GB from unused Pacman downloads, leaving297.10GB on home and6.12GB on root.
All five active remote VM process generations were reverified unchanged. Cleanup
receipts and fixed allowlisted scripts are under checkpoint173/arch-cleanup;
current packages, source, personal data, active AI models and Steam remain intact.

## Previous integration batch — checkpoint170

The user explicitly requested all seven development optimizations before resuming
the remaining parity matrix. Extend existing MCP/scripts rather than introducing
another execution stack. Current native operations retain their exact ownership
and may finish safely; no pending installer or personal environment is reset.

| Task | Exclusive owner | Files/environment | Acceptance |
| --- | --- | --- | --- |
| Portable checks | root integrating windows_reconcile120 work | Python platform checker/tests | Executable absent-API regressions in routine checks |
| Artifact reuse | artifact_impl170 | native_artifact_reuse.py and its tests | Verified bytes/build inputs and Git-derived equivalence; original source retained |
| VM baselines | baseline_impl170 | native_vm_baseline.py and its tests | Typed immutable capture and fresh restore; live/unknown fixtures rejected |
| Preflight/batches | preflight_batch170 | native_fixture_preflight.py, native_scenario_batch.py and tests | Current prerequisites, dependency handling, no uncertain replay, scoped collection |
| Matrix/integration | root | MCP registration, acceptance matrix, docs/hygiene | Requirement/evidence/next-action view plus bounded worker handoffs |
| Windows receipt repair | root integrating windows_receipt_fix170 | InstallJobStore and protocol tests | C# PascalCase phases decode; native CP117 unknown preserved |
| Linux reusable scenario | linux_schedule169 | integration runner and tests | Preflight, benchmark, scheduled refresh, listener traffic and scoped cleanup |

The earlier e9c6ea1 test-portability correction is pushed with its own valid
prepush receipt; all five required exact-SHA workflows passed. Its parent f6599f2 native
APK and macOS pair retain their original source identities. The new infrastructure
batch is frozen for integrated validation. The full agent-tools selection passed
333 tests with six platform-specific skips; the Windows decoder selection passed
14 executed tests with its real C# encoder test reserved for Windows CI. Fresh
stdio MCP matrix inspection passed. Root reviewed the implementations and added
regressions for stale-SHA acceptance and misleading batch outcomes. Final prepush
and the new exact-SHA delivery loop remain.

All seven requested optimizations now have implementation/policy coverage. The
fixed native batch recipes are Linux scheduled refresh, Linux bundle preflight,
and Windows credential validity; they are not arbitrary scenario executors.
Baseline provider components are tested, but actual capture/restore still needs
a known-quiescent disposable fixture with verified preparation evidence. No
unknown installer was reset. The Windows CP117 second install remains public
unknown; preserve its correlation and recover it with the corrected package.
Native parity resumes after this infrastructure checkpoint is validated.

## Previous integration batch — checkpoint169

Checkpoint f6599f2 delivered Android document response-loss identity repair, Mac
resource guards and optional same-source DMG fixture CI/signing verification.
Its Windows CI exposed two test mocks assuming POSIX os.getsid exists on Windows;
the causal portability correction is delivered by e9c6ea1 with all five required
workflows green. Earlier checkpoints0bcf54e and8d7748c also passed all five.

The immutable Mac pair build36109565762 and verified nondebuggable x86_64 APK
in checkpoint169/android-current remain bound to f6599f2; do not relabel them.
Focused Android client/provider tests passed40, Mac fixture workflow/signing
checks13, and monitor checks13. Historical results do not certify checkpoint170.

## Checkpoint168 — resource admission and native continuation

All five required workflows passed for `0bcf54eea8a905721d2e7989d968e49cc400717f`.
The SSH correction is pushed as `8d7748c127ad3bc57d4770dc5a7c3783921003de` after
full prepush; exact-SHA Linux/Windows package checks are still running, with Fast,
Android and macOS successful at the last observation. Native acceptance remains open.

The macOS monitor previously stopped the owned guest on one warning sample. A
causal regression now covers warning then normal, and the guard requires30 seconds
of continuous warning plus less than2GiB free/inactive/speculative page headroom,
while retaining immediate critical/unknown-pressure stops. All13 focused tests pass. A fresh boot was admitted with7.46GiB free/inactive/
speculative pages, normal pressure and more than8GiB disk reserve; its live monitor
is checkpoint168/macos-resume. The retained legacy installation remains unknown;
no replay occurred. A separate worker owns optional CI same-source Mac fixture-pair
packaging to remove host build pressure. Root owns monitor/tests/docs/hygiene.

Windows public check/download passed and one guarded installation is accepted,
operation b1e72b34-8289-4232-95fa-accefd6639b9; real UAC approval is in progress.
Android API35 completed its56,000-domain baseline export before a guarded small
routing-setting response-loss test. Linux's next gate is fresh Fedora2328 admission
and scheduled refresh, preserving the original recovery owner and receipts.

## Checkpoint167 — active verification

Checkpoint `0bcf54eea8a905721d2e7989d968e49cc400717f` is pushed after full
prepush success; all five required workflows are being observed for that SHA.
The next small correction covers SSH recovery after adopting a recovered socket:
the prior host-only intent kept the old configured identity and blocked renewal.
A causal RED preceded route-keyed intent storage; legacy receipts remain intact
and pending/foreign legacy outcomes remain fail-closed. This correction is not
yet included in the pushed checkpoint.

Arch access is restored. API29 denial is proven and the original consent/source
state is restored with runtime OFF; the interrupted grant operation expired, so
its outcome remains unknown. API35 read timeouts were traced to sequential transfer
of an existing11.48MB document, not a stuck provider; a longer baseline export is
running before any response-loss mutation. Windows public update prerequisite
admission passed with an exact temporary fixture administrator.

Five historical local trees were independently checked against private archives,
restored modes/content and current source manifests, then removed with sibling
RESTORE.md pointers. Receipts are in checkpoint166/archive-review. Disk reserve
is now about9GiB. The macOS VM remains stopped because fresh host pressure level2
fails its normal-pressure admission; no installer replay or host VPN action occurs.

## Current continuation — checkpoint166

HEAD/origin/dev is `b542ecaef78fae0577365baeeb5749559e1840bf`, version
2.1.18. Its full local prepush passed; Windows CI36033866043 failed a CONNECT
capacity-response close race. The bounded request-drain repair now includes an
absolute one-second deadline and causal regressions. It awaits the next full
prepush and exact-SHA CI. No final delivery claim is supported.

Installed Fedora RPM2.1.17 passed proxy traffic through GUI close, frontend crash
and reattach: all300 ordered frames arrived and controller/runtime identities
remained unchanged. Public OFF/quit succeeded; the original recovery owner remains
OFF. Root independently reviewed checkpoint162/linux-rpm-lifecycle/root-review.json.
This proves the frozen installed RPM scenario, not final-source VPN or scheduled
refresh. New runtime-config discovery follows the owned process and mixed-in tag;
causal tests reject the former static filename and all-mixed-inbound assumptions.

Windows CP117 ordinary-user base MSI2.1.15 installed successfully (native MSI log
exit0). The next step is the app's public update to the frozen2.1.16 target, after
TLS, artifact, ordinary-user and administrator-credential admission. Direct target
MSI installation would bypass the required product path and is prohibited.

API29 CP165 public ON/OFF succeeded with the frozen2.1.17 nondebuggable APK;
root verified all56 retained evidence hashes. CP166 subsequently showed a real
system consent dialog and denial returned PERMISSION_DENIED with runtime OFF.
The grant operation da74c879... remains pending at the last observation: nested
Arch SSH failed while gateway access worked. Preserve its identity, fixture and
consent state; do not replay ON. API35 document response-loss acceptance is separate.

macOS remains stopped below its8GiB disk reserve. Five historical archives were
copied privately to Arch. Initial extraction lost permission bits; corrected
preserved-mode restores compare successfully. Root is reviewing the reusable
verifier and must recheck local sources before any exact-path cleanup. No local
archive candidates have been deleted; the pending macOS installer is not replayed.

| Task | Agent | Owned files/subsystem | Environment / next gate |
| --- | --- | --- | --- |
| Integration | root | Hygiene, docs, version/CI | Review portable regressions, full prepush, exact-SHA delivery |
| Windows update | windows_public_update166 | Native evidence only | CP117; public update after prerequisite admission |
| Android consent | android_consent165 | Native evidence only | API29 5684; recover exact pending grant and restore fixture |
| Android document | android35_document166 | Native evidence / private device alias | API35 5682; owner-bound response-loss proof |
| Archive verifier | archive_verify166 | native_fixture_archive.py and test | Portable/path-mode review; no local cleanup |

## Checkpoint163 — portable test admission

Pushed checkpoint `3cf1b2087828cfe4aefd97cd7e03fcf402839092`, version 2.1.18,
after full local prepush success. Windows package CI exposed a second POSIX-only
test setup assumption in Linux credential tests. A causal absent-geteuid suite
regression and independent portable admission/import tests now cover it; the
other exact-SHA workflows are still being observed. Final delivery remains open.
Windows CP117 account access is verified and MSI admission is in progress.
Android API29 consent-denial admission is assigned. macOS boot remains deferred:
about 1.5 GiB disk free is below the retained fixture's 8 GiB reserve, and its
receiptless protected operation must be reconciled before any new installation.
Linux RPM 2.1.17 installation/recovery proof is locally retained under
checkpoint162/linux-rpm-recovery; target-package traffic/lifecycle remains open.

## Checkpoint162 — credential recovery

Checkpoint `dd10018a6ded3a68181bbb15f97100038a3f6097` was reviewed, passed the
complete local prepush tier and pushed to origin/dev. CI is not complete: Fast
Checks/Android/Linux failed a macOS test assuming every host uses /var temporary
paths; Windows failed because invalid credentials reached POSIX PTY allocation
before rejection. Root has causal fixes: explicit temporary symlink alias fixture
(real Arch RED then all 14 GREEN), and credential rejection before platform
resources (portable RED/GREEN). macOS package CI run36026211545 completed successfully; all other required
workflows need a new push containing the portability repairs.

User additionally requires credential handling integrated into MCP. The owned
Windows fixture's only retained credential was conclusively rejected by native
LogonUser. Do not ask the user to recover agent-created fixture secrets. Implement
private handle storage, exact environment/account/SID/purpose binding, durable
non-replay recovery, and verified atomic active-reference publication. Never put
passwords in public tool arguments, output, logs or tracked source. The Windows
reset is restricted to the explicitly configured task account and must preserve
pending installer work. Recovery correlation `99af1dac-6bec-4202-9b40-a7118c7a7ee1`
now completed through fresh stdio MCP: one reset, one fixed probe, terminal
verified=true, and atomic private inventory/active-handle publication. The old
credential file remains preserved. Earlier correlation fd25f70a-9f78-473c-9a89-0e00edd58de8
was rejected before mutation because numeric task state1 was misread as Ready;
it is Disabled. Explicit string-state admission and rejection-stage tests prevent
that interpretation error. No UI, MSI or VPN action followed the recovery.

| Task | Owner | Scope | Gate |
| --- | --- | --- | --- |
| Integration/CI | root | Shared MCP routes, schema, docs, delivery | Review credential backend; rerun full prepush after final edits |
| Credential recovery | windows_access_recover162 | Store, fixed backend, reset script/tests; owned CP117 | Native reset/probe/publication verified; final integrated checks pending |
| Android proxy | android_proxy_origin162 | Owned API29 only | Clear exact stale task proxy through supported system observer, then one public refresh |
| Linux envelope | linux_envelope162 | Driver and tests | Separate stdout from PTY; complete 29-test Arch harness passed |

Fedora2328 native RPM replacement succeeded with frozen base2.1.16/target2.1.17.
Protected job `7b7b99aa-6401-4289-9bb1-c0d74355269f` is SUCCEEDED/OK. Replacement
owner `1780cc81-65a6-4284-a424-2178b94e2690` recovered exact origin/request/operation;
installed image matches frozen pair and rpm -V is clean. Runtime remains OFF.
Original fixture password hash/aging was restored and private auth directory
removed. No installer/package manager remains; replacement owner is alive. Guest
proof is under the frozen cp161 RPM bundle's native-recovery.json. Driver stdout
parsing failed after success; no installer was replayed. Actual CLI emits compact
JSON, so earlier pretty-print attribution was unproven. The revised driver uses
separate private stdout capture rather than parsing mixed terminal prompts.

API29 CP160 APK installed successfully on the fully captured second attempt. One
pinned fixture refresh failed with dns=none, HTTP loopback proxy and errno111;
fixture selection/subscription cleanup completed. NetworkMonitor and unrelated
apps also targeted the old task proxy 127.0.0.1:29579, proving emulator-wide stale
proxy state despite absent settings. Preserve app system-proxy behavior; cleanup
must clear effective routing and verify it, not merely delete settings keys.
The supported http_proxy=:0 observer clear then produced a null-proxy broadcast
and HTTP/HTTPS204 from NetworkMonitor. The subsequent pinned refresh operation
`b2d2aca7-0779-41d1-911c-241454fc0259` committed OK (one refreshed, zero failed).
Original selection was restored, exact fixture removed, runtimeOFF and all ten
operations terminal. Evidence: checkpoint162/android-refresh and android-proxy-cleanup.

macOS remains stopped. Heavy swap and low disk space prevented admission. Root
removed only reproducible app/build/intermediates release/nativeFixture native-lib
outputs after all host builds finished; source, APK outputs and frozen evidence
remain intact. Free disk increased to about2.18GB; this alone does not admit a VM.

## Historical continuation — checkpoint160

The goal remains incomplete. HEAD/origin/dev is
`0701be421949d67d5430df90714df32f3df0058c` (version 2.1.17).
Its required workflows are terminal: Fast Checks, Android and Windows passed;
Linux run36017568418 and macOS run36017568724 failed. Local repairs await a
new complete prepush receipt, reviewed push and exact-SHA CI verification.
Historical sections below are evidence records, not current ownership or status.

The checkpoint160 full prepush suite passed (prepush-result.json), then further
review found the Windows real-SSH composition gap and Linux detached-driver
admission/deadline gaps. That receipt must not certify subsequent edits. The
Linux delayed-prompt timeout itself was traced to literal backslash-n output in
the fake child, not to product terminal scheduling. A fresh complete prepush is
required after these repairs.

The dirty batch intentionally spans MCP/SSH safeguards, native fixture helpers,
package regression repairs and bounded Android failure diagnostics. No product
runtime upgrade or release operation is included.

| Task | Owner | Exclusive scope | Current gate |
| --- | --- | --- | --- |
| Integration/delivery | root | Shared MCP wiring, schemas, bundles, WIP/ledger, host Gradle, metadata, push | Review all changes and run final managed prepush |
| Linux auth review | root after linux_auth_review160 handoff | Auth helper, public install driver and their tests | Complete Arch bundle: 19 auth and 28 driver tests pass, no skips; real installer pending |
| Windows probe review | root after windows_probe_review160 handoff | Fixed SSH/QGA probe, admission helper and tests | Real Linux socket regression passed; native Windows probe pending |
| MCP documentation | mcp_docs160 | agent_tools/README.md | Document fixed actions/private inventory without claiming native success |
| Android verification | root | Diagnostic client/collector/tests | Causal RED exit1, GREEN exit0 in checkpoint160/android-network |

Linux: the prior pre-authorization install is terminal CANCELLED; its matched OFF
owner was subsequently quit through the public API and absence verified. Fedora
2328 has a P-status fixture account and sudo access. The new opt-in auth helper
has 19 passing component tests after independent review; the explicit driver opt-in
is integrated. Complete Arch verification passes 19 auth and 28 driver tests
with no skips, including retained deadline ownership.
No temporary password has been provisioned. The target 2.1.17 HTTPS fixture is
prepared; RPM replacement and next-owner recovery remain unproved.

Windows: the fixed probe executed once through real MCP for CP117, correlation
`f604974c-5963-4b61-b538-7d2d5ad76c16`, and reached terminal invalid-credentials.
No account reset, login, UI, MSI or VPN action occurred. Receipts are retained in
checkpoint161/windows. Recover the owned fixture credential before MSI work;
do not infer validity from older probes or replay an installer to test it.

Android: the errno-enabled API29 APK installed successfully, but its one refresh
still failed with errno111. The failure-only network-category collector now has
causal unit evidence. The newly frozen APK SHA256 is
`42cbaba1119e642bc4d6a73be7e682282570e9acff4a544778cbc9e10839c5c6`;
checkpoint160/android-network/build-inputs.json records unchanged build inputs.
Its first staged install failed before any refresh; that fallback incorrectly
discarded ADB error text. Read-only signer/session reconciliation and one explicitly
authorized fully captured retry are in progress. Do not claim a CP160 network result. The
fixture subscription was removed and runtime remained OFF.

macOS: literal /tmp versus /private/tmp mount identity reproduced on empty HFS+
and APFS images; canonicalizing the owned directory before attachment fixed both.
All owned scratch images were detached. This component evidence does not prove
product replacement; the next CI run must verify the package repair. Latest VM
capacity admission was below the required 6144MiB, so no VM was booted.

## Historical continuation — checkpoint155

Checkpoint155 repair `0701be421949d67d5430df90714df32f3df0058c` is pushed.
Fast Checks and Android passed; macOS run36017568724 again failed with a busy
mountpoint and `image-device-changed`. The prior cleanup change did not establish
or fix that cause. Linux and Windows package workflows remain under observation.

The next dirty batch intentionally includes the complete Android-emulator memory
parser, bounded Android errno diagnostics, retained Linux authentication/PTY
fixtures, and a fixed Windows credential-validity probe. New probe code is not
eligible for guest execution until its bootstrap, correlation journal and tests
are complete. No generic QGA execution capability is authorized by this design.

| Task | Writer/operator | Exclusive scope | Current gate |
| --- | --- | --- | --- |
| Delivery/integration | root | Shared MCP wiring, bundles, docs, checks, commits | Review completed worker diffs before freeze |
| Linux auth/PTY | root after linux_auth156/linux_pty156 handoff | Authentication helper and public fixture driver | Reviewed component tests; no password provisioned yet |
| Linux native | rpm_retained157 | Fedora2328 read-only admission | Actual account lock status before new authentication |
| Windows probe | windows_probe_finish157 | Fixed QGA probe module/tests | Finish durable execution before native use |
| macOS cleanup | mac_cleanup156 | Package cleanup script/tests | Establish actual CI cause or add diagnostic evidence |
| Android native | android_errno156 | Owned API29 emulator5684 | New frozen diagnostic APK and one refresh experiment |

The previous Fedora install was deliberately cancelled through its public API
after the SSH input channel was lost. Exact operation
`d2c85157-79a6-4718-a9a7-3bb40e39e778` became terminal CANCELLED, update returned
to ready, no authenticated worker receipt was created and no installer remained.
This proves pre-authorization cancellation, not replacement. The account has no
verified password source; the TLS store password was not used for OS auth.

Android errno tests have causal RED/GREEN evidence in
checkpoint156/android-errno/causal-{red,green}.{log,xml}: four tests, no skips,
one intended RED assertion then all GREEN. The earlier constructor-default test
failure was a test-fixture defect and is not causal evidence. The new nondebuggable
APK SHA256 is `9cc80d0fb48200b41efdee46311b6f40c2dadd939ad873426c549bebaefaeda9`;
its recorded source-input fingerprint includes the uncommitted diagnostic patch.
It is not an exact-commit release artifact.

Checkpoint153 `762190454129a9b203bbd5c734f15103b3100c0e` is committed and
pushed after a valid full prepush receipt. Fast Checks run36016454696 exposed a
Linux-only regression: successful durable preflight evidence includes a
`failurePath` that its exact success contract rejects. A portable generated-worker
regression reproduced this before repair; focused checks now pass (four tests,
one Linux-only skip). Success omits the field and failure retains it. Other required
package workflows are still being observed; this push is not verified complete.

Current ownership: root owns documentation, metadata and delivery;
`mcp_review155` owns the SSH scenario adapter and its tests;
`rpm_stage154` owns Fedora2328 fixture readiness (no target installation yet);
`android_network_read153` owns one API29 refresh experiment;
`mac_readiness155` performs read-only local capacity and artifact reconciliation.
Windows CP154 visibly selected vpncp117 but received incorrect-password;
historical successful credential probes do not establish current validity.
No additional credential attempt or account reset is authorized to a worker.

Fedora2328 now has the verified seven-file bundle and passes the frozen RPM base
guard. Its HTTPS fixture still advertises base2.1.16 rather than target2.1.17;
fixture-only correction precedes any public installation. API29's CP153 refresh
failed at connection stage without an HTTP status; later shell TCP443 succeeded.
This does not prove reachability at the earlier app request or establish its cause.
The test subscription was deleted and original selection restored after terminal
failure. Current Linux host memory admission remains unknown because two QEMU
allocations cannot be established; they are not counted as zero.

Fresh macOS admission sampled available memory5200/5139/5378MiB, below the6144MiB
required for a4GiB guest plus headroom. No boot occurred. The retained target
app-image recovery candidate belongs to `vpn-control-boot-control53`, not fixture43;
it is historical base2.1.15/target2.1.16 and is not current-package acceptance.

The following checkpoint153 baseline is historical where superseded above.

Checkpoint148 `d382767ebb028413739a351f723a33f4d87d6836` is pushed after
full prepush. Fast Checks, Android and Linux passed for that exact SHA. Windows
run36007034411 failed its CONNECT-capacity response test with WinError10053;
the bounded half-close/drain repair passes focused tests but awaits the next CI.
macOS run36007033958 still failed cleanup with `image-device-changed` and a busy
mountpoint. Its cause is under investigation; delivery is not complete.

The current dirty batch intentionally combines native-fixture MCP transfer and
forwarding, Linux memory admission, RPM source-pair admission, Windows relay
shutdown and routine check wiring. Product versions remain unchanged until the
coherent checkpoint's final content edit and managed version bump.

API29 now runs the frozen nondebuggable version2.1.17/code16740 APK from
checkpoint147, SHA256
`08a09cee6c79900d300ec0731590fe0b74b325505ddb897d0596f53c329e05c2`.
Verified MCP publication and one data-preserving ADB installation succeeded;
installed signer/hash match and the original subscription survived. Runtime is
stopped and no operations are active. This is fixture bootstrap, not public update
acceptance. The desktop ADB client is the older CP140 package, so this is explicitly
mixed-source evidence. See checkpoint150/android29-native/bootstrap-receipt.json.
The subsequent refresh diagnostic requires review; no refresh has been submitted.

On owned Fedora2328, the previous stopped owner exited through public quit.
An offline reinstall of the frozen base RPM completed with exit0. Installed
NEVRA/header, clean rpm verification and application image all match the frozen
base. The target update has not started. See
checkpoint150/rpm-native/admission-summary.json. Historical guest2327 and its
unknown installer remain untouched.

Nested SSH access and verified APK staging work. Transfer146 remains
unknown/not_published and has not been replayed. Windows CP117 has no interactive
user; exact frozen MSI hashes were rechecked. Its loopback VNC-forward helper is
being corrected for macOS process identity and Unix-socket path limits before use.
No Windows credential entry or installer action has occurred in this continuation.

The local macOS VM remains stopped pending fresh resource admission. Remote Arch
has ample measured capacity and normal PSI, but the new Linux admission rejected
four swap-in pages during a two-second sample. Independent review identified
swap-in-only rejection as stricter than the established capacity policy. A causal
regression and narrow correction are in progress; swap-out, OOM, pressure and
capacity safeguards remain. No additional VM has started.

Remaining acceptance includes current-package platform installation/recovery,
runtime and GUI detach traffic, Android action/document lifecycles, and targeted
visual review. The affected visual set is21 scene/platform pairs: nine Android
and four each on Linux, Windows and macOS. Full release catalog capture is outside
this non-release checkpoint. Exact-SHA all-five CI remains mandatory.

The user requested all discussed MCP improvements. Implemented modules now cover
artifact replicas and byte verification, fixed verified scenario bundles,
private environment reservations, live read-only observation composition,
durable execution, compact next-action guidance and automatic redacted failure
receipts. Real FastMCP stdio tests exercise public registration and serialization.
Independent review added causal tests for stale artifact paths, lost terminal
states, PID generation mismatch, reservation release uncertainty and bundle races.

Real MCP evidence in checkpoint152: artifact registration/verification passed;
the fixed Windows VNC tunnel opened and separately reported ready after an RFB
banner check. A screenshot confirms access to the owned Windows lock screen; no
credential entry or MSI action occurred. Tunnel correlation is
`1e4df347ee3b4c75a327e088c0813b6e` and remains owned/open for Windows work.
A second preflight with the fully frozen runner succeeded in
checkpoint153/mcp-final under correlation
`preflight-a0388f86bd494ac49bce414ff02212e2`. Live host observation reached Arch
and inventoried five QEMU processes, but withheld admission-compatible memory
because two allocations could not be established. They were not counted as zero.
The Linux bundle import preflight submitted once, then a separate resume recovered
terminal exit0 for correlation `preflight-c545e9fee18348dd97cd97a456a30554`,
PID2922038/startTicks2941336. This is component preflight evidence, not a product
update. Other product-changing scenario adapters remain future integration.

API29 diagnostic admission discovered that the preserved original subscription
actually refers to localhost, not the earlier pinned public GitHub fixture.
A new explicitly owned public fixture subscription was added successfully, which
automatically selected it. The exact original source was restored, the new-ID refresh failed terminally
with CONNECTIVITY, and the owned temporary subscription was deleted. Diagnostics
show direct/system-default routing and ConnectException before any HTTP status;
connection setup remains an open native failure. Runtime is off and no operations
remain active. Unknown
operations are never replayed. See checkpoint153/android29-refresh receipts.

| Task | Agent | Owned subsystem | Dependencies / next handoff |
| --- | --- | --- | --- |
| Integration153 | root | MCP registration, docs, metadata, validation and delivery | Final reviewed freeze, prepush, checkpoint push and exact-SHA CI |
| Android refresh153 | completed | API29 fixture and redacted diagnostics | Original state restored; connection-stage failure awaits causal diagnosis |
| Public contract153 | completed | Real stdio MCP test | Failure receipts and next-action guidance verified; final full tier pending |
| Native tools152–153 | completed | Separate reviewed modules and causal tests | Root integration and current endpoint evidence; no deployment claimed |

## Historical continuation — checkpoint147

Checkpoint146 `4ead8b79a85df7aeef862be932693d2e6462a21c` was pushed after
full prepush passed. Its macOS workflow36001020956 failed: mountpoint removal
remained busy across all five retries. Increasing retries alone does not establish
the cause; the CI worker is investigating and preserving failure diagnostics.
Exact-SHA delivery remains incomplete.

The Android observer now has private per-device profiles and a public MCP/CLI
route. Focused fake-executable tests prove device admission and pinned ADB use;
review is tightening envelope validation, redaction and bounded remote capture.
No native observation success is claimed. The retained transfer correlation was
rechecked through MCP in checkpoint147/transfer-recheck.json and remains UNKNOWN
with `ssh_transport_unavailable`; it was not resubmitted.

Android refresh diagnostics now preserve typed HTTP status and bounded redacted
failure traces without changing routing. The original one-test assertion RED and
three-test GREEN are recorded in checkpoint147. The subsequent cycle-safety test
now passes after correcting its coroutine exception identity assumption; all four
focused tests pass in android-diagnostics-green-final2.log.
These diagnostics enable attribution of the retained CONNECTIVITY native failure;
they do not prove that the underlying network failure is repaired.

| Task | Agent | Owned subsystem | Dependencies / next handoff |
| --- | --- | --- | --- |
| Integration147 | root | Host schema, MCP registration, docs, shared builds, delivery | Final focused union and managed prepush after workers stop editing |
| Android diagnostics147 | android_connectivity147 | Refresh loader, download client and diagnostic tests | Correct cycle regression; root schedules Gradle |
| Android observer147 | android_observe147 | Observer module and tests | Bounded capture, typed response validation, safe proxy summary |
| macOS CI147 | mac_ci147 | Package smoke cleanup and quick regression | Investigate persistent busy mountpoint; no host/VM mount mutation |

## Historical continuation — checkpoint146

The user prioritized reusable VM/SSH MCP workflows before resuming platform
acceptance, with failure-driven tools and fast regressions. The goal remains full
GUI/CLI parity; tool work does not replace native acceptance.

Checkpoint145 `a4d1457d79027d94457e5c36b8581c3ec71404b8` is committed and
pushed after full prepush passed. Exact-SHA CI found a second macOS cleanup failure: empty mountpoint removal
was busy after confirmed detach. Its bounded retry regression now passes; the
next pushed SHA must rerun all required workflows. Version
2.1.17 includes the preserved checkpoint144 Git-source/Android-history changes.
The previous macOS CI failure was owned DMG cleanup after successful smoke; the
new identity-checked cleanup has six passing regressions, with native CI pending.

Private `.vm-hosts.local.json` is mode0600 and gitignored. The SSH MCP probe reached
Arch through the declared gateway. Existing-job observation correctly reported a
missing process as unknown through the real MCP transport; no work was replayed.
Canonical staged Python preflight and memory planning are implemented. Native
inventory access on a Windows coordinator remains explicitly unsupported pending
ACL-safe handling; POSIX coordinators can reach Windows guests.

Current work adds fixed-scenario verified transfer, beginning with the desktop
update entrypoint and its canonical siblings. Anchored directory access, exclusive
publication, receipt/hash verification and bounded observation pass focused tests.
The first real transfer correlation `transfer-c1f1aaee-a372-41d8-94e6-aa118e5f548c`
is UNKNOWN: subsequent SSH diagnostics report the gateway network unreachable.
Its intent and destination are preserved; only status observation is allowed, not
resubmission. The MCP now distinguishes SSH transport unavailability while retaining
unknown outcome. Native success evidence remains required. Transfer stages bytes only and must
retain correlation across interruption without overwriting existing destinations.
Durable scenario execution and measured environment admission remain later slices.

Linux's frozen base2.1.16/target2.1.17 package build produced its fixture receipt;
application installation remains deferred. API29 refresh still reports CONNECTIVITY
after proxy cleanup; original source and stopped runtime were restored. API35
stale proxy cleanup passed guarded admission. Existing unknown installers and
macOS/Windows interactive/memory boundaries remain unchanged.

| Task | Owner | Exclusive scope / next handoff |
| --- | --- | --- |
| Integration146 | root | Host schema, MCP registration, native smoke, metadata/delivery |
| Transfer146 | completed; root | Module/tests reviewed; real correlation UNKNOWN, await connectivity |
| CI145 | root | macOS post-detach rmdir regression/fix integrated; next-SHA verification required |
| Native acceptance | deferred | Resume after useful tool slices; preserve jobs and artifacts |

## Historical continuation — checkpoint143

Checkpoint142 `043697a1c7e7dfde091bc2101a0afcecf09ac263` is pushed after full
prepush passed; required exact-SHA CI is still being watched. Version2.1.16,
Unreleased8 before this batch. The Windows missing-helper diagnostic correction
has passed that workflow's hygiene step; full package completion remains required.

API29 refresh terminally failed because stale global proxy host/port fields
survived behind `http_proxy=null`. Targeted subscription cleanup restored the
original source. A causal effective-proxy admission regression and real lifecycle
wiring now pass54 focused tests. Native repair is limited to the two revalidated
task-owned stale settings, with cached network state verification before a new
refresh scenario. No uncertain operation is replayed.

The macOS memory guard stopped target packaging, then a read-only boot. A strictly
read-only/noowners offline mount recovered logs and the completed base DMG,
SHA44ddb727…, with the disk detached afterward. The target reached app-image
creation but has no DMG; no package-pair success is claimed. Root is assessing
canonical packaging of that frozen app image without a VM boot. Rollback114 is
untouched. Export pointer: checkpoint143/mac-artifact-export.json.

| Task | Owner | Exclusive scope / next handoff |
| --- | --- | --- |
| Integration143 | root | Android guard review/docs, CI, shared checks and delivery |
| Android proxy143 | android_proxy143 | API29 exact stale proxy repair and effective-state evidence; no refresh replay |
| Linux build143 | linux_build143 | New Fedora2328 build-only dependencies and immutable ba35-equivalent2.1.16/2.1.17 pair; no app replacement |
| macOS artifact143 | mac_artifact_read143 | Read-only packaging feasibility; VM remains stopped |
| Windows console | root | Host unlock requested; interactive acceptance pending |

## Historical continuation — checkpoint142

Checkpoint141 `6e3c167fac21b7d6a69369a682d177cfb6fbaec5` was pushed after
fresh full prepush passed (checkpoint141/prepush-final-result.json). Windows
workflow35991779882 failed release hygiene; exact-SHA delivery is incomplete.
Root owns the CI correction and renewed delivery gate. Version2.1.16,
Unreleased8 after the missing-helper diagnostic correction. No release is authorized.

The current macOS Java marker and Gradle configuration diagnostic pass; one
immutable package-pair build is running under mac_build141. Linux's existing
public download completed once and reached ready; the earlier pending observation
was taken before its receipt was written. Root reviewed its exact owner/revision
and terminal selector driver, and admitted one public install in new Fedora2328.
That install reports a protected SUCCEEDED receipt for jobd1d5a85f… and operation
7f678925…; the replacement owner reports installed=true with cleanupCode OK and
runtime off. RPM verification is clean at2.1.16. Root verified the exported
acceptance JSON hash82c0f0ed… and its receipt/public envelopes at
checkpoint142/linux-rpm-acceptance.json. This pair uses source934bdbd…, not the
latest checkpoint SHA; later refresh/operation/shared selection changes prevent
claiming whole-package current-source coverage.
The old CP120 unknown installation remains untouched. Android API35 status also
succeeds with the ADB port unset, so the earlier environment correlation is not
proof of a port-related product defect. API29 now has an immutable public HTTPS
fixture URL for its bounded subscription refresh acceptance.

| Task | Owner | Exclusive scope / next handoff |
| --- | --- | --- |
| Integration142 | root | CI correction review, metadata, checks and exact-SHA delivery |
| Fixture review142 | fixture_review142 | Bounded Windows hygiene failure diagnosis/fix; fixture scripts/tests |
| macOS build141 | mac_build141 | Same-source package pair only; live Tart/relay, no installation |
| Linux install142 | linux_install142 | One admitted public install and receipt recovery in Fedora2328 |
| Android refresh142 | android_refresh142 | API29 test subscription add/refresh/readback/targeted cleanup |
| Windows console | root | Host remains locked; interactive MSI acceptance pending |

## Historical continuation — checkpoint141

Checkpoint140 `cc9a995eb81451f3be6571fd0a54bd37f473d96f` is pushed after
full managed prepush passed. Version2.1.16, Unreleased5 at that commit. All five
required exact-SHA workflows and advisory VPN Integration succeeded; receipt is
checkpoint140/commit-result.json. The checkpoint delivery is verified, but the
full parity goal remains incomplete.

API29 now has the compatibly signed nondebuggable2.1.16 APK, SHA4347e057…,
installed with one actual data-preserving adb install-r. A failed wrapper parse
was proved prelaunch before that invocation. The whole ba35 Linux CLI bundle is
staged separately; no replacement-JAR mixing. Public status with no owner remains
UNAVAILABLE and does not imply OFF. Evidence: checkpoint140/android29-upgrade.

macOS's CP140 network success claim is unproven: its reconstructed probe record
does not establish verified helper execution. CP141 found that Tart did not
forward piped stdin, creating an empty helper that exited0 without probing.
Preserve those original records and this correction. A verified replacement
helper and compiled Java probe now expose a real403 CONNECT-header rejection.
The verified Java probe subsequently returned HTTP200 after the default-port
CONNECT correction. A later dependency build encountered relay saturation; the
capacity is now bounded at32 with an explicit503 overload response and16 passing
relay tests. The verified Java marker returned HTTP200 and the preserved
checkout passed `:desktopApp:tasks --all` in1m16s with the new relay. This closes
the configuration diagnostic, not package compilation or installation. The prior8GiB disk reserve was only an
estimate, not a repository requirement; fresh capacity monitoring remains needed.

Linux's exact watcher remains observational, without a protected receipt. The
unknown installation cannot be cleared through cancellation or inferred failure.
Preserve its original guest and correlation. Independent RPM acceptance requires
an isolated guest, not another account/workspace bypassing the same barrier.

| Task | Owner | Exclusive scope / next handoff |
| --- | --- | --- |
| Integration141 | root | CI watcher, docs, source review, shared build scheduling |
| Android refresh141 | completed; root integration | API29 streams observed; public subscription resource/parser test passes, awaiting push for HTTPS refresh |
| Relay close141 | completed; root integration |16 relay tests pass; fresh full prepush required after final additions |
| macOS build141 | mac_build141 | Live owned Tart boot-control53; updated relay and dependency diagnostic, then root build gate |
| Linux recovery141 | completed | New clean guest2328 booted, cloud-init done, frozen package hashes verified; handed to install142 |
| Windows admission141 | completed; root console | No interactive user; host UI unlock requested. No installer or credentials entered |
| Android35 current141 | completed | Current APK; pinned status/stats/log streams and client-only SIGINT verified |
| Guest transfer141 | completed; root integration | Public transfer guard rejects empty/stale/missing helpers;6 tests pass |
| Linux install142 | linux_install142 | New Fedora2328 base installed; diagnosing existing download, no install admitted |

API35 streams used the current nondebuggable APK and whole packaged CLI with
explicit ADB environment. Each emitted an owner-pinned record and exited130
after client-only SIGINT; stderr was empty and subsequent status/operations
retained controller fb144616… with no operations. This establishes stopped-state
stream behavior, not live traffic or nonempty incremental logs. Evidence:
checkpoint141/android35-current/owner-diagnosis/streams15. API29 public HTTPS
refresh awaits publication of the test-only loopback subscription resource; its
actual Android parser regression passes.

## Historical continuation — checkpoint139

Checkpoint138 `1ff5bedf0592bf9486ac767ae0daa693b0a2cc21` passed local prepush and
was pushed, but Windows workflow35984122823 failed in the new Linux fixture tests:
their simulated Linux actor still used Windows filesystem permission bits. A local
Windows-stat reproduction fails before the test-only repair;12 focused tests now
pass. Exact-SHA delivery is not complete. Preserve checkpoint138/commit-result.json
and checkpoint139/windows-ci logs. Product application source remains ba35.

The Linux helper was exercised on the original bad guest state and rejected it.
Root verified that both `.local` and `.local/share` were task-created root0755
ancestors containing only this fixture, changed their ownership through pinned
file descriptors without recursion or mode changes, then reran the helper
successfully. Evidence: checkpoint139/linux-repair. The admitted retry reached
polkit identity selection, but the fixture driver only recognized a password prompt.
Its driver exited; operation0a8f3ccf-c3e9-4007-a6b5-849b14c3fe9b remains
OUTCOME_UNKNOWN/nonfinal without a protected receipt. Preserve the owner shell,
job8af17487-490a-4073-8908-343861e36b0d and inputs; do not replay. RPM remains
2.1.15 with clean verification. Evidence: checkpoint139/linux-install.

The compatible ba35 Android nativeFixture build succeeded inside CP120:2.1.16,
code16720, nondebuggable x86_64, retained a43 signer, APK SHA4347e057….
API29 read-only admission finds the matching old2.1.15 APK and no app-owned VPN or
foreground service; public status still has unavailable owner metadata. This does
not establish the operation ledger or configured state. No upgrade has run.

Windows current ba35 pair is staged with matching guest hashes. Review found its
initial ACL lacked the intended user's RX entry; raw receipts are retained in
checkpoint138/windows-stage. A typed-SID generator and complete ACL validator are
verified by native PowerShell parsing and one successful ACL application. All five
staged hashes remain unchanged; both MSI files inherit recipient RX. Evidence:
checkpoint139/windows-acl/manifest.json. No installation or login was performed. The original setup did
not retain its error output, so the precise translation-error mechanism is not proven.

macOS's same-source base build failed before packaging because guest TCP access to
Google's repository timed out before TLS; the host reaches those same URLs. The
owned guest was stopped gracefully with child exit0, preserving historical unknown
installer state. A restricted opaque CONNECT relay and certificate-verified POM
preflight pass13 focused tests; no relay listener or build retry has started.

| Task | Owner | Exclusive scope / next handoff |
| --- | --- | --- |
| Integration139 | root | Windows CI test correction, shared wiring/docs, review and delivery |
| Linux selector140 | linux_selector140 | Dedicated fixture regression; no native mutation or replay |
| Android staging140 | android_stage140 | Export verified APK and read-only API29 admission; no upgrade |
| Windows stage ACL | completed; root review | Native ACL and unchanged hashes verified; installer/login pending |
| macOS admission140 | mac_admission140 | Read-only resource/startup plan; root owns reviewed relay files |

Independent review fixed mandatory captured QGA output and exact-stage binding
in ACL validation, with bounded relay reads in tests. All source ownership has
returned to root:34 fixture tests pass; the Linux harness runs22 tests with two
platform-specific skips. CP140/fixture-review and linux-identity-selector retain
the review/regression evidence. Android staging140 owns one compatible API29
upgrade; Linux selector140 is now read-only reconciliation; macOS admission140
owns bounded boot/network preflight. Heavy host checks are serialized behind it.

This intentional batch combines the CI test correction, exact-account terminal
selection and two reusable native fixture checks. Final review, metadata, full prepush and exact-SHA CI remain required.

## Historical continuation — checkpoint138

Checkpoint137 `ba35d802fba025e326e3fa837f2a1c1f89968f12` is pushed; all five
required exact-SHA workflows and advisory VPN Integration passed. Version remains
2.1.16. Managed delivery receipt: checkpoint137/commit-result.json. The full parity
goal remains incomplete. This batch intentionally combines the Linux fixture
provisioning regression with continued independent native artifact preparation.

Linux CP137's single public install failed before authorization. The new fixture
account's `.local` was root-owned0755, and UID1001 cannot write it, preventing
creation of `.local/state`. No current input/correlation/protected receipt remains;
do not infer its entire creation history from absence. RPM remains the verified
base2.1.15. Original public envelopes and effective-access evidence are retained in
checkpoint137/linux-install. Add causal quick regressions and a reusable target-user
setup path before repairing the exact fixture directory or retrying. This is a
fixture provisioning defect, not an established product installer defect.

macOS control53 is running under the resource guard after two positively identified
idle host Gradle daemons were stopped. The historical rollback114 operation remains
OUTCOME_UNKNOWN: its legacy correlation selects MACHINE authority, and the exact
receipt is currently absent from the protected machine root. Source deliberately
blocks replay and cannot prove not-started after reboot. Preserve its app, owner,
state and inputs. Sealed evidence: checkpoint137/macos-recovery. A separate clean
same-source fixture is being prepared in this guest; no new installer is authorized.

Current Android ba35 APK is verified but its official signer differs from the
retained test base. Do not uninstall or install across the mismatch. Compatible
fixture signing and the whole current Linux CLI package are under admission.
Windows current ordinary MSI is verified; test-only same-source pair workflow
35982037383 was dispatched once for ba35, base2.1.15/target2.1.16. Console sign-in
remains pending; do not replay installation or expose credentials.

| Task | Owner | Exclusive scope / next handoff |
| --- | --- | --- |
| Integration138 | root | WIP, review, routine-check wiring, host builds and delivery |
| Linux fixture regression | root; linux_scheduler132 review | Helper/tests implemented;11 focused tests and docs hygiene pass, native repair pending |
| Linux native | paused; no install operator | CP120 failed attempt preserved; native retry waits for builder release |
| macOS fixture | mac_admission125 | control53 sole operator; same-source build authorized with private JDK, preserve rollback114 |
| Android artifacts | android_document_plan131 | CP120 sole operator for isolated SDK/signing preparation; no build or emulator mutation yet |
| Android acceptance audit | android35_cold120 | Ignored evidence audit including CP132–136; no native actions |
| Windows pair | windows_base118 | Exact run35982037383 observation/download; no guest actions |
| Windows console | root | CP117 user sign-in pending |

## Historical continuation — checkpoint137

Checkpoint136 `934bdbd5ca5ae971f379559b8737bd9d53bc9d61` is pushed with all five
required exact-SHA workflows and advisory VPN Integration successful. Version is
2.1.16. Its foreground macOS resource monitor and seven focused regressions passed
full managed prepush. The retained native monitor recorded pressure2 after25
seconds, graceful exact-guest stop and child exit0. The installer journal remains
untouched; do not reboot while this resource condition persists.

API35's frozen replay completed. Root independently verified3699 non-self manifest
entries, identical first/replayed response bytes, public revisions0/1/2 and full
restoration of the original56000-domain routing data. Evidence and limits:
checkpoint136/android35-replay-complete/root-review.json. This uses the recorded
2.1.15 APK and actual512m heap, not API29's48m or newest-package acceptance.
The source child manifest's self-reference is preserved and explicitly excluded
from verification; do not reproduce that manifest-generation mistake.

API29's one CP136 refresh reached authoritative RUNTIME_FAILED with failedCount1
and no fixture HTTP request. Its exact subscription and private fixture remain
preserved for diagnosis; do not replay or remove unknown resources. Public UID2000,
48m heap, SSH disabled, certificate chain/SAN/validity and recorded reverse/trust
setup were checked. Empty HTTP logs cannot distinguish TCP versus pre-HTTP TLS
failure. The product currently discards Android refresh causes; desktop can persist
raw exception text. CP137 adds causal regressions before safe cross-platform failure
reporting. Native retry waits for reviewed changes and a new frozen artifact.

Linux's CP135 scheduler evidence is sealed. CP120 completed the immutable934
same-source base2.1.15/target2.1.16 pair with verified private Linux x64 JDK17.
The initial builder dependency transaction was rejected before installation; root
then reviewed and authorized its18 coupled upgrades (not unrelated removals).
Completed receipt and hashes are in checkpoint136/linux-final-pair. Exact base
installation/admission and guest-only target HTTPS preparation are now authorized;
update installation waits for review of the concrete fixture/handoff command.
Base installation/admission passed; public check/download are now authorized.

Windows CP117's console now works through notarized TigerVNC1.16.2 and the retained
loopback tunnel; no server authentication or exposure changed. The current test
account still needs interactive sign-in. A user-entry request is pending; its private
credential copy is outside repository/evidence and no secret was printed. Root is
not driving the console while awaiting user entry.

| Task | Owner | Exclusive scope / next handoff |
| --- | --- | --- |
| Integration137 | root | WIP, host Gradle RED/GREEN scheduling, review, metadata, checks and delivery |
| Refresh shared/desktop | windows_base118 | Source and tests implemented; final outer-code mapping follows verified RED |
| Android refresh | root review; worker retired | Focused GREEN and independent re-review passed; no native replay |
| Android35 replay | complete, no operator | emulator5682 preserved; reviewed evidence exported |
| Linux pair | linux_accept120 | CP120 exact base installation/admission and target fixture preparation; no update handoff yet |
| Windows console | root; user sign-in pending | CP117 only; private credential entry request pending |
| Localization | completed, workers retired | Three disjoint catalog owners translated all65 non-English catalogs; root checks passed |
| macOS | root | Guest stopped by recorded pressure guard; preserve installer journal/inputs |

CP137 refresh implementation passed80 focused tests across nine classes with no
skips; final XML and counts are retained under checkpoint137/refresh-failures.
Review regressions prove userinfo redaction, stale-route classification and retention
of known committed state after observation failure. A real operation-runner regression
also proves the outer PERSISTENCE_FAILED code matches validated failure details.
All66 catalogs pass localization/status checks. Full prepush and delivery are pending.

## Historical continuation — checkpoint135

Checkpoint134 `8fcd7225d84a232db5897763801fc47782c2ffc5` passed all five required
exact-SHA workflows. Checkpoint135 `79a2a35388cdbd7590e43593b75a27d4e733c139` is
pushed after the full managed prepush tier; version2.1.16. All five required
exact-SHA workflows and advisory VPN Integration passed; managed receipt is
checkpoint135/commit-result.json.

Linux CP133 accepted the HTTPS source but manual refresh persisted Connection
refused before runtime startup. Its fixture bound only IPv6 localhost, while a
diagnostic using the installed17.0.20.1 JVM resolves IPv4 first and reproduces the
refusal. This is fixture address-family mismatch, not a product TLS change. CP135
prefers IPv4 when available for both the HTTPS listener and the loopback-pinned
SOCKS upstream, retaining IPv6-only fallback and rejection of non-loopback answers.
The causal quick test first failed with connection refused; five HTTPS and sixteen
SOCKS tests now pass. Evidence: checkpoint135/linux-localhost. The original failed
native attempt is preserved in checkpoint133/linux-scheduler-https.

The corrected CP135 native run passed scheduled HTTPS refresh at the normalized
five-minute interval (299.914s between actual product fetches), with1435 successful
TUN samples and unchanged controller/runtime/active selection/source. Public off
and quit completed. Root exported and verified the eight-file native evidence
manifest in checkpoint135/linux-scheduler-ipv4/native-evidence; root-review.json
records exact identities and limits. Fresh cleanup finds no owner/runtime/TUN and
RPM verification passes. This is installed6ee/2.1.15 RPM evidence, not a claim for
the newest2.1.16 package. Arch rebooted after the completed run; the retained guest
was booted only to retrieve evidence, without replaying the scheduler.

API35 admission reidentified only emulator5682, UID2000, nondebuggable2.1.15 APK
SHA1ac2ac0d823bf6f0403f57ea3156c90209a3d91c64ccf4af919132c32af92401,
OFF with no proxy/reverse mappings. A newer installed receipt is present; the old
cancel session is historical. No installation was resumed. Exact large-request
replay on API35 is a separate bounded task; its actual heap is512m, not48m.
After the Arch reboot, the retained API35 AVD was cold-booted with its existing
userdata. Its public routing query completed with an11.48MB response containing
56000 domains, contradicting the proposed empty-state prerequisite. The guard
stopped replay before mutation. Preserve this actual original state; root is
reviewing a distinct candidate plus exact guarded restoration. Host console access
briefly returned but CUA subsequently reported the Mac locked again.

| Task | Owner | Exclusive scope / next handoff |
| --- | --- | --- |
| Integration135 | root | Shared fixture correction, metadata, host builds and delivery |
| Linux scheduler | complete | CP120 Fedora evidence sealed; guest idle, no owner/runtime/TUN |
| Android35 replay | android35_install125 | emulator5682 only; reviewed replay/restore flow, no installer or UI action |
| Android29 | no active operator | Restored/OFF before Arch reboot; emulator not restarted |
| Windows readiness | windows_base118 | Retained CP117 booted; read-only QGA snapshot, no installer/task/login |
| macOS readiness | mac_admission125 | Resource admission and read-only retained-journal reconciliation; no installer replay |

## Historical continuation — checkpoint134

Checkpoint131 `e715284fb85430344b10ffe144264d02a6599467` is pushed with all five
required exact-SHA workflows successful (managed checkpoint131/commit-result.json).
Product version remains2.1.15. Product source is unchanged from the frozen6ee249e
artifacts used below. Full parity remains incomplete; earlier continuation sections
are historical observations, not the current acceptance ledger.

API29 emulator5684 now proves the effective48MiB maximum heap using the supported
emulator userspace boot option. With the exact nondebuggable2.1.15 APK, CP132 passed
the56,000-domain/11,536,164-byte import, full logical readback, retained operation
wait, new-request no-op, private export and existing-destination rejection. An
app-only background-process reclamation was followed by a new PID/controller and
matching complete cold readback. Original routing was restored and runtime stayed
OFF. Root verified135 manifest entries in checkpoint132/android-documents. The
status response was observed after commit; it does not prove responsiveness during
parsing. Export formatting/metadata differs from input bytes; logical content matches.

CP133 additionally replayed the identical large logical request through the public
authenticated document provider. Both results are exactly equal, including request
and operation identity; revision advanced1→2 on import and stayed2 on replay.
Restoration advanced revision to3, runtime remainsOFF, heap remains48m. Root
verified the exported3831-file bundle in checkpoint133/android-replay; see its
root-review.json. This did not inject response loss. Remaining security, resource,
export-race, GUI and API35 scenarios are separate gates.

CP134 public-provider negatives reject wrong lengths, wrong hashes, unsealed
submission, unavailable results, forged IDs and discarded IDs. Same-context begin
is idempotent. Routing and revision3 are unchanged; runtime staysOFF. An initial
evidence comparison incorrectly included generated `exported_at`; preserved raw
results prove this was the only difference. The full-document comparison helper
now excludes only that field, with causal1-failure RED and6-test GREEN in the
routine Android evidence suite. No native rejection scenario was replayed to fix
the comparison. Evidence: checkpoint134/android-document-negative.

CP132 Linux scheduled-refresh setup failed before fetching or starting VPN because
the fixture supplied HTTP, which the existing HTTPS-only source validator correctly
rejects. This is invalid fixture input, not a product defect. No scheduler or TUN
acceptance is claimed. Public off/quit completed; fresh cleanup found no owner or
TUN. Failed evidence is preserved in checkpoint132/linux-scheduler. The next run
must use trusted guest-only HTTPS and preserve hostname/certificate validation.

| Task | Owner | Exclusive scope / next handoff |
| --- | --- | --- |
| Integration134 | root | Shared files, evidence review, metadata, builds and delivery |
| Android document negatives | root | Owned API29 emulator5684; bounded public-provider rejection checks |
| Linux HTTPS scheduler preparation | linux_scheduler132 | Ignored checkpoint133/linux-scheduler-https only; no native authorization yet |
| Windows | no operator | Production UAC/ordinary-user and successful MSI/recovery gates remain open |
| macOS | no operator | Guest stopped for host resource limits; preserve pending journal and inputs |

## Historical continuation — checkpoint131

Checkpoint129 `041000b66c9af241e37e34ebe3b77cfec9205970` is pushed and all five
required exact-SHA workflows passed. Product version remains2.1.15. Managed
receipt: checkpoint129/commit-result.json. The overall parity goal remains open.

CP130 installed-Fedora RPM evidence now records206 successful HTTP204 requests
bound to the TUN interface, with start/end timestamps across GUI close, crash and
reattachment. Completion counts across the five transition phases are98/44/9/49/6.
Controller identity is retained through final reattachment/off; runtime identity
is explicitly queried through crash, before the final reattachment acknowledgment.
Do not infer a post-ack runtime identity query. Root verified both manifests and
fresh cleanup (no owner/runtime or TUN; rpm verification succeeds). Evidence:
checkpoint130/linux-tun-timing, linux-tun-timing130-export and linux-root-review.json.

API29 emulator5684 retained its exact current target and empty/OFF baseline after
a controlled restart. Emulator36.4.10 rejected the proposed heapgrowthlimit
property; this is fixture admission failure, not a product failure. A supported
append-userspace option for maximum heap size is now under native admission.
No48MiB import acceptance is claimed until the effective limit and public flow
are verified. Initial failure evidence is under .runtime/checkpoint130/android48-admission
(outside the usual parity-evidence subtree).

Root separated existing-emulator admission from AVD creation in
android_avd_sdk_preflight.py. The launch-only path preserves explicit SDK/AVD
environment and image checks without requiring the unused avdmanager. Creation
retains its stricter SDK-root rule. Eleven focused tests pass with causal failing
evidence preserved. Final metadata/prepush and delivery of this new script slice
remain required; checkpoint129 remains the last fully verified pushed SHA.

| Task | Owner | Exclusive scope / next handoff |
| --- | --- | --- |
| Integration131 | root | Evidence review, documentation, shared files and delivery; checkpoint129 CI complete |
| Android48 admission | android_heap_boot131 | Owned remote API29 emulator5684 only; verify supported48MiB maximum, no document mutation yet |
| Linux TUN continuity | complete | One native attempt plus read-only export; guest idle, evidence limits above |
| Windows broker audit | complete | No code defect found in bounded review; real production-path UAC denial and installed ordinary-user/autostart evidence remain open |
| macOS | no operator | Guest stopped after memory pressure; preserve pending installer journal and inputs |

Remote fixture execution must use the retained full SSH chain, then validate
guest username, hostname and OS before mutation. Changing destination text while
reusing a ControlMaster socket does not retarget that connection. CP130 caught a
read-only gateway observation before mutation; the corrected runner rejects it.

## Current continuation — checkpoint129

Corrective checkpoint128 a52faf3aabd3a7b92c2f9e240fe890798349a501 passed local
prepush and is pushed. Windows CI passed the repaired Android tests, then exposed
a macOS test process-row using host Windows separators. The test-only correction
now exercises native and PureWindowsPath forms locally, including a non-vacuous
ambiguity check; causal RED and23-test GREEN evidence are retained. Final metadata,
prepush and a new exact-SHA CI cycle remain required.

The CP120 installed-RPM retry passes package/capability admission,110 TUN HTTP
requests,110 ordered raw proxy echoes and preserved controller/runtime through
GUI close and guarded frontend crash/reattach, followed by off/quit and no TUN or
runtime process. Root verified the manifest and identities in
checkpoint128/linux-root-review.json. Per-frame raw proxy timestamps cover close
and crash; the TUN sampler lacks per-attempt timestamps, so do not claim it proves
TUN requests overlapped the crash. Full evidence is in
checkpoint128/linux-vpn-continuity-retry128 and its separate retained export.
No additional native retry is active. The Mac guest remains stopped after the
resource monitor's pressure2 event; journal/inputs remain preserved.

## Current continuation — checkpoint128

Checkpoint127 `a27624a054d888e5004e4511747ab3a97a5e6a1c` is pushed after a
successful managed prepush, product2.1.15 / Unreleased6. Windows package CI failed
in the newly added Android installer flow tests: POSIX private-mode and ADB PATH
assumptions were not isolated at their OS boundary. Exact failed log:
checkpoint128/windows-ci-failed.log. A focused test portability correction passes31 local tests including Windows-stat
simulation; checkpoint127 delivery is not certified. Other workflows are still
being observed by exact SHA.

API29 document preflight cannot prove48MiB: heapgrowthlimit is empty and heapsize
is512m. Root's raw recheck with the approved ADB PATH/server5037 returns public
status and routing show OK under the installed owner, OFF and empty routing.
The earlier worker's summarized UNAVAILABLE result is not established as a
product failure. Preserve both checkpoint128-android-preflight and corrected
checkpoint128/android-document-recheck evidence. No document mutation ran.

| Task | Owner | Exclusive scope / next handoff |
| --- | --- | --- |
| Integration128 | root | Shared docs, exact-SHA CI, Mac guest reconciliation; no late approval of the ended rollback driver |
| Windows CI portability | completed; root integrating |31 local tests pass; native CP117 Python not available on inspected service PATH; exact-SHA CI required |
| Linux VPN continuity | linux_vpn_continuity128 | Native attempt retained identities but traffic failed from serial fixture starvation; local corrected-runner proof only before retry |
| Android document preflight | complete | No48MiB acceptance; current target retained on5684/5682 |

The Mac operation remains unknown after public cancellation. The protected
SecurityAgent window is present on-screen but omitted by screencapture; the host
Screen Sharing application times out through UI automation. Manual cancellation
was requested, then superseded when the durable monitor observed host memory
pressure2 and gracefully stopped only the owned guest (Tart exit0, stopped state).
Monitor stop.json/terminal.json and final samples preserve the cause. No terminal
installer result follows from guest shutdown. Preserve the exact operation and
inputs; require fresh resource admission and next-owner reconciliation before any
new installation or retry.

## Current continuation — checkpoint127

Checkpoint126 delivery `fcab2d0e531c13663f72be2e0ad1b6d1d5c183f3` is pushed,
product2.1.15, Unreleased5/10. Full managed prepush and all five required exact-SHA
workflows passed; receipt: checkpoint126/commit-result.json. Checkpoint125's
Windows POSIX-mode test failure was corrected without dropping the Windows
behavior checks. Full parity remains incomplete.

Current native evidence, independently reviewed by root:

- API29 current6ee base: packaged CLI manual subscription refresh produced one
  real HTTPS GET and cache0→1, then restored the original source and deleted the
  exact fixture subscription. Fifteen envelopes share one command owner epoch;
  cleanup restored UID2000, null proxy and no reverse mappings. Evidence:
  checkpoint125/android29-refresh/root-review.json. Connected/scheduled refresh,
  SSH and current48MiB acceptance remain open.
- API35 current6ee pair: corrected cancellation driver confirmed the exact
  PackageInstaller receipt as cancelled/installed=false, preserving historical
  operation handoff. A subsequent real Update installed exact target2.1.15/code16700
  (SHA1ac2ac0d823bf6f0403f57ea3156c90209a3d91c64ccf4af919132c32af92401).
  The replacement owner reports installed=true and runtime OFF. That success run
  lacks pre-approval operation-to-receipt capture: the old in-memory operation is
  correctly NOT_FOUND after replacement. Do not count it as a fully correlated
  harness pass or downgrade the now-installed target. Evidence:
  checkpoint126/android35-cancel and android35-installed. The corrected two-phase driver passes30 focused tests, including main-to-action
  option forwarding and TTY flow. API29 installation attempt127 stopped before
  download with UNSUPPORTED: the fixture advertised arm64-v8a for the x86_64 APK.
  API35 secondary ABI support masked that mismatch. Payload-derived metadata and
  regression coverage passed. A separate immutable rerun then installed target
  2.1.15/code16700 with exact1ac2 hash: operation8bdf2f27-c9fe-4eee-b640-8905a85eebff
  captured receipt f2da3dac-df27-4d19-bef9-6855b0b23b9c/session824108056 before approval;
  replacement ownerf58c6b37-af10-47ca-aed7-3550228f6cb5 reconciles installed=true.
  Noninteractive rejection, Unknown Sources grant, exact package bytes and cleanup
  pass. Root verified24 exported artifacts and recorded the original self-including
  manifest defect; a separate manifest uses the existing tested helper. Evidence:
  checkpoint127/android29-installed-rerun/root-review.json. Broader installer
  failure/process-loss scenarios remain open; both5684 and5682 now retain target.
- Linux current6ee RPM: normal close and guarded frontend crash each retained
  one controller/runtime and110 ordered synthetic proxy frames, then public
  off/quit completed. Root verified hashes and timelines in
  checkpoint125/linux-current125/root-review.json. The VPN fixture first failed
  because /tmp is mounted nosuid, suppressing file capabilities. A private
  home-backed workspace now passes exact-binary mount/capability admission, real
  public VPN start, TUN UP and one DNS-free synthetic HTTP request via the loopback
  SOCKS endpoint. Public off/quit succeeded and exact postflight shows no owner/TUN.
  Evidence: checkpoint126/linux-vpn/vpn_home_result.json. This is basic TUN traffic,
  not GUI/scheduled continuity in VPN mode or every Linux package format.
- Windows CP117: native LogonUser validates the protected ordinary-user credential,
  but the single RFB login attempt failed. A settled nonsecret QMP probe proved
  all nine characters arrived; immediate frames undercounted them. Three bounded
  keyboard navigation attempts still did not select vpncp117. No further
  credential submission occurred. The temporary login policy is restored to0,
  the failed base MSI task stays disabled, and no replacement is claimed.
- macOS: the durable monitor retains the running owned guest under normal memory
  pressure. Fresh ordinary owner330a0ea2-6681-4af6-a1d2-118593354b0d reached READY
  after renewing only expired private fixture TLS trust. The reviewed harness
  now has explicit machine receipt authority and strict owner identity (23 tests).
  Operation78e1a9d4-c1ec-4795-b729-430ecc61f2b1 was accepted; its harness process
  subsequently ended before staging, so no fault-injection lock remains held.
  Fresh public status retains job e6bfc9a0-ff67-4047-be27-4220493ea088 as unknown,
  installed=null and handoffReady=false. Watcher and authorization processes are
  live. CoreGraphics reports an on-screen protected SecurityAgent window even
  though screencapture omits it. Public cancellation was accepted as cancelling
  but a subsequent poll remains unknown; no terminal cancellation is claimed.
  Root owns guest reconciliation and
  preserves the operation without replay or late approval. This is the older
  source pair, not current-source installation acceptance.

| Task | Owner | Exclusive scope / next handoff |
| --- | --- | --- |
| Integration127 | root | Shared files, artifact verification, host builds, docs, delivery and exact-SHA CI |
| Android two-phase driver | completed; root owns integration | Thirty focused tests pass; native fixture preparation is separate |
| Linux VPN126 | completed; root review | CP120 guest2327 idle after real TUN/traffic/off/quit; guard/tests awaiting integrated checks |
| Windows input125 | completed; guest reserved | CP117; navigation unsuccessful, no credential or MSI retry |
| macOS rollback127 | root | Exclusive owned Tart guest; reconcile exact unknown operation before further installation |
| Android29 install127 | completed; root reviewed | Correlated API29 installation passes; both owned AVDs retain target2.1.15 |

The clean6ee source archive produced nondebuggable x86_64 nativeFixture APKs
for2.1.14/code16680 and2.1.15/code16700. Root verified package identity, versions,
matching fixture signer, native libraries and hashes. Immutable inputs and results
are under `/private/tmp/vpn-android-pair123.ptbx1tze/frozen`, including
SHA256SUMS.txt, source-receipt.json and verified-artifacts.json. Both builds passed;
this establishes packaged inputs, not native installer acceptance. The four
Android installer/trust/update/transport harness selections passed61 tests.

Linux disconnected public serve survived35.00008 seconds without control requests,
past the30-second idle policy, with the same PID alive; status remained OFF and
public quit ended that owner cleanly. Evidence: checkpoint121/linux-lifecycle-idle.
Its sourceProvenance field uses a stale directory prefix; the actual frozen pair
receipt is `.runtime/checkpoint119/linux/fedora2326-fixture-receipt.json`.

Historical macOS resource attempts: Tart rejected3072MiB because this guest
requires4096MiB; configuration remains2CPU/4096MiB. Some earlier attempts raised
host memory pressure, but later normal-pressure observations supersede a blanket
RAM blocker. Raw free pages alone are not sufficient for resource admission.

Checkpoint124 continuation: CP120 installed d27-package proxy traffic passed,
then a minimal Xvfb session proved GUI attach, frontend-only crash and reattach
with unchanged controller/runtime. One existing SOCKS tunnel echoed93 ordered
frames without reset/EOF/error across those transitions; the maximum observed
send interval was1.05144 seconds, so this is connection continuity rather than a
zero-latency claim. Full envelopes and sampler evidence are under
checkpoint124/linux-traffic/gui-continuity. A later normal-close run reports110
ordered frames through WM_DELETE_WINDOW and reattach; independent review and
repeat on the6ee package are assigned to linux_current125.
The minimal X11 dependency transaction succeeded after Openbox's optional test
environment dependency chain encountered an external Cisco repository403.

The6ee CI macOS DMG and Linux package artifacts are retained in
checkpoint124/macos-ci-6ee and linux-ci-6ee with run/source/hash receipts. The
DMG-extracted arm64 CLI passes codesign and version checks and is available for
Android control; this is not macOS installed-package lifecycle acceptance.

Android fixture attempts accepted no installer or subscription operation. API29
CA push incorrectly used a Mac-local path with remote Arch ADB; API35 prepared
trust but addressed a Mac-local fixture server through Arch-local ADB reverse.
Both are cleaned, unrooted and have no remaining owned reverse mapping. API35
clean public status confirms runtime stopped on the new6ee base APK. Colocating
the public Linux CLI and fixture drivers on Arch is complete. Both device status
reads pass through the6ee packaged Linux CLI. The target APK transfer completed
with SHA1ac2ac0d823bf6f0403f57ea3156c90209a3d91c64ccf4af919132c32af92401;
checkpoint124/apk-transfer-result.json records verification and the gateway staging
was removed. Refresh fixture proxy/TLS topology remains under review before native
execution; artifact transfer alone is not acceptance evidence.
Do not infer protocol incompatibility or owner loss from a sanitized transport
UNAVAILABLE response. Use public_cli_environment and retain raw adapter errors.

The Android installer worker accidentally replaced the historical checkpoint117
adb-capture118-master binary while creating a fixture adapter. Its adjacent C
source remains SHA280dfb9b6796c9bab492479bfcb5206deb0f5f69c9136c75869e83fe39d08448;
the rebuilt binary is SHA98b08f32abcd9ada95c9845b36981e16087565f2e9975e035d419ad72f738486,
not the original7c4b hash. Preserve historical receipts without rewriting their
hashes. New runs must use separately staged immutable copies and record actual
inputs; the replacement does not recreate the original binary evidence.

## Prior continuation — checkpoint121

At13:06 Moscow September23, HEAD/origin/dev is
`fd6eec74ea2f12e7ee500a22aef748a9178f84a9`, product2.1.15, after full
prepush and reviewed checkpoint delivery. All five required exact-SHA workflows
passed; managed watcher10179 exited0. The prior
c4532e3 and d27affd checkpoints passed all five required workflows. Full parity
remains incomplete; older native packages do not certify the final delivered SHA.

| Task | Owner | Exclusive scope / next handoff |
| --- | --- | --- |
| Delivery121 | root | Shared integration, documentation, host checks, delivery and evidence review |
| Windows interactive admission | windows_reconcile120 | CP117 only; disable failed owned task, refresh login, prove SID1002 ordinary interactive session before any MSI retry |
| Linux RPM acceptance | root | CP120 same-source replacement/recovery passed; two causal PTY regressions reviewed for delivery |
| Android29 cancellation | android29_cancel120 |5684 public cancellation scenario, persistent relay, exact operation and cleanup |
| Android heap admission audit | android35_cold120 | Read-only private AVD configuration/evidence audit; no emulator restart |

API35 private export and existing-destination rejection passed. Cold process
reopen also returned all56,000 exact routing entries under a new owner epoch.
Root independently compared full rules; the corrected receipt verifies installed
APK SHA1af2a6c40afe47bca10d40344f9a33ab7f71b774f710a41c4fdf8780502d00ca.
Evidence: /private/tmp/vpn-control-android35-cold120.5GKcLn and checkpoint120
root-review records. The observed heap growth limit was192MiB, not48MiB;
native48MiB acceptance remains open. Retained wait now passes: concurrent public
operations list correlated synchronous no-op request8b586b26-7f8a-4bab-b921-
5896ef768408 to operation38f69731-1212-4d4a-9828-c98c324e69b8 while the first
large response was draining. Import and wait both exit0 with all56,000 exact
fixture rules and unchanged revision0. Root independently checked both response
hashes and every rule field (checkpoint121/android35-wait-root-review.json).

API29 benchmark produced a real secondary measurement. The ten-candidate
Find Best cancellation now passes on5684: operation
18f766f7-078a-4b15-a24e-44019b972b8f reached terminal CANCELLED at progress2/10,
committed=false, RUNTIME_NOT_CHANGED after actual stalled probe traffic. Root
verified48 evidence hashes under /private/tmp/vpn-control-android29-cancel122.
All ten synthetic candidates were removed, original batch3/retry1/window5 settings
restored, revision30 runtime OFF with no selected/active location, and owned relay
and reverse mapping removed. Earlier short attempts remain timing limitations;
API29 reports empty heapgrowthlimit and512m heapsize, not48MiB evidence.

Windows CP117 base task is terminal1601, READY with no instances or msiexec.
MsiInstaller1015 records access denied connecting to the service; batch-context
causation is not yet proven. The enabled ordinary account vpncp117 is SID1002,
but the visible login tile is parityagent SID1000. No credential was typed into
the wrong tile. The failed owned task is being disabled before controlled login
refresh; MSI retry requires the existing original-recipient admission guard.

Linux CP120 prior public update job9f839ce8-2fff-443f-a700-d8438a7bdd84 was
publicly cancelled with authoritative final CANCELLED/installed=false, no worker
remaining. A credential-free guest probe showed reopening a PTY master through
/proc/self/fd allocated a different PTY and did not deliver its marker to the
original slave. Earlier password delivery by that method could not reach polkit.
Causal retained-master and controlling-terminal regressions now pass21 tests in
the actual Linux guest, after both old behaviors failed. The corrected driver's
public retry job02bf3dc0-2404-4e8c-ae66-a7d987afd7bf succeeded with protected
seq4 and next-owner installed=true/cleanupCode=OK. RPM verification and public
version2.1.15 passed; runtime remains OFF. Frozen packages are d27affd source,
base2.1.14/target2.1.15; this is not final-source or live-traffic acceptance.
See checkpoint121/linux/receipt.json. Root owns guest2327; previous unknown
jobs in other guests are unchanged.

macOS CP114 fresh guest-private TLS fixture completed public check and target
2.1.14 download. No installer was submitted. Owner was publicly quit and only
vpn-control-boot-control53 gracefully stopped when host memory pressure rose.
Its recorded controller epoch is no longer live; next boot requires fresh public
admission. Machine rollback/recovery and GUI return remain open.

## Prior continuation — checkpoint120

Checkpointc4532e3669885e5ec3b132a0be70de0470d59b5a was pushed after full
prepush and independent review of the stream interruption fix. Its exact-SHA
watcher26163 is active; prior d27affd passed all five required workflows.
The causal Android stream test failed expected130/actual2 before the fix; all20
focused stream tests pass after it. Mutation uncertainty handling is unchanged.

| Task | Owner | Exclusive scope / next handoff |
| --- | --- | --- |
| Delivery120 | root | Shared integration, routine wiring, host checks, evidence and delivery |
| Windows reconciliation | windows_reconcile120 | CP117 single base-task instance and exact frozen helper test; no replay |
| Android35 export | android_readback117 |5682 public export into trusted private temporary directory |
| Android29 cancellation | android29_cancel120 |5684 fresh foreground admission and read-only transport diagnosis |
| Linux RPM acceptance | linux_accept120 | CP120 guest2327 public same-source update after successful base install |

API29 normal benchmark operation65f563b9-6649-4d9b-a462-30dae860a376 succeeded
with secondaryStatus=ok and secondaryTotalMs=1390.65995. Root verified10 receipt
hashes and the public status/wait results. Fixture is OFF, empty, source=current-
locations revision5. Shared preflight files were overwritten by the normal run;
they do not prove earlier stalled cancellation. Cancellation remains unverified.

API35 large export diagnosis found a correctly rejected destination under the
non-sticky0777 projects ancestor; transfer completed. Existing causal regression
covers this admission rule. Retry now uses a trusted0700 /private/tmp parent.
Retained no-op status/wait each timed out without a terminal outcome; no replay.

Windows CP117 start failures are batch-logon denial, not bad credentials:
Security4625/type4/status0xC000015B and TaskScheduler101/error0x80070569.
No installer child started. Temporary Operational logging was restored disabled.
The deterministic admission helper is wired into Windows package CI. Native denial
was reproduced before a narrow batch-right repair and admission then passed.
Exactly one base task instance4C89AAFD-20D3-44CB-8677-6CC9B24AA339 was started;
its outcome is being reconciled, never replayed after observer timeout.

Linux base2.1.14/target2.1.15 DEB/RPM/Arch packages completed from d27affd source.
Root checked source fingerprint and equal code fingerprints in the build receipt.
Existing Fedora2326 owner still reports unknown nonterminal jobbacae2d1-5029-4e39-
a69a-6cba7407c64c, installed=null. Preserve it and prepare a separate clean guest
for acceptance. New CP120 Fedora2327 completed cloud-init; native base RPM
installation acquired xdg-utils and desktop registration succeeded. rpm verification
and public CLI version2.1.14 passed. The target remains staged for public update.
Mac remains stopped for host memory pressure. Full native and
visual acceptance and final delivered-source verification remain incomplete.

## Prior continuation — checkpoint119

At11:56 Moscow September23, HEAD/origin/dev is
`d27affd35f43b7c033676a76d2cc2b8219ee5b46`, product2.1.15. Its complete
prepush passed; Fast, Android, Linux and macOS required workflows passed.
Windows package remains running; do not claim exact-SHA delivery complete yet.
The preceding8e0a6b3 checkpoint passed all five workflows. Full parity is incomplete.

| Task | Owner | Exclusive scope / next handoff |
| --- | --- | --- |
| Delivery119 | root | Shared integration, host Gradle, docs, metadata and exact-SHA CI |
| Stream interruption | stream_audit118 | Shared stream boundary and focused tests; preserve uncertain mutation outcomes |
| Windows base118 | windows_base118 | CP117 existing task read-only diagnosis; no further launch authorized |
| Android29 diagnosis | android29_actions118 |5684 benchmark evidence analysis only; fixture cleaned |
| Android35 export | android_readback117 |5682 retained result and failed private export diagnosis |
| Linux packages | linux_build118 | Fedora2326 immutable current-source base/target build; preserve existing controller |

API35 full readback and new-request no-op import returned all56,000 entries,
matching the fixture with revision1 unchanged. Large private export returned
PERSISTENCE_FAILED and requires diagnosis. Original operation status/wait expired
with NOT_FOUND; no replay. The shared gateway master remains borrowed by platform
workers and must not be closed while in use. Evidence remains in checkpoint117.

API29 persistent relay preflight passed and a benchmark reached the stalled relay,
but completed RUNTIME_FAILED before cancellation, with null timings. This does not
prove finite measurements or cancellation. Exact synthetic location, relay and
reverse mapping were removed. Runtime is stopped, locations/subscriptions empty;
source=current-locations revision3 is an approved disposable fixture deviation.

Linux private QEMU asset preflight and diskless probe passed, and the second
memory restore completed successfully. Fedora2326 is running with original4GiB/
2CPU; current-source2.1.14/2.1.15 pair is building inside it. Preserve the existing
controller serving cp85-rpm-failure; no installation/runtime mutation is authorized
by the build assignment. Original memory and first-attempt evidence remain intact.

Windows CP117 is isolated from preserved CP95 unknown installer state. Verified
same-source8e0a6b3 MSI pair is staged, with a nonadministrator fixture account.
The registered limited task still reports0x41303 (never run) after an explicit
start returned; no child, MSI or receipt exists. Diagnose rather than repeatedly
launching. Mac remains stopped for host memory pressure; its machine-owned
rollback/recovery, other native scenarios and final visual gates remain open.

## Prior continuation — checkpoint117

At11:09 Moscow the authoritative worker inventory was empty. The Android large
import has a successful terminal receipt; its following full-readback client is
absent and has no exit receipt, so readback remains unverified. Do not repeat the
import. Root is integrating SDK admission and the workflow parser gate before
prepush. Prior ownership rows below are historical, not active assignments.


77976806328da03f43a7952224ec272d69787a74 passed all five required exact-SHA
push workflows; managed watcher1593 exited0. The next checkpointadd840ad234c23f0588fc1dbc0a0a68c480ecd70
was pushed after complete local prepush passed, but Windows push35833398572
failed and manual fixture dispatch returnedHTTP422: runner.temp is unavailable
in job-level env. Watcher88997 exited1. This is not a verified delivery.
The workflow now initializes FIXTURE_ROOT through a PowerShell step/GITHUB_ENV;
a causal regression failed before repair. A fresh worker workflow_lint117 owns
only a pinned real actionlint runner and its tests; root will wire it into routine
checks before another full validation/push. No release/main operation occurred.

API35 packaged status/stats/capabilities and initial watch/follow records passed.
Root independently verified40 stream evidence hashes and same controller
0ab99cc7-32e5-47a2-8bda-c5e9416a56cd; local TERM143 stopped only each client.
First records took12–14 seconds; earlier3-second cutoff was insufficient evidence.
Full duplicates/rollover/owner-replacement stream scenarios remain open.
android35_document116 owns only emulator5682 large-document work. Baseline export
under the repository returned PERSISTENCE_FAILED before mutation; a private
trusted /private/tmp output path is the next discriminator, not a claimed fix.

API29 worker created only private SDK/AVD vpn-control-parity116-api29 on5684,
PID67529,2GiB/2CPU. Shared avdmanager symlink resolved to /opt/android-sdk and
could not see the selected SDK's image; copied real tools under the private SDK
fixed creation. No shared SDK edit. Target2.1.14 installed once into the fresh
nondebuggable guest; exact APK hash matches API35. Command observation timed out,
so the worker checked installed package state instead of retrying installation.
Private-SDK/AVD admission needs a quick causal regression before reuse.

| Task | Owner | Scope / next step |
| --- | --- | --- |
| Delivery117 | root | Workflow parser fix, routine integration, metadata, prepush and exact-SHA CI |
| Workflow lint117 | workflow_lint117 | New pinned checker and test only; real parser RED/GREEN |
| Android35 documents116 | android35_document116 | Exclusive5682, synthetic large routing after baseline, no VPN/installer |
| Android29 baseline116 | completed |5684 remains running; root owns next assignment, no replay |
| Linux resume116 | completed | Read-only2326 inventory; no resume authorized |

Linux2326 is separately memory-parked at
/home/kardinal/vpn-control-install-vm-cp83-fedora-20260920,6GiB/4CPU; do not
cold-boot a parked disk in place of the documented memory restore. CP99 package
inputs are historical. Its read-only identity/resources are checkpoint116/linux.
Mac boot remains deferred for local memory headroom. Unknown installation
correlations and Fedora2316 memory remain preserved.

## Prior continuation — checkpoint116

Checkpoint77976806328da03f43a7952224ec272d69787a74 was pushed after the
complete managed prepush tier passed. Its exact-SHA managed CI watcher is live
(session1593); all five workflows were in progress at10:29 Moscow September23.
Do not reuse the older9e57 CI receipt as evidence for779.

| Task | Owner | Exclusive scope | Evidence / next step |
| --- | --- | --- | --- |
| Delivery116 | root | Docs, metadata, host Gradle, commits, CI | checkpoint115/prepush-result.json; CI watcher1593 |
| Android baseline115 | native_evidence115 | Owned API35 serial5682 only; ignored evidence | qemu59345, UID2000, nondebuggable2.1.14; packaged CLI read-only commands next |
| Windows fixture116 | windows_artifacts115 | New manual-only workflow and its test | Build same-source base/target on disposable CI; no dispatch yet |
| Linux regression116 | linux_regression116 (done) | DesktopLinuxInstallWorkerTest.kt only | Root focused five tests pass; actual shell RPM failure branch |

Android baseline confirms boot of only the existing private AVD at2GiB/2CPU.
Direct content call status/capabilities returned empty output and are not valid
provider protocol evidence. Use the packaged adapter. The first launch omitted
ANDROID_AVD_HOME and failed; its raw error is retained, causal regression still
required. API29 image files exist but completion receipt is insufficient.

Mac VM remains stopped: root deferred its4GiB reservation with roughly11.5GiB
physical compressed memory and1.6GiB swap already in use. No unrelated process
was stopped. Arch had53GiB available before the Android allocation. Keep unknown
installer records and parked Fedora memory intact.

## Prior continuation — checkpoint115

On 2026-09-23 startup revalidated dev at9e57f01, equal to origin/dev, and
preserved ten dirty fixture/doc paths. The previous turn was a status estimate,
not implementation progress. No previous collaboration workers were live.
Fresh bounded workers own fixture review (fixture_review115), retained local
native evidence inspection and exclusive owned API35 discovery/admitted boot
(native_evidence115), and readiness helper/tests (readiness115, completed).
Root owns docs, integration, other environments and delivery. Android permission
is limited to existing vpn-control-parity113-api35, serial5682,2GiB/2CPU after
10GiB free-memory and unoccupied-port checks, then read-only baseline; no install,
clear, force-stop or mutation replay is authorized to that worker.

The old Arch SSH control socket refused connections. Root authenticated a new
session using the authorized key and created a distinct arch115 control socket;
no guest or installer was restarted. Tart reports the owned macOS boot-control53
VM stopped; its old IP times out. Historical process identifiers are not live
state. Reinspect retained operations after any capacity-admitted normal boot.

The dirty batch remains QGA bounded reads, fixture dependency inventory, macOS
public-status readiness, their causal regressions and routine documentation.
No current dirty batch pre-push receipt or delivery exists yet.

Current read-only native discovery establishes that Arch is reachable through
the new authenticated session, with54480MiB available and no qemu/emulator/SDK
manager process observed. This supersedes historical capacity estimates but does
not authorize replay of retained installer jobs. The Android CLI113 folder lacks
raw stdout/stderr/exit receipts, so its prior worker success summary is unverified.
Mac machine114 exports prove preparation/download only, not installation.

## Previous continuation — checkpoint114

Checkpoint9e57f01f31f66607627606468de773afae99f7fc (product2.1.14) was
committed and pushed after the complete managed pre-push tier passed. Its exact
CI watcher completed successfully: all five required workflows passed for that
exact SHA, as did advisory core VPN Integration. Its managed receipt is
checkpoint113/commit-result.json. Do not substitute the earlier40307db receipt.

The fresh macOS pair is /private/tmp/vpn-macos-parity113-pair, source fingerprint
23ada94d67f67ef024c889a29d125b7af99356f4f45a62f06edce32d8cb08cbd and same-code
fingerprint dee8037d0404750a1d7c96abef65250b9cd42eb827d8981c0885e27fa0b3724a.
Base2.1.13 DMG631be2d775ea4abf75c8f1d8d1e9fc3b8411540ebacad6ebf2256ce4ae654b46
and target2.1.14 DMGd90d2cd96d4d7a1cb424cf2dc1e9665372c60818cb8604b2d7add255e643eba7
passed independent hash and strict signature verification. CP113 submitted one
operation7a3ab594-00e5-4b4d-849d-bd5a35465190/job8ff62b6a-adbd-4d46-866e-eff279603bd8,
which reached protected SUCCEEDED/OK sequence4. The observer captured automatic
GUI17540 and internal owner17543 before any post-terminal public query. Its first
status read failed and discarded command output; a later read succeeded under
new epoch ed34bea8-7f35-4f65-b44a-2c4fd595e844, runtime OFF. An endpoint-readiness
race is an inference, not recovered stderr. Same-job final identity, visibility,
and recovery now passed: public updates status reports the exact origin request,
operation and job with installed:true and cleanupCode:OK. Root verified16 manifest
entries, including the target tree/version/signature, automatic process captures,
guarded GUI visibility acknowledgment and empty post-cleanup process captures.
Only the new owner and verified server were stopped. Evidence and limits are
checkpoint113/macos-return113/root-review.json. This closes current user-local
replacement/automatic-return/recovery, not machine rollback or interruption.

Windows native image admission is now root-reviewed: old managed component
rejected the image owner/ACL; the corrected component returned exit0 and its
success marker. Both ran as parity95/SID1002 with elevated:false. The apphost hash
is identical between .NET component variants; their managed DLL hashes differ.
This is not NativeAOT or MSI replacement evidence. Receipts/hashes are under
checkpoint113/windows-admission-root-review.json and windows-code-hashes.json.
The actual Windows empty-output receipt regression also passed (QGA child4752,
exit0), including its old-expression rejection and four direct child exit cases.

Android API35 now has an exclusively owned remote x86_64 AVD:
vpn-control-parity113-api35/emulator5682, PID1622752/start6569944,2GiB/2CPU,
private root /home/kardinal/.vpn-control-parity113. The frozen nondebuggable target
APK is installed; direct UID2000 provider status/capabilities passed with runtime
stopped. Those reads did not exercise the packaged desktop CLI. Evidence was
exported to checkpoint113/android-guest113. A fresh worker owns the default CLI
and stream/document tests. The same-source nondebuggable base2.1.13/code16660 APK
also built and passed ABI/signer/manifest inspection; its SHA256 is
75e46211534d6de219e53916483b7f35949d1d28a05da274ca0b3de5cc367bbe. The exact API29
Google APIs x86_64 system image download is separately running under PID1666739;
do not create or start another emulator until resource admission and ownership.

Remote relay refusal was caused by an expired read-only QGA collector that
remained alive after its local wrapper timed out. Root verified and stopped only
that collector; queued connections drained. The new bounded, synchronized
read-only QGA helper and causal tests are the next dirty batch. An independent
native read/open/close passed with exact receipt hash. Existing unknown installer
jobs, parked Fedora memory and old macOS owner881 remain preserved.

The latest native GUI-return diagnosis separates successful replacement from
failed return. With the jpackage marker absent, direct launch from SSH still
fails graphical-session admission; Launch Services starts the same installed
bundle and its authenticated controller in a separate workspace. The native
worker now uses Launch Services for GUI return and the captured launcher for
headless serve. Three portable C regressions pass, the actual ARM64 worker
compiles, and both assigned Darwin component tests pass on the final revision.
Fresh packaged replacement/return remains open; no component result certifies it.

Windows original-user image-admission RED and GREEN probes have both reached
terminal expected outcomes under the ordinary-user token. Root is reviewing
the exported native output and identities before accepting this component gate;
full MSI replacement and recovery remain open. Neither probe ran an MSI.

Fedora2316 was safely memory-saved and parked after QMP completion and exact
process/media checks, preserving the unknown CP79 installation and controller.
The 4,051,683,404-byte memory image is retained under memory-park112 in its owned
remote root. Available remote RAM is approximately12GiB: sufficient for the
planned Android allocation, below the14GiB Linux admission threshold. Do not
restore the saved guest or replay its pending install without a resource review.

Android remote preparation found only an API35 x86_64 image and no suitable
nondebuggable x86 build route. A bounded worker owns app/build.gradle.kts and
scripts/test_android_native_fixture_build_type.py to add an explicit test-only route,
preserving production release ABI and signer behavior. No Gradle or emulator
operation is assigned to that worker. API29 still needs its system image; existing
unknown/protected AVDs remain untouched.

The corrected nativeFixture build now passes (checkpoint112/
android-native-fixture-build2.log). Root independently verified the frozen target
APK as x86_64-only, nondebuggable, package com.kardinal.vpncontrol, version2.1.14/
code16680, with signer a43b5330501b02f5558fa381c52e7f7dcdd9db362d6807d449d7bbb5e207c5a0.
APK SHA256 is1af2a6c40afe47bca10d40344f9a33ab7f71b774f710a41c4fdf8780502d00ca;
tracked runtime bytes match the merged input, and the AGP-stripped output matches
the APK runtime entry. Evidence is checkpoint112/android-x86-target. This is
built-artifact evidence only. android_guest113 owns preparation of a new remote
API35 AVD with a10GiB free-memory gate and maximum2GiB/2CPU allocation; protected
and unknown AVDs remain excluded.

Checkpoint `027fcc6a2378a8dabb7f1030c1a47cc804498ecf` (product2.1.14)
was committed and pushed after the complete managed pre-push tier passed.
Windows CI35560957259 failed because the new real Unix-socket fixture test used
its Windows temporary path as an Arch QGA endpoint. The correction keeps payload,
hash and quoting checks portable and limits the real Unix transport roundtrip to
Unix hosts. Correction40307db4121bae3bd307126324615af8d55194ec is pushed after
the complete managed pre-push tier passed. All five required exact-SHA workflows
passed; managed watcher81052 completed successfully. Its receipt is
checkpoint109/commit-result.json. Advisory core VPN Integration also passed.
Prior282c937 passed all five required workflows.
The delivered batch includes Windows image admission/pin lifetime fixes, durable
macOS rollback observation, strict Android installer acceptance, private fixture
staging, prompt/serial/manifest regressions and their routine wiring.
Full parity remains incomplete.

| Task ID | Agent | Owned files/subsystem | Shared files reserved | Artifact / environment | Current check / next handoff |
| --- | --- | --- | --- | --- | --- |
| Delivery114 | root | Shared integration, metadata, evidence review | Host Gradle, commits and push | 9e57f01 all required CI passed | Review and deliver bounded-observer regression batch |
| Android CLI113 | android_cli113 | Ignored CLI transport evidence | No tracked edits or other AVDs | Exclusive owned remote emulator5682 | Default packaged CLI streams/documents; provider-only result already passed |
| Android image113 | passive observer1680016 | Existing SDK download1666739 | No AVD start | Remote exact API29 x86_64 image | Retain same download handle and terminal package metadata |
| Mac machine114 | mac_machine114 | New private machine rollback fixture | No existing app/job changes | Exclusive owned Tart VM | Prepare exact /Applications fixture; root review before one install |
| Mac readiness114 | mac_readiness114 | macos_fixture_processes.py and test | No VM or shared docs edits | Deterministic readiness fixture | Preserve attempted read output and wait for endpoint readiness |
| Windows build114 | windows_build114 | Read-only native build inventory | No installer/runtime commands | Exclusive CP95 QGA | Exact JDK/SDK/NativeAOT prerequisites and same-source MSI build plan |
| Linux gate114 | linux_gate114 | Read-only failure/recovery coverage audit | No VM/build/edit | Current tests and historical receipts | Distinguish pre-install rejection from transaction failure/recovery |
| Delivery111 | root | Shared integration, docs, metadata, delivery | Host Gradle and shared product files | Pushed40307db, all five CI passed | Next observer regression batch and native evidence review |
| Windows image103 | windows_image103 | Coordinator helper image admission, original-user image-pin lifetime and focused tests | No shared Kotlin edits or VM mutation | CP102 read-only evidence | Reviewed fix and RED/GREEN source bundle frozen; native execution pending |
| macOS native105 | mac_native105 | Private native preparation/evidence | No tracked source edits | Exclusive owned Tart guest | User-local rollback/recovery passed; root verified21 hashes; fixture cleaned |
| Windows native112 | windows_native112 | Read-only RED/GREEN evidence export | No product/MSI commands | CP95 guest; probes terminal | Both expected results reached; verify underlying receipts and hashes |
| macOS return108 | completed | Private GUI-return observer/evidence | No tracked edits | Owned Tart guest now available | Replacement succeeded; causal Launch Services comparison and two component tests passed; fresh package next |
| macOS observer111 | root | Process observer, completion runner and tests | Root owns hygiene/docs | Local synthetic fixtures only | Five role, seven runner and eleven rollback tests pass |
| Linux baseline110 | completed | Private native public-launcher evidence | No old-owner changes | Existing owned Fedora2316 | Baseline passed on historical2.1.12; own new controller quit publicly |
| Linux capacity112 | linux_capacity_plan112 | Read-only parking evidence export | No restore or VM mutation | Fedora2316 saved and parked | Preserve unknown CP79 memory/disk; root receipt review |
| macOS fix112 | root | Native relaunch environment primitive and regression | Host builds/docs/delivery | Native108 failure; portable native RED/GREEN | Actual worker compiles; fresh package return still required |
| Manifest104 | manifest_regression104 | Fixture manifest writer and tests | Root owns docs/hygiene | Private temporary fixtures | Manifest/path-safety review and focused checks pass |
| Certificate scope102 | certificate_scope102 | android_fixture_trust.py and its routine tests | Root owns docs/hygiene | Private temporary OpenSSL fixtures | Causal serial-path regression and helper integration |
| Android fixture113 | android_remote_plan113 | app/build.gradle.kts and fixture regression | No Gradle, hygiene, metadata or AVD changes | Remote API35 x86 route; local5596 stopped | Add explicit nondebuggable fixture; root builds after review |
| Windows receipt113 | windows_empty_output113 | windows_native_fixture.py and its tests | No VM, docs, metadata or other source edits | Local deterministic fixtures | Empty-output causal regression and reusable receipt reader |
| macOS package113 | mac_package_plan113 | Read-only package recipe | Root owns Gradle and package execution | Fresh immutable ARM64 pair planned | Exact version/runtime/signing inputs and fingerprint recipe |
| Linux pending | root | Resource allocation and acceptance scheduling | No old guest restore | Remote Arch; Fedora2326 parked | Current packages ready; remote capacity insufficient for another admitted guest |

Checkpoint111 read-only document audit found existing deterministic coverage for
transfer binding/expiry/integrity, failed spool persistence, retained results and
no-overwrite export publication. It found no new source defect. Remaining proof
is the current nondebuggable default Android document path on both APIs, Android
GUI picker/private export, and current installed desktop export paths. Existing
unit/process evidence does not replace these native gates.

CP95 reboot invalidated historical process identities: old PID2968 is now a
Windows service, and old controller6612 is absent. Unknown install records remain
preserved. A single S4U task registration failed with access denied before task
creation despite confirmed SYSTEM authority; no probe ran. One protected
LogonUserW check subsequently succeeded, closed its token and removed its exact
credential temp. The retained credential is valid; the UI password-entry failure
does not prove a stale password. Ordinary-user probe launch is being prepared for
review, without product/MSI commands or persistent policy changes.

Fedora2316 cp79 owner16278 (start ticks652956) remains a disconnected persistent
controller with no runtime child. Its job6bc79509-a517-40b4-89be-ae3f945a47e9 has
no protected receipt and remains unknown; do not replay or stop it. A distinct
workspace can exercise disconnected/public proxy-only behavior without touching
the pending installation. Package provenance must be recorded before attributing
that guest's evidence to current source.

Native108 attempt2 uses the exact tracked canonical bundle identity and process
observer. Its single accepted install operation7fbfc860-4192-4431-ba94-9590cc8f6e42
reached protected job17a28d33-8097-49cd-b25b-51cb167d9424 SUCCEEDED/OK sequence4.
This establishes replacement, not automatic GUI return: the observer had not
seen a returned owner/frontend and terminated after240 seconds with exit1. No
public command bootstrapped that return. Target version2.1.13, codesign and exact
canonical target digest passed read-only verification; installed inode957596 is
distinct from original939688. Preserve the receipt and distinguish successful
installation from failed automatic return. The native worker now clears the
inherited jpackage marker before exec, with a causal portable C regression and
successful root ARM64 compilation; current-package return must be rerun.

Checkpoint106 contained an owned Windows fixture staging failure before any guest
fixture execution. The staging script ran remotely through `python3 -`, interpreted
`__file__` as the remote working directory, and recursively buffered unrelated
remote files while holding QGA. Its exact identified Python process reached about
5GiB RSS. After PID/start-time/socket verification, only that client was terminated;
QGA accepts connections again. No installer, VM, runtime or guest test was stopped.
The bounded local-payload regression and corrected standalone receiver now pass;
do not reuse that old staging script. Native Windows RED/GREEN execution is
assigned to windows_probe107 and remains pending.

The checkpoint106 Android audit found that the installer lifecycle harness records
status/wait without asserting successful target installation. The corrected driver
requires explicit expected outcome, exact correlation, and target version/code/hash
for success; its17-test suite passes. Existing capture-only or cancelled runs cannot
certify installed-package acceptance. No emulator was started by this audit.

Checkpoint105 closes user-local macOS rollback and next-owner failure recovery
for the frozen3ba018f base2.1.12/target2.1.13 DMG pair. Root verified21 guest
evidence hashes and exact controller/request/operation/job correlation. The
worker published FAILED/PERSISTENCE_FAILED sequence4 after the deliberately
immutable candidate prevented replacement; the exact original base inode/tree
and signature were restored. A new controller recovered final failure with
cleanupCode:OK and installed:null. Observed runtime remained OFF. The driver
finished in7 seconds; its owner quit publicly and only its verified server was
stopped. Prior owner881/watcher12320 and their unknown jobs remain preserved.
Evidence: checkpoint105/macos/root-review.json. Machine rollback, interrupted
recovery, automatic GUI return and final-source attestation remain separate.

CP102 Windows read-only evidence confirms the worker-ready helper hash matches
its original-user-owned installed image. Coordinator image inspection still uses
machine-only ownership checks for that image; this is a causal hypothesis for the
post-bootstrap failure, pending regression and native execution proof. Protected
receipt ACLs must remain strict.

The fresh macOS rollback job3bf3b125-8411-42c8-8a1b-ee7ea0d8b232 reached
WAITING_FOR_EXIT with owner12216 live. A public quit returned BUSY; no owner was
killed. The temporary candidate immutable flag and fixture lock were removed.
The fixture omitted a post-readiness public status acknowledgement; raw receipt
reads cannot release DesktopOwnerExitGate. Same-job continuation through exact
public operation status is assigned, retaining the staged-candidate rollback
fault and original owner identity. No product exit defect is established.
Preserve older owner881. The exact public acknowledgement subsequently returned handoffReady:true and
the owner exited. The protected receipt remained WAITING_FOR_EXIT during the
observation window. An additional fixture lock was identified and released.
PID12320 is the watcher role; the actual coordinator is absent and no exact
launcher/gate lock holder remains. The receipt is stale/nonterminal; exit cause
is unproven. Only our staged-candidate immutable flag was removed after
identity/signature verification. No same-job replay or rollback success is claimed. Native public
rollback is not yet proven.

CP101 macOS now proves sampled traffic across a fresh scheduled operation on the
frozen3ba018f target DMG:252/252 successful probes, maximum observed gap1.2206s,
one fresh application HTTPS request, exact operation wait, same controller/runtime.
The operation ended RUNTIME_FAILED after Find Best target validation; successful
Find Best remains unproved. Root verified all301 manifest entries. Public off/quit
returned OK; only protected owner881 remains. Evidence:
checkpoint101/macos/cp101-collected and root-manifest-review.json.

CP100 Windows is authoritatively CANCELLED. Its credential sequence followed the
not-started marker and cannot prove approval. CP102 prepared helpers in advance,
rejected a changed screenshot without input, then admitted one guarded input
8.664seconds after fresh review. Public recovery now retains unknown job
b066a7a6-8016-492d-9e09-476d7288d027, operation
b5342e30-6290-4408-a68a-82b4fd00dccb, request
da4446e4-8b4b-419b-9a91-e107df048cf4, controller
8e027d3b-019e-448f-ba03-ede600624db9. Handoff is unacknowledged and installed
remains null. Do not replay, cancel, quit or stop this owner/VM without new
terminal evidence. Base version2.1.13 remains observed. Raw evidence:
checkpoint102/windows/recovery-result.json and prompt captures.

Read-only Android inventory identifies AVD5594 as API35 with VPN Control2.3.2
installed but no app process. A system Legacy VPN has unproven ownership;
preserve the emulator. Ordinary pending installer sessions remain uncertain.
Remote Arch checkpoint106 reports10442MiB available after staging-client
containment, just202MiB above the Android threshold. Recheck immediately before
any start; Linux remains3894MiB below its14336MiB threshold.
Multiple existing QEMUs are present; preserve them pending ownership/lifecycle
verification, rather than assuming CP95 is the sole running guest. API29 image is absent there;
existing API35 environments lack established ownership. Evidence:
checkpoint101/android-capacity and remote-android-admission.md.

The current-source macOS base2.1.12/target2.1.13 pair is built under
/private/tmp/vpn-macos-3ba018f-pair. Both package hashes and common code fingerprint
were independently verified. Source fingerprint:
2c94f668537f0d73e7858716dea54197f119be1fb3fd2ce0ad6ab29e5f415ab2.
Evidence: checkpoint98/macos-pair-receipt.json and macos-pair-root-verification.json.
This is package-build evidence, not native installation or traffic acceptance.

Current source audit confirms Android watch/follow dispatch precedes the legacy
adapter flag rejection. Shared streams pin owner identity, retain cursors/gaps and
per-read timeouts. DesktopCliOutputHealth checks idle output pipes each poll;
DesktopCliStreamPipeTest exercises real child-reader closure for JSON and human
output. Historical CP25 idle-follow failure is superseded by this implementation.
Current nondebuggable API29/API35 default-document transport stream execution is
still required; legacy-provider records do not close that gate.

Linux corrupt-package rejection already has deterministic coverage in
DesktopLinuxUpdateServiceTest.changedVerifiedPackageNeverReachesNativeAdapter
(the fixture selects RPM), with exact protected receipt correlation separately
covered by DesktopLinuxInstallCorrelationTest. Current native RPM preservation
and recovery remain open; no duplicate test or native success is inferred.

## Checkpoints95–98 evidence

The Windows same-source base2.1.13 and target2.1.14 MSIs built successfully and
were exported with verified hashes (checkpoint94/msi-export-result.json).
The fresh Windows standard user parity95 now has verified per-user Python3.13.15
AMD64 with a non-elevated token (checkpoint95/windows-fresh/python-verification-result.json).
The installer succeeded; a separate inline PowerShell/Python verification quoting
error was resolved using a script file without rerunning installation.
The source-to-bdaa57 delta contains Android tests/fixtures and documentation only;
this does not itself prove a native installation outcome. Earlier unknown Windows
and Linux jobs remain preserved and must not be replayed.

Android CP89 was restored using its exact compiled-parser identity, and CP94 B
was removed by stable ID (checkpoint94/android/restoration-summary.json).
CP96 cleanup leaves only CP89, runtime off, revision18. The small-frame fixture
uses the supported legacy public provider, not the default desktop CLI document
transport; its evidence must retain that distinction. The document wrapper's
roughly ten-second overhead came from eight separate guest `content` processes;
a persistent shell did not remove that cost.

macOS CP94 continuous GUI lifecycle passed32/32 traffic requests. CP95c passed
335/335 requests and scheduled refresh fired twice, but refresh TLS failed because
the fixed-response SOCKS fixture answered TLS with plaintext HTTP. This is a
fixture defect, not proof of a scheduler or product TLS defect. The new exact
loopback forwarding mode has causal EOF, cleanup and backpressure regressions;
CP96 then captured an application HTTPS GET and SUBSCRIPTION_REFRESHED after
AUTO_REFRESHING_SUBSCRIPTION, retaining the same controller and active runtime.
Its subsequent Find Best failed target validation and restored the previous
connection; this does not prove successful scheduled Find Best. The sampler has
seven early fixture-port failures among326 requests, so it is not an all-pass run.
The corrected interval from00:44:40Z has319/319 successful requests. Root verified
the corrected manifest; the original self-including manifest is preserved as invalid.
Audit confirms automatic refresh bypasses DesktopOperationRunner; its missing
operation identity/history is a product gap under CLI-003/005. The implementation now tracks scheduled refresh, retains committed source outcomes
after post-refresh failures, and preserves unknown outcomes for recovery. Seventy
focused tests pass with no skips. Native TLS success predates this change and does
not close the rebuilt operation-visibility scenario.

CP96 Android cleanup is confirmed by its original receipt listing all11 transfers.
A later discard correctly returned NOT_FOUND. One fresh UID2000 create/discard
probe returned the expected empty bundle and both commands exited0; no parser
fix is warranted (checkpoint96/android-cancel/21-cleanup-probe-*).

## Checkpoint94 evidence (historical)

Latest pushed checkpoint is `c880e05275184ed242b611684ab8eacf3a62d97b`
(product2.1.13). All five required exact-SHA workflows passed; receipt:
checkpoint93/commit-result.json. Full parity remains incomplete.

| Task ID | Agent | Owned files/subsystem | Shared files reserved | Dependencies / environment | Current check / next handoff |
| --- | --- | --- | --- | --- | --- |
| Windows package94 | root; windows_build63 retired | Ignored same-source Windows fixture/build scripts | Root owns integration and delivery | Root exclusively operates existing Windows AMD64 VM | Verified source archive bd218828 fingerprint; ordinary-user build wrapper4160 and Python1240 observed live; no MSI replacement yet |
| Android stall94 | root; android_fixture54 retired | Benchmark relay and Python tests | Root owns docs and delivery | No native operation by this worker | Causal RED captured; corrected relay six-test GREEN; native cancellation rerun remains |
| Android selector94 | android_dispatch59 | Location presentation/control tests and smoke-android guidance | Root owns product code and delivery | No AVD operations | Focused list/delete and stable-ID tests pass; numeric cleanup was fixture misuse |
| Android recovery94 | root; fixture_review92 read-only recovery | Ignored restoration evidence | Root alone authorizes emulator mutations | Owned5596 stopped; prior CP89 fixture mistakenly deleted, CP94 B remains | Recover exact original raw record/identity before restoration; native worker retired |
| macOS traffic94 | mac_resume73 | Ignored native evidence | Root owns integration | Exclusive Tart vpn-control-boot-control53 | Same controller/runtime and five traffic probes through attach/hide/show/close passed; continuous32/32 traffic checks and identified frontend termination passed; native visible-property query gap retained |
| Linux evidence94 | root; linux_rollback66 retired | Ignored recovered raw receipts | Root owns integration | No VM mutations | Nineteen raw files hash-verified; terminal failed receipt retained; full restored-tree proof still absent |

Windows archive SHA256
`1df24d3574e853939162aac6337b50872c057674bbf387e1c3a9d451936a0c58`
was verified after remote and guest transfer. The ordinary-user build preflight
passed Python/JDK/.NET probes; fresh base2.1.13/target2.1.14 use source fingerprint
`bd218828827b1662debe41f7a6e2026bc57fb9a272ea5cf1664cc0f8d5bff82e`.
No original unknown installation was replayed. QEMU memory parking has only been
reviewed, not executed; no additional VM or freed RAM is claimed.

Android Find Best committed through the tracked default-target relay, with four
actual chatgpt.com CONNECTs. The cancellation fixture ended prematurely and is
fixed under its own causal regression. Cleanup then misused stale numeric indices
after sorting; the prior task fixture must be restored before further native work.
See checkpoint94/android/receipt.md and parity-failure-regressions.md.

Checkpoint91 proves the original-user bootstrap with the same NativeAOT image
SHA256 `05510b3c22df1fdd6301dba4f7af9918dce82ff2cfa004ae3dfa3682e459e20a`
(case-insensitive hex): ordinary and same-user elevated runs return0 with exact
non-elevated child identity and bounded pre-admission cleanup. See
checkpoint91/windows/ordinary-result.json and elevated-progress2.json. This
protected ProgramData test image does not prove the actual per-user installation
path, a different approving administrator, or MSI replacement. Checkpoint92's
read-only image-acl.json confirms the real helper is original-user-owned under
AppData; its old native self-pin used machine-only trust. The same old image then fails from an isolated original-user-owned AppData directory
with exit91 / Installer mutation rights rejected (checkpoint92/windows/peruser-result.json).
This reproduces the self-pin incompatibility without an installer role; the
production fix and routine causal regression are recorded below. The original unknown
job is preserved.

Checkpoint93 adds a routine noninteractive apphost/private-user-directory test
before the interactive Windows test gate. Its actual NativeAOT fixture first fails
with the same mutation-rights rejection (red-result.json, image93f8aba9). The fix
threads only the captured original interactive token SID through the retained
image/ancestor checks and child image reinspection; the coordinator already binds
that SID to the authenticated owner. Machine receipt trust is unchanged. Matching
principal/image admission and rejection of an unrelated principal now pass in the
same user-owned layout (green-result.json, image6a87706e). Focused host checks run
17 tests successfully with7 Windows-only skips; independent review found no
blocking concern. Full MSI replacement and post-fix elevated bootstrap remain
native acceptance gates, not implied by this image-pin component result.

The initial checkpoint91 fixture build omitted loader.manifest and failed CS1926.
The replacement frozen fixture uses an inventory derived from the actual helper
project; build and native bootstrap pass. The reusable inventory and four quick
regressions were pushed in cad9aeb. They support native probe staging, not a change
to production package-building behavior.

Linux checkpoint91 adds a PTY response guard that requires both the exact prompt
and disabled echo after the terminal input flush. Its quick regression passes;
the actual packaged Java no-op authorization passes with the guard, child/owner
exit0, and no retained probe processes. See
checkpoint91/linux-analysis/java-auth-ready-receipt.json. This prevents a fixture
race but does not establish it as the historical checkpoint85 installer cause.
The helper is for interactive native fixture drivers; the tracked noninteractive
public-install harness does not automatically enter credentials.

Linux current pair source fingerprint
`cf5e2b517284a76c7da7e430dc6f4b83998b3d1bfac635e95ee7e7d65219d738`
comes from ee80dcf. Both RPMs and their immutable server archive were verified
before copying to the fresh guest. See checkpoint85/linux-rpm-export.json and
linux-transfer.json. The running failure fixture is
`/home/vpnfixture/cp85-rpm-failure`; its durable driver PID4658 has exited. The original public attempt returned
OUTCOME_UNKNOWN/exit2, handoffReady=false, job
`bacae2d1-5029-4e39-a69a-6cba7407c64c`, operation
`55fe0251-14e5-434f-8616-ef8a61ad86f9`. Owner4661 remains alive; no privileged
worker or package-manager process remains, and no protected job receipt exists.
Polkit records failed authentication. The private fixture credential matches the
ordinary guest account and the account is not locked. Isolated fixed /usr/bin/true
authorization passes both directly and with the same separate owner/tty-agent
arrangement, including --disable-internal-agent. PAM reported a conversation
failure on the original attempt; the installer-specific cause remains unproven. Preserve the unknown journal/inputs and do not replay this job.

Checkpoint89 also calls the actual installed Java terminal-agent launcher against
the same separate-owner fixed /usr/bin/true authorization probe. Registration,
password exchange and child exit0 pass; only that probe's terminal-agent lease is
closed after the no-op owner completes. This excludes a general failure of the
packaged Java launcher, but does not resolve the original installer exchange.
Evidence: checkpoint89/linux-analysis/java-result.json and retained guest
/home/vpnfixture/cp89-java-auth. No installer operation was repeated.

Windows checkpoint85 failed before compilation because PowerShell5.1 promoted
native stderr under `ErrorActionPreference=Stop` with merged redirection.
The ordinary-user checkpoint87 reproduction independently confirms the warning
becomes a terminating record and leaves a zero-byte capture. Existing unknown
MSI jobs remain untouched. This is a fixture failure, not evidence of a product
helper defect. The exact quick regression passed in the ordinary-user AMD64 guest after root
corrected capture and direct-child waiting. Checkpoint88 NativeAOT helper
validation, owner admission and package preflight all pass with exit0. The
original unknown MSI job is unchanged; successful MSI replacement remains open.
See the failure ledger for exact RED/GREEN evidence and superseded candidates.

Checkpoint89's read-only NativeAOT probe admits the original pending Windows job
2946b6ab-1e10-4edd-b045-8f23cc2395bc, owner8352 and its actual MSI. It returns0
after package preflight; the request digest is unchanged. A separate synthetic
job also publishes worker-ready successfully using unchanged production sources,
then exits0 and removes its own synthetic inputs. Neither probe runs installer
roles or MSI replacement. Evidence: checkpoint89/windows/result-transport.json,
ready-progress.json and worker-ready-inputs.json. Elevated coordinator/original-user
bootstrap and real replacement remain open.

Android5596 now proves one real nondebuggable ARM64 benchmark measurement with
code73 APK hash74af8c726d625964ba35a5691d2aaa53e88a0377fefe259f76b8dd55fc820330.
The initial source rejection was correct for the empty subscription selection.
After selecting current-locations, the initial benchmark failed because the old
retained relay only allowed github.com while validation defaulted to chatgpt.com.
Public guarded settings.set temporarily aligned the URL with the relay; operation
e2f98183-6313-471e-92d8-6cc4ded3fda1 completed OK with secondaryTotalMs1091.471209
and confirmed github.com:443 relay traffic. The original URL was restored and the
owned reverse/relay removed. AVC messages did not establish the failure cause;
no native ARM64 crash occurred. This does not prove the default target or VPN path.
Evidence: checkpoint89/android/discriminator-evidence.sha256 and diagnosis.md.
Checkpoint90 adds prevention coverage to the existing routine benchmark fixture
suite. The tracked relay already permits the product default; the obsolete
ignored relay caused the failure. The regression derives the real default URL,
uses no external network, and retains denial of unlisted targets. The extracted
historical policy fails;5 current tests pass. See the failure ledger.

Root booted the existing owned ARM64 AVD on5594, discovered version2.3.2, and
preserved its data without installing an older APK. The separate new5596 AVD is
the code73 benchmark comparator. Host memory admission was69% free before these
2GiB starts; the existing4GiB Tart guest and unrelated environments are preserved.

## Resumed Native Batch — 2026-09-20

Checkpoint77 was pushed as `c8f30e02f54687d662f26e592ff862038211f310` after
full prepush passed. macOS CI35529722794 exposed an outdated embedded test call;
its correction preserves terminal-receipt cleanup and adds ordinary local
compile-only coverage. The corrected full seven-test fault suite passes inside the
owned Mac VM (checkpoint79/macos-ci). The repair was pushed as
`be009403669c0a1203c2f767b7ddf3d677a4bbfb`; all five required exact-SHA workflows passed
(checkpoint79/macos-ci/commit-result.json).
The current immutable Mac pair `/private/tmp/vpn-macos-code79` built successfully
from c8f30e0; subsequent repair changes only the test harness and documentation.


An earlier fully CI-verified checkpoint is
`94dbd582e0268fb31f4522b3136520efb8c7594c` (product2.1.12).
All five required workflows succeeded for that exact SHA;
checkpoint74/commit-alias-result.json contains the managed receipt.
The earlier e2e88ad freeze remains the source of the Windows/Linux/Android fixture
packages below. Native completion is still open.

Checkpoint74 delivered a focused integration batch:
desktop cancellation returns promptly when a recovered unknown installer cannot
be cancelled, and a reusable Android installer driver forwards file-based
continuation into its action. The desktop causal RED is a virtual-time timeout;
31 focused desktop tests pass after the fix. The Android driver has original-code
RED evidence and passing quick tests, wired into release hygiene. Windows CI then
exposed two fixture portability causes: executable suffix and path spelling.
Both now have quick regressions; the final selections passed33 preflight and11
driver tests, and final Windows CI passed. See the failure ledger for exact paths.

The current macOS pair at `/private/tmp/vpn-macos-code75` uses3055e97; subsequent
94dbd58 edits affect only Android fixture tooling/tests and documentation. Root
verified its exact DMG hashes, and the guest verified the installed base signature.
After positively checking runtime OFF, root exercised owner loss and reopened the
original workspace with the new installed package. Public cancellation returned
OUTCOME_UNKNOWN/exit2 in0.17 seconds while preserving the exact original unknown
install job. See checkpoint74/macos/current-package-cancel-root-review.json.
This closes the cancellation-hang revalidation. Root also reviewed current-package
machine authorization denial and successful replacement to2.1.14 in a separate
fixture: jobb7c7c0c1-8855-42e6-b08c-ac25b206715c, operation
e26dd649-3ac1-42b6-a8d9-295c641b600e. The root-owned protected receipt is sequence4
SUCCEEDED/OK; the replacement owner recovered the exact original request and
reports installed=true, cleanupCode=OK. Downloaded target hash matches the frozen
DMG and the installed target passes strict deep signature verification. See
checkpoint76/macos-auth76/root-review.json. This ad-hoc signed fixture does not
prove notarization, rollback, GUI return or traffic continuity.

The separate denied job440b86ce-8db3-4e62-867a-3082f23a2851 is authoritatively
CANCELLED/not-started but retains approximately141MB of inputs. Production cleanup
now binds its not-started disposer, stages the current packaged helper for legacy
inputs, rechecks protected authority and safely retries exact0600 helper promotion.
Naming, repeated-owner idempotence and interrupted chmod have causal regressions.
Independent focused review found no blocking defect; integrated-focused-green
records60 tests,0 failures and1 platform-specific skip. The final expanded union
passes64 tests with0 failures and1 Windows-only ACL skip on macOS;
checkpoint77/final-union-green preserves every XML. Installed current-package cleanup now passes in checkpoint81/macos: the exact
140947456-byte denied input was removed, terminal CANCELLED/installed=false and
disposition digest remained unchanged, and a fresh owner repeated cleanup with OK.
The unrelated unknown owner remained alive and OFF. Root verified the exported
raw-evidence hashes; GUI return/rollback remain separate gates.

Installed macOS checks confirm static commands create no workspace, missing-owner
status exits2, query-created owners are disconnected/transient, and explicit serve
stays alive while disconnected. Duplicate serve incorrectly supervised an existing
owner. The corrected implementation preserves authenticated promotion of a transient
owner but immediately returns with an existing-owner message. Its causal regression
records an unwanted second polling request before repair; real process coverage
checks both transient and persistent cases. Installed DMG proof now passes in
checkpoint81/macos: duplicate persistent serve returns0 immediately; settings-show
creates a transient owner, serve promotes the same epoch, and after35 seconds
without polling the same owner remains alive and OFF. Root verified8 evidence
hashes; new owners were publicly quit and original unknown owner preserved.

Installed RPM traffic survived GUI attach, close/reopen and crash with the same
runtime identity; off succeeded but quit returned CONFLICT for the dead frontend.
The fix pins authenticated process identity at attach and releases only a proven
dead generation. Unknown/live/replacement identities remain guarded. A portable
stdin-gated JVM child exercises the actual owner quit path. See checkpoint77/linux
for causal RED and native evidence; package revalidation remains pending.

Android checkpoint78 replaces the earlier synthetic HTTP fixture with real SOCKS
byte forwarding. Foreground-service traffic succeeds, but benchmark subprocesses
SIGSEGV under ARM64 translation before SOCKS negotiation. Find Best fails without
changing activeA/pendingB; no real timings or in-flight cancellation are claimed.
Public off/delete cleanup succeeded. Compare the same source on native ARM64 before
attributing this to the product; no runtime upgrade or implementation fix was made.

Windows cp78 reached update checking but its retained fixture certificate expired
September9. Root verified public certificate dates, renewed only disposable inputs,
then confirmed ordinary-user public check/download/READY for target2.1.13 in cp80
(controller7a39aed3-e5df-44f1-94fd-36c22408ad9d, downloaded130986356 bytes).
An installation command was launched once before the remote SSH route became
unreachable. The gateway recovered and the Arch key was unlocked through its normal
prompt, creating task-owned socket vpn-control-arch81.sock. The original install
operation/prompt/outcome is being inspected; it must never be replayed on uncertainty.
The old cp78 owner was verified OFF and quit through public control. Certificate
admission now has a quick causal regression; no global trust settings changed.

Linux checkpoint79's corrupt-package scenario did not produce RPM failure proof.
The ignored driver matched `password` in Java's `trustStorePassword` diagnostic
and wrote the credential before the actual polkit prompt. Timeout and PTY loss
are not established causes. Checkpoint82 adds a strict ANSI-aware current-line
`Password:` matcher and routine harness regression; causal replay of the exact
old predicate fails and the17-test harness passes. Durable native authorization
and corrupt-RPM failure evidence remain open. Preserve UNKNOWN job
6bc79509-a517-40b4-89be-ae3f945a47e9 and its original workspace/records.

Windows checkpoint82 inspected the original cp80 attempt through the ordinary-user
public launcher: op09aa1b2b-94cc-4b64-a6ab-9908014d59c1 is CANCELLED/final,
exit130, installed=false. A subsequent explicit attempt reached visible UAC for
vpn-control-install-helper.exe. After normal UI approval, op
48e8e749-5380-447e-b13e-750676217edd / job
2946b6ab-1e10-4edd-b045-8f23cc2395bc reports OUTCOME_UNKNOWN/nonterminal,
handoffReady=false, installed=null; public version remains2.1.12. Preserve this
job and inspect its evidence; no automatic retry or successful replacement claim.
Raw ordinary-user responses and prompt captures are in checkpoint82/windows.

Checkpoint82 prompt admission was pushed as631d3fb462e01eafdd0ca8c9758282590e389236;
its exact-SHA CI is being observed. Precedingc19e9b5f37a8e8ba580758552bb22e530849c94e
has all five required workflows successful. Checkpoint83 extracts terminal handoff
admission into the routine Linux harness: a complete ACCEPTED/handoffReady response
plus exit0 survives a PTY EOF/reaping race. The old ignored driver guard fails the
extracted causal test;18 routine tests pass after repair. Evidence is explicitly
an extracted fixture regression, not a newly found product protocol defect.

Checkpoint82 Linux reached protected WAITING_FOR_EXIT but the preserved unknown
owner16278 retained a READ lock on the machine gate. It ended FAILED sequence3;
a replacement owner recovered exact jobb32f0d40-f03f-4af7-8219-808753e05ee8 /
op e0a17c7e-b47c-486e-944c-274e3343e883 with cleanupOK and intact base. This proves
blocked-replacement failure recovery, not corrupt-RPM execution.

For an uncontended RPM scenario, root prepared an independent pinned Fedora44
cloud image in /home/kardinal/vpn-control-install-vm-cp83-fedora-20260920 on Arch,
SSH2326,4GiB/2CPU. Resource admission observed13GiB available and zero PSI while
retaining8GiB minimum headroom. Existing guests/unknown jobs remain untouched.
Cloud-init completed with only a hostname warning; fresh baseRPM2.1.12 installation
and verification passed. Fresh fixture-only TLS was used without global trust edits.

Checkpoint83/native-manifest (checkpoint83/linux/native-manifest.json) records the
frozen package source fingerprint96541f180957219f0cb7fbb5a6bb88b7237fb3c5ef344a2fb16c31b2ec50c567.
The deliberately corrupted private target passed public download/hash verification
against its test manifest, reached authenticated handoff and protected FAILED seq4
(after INSTALLING). Next-owner recovery matched jobdfed9d7a-bf80-46cc-98f7-f574b0d50bfc /
op82935a95-43a6-418f-a869-c4428874064e, final RUNTIME_FAILED/cleanupOK/installed=null.
Independent rpm verification reports DIGESTS NOT OK; installed base2.1.12 remains
clean. Installer stderr was not retained. This closes this frozen RPM failure and
recovery scenario, not final-source packages, connected intent, GUI lifecycle or
successful retry. The EOF race occurred again, but the repaired harness retained
the complete acknowledged handoff instead of discarding it.

Windows source/component diagnosis remains open. Bounded worker staging did not
run a probe; root owns the next direct QGA file-write staging attempt. Existing
unknown job2946b6ab-1e10-4edd-b045-8f23cc2395bc remains untouched.

Checkpoint84: fc3e0018415b115edce2bd7346ebf1d71ed47b72 was pushed after full
prepush. Windows package CI35534449946 failed in two pure PowerShell fixture
probes with30-second timeouts; cause is under bounded investigation, so this
checkpoint is not fully verified. Checkpoint631d3fb has all five workflows green.

The explicit intact-RPM retry in Fedora2326 reused the terminal-failed workspace.
A fixture copy first failed read-only package admission before app launch; a new
private read-only copy then passed check/download. Public status overwrote READY
with the historical failure. No second installer was launched. Native outputs are
in checkpoint84/linux/native-retry-failure.json. A new quick regression failed
before the product change; DesktopUpdateService now publishes each distinct
terminal observation once per owner while retaining the complete correlation list.
Cleanup-only metadata changes do not revive old failures; new unknown/terminal jobs
remain visible. Focused recovery/cleanup/exit tests pass. Current-source native
retry is still required. The guest's retry owner remains OFF and must be inspected
before replacement; preserved unknown jobs in other guests remain untouched.

Root restored Windows QGA by stopping only two exact stale task nc transports
(479948/479968), leaving all guest processes unchanged. windows_probe84 prepared
an ignored original-user component bundle and then took exclusive ownership of
scripts/test_windows_native_fixture.py for the CI timeout investigation. The unchanged
Windows rerun passed hygiene; a speculative -File/-NonInteractive candidate is saved
only in ignored checkpoint84/windows and not accepted as a proven causal fix. Root owns
DesktopUpdateService and DesktopRecoveredUpdateStatusTest plus docs/builds/delivery.

Checkpoint84 Windows native AMD64 component checks passed on current frozen helper
sources: ordinary-user token scalars and same-user UAC original-user child launch.
SDK10.0.400 managed apphost, ordinary/elevated session1; exact input/output hashes
are in checkpoint84/windows/native-component-summary.json. This is not NativeAOT
package or MSI replacement evidence. The old unknown job remains unchanged.
Independent recovery review found a first-late-observation and publication race;
a second quick RED reproduces it, and the fix evaluates newer update state inside
the publication transform while always retaining unknown/live installation blocking.

| Task | Agent | Owned files/subsystem | Shared files reserved | Dependencies / environment | Current check / next handoff |
| --- | --- | --- | --- | --- | --- |
| Integration | root | Desktop lifecycle/cleanup fixes, evidence, docs, host builds and delivery | All shared files | One host Gradle invocation | Final focused union, prepush and checkpoint delivery |
| Windows MSI | root | Ignored native installer/evidence | No source edits | Owned Windows AMD64 guest6GiB on Arch | Public check/download READY; install accepted as09aa1b2b-94cc-4b64-a6ab-9908014d59c1; SSH restored, inspect original outcome |
| macOS | root; fixture_cert80 retired | Installed-package evidence reviewed | Root owns source | Owned Tart4GiB guest | Cleanup/repeated-owner, persistent duplicate and transient promotion pass; remaining GUI/traffic/rollback gates |
| Linux | root; linux_auth82 retired | Native evidence and harness fixes | Root owns source | Fedora2316 preserved; fresh Fedora2326 4GiB | Frozen RPM failure/recovery passes; current-package crash/quit, retry and attestation remain |
| Android | android_benchmark78 retired | Completed checkpoint78 evidence | No source edits | Remote2GiB API35 AVD5680 remains live | Native ARM64 comparison; remaining acceptance matrix |
| Review | serve_review79/mac_cleanup_review79 retired | Read-only bounded reviews complete | No edits | No VM ownership | Serve promotion retained; cleanup review has no blocking finding |

These are fresh bounded Terra/medium assignments. Earlier worker names below are
historical. The ignored checkpoint70 ownership record tracks current execution;
capacity measurements from September16 must not authorize new starts. Root restored
the normal Arch SSH hop on September20 using the authorized key passphrase, without
changing guest or installer state.

Root independently verified all22 exported Linux evidence hashes and the exact
protected-success/public-recovery tuple for job1984e6b7-b668-4ab4-95b4-a93af47f817e,
operation65da4189-d491-4343-956e-72e0a2347057. A distinct replacement owner recovered
the original request and installed2.1.13; see checkpoint70/Linux/root-review.json.
This proves the current DEB update/recovery, not transient startup or GUI traffic.

Linux worker74 reports current-source RPM success for job
5d3b32f1-fce3-438c-8701-5605dccc786d, operation
94bfa593-450f-4d5c-a9d3-26bfe79e4956, protected sequence4 SUCCEEDED/OK, and exact
replacement-owner recovery. A stale out-of-band fixture marker was preserved and
replaced with the exact frozen marker only after verifying installed base bytes.
Root verified42 exported text/state artifacts, the exact accepted/protected/recovered
tuple and seven CLI exits. The RPM binary remains remote with its manifest hash;
see checkpoint76/linux-rpm/root-review.json. GUI traffic and RPM failure/rollback
remain separate gates.

API35 public cancellation is confirmed for receipt
d8672b66-ca34-423f-9a02-58fa754db70f/session657342161. The separate observation124
failed with `Can't find service: packageinstaller`; it does **not** prove native
session disposal. Keep that check open. See
checkpoint70/android/cancellation-root-review.json. Independent cold-owner
confirmation redisplay and subsequent exact target installation are separately
reviewed in the existing checkpoint70 Android root-review records.

Windows code72 already contained complete successful nativeAMD64 builds after the
interruption. Root verified exported build records and independent guest MSI
hashes against the same-code pair receipt; checkpoint73/windows/root-review.json.
The later wrapper's existing-directory failure must not trigger another build.
Android target2.1.14 is at `/private/tmp/vpn-android-code73`; it reuses the exact
installed2.1.13 base bytes and compatible signer. Root verified both package
hashes and unchanged runtime bytes in checkpoint73/android/root-review.json.

macOS operation3d0f4c35-8184-431e-90c7-de57163f1402, job
33db51ee-dc08-4f6a-81c4-c37ae76a0a02 remains unknown after the VM stopped before a
confirmed cancellation. Earlier screenshot disappearance was not proof of Cancel:
the wallpaper gesture can hide the prompt. Root restarted the positively stopped
owned VM with detached logging and recovered the exact original tuple under a new
controller. The subsequent public `updates cancel` request exposed the bounded
response defect now covered by the new regression; no installer was replayed.

## Completed Code-First Integration Batch

The user requested completing all known implementation work before the next broad
native cycle. Finish source gaps in parallel, use cheap causal regressions while
coding, then freeze one coherent source/package set. Run complete platform scenario
batches against that freeze, collect independent failures, and fix them together.
Unknown accepted mutations remain preserved; discovery never authorizes replay or
unsafe overlapping installers. Existing native results retain their exact identities.

| Task | Owner | Exclusive source scope | Current check / next handoff |
| --- | --- | --- | --- |
| Android actions | android_code69 | Connection control; location service/ViewModel/UI callback binding and focused tests | Durable-selection response-loss fix passes15 tests; rendered benchmark target fix passes10 focused tests and Android compilation |
| Installer reconciliation | installer_code69 complete; root integration | DesktopInstallHandoff and tests | Prior worker diagnostics reset only on clean new admission;18 tests pass |
| Windows build paths | windows_execute68 complete; root review | Native Directory.Build.props and native helper tests | Canonical output paths; actual pinned-MSBuild evaluation passed, full package build deferred |
| Android fixture readiness | android_api35_68 complete; root integration | Android TLS preflight script/tests; ignored interactive driver | Exact selected ADB in child PATH before fixture/device mutation; real subprocess and early-admission coverage,29 tests pass |
| Documents/persistence | documents_code69 complete | Read-only document/spool/export/preferences audit | No established additional implementation defect; native gaps remain |
| Desktop GUI dispatch | desktop_gui_code69 complete | Desktop GUI commands/Main and HeadlessSession/ControlSupport with tests | Captured benchmark owner/revision checked in frontend and owner mutation lane;16 focused tests pass |
| Integration | root | Shared boundaries, docs, host Gradle, metadata and delivery | Batch review, final checks, then immutable artifacts and broad native pass |

Windows source audit70 found the previously listed production blockers already
closed: scoped broker factory binding, prepare-before-stop, captured CUSTOM inputs,
ordinary GUI/LIMITED autostart and original-user MSI recovery are wired. It found
no additional reachable source defect; native verification remains mandatory.
The known code batch is ready for integrated prepush after metadata. Android
focused counts are15 connection plus10 service/presentation; desktop installer18
and benchmark/session/capability16. Script suites pass29 Android and25 Windows
checks (one Windows-only check explicitly skipped on macOS, guest MSBuild probe
recorded separately). No new native scenario was started during this batch.

Independent review confirmed Android connection mutation admission remains held
through post-commit reconciliation; the proposed unrelated-revision interleaving
was retracted after tracing GUI, scheduled-refresh and service writer paths.
Do not treat missing-API tests or malformed manual probes as causal product REDs.

## September16 Current Operations

Gateway access is restored through ssh.karapsin.com:2228, then the authenticated
Arch hop socket /home/kardinal/.ssh/vpn-control-arch60.sock. The earlier failure
was pre-authentication reachability; no host VPN/network configuration was changed.

Ubuntu current-source DEB update/next-owner recovery passed (checkpoint60/linux-review).
A separate fresh Ubuntu installation now proves acquisition of absent xdg-utils,
with exactly two added packages and zero upgrades/removals. Root verified all18
raw file hashes, package inventories, APT output and empty dpkg audit in
checkpoint63/linux-fresh/root-review.json. The initial desktop-directory absence
and complete executed command transcript were not captured; status.exit is blank,
so its numeric exit is not certified. Both Ubuntu guests are stopped.

Arch public update reached protected sequence4 SUCCEEDED/OK for
job4c9e32b9-4bc2-4597-8f90-824766742dcd. Operation694afeb8-05b4-4aa6-bcf1-c182af76df10
recovered under a replacement owner with exact origin correlation; root checked
checkpoint61/linux-arch raw results. The earlier attempt reached a real terminal
polkit prompt without driver credential input, then was safely cancelled after
confirming no protected job/worker. A missing GUI agent was an incorrect diagnosis.
Arch2317 rollback is now independently verified in checkpoint68/linux-rollback/root-review.json: inotify captured original-to-backup, staged replacement, failed replacement removal and exact original restoration. Public next-owner status retained the failed job/operation identity. The guest is stopped and fixture cleanup is recorded.

Windows2314 remains the ordinary-user native package environment at6GiB. The
corrected-source build passed dependency resolution and reached native helpers.
Task-local tool discovery was repaired; an actual linker probe then isolated raw
parent-segment output paths exceeding the native path limit. Canonical output
paths and a real pinned-MSBuild regression are in this code batch. No MSI
acceptance is claimed; a new frozen package build follows source integration.

The macOS control53 guest is stopped after public off/quit and fixture cleanup.
Current corrected DMG base2.1.12 passed immediate GUI crash/reopen:32 forced proxy
traffic samples, zero failures, unchanged controller/runtime, replacement frontend
within1.45 seconds. Post-reopen hide/show was sampled; initial hide/show preceded
sampling. Root reviewed checkpoint62/macos-crash63/root-review.json. User-local
same-source update to2.1.13 recovered the exact successful receipt; root reviewed
checkpoint62/macos-update64/root-review.json. Explicit reconnect/GUI commands were
used, so automatic return intent is not certified. Full executed update harness
transcript is missing; individual outputs/correlations remain. Machine-owned
installation, rollback/interruption, actual close-button and visual gates remain.

API29 nondebuggable base-to-target installation now passed in owned emulator5656.
Exact installed target SHA441dbc8b67bff428b2bb19fdedfc9ff8543c8c9465dd56f0f77f34ce3f29246d
matches the frozen APK. Public status under replacement controller7a7724e7 reports
receipt85e5b6ba-ffd3-4124-9d78-4fd5eabe95c9/session357363557 installed=true and no
recovery unavailability. Root checked checkpoint66/android-install-recovery-root-review.json.
The earlier permission-denial operation was separately correlated through terminal
status/wait. Multiple explicit retries reused the same pending session after two
recorded driver mistakes (non-TTY EOF and a tap outside current dialog bounds).
The proposed API29 transport defect was retracted: malformed manual command grammar
caused its rejection; actual public transport succeeds. The packaged-CLI/Python
harness defect was fixed in d371254. Interactive drivers now have an explicit stdin
preflight before fixture mutation; isolated causal replay shows the unguarded driver
reaches fixture launch while the guarded driver rejects without creating output.
API35, deliberate process-loss cases, confirmation cancellation and remaining action,
traffic/document/visual gates remain open. API29 is stopped. Owned API35 emulator5658 is the only local VM/emulator,
configured at2GiB. It is idle before installer admission; native scenarios wait
for the combined source freeze.

## Delivery And Current Integration

Latest pushed checkpoint: `3f5715f30e5c9337b84b3377e18c850241b5e3ee`, version2.1.12.
All five exact-SHA required workflows succeeded; managed result:
checkpoint66/interactive-commit-result.json. Current code-first changes are not
covered by that receipt and require their own prepush, push and exact-SHA CI.

Corrected macOS pair source11efe6f8fe46bcbbde522111caf808250f3a24ff00d39bf80dcfa17fdf595780
matches794d01e (1499 snapshot entries checked); subsequent2c3aae9 changes tests/docs.
Both packages have identical code fingerprints, ARM helper minos11.0 and verified
bundle signatures. Base DMG SHA c0e402917d645299da7394efb1f4fad43ee356461d8cdaac7291d668abf4e130;
target DMG SHA9a188d037673a38f54f5fa025c0a95bdbcb2322ee5aa64d199855a535b14080a.
The earlier minos26 pair is retained but invalid for the macOS15 guest.

The checkpoint includes the frontend process-exit repair and managed visual VM
resource admission. The prior macOS CI failure was reproduced with software
rendering: cleanup returned but AWT threads kept the JVM alive. Explicit process
exit follows frontend teardown; fixed macOS workflow34820110381 passed. This is
separate from native installed-package lifecycle acceptance.

Root investigated fixture43's black screen on user request. Normal and recovery
boots failed; a clean clone with the same configuration booted. Firmware reset did
not help. Read-only APFS checking found zeroed object-map blocks and an unreadable
container keybag. Standard repair on a separate copy failed with exit8. The cause
of the corruption remains unknown; do not attribute it to RAM exhaustion without
evidence. Original firmware was restored and all disk attachments detached.
Original `vpn-control-machine-fixture43`, its full preserved backup
`vpn-control-machine-fixture43-before-repair53`, and the separate repair copy
`vpn-control-disk-repair53` remain stopped. Do not replay their unknown installers.
Replacement `vpn-control-boot-control53` boots macOS15.7.7/24G720, responds to guest
commands and shows Finder. Current-source user-local synchronous installation and
exact new-owner recovery now pass, both synchronous and asynchronous. Machine-owned
authorization denial and successful replacement/recovery also pass on the current
pair (checkpoint56/macos-machine). The runtime/GUI and rollback matrix remains open.
Evidence: checkpoint53/mac-boot-repair/recovery-result.json and fsck-repair-copy.log.

Keep at most one local4GiB macOS fixture and no local Android alongside it. Arch
may host additional Windows/Android/Linux guests after current capacity/access
checks. Historical September14 state follows; the September16 operations above supersede it. Root gracefully stopped
idle Arch2317 and Fedora2316 after checking absence of app/VPN/installer work;
Fedora's old loopback fixture server had no clients. Both QEMU processes exited;
disks, packages and receipts remain intact. Arch host has about12.7GiB available
and zero recent memory pressure; Windows2314 and Ubuntu2307 remain running.
Ubuntu old controller89494 was later reconciled off with terminal operations and
publicly quit; its workspace remains preserved. See checkpoint54/*poweroff.json and
resource-after-recovery.txt. Recheck capacity before any new guest or heavy build.
Managed visual admission covers configured allocations, live Tart discovery and
serialized reservations; direct shell/remote launches still need coordinator checks.

Committed atff8de90: Fedora package selection follows exact distribution ID then
ordered ID_LIKE, avoiding build-tool dpkg selecting DEB on Fedora. All11 focused
selection tests pass. Current-source RPM recovery subsequently passed; DEB and
Arch acceptance remain open.

Current integration:

- Direct visual preflight rejects stale primary-display statusbar geometry before
  device/output mutation. Normal reboot of owned5600 restored Pixel6/API35 geometry
  from cutout128/statusbar63 to128/128; screenshots still require fresh review.
- Shared installer handoff repair retains exact uncertain external jobs rather than
  implicitly cancelling after commit attempt. Explicit public cancellation remains
  supported. Three causal regression failures recorded before repair. This does
  not establish the exact cause of the earlier macOS native async cancellation.
- API35 SSH authentication/restart and payload52 management-SOCKS token transfer
  succeed. This proves the SSH payload chain, not all-app VPN/TUN traffic.
  Public cleanup restored stopped/default/empty state at revision44.

Evidence resides in checkpoint51: fedora-visual-{prepush,commit}-result.json,
ci-ff8-windows-failed.log, visual-python-crlf-{red,green}.log,
install-commit-boundary-{red,green2}.log and android-ssh-private/run/payload7-receipt.md.

One host Gradle operation at a time. Metadata/prepush must follow the last content
edit; no receipt from a prior content state is reusable. No release is authorized.

## Checkpoint52 Native Continuation

`3d70d75853dbd2ddb49731999547063d255f3633` passed full prepush and all five required exact-SHA workflows (checkpoint51/commit-geometry-commit-result.json). Its immutable
Linux/macOS pairs share source fingerprint
`729cbe42350b61e7d8a0bc46ecd63f6bd429dc37ae7c28da06d765a870084d6a`,
base2.1.11/target2.1.12. Source/runtime capture is host-only; native builds run
inside the owned guests. Local prepared copies were retired after both archives and guest transfers were hash-verified; retained `/private/tmp/vpn-{linux,macos}-pair-3d70d75.tar.gz` archives restore them. See prepared-copy-capacity-release.json.
Archive and transfer receipts are checkpoint51/{linux,macos}-pair-3d70d75-{archive,transfer}.json.
Fedora pair is `/home/vpnfixture/source-3d70d75/vpn-linux-pair-3d70d75`,
root supervisor40721 with durable root-build-result.json; linux_install52 now owns
that guest and public replacement gate. mac_install50 owns fixture43 and the new
verified archive `/private/tmp/vpn-macos-pair-3d70d75.tar.gz`. Prior unknown
installer jobs and failure evidence remain preserved.

The recaptured six Android scenes at build/visual-actual/android-installer-3d70d75
are rejected: SystemUI ANR overlay contaminated the frame despite geometry128/128.
WindowManager and DropBox show boot-time KeyguardService ANR amid high CPU load.
The normal Wait button dismissed it; no kill/reset. A debug-only primary-window
ANR guard has causal RED (3 tests,1failure, compilation passes) in
checkpoint51/android-anr-guard-red.log and GREEN in android-anr-guard-green.log.
The guarded recapture and six-scene review passed as recorded below.

Root reviewed payload52 raw replies/relay/target transcripts: complete token over
management SOCKS2081→SSH→selected location succeeds. This is bounded component
payload proof, not all-app TUN proof. Raw files under android-ssh-private/run/
payload52-*; public cleanup stopped/default/empty at revision44, temporary forward
removed. windows_login52 replaces the stopped Windows operator; credentials remain
private in the owned VM directory, and old login-input uncertainty must be inspected
before any repeat.

Current continuation evidence:

- Fedora RPM public replacement/recovery passed at the frozen3d70d75 source:
  installed2.1.12, job96630884-c147-4a4e-815b-eb0eb450ffa5, operation
  ffd7a8e1-8cb4-45fc-8b8a-ede9f66d2142, protectedSUCCEEDED/OK and replacement
  owner recovery matching the same correlation. Root independently read the public
  result and queried installed RPM. Guest raw evidence is
  /tmp/vpn-public-install-evidence-ugbgdqgr; freshDependencyEvidence remains null,
  so this does not certify the fresh-DEB dependency gate.
- Guarded Android capture completed and root opened all six complete frames:
  no clipping/ANR, legible state/action labels. Six new Android-only baselines were
  recorded and all six geometry/contrast/comparison checks passed. This is a subset
  baseline review, not full-platform or release attestation. Evidence:
  checkpoint51/android-installer-six-{scenes,review}.json, android-installer-six-verify.log,
  build/visual-actual/android-installer-guarded52. The capture includes the dirty
  debug-only ANR guard; final delivered-source attestation remains required.
- Remaining Windows Python CRLF scene arguments are normalized only at trusted text
  producers. An executable miniature fixture tests real wrapper/selector behavior
  and exact Gradle/stamp arguments. Binary framebuffer output remains unfiltered.

Windows ordinary-user preflight now passes on the previously installed2.1.10
(oldsource1b) nativeAMD64 package: help/version/capabilities exit0, missing-owner
status exit2/UNAVAILABLE without starting an owner. Exact interactive SID ends1000;
worker windows_login52 retained raw guest outputs and removed only its temporary
limited tasks. This clears guest login access, not current-source broker/MSI gates.

## Current Environment Ownership

| Task | Owner | Exclusive scope | Next evidence |
| --- | --- | --- | --- |
| Integration/delivery | Root | Shared source, docs, sole host Gradle | Windows frozen pair transfer; review native evidence and final delivery |
| Linux next package | linux_arch61 | Ubuntu2307 reconciliation, then owned Arch2317 only after slot handoff | DEB accepted; preserve artifacts before a graceful VM switch |
| Windows native build | windows_build60 | Windows2314 at6GiB | Python stage verified; reconcile failed interactive setup task before retry/build |
| macOS traffic | Root; capture workers complete | vpn-control-boot-control53 | Packaged proxy traffic through GUI attach/hide/close/crash; installer slice complete |
| Frontend crash recovery | frontend_crash60 | Visibility control, owner lease and constructor integration, focused tests | Causal RED captured; root reviews and runs GREEN before packaging |
| Android pair | Root | /private/tmp/vpn-android-pair-ae92601 | Both release APKs built and verified; no AVD running |
| Android native | Root; preparation worker complete | Local task AVDs remain stopped | Execute prepared API29/API35 scenarios after macOS releases local slot |

All source pairs use ae926016 product code. The Windows docs56 snapshot includes
the then-current WIP documentation delta and has its own fingerprint; subsequent
documentation edits do not modify any captured inputs. Completed workers have no ongoing write
ownership. Native operators may not start unrelated VMs or overwrite frozen stages.

## Checkpoint59 Stream Acceptance

Public Android streams already dispatch before the non-stream adapter. New desktop
transport tests exercise the actual ADB document client with a fake provider: log
tail/cursor propagation, owner replacement and post-submission loss. This is a
coverage addition, not a product defect repair. CLI-004 permits exit2 for both
unavailable transport and unknown outcomes; observation alone does not justify
changing that classification. Focused Android stream/ADB/document suites passed
37 tests with zero failures or skips. The initial new-test assertion incorrectly
expected exit2 for explicit CONFLICT; corrected to CLI-004 action-failure exit1.
No production change was necessary. API29/API35 installed tests remain required.

Root reviewed the executed sampler and verbatim installed-package captures under
checkpoint59/macos-output/guest/output59. JSON status/stats and human status/stats/logs
clients emitted output, then each exited naturally with130 when its output reader
closed; no TERM/KILL fallback occurred. Human output stayed on stderr. Forced SOCKS
token traffic succeeded before and after; controller/runtime, revision4 and all four
owned process identities remained unchanged. Review: checkpoint59/macos-output/root-review.json.
Checkpoint58 genuine captures also prove repeated JSON status/stats, logs limit0 and
real foreground-terminal Ctrl-C130. Earlier reconstructed checkpoint58 summaries are
explicitly not raw evidence and must not certify their unrecaptured claims.
GUI hide/close/crash and owner replacement remain untested in this native slice.
The host is still locked; preserve the live connection until GUI checks can resume.

## Checkpoint60 Native Progress

- Root reviewed the Linux protected success and exact original operation/job tuple
  under a distinct replacement controller: operatione53f848d-7fdc-41a1-afd6-c54414da0493,
  job3f9855f7-edf0-4be3-9fda-3968d916d06b, replacement86ffe18f-350c-4969-8648-b28acfa7e58c.
  Public target2.1.12 and dpkg2.1.12-1 agree. Raw result/summary and hash verification
  are under checkpoint60/linux-review. This closes current same-source DEB update
  recovery, not fresh dependency acquisition. The PTY wrapper hit end-of-stream EIO
  after durable child success; no installer was replayed.
- Installed macOS routing/location exports succeeded in private disconnected
  workspaces with Unicode/space paths, mode600 output and mode700 directories.
  Existing destinations were preserved; invalid output and JSON/raw combinations
  rejected. Both export types include timestamps, so separate invocations do not
  prove byte equality. Root reviewed the saved script and raw results. The first
  export archive contains an expired private owner token from an overbroad scan:
  keep it confidential/ignored and never publish it. Later captures avoid that scan.
- Proxy traffic passed561 requests across public hide/show and205 requests across
  the second deliberate frontend crash/reopen, with unchanged controller/runtime
  and revision4. Root inspected raw samples and exact admitted frontend PIDs.
  The first sampler expired before the first crash and does not certify that event.
  See checkpoint60/macos-lifecycle/root-review.json and saved scripts/raw captures.
- Immediate GUI_SHOW returned UNAVAILABLE twice after frontend-only crashes, while
  a later request succeeded after lease expiry. The causal quick regression records
  expectedOK/actualUNAVAILABLE before any product edit:
  checkpoint60/frontend-crash-causal-red.xml. Repair uses a read-only identity probe
  and exact stale-registration revocation; uncertain visibility actions must not
  replay. All24 focused tests now pass without skips. Independent review caught raw-OK
  identity acceptance and lease-expiry races; two causal failures preceded their
  corrections, and re-review found no remaining issue. Rebuilt installed-package
  retest remains open. Evidence: checkpoint60/frontend-final-green and
  frontend-review-causal-red.xml.

## Checkpoint55 Current Artifacts And Acceptance

- macOS pair at guest /private/tmp/vpn-macos-pair-ae92601 built successfully on
  macOS15.7.7 ARM64 with Temurin17.0.20.1. Base2.1.11 and target2.1.12 have identical
  code fingerprint4e10547a70bd27121fa8ac2bec715e9d98cdbb5a272256fdc2a41af59dc84bac.
  Source fingerprint3c89f3a5f543c5dad864fe9895c966251cda1bda6da1dd87d3bdf0c6b05471ac.
  DMG/package receipt: checkpoint54/macos-pair-ae92601-receipt.json.
- Installed user-local synchronous update passed from mounted base DMG through the
  public installed CLI. Job05a3b7df-96e4-47c6-8fed-e8b2126054f1, operation
  32897df4-2881-4d87-8600-d1e1c9a71f36 recovered under a new owner with the exact
  original tuple, succeeded/OK, installed=true and cleanupCode=OK. Target2.1.12
  reports runtime off. Root inspected/copied raw public results under
  checkpoint55/macos-userlocal. Async installation also passed: joba459debf-4920-412b-b540-a804d00d949c and operation
  a1f604f9-35ea-4849-9567-ee94e3c41e67 recovered the exact original tuple with
  installed=true/OK and cleanupCode=OK. Initial async acceptance legitimately had
  no job yet; the request was not replayed. Root inspected raw async wait/recovery.
  Fresh-state help/version/capabilities left state absent, and status returned
  UNAVAILABLE/exit2 without startup. Packaged ARM64 helper hash is in native-helper.json.
  These close those cases, not the whole Mac matrix.
- Linux ae92601 archive hash460de0b04408deb51b5dd26eb16fe440ea19f339843e1e047ddc6556a0584fdf
  is verified in Ubuntu. Ordinary GNU tar could not populate its read-only source
  directory; that failed tree is preserved. The existing tested
  extract_readonly_archive helper extracted a new source-ae92601 tree correctly.
  Both native builds now passed; all six DEB/RPM/Arch hashes and sizes match the
  receipt, and code fingerprints match a133e6c578f616259760f05cb54dbdc152fc958d3e14cc5788f11eaec88b90ef.
  Root reviewed checkpoint56/ubuntu-fixture-receipt.json and terminal output.
  After public off/terminal-state reconciliation and quit of the historical owner,
  the verified base DEB was installed by explicit fixture downgrade only: one
  package downgraded, no unrelated install/remove/upgrade. Public update is next.
- Android pair preparation includes the real tracked AAR/native inputs and excludes
  the runtime-source gitlink. Source fingerprint0877a6cae1ba2411666a4d2de5f38929f7354339f6eb3faa8d035039a13bb27d;
  base2.1.11/code16620 and target2.1.12/code16640. Root started sequential release
  builds with fixture signing, two workers and2GiB heap; both passed. Both APKs are
  nondebuggable ARM64 with matching signer a43b5330501b02f5558fa381c52e7f7dcdd9db362d6807d449d7bbb5e207c5a0.
  Base SHA d2a2575de17afe13974af08f6969ca9afb7364641d3a91dd0212fdeec520db5f;
  target SHA441dbc8b67bff428b2bb19fdedfc9ff8543c8c9465dd56f0f77f34ce3f29246d.
  The packaged native hash differs from the tracked input because the pinned NDK
  strips it; root independently reproduced that exact transformation and verified
  identical packaged bytes in both APKs. Receipt: checkpoint55/android-pair/receipt.json.
  Native API29/API35 use remains pending; older APK receipts below are not substituted.

Windows docs56 pair is prepared at /private/tmp/vpn-windows-pair-ae92601-docs56,
source fingerprint baf1a96a1c5c709286aadc169fa99210eaca855ca091753818d650cfef1c93cc.
Its archive SHA9941fcf905b058d4ffd72c7e0ec19f8d1b34fe1eb153252062868e1266eeb66f
is recorded in checkpoint56/windows-pair-preparation.json. It captures the verified
pinned1.13.4 AMD64 runtime; native packages have not yet been built. The first
Windows CI artifact download ended in a network read timeout; a separate retry
retains exact workflow34821933061 identity.

Current machine-owned macOS authorization denial returned terminal CANCELLED,
installed=false and preserved base2.1.11/off. Grant job85c05083-75ca-468a-939e-d1dd5fe19535
and operationc1359f99-4e9b-4585-afb4-d8f22d517116 recovered the exact origin tuple
under controller66a5ae1f-fe55-4ceb-b4f1-2ff3c2966a1f with installed=true/OK and
cleanupCode=OK. Root reviewed the raw envelopes in checkpoint56/macos-machine/raw.
Target2.1.12 signature/hash/root ownership passed; public quit and fixture/mount
cleanup passed. No runtime was started in this installer slice.

Android preparation at checkpoint56/android-next separates base no-update TLS
from target installation and preserves fixture trust through the full action.
The existing TLS and update fixture suites passed23 and8 tests respectively.
This is preparation, not current API29/API35 native acceptance.

## Historical Native Evidence And Its Limits

### Android

Frozen current-source pair uses fc82 product source, with only documentation changes
at build time and explicit test version overrides. Both are nondebuggable release
APKs with the compatible fixture signer, not production-signing certification:

- base2.3.11/code17420 SHA632d36233f69af3c689af77d4967c83ec491f3931baeacecf5469291a8310137
- target2.3.12/code17440 SHA63800963830d95d9db4b5937490aec1117e56a71858214f9d99164a4b785289e
- signer SHAa43b5330501b02f5558fa381c52e7f7dcdd9db362d6807d449d7bbb5e207c5a0

API29 AVD5594: current target, 48MiB heap-growth limit, 56,000-domain/11,536,164-byte
public import, same-owner readback and cold-process readback passed. Normal am kill
reclaimed PID4460; cold PID13689 and a new controller read the same semantic digest.
All read/import exits0. No root/run-as/force-stop/data clear or live VPN. The AVD
was shut down normally with data retained. Receipt:
checkpoint51/android-api29-current-20260914T0559Z/receipt.json.

API35 AVD5596: current base, 192MiB heap-growth limit (not48MiB), 56,008-domain /
12,488,469-byte import and retained result, normal process reclamation, cold
readback, private0600 export, no-overwrite failure and identical no-op import
passed. No-op retained the cold owner's revision0. Existing-output export returned
PERSISTENCE_FAILED/exit1 and preserved its digest. Cleanup restored empty routing
and stopped runtime. Receipt:
checkpoint51/android-pair/current-base-cold-document-receipt.md.

Earlier source33e2 fixture evidence remains useful but is not current-package proof:
real HTTPS benchmark1289ms; accepted cancellation bdfc03ea-c549-43fd-82ac-242fc9a4b891
preserving exact activeA/runtime and pendingB; successful retained diagnostics
export to a private path. Prior export rejection came from a0777 writable ancestor,
not rejection of ordinary0755 directories. See checkpoint49/android and
checkpoint50/android plus android-diagnostics/receipt.md.

Fixture trust provisioning and public app control are separate scopes. CLI-001
requires nondebuggable app control without root; it does not forbid the explicitly
authorized disposable guest-only CA setup. The existing driver copies certificates
to newly created staging, relabels only that staging, temporarily mounts it into
the guest zygote namespace and restores UID2000 before the public action. It does
not rewrite original system certificate files, SELinux policy or host trust. Keep
setup/cleanup privilege explicit in evidence, verify every actual public action
uses UID2000 without run-as, and require exact mount/proxy/forward cleanup. This
corrects the earlier tracker interpretation that treated all fixture provisioning
as forbidden. Historical receipts still cannot certify current APKs or unrecorded
public caller identity; run current API29/API35 scenarios with complete evidence.

### Linux

Fedora2316 exactbbb RPM SHA
ed6e8f912d83871437514fd695c73024019840ae893fe30a32f0d36c42bab12c:
installation, immediate GUI close/reopen1.3435s and token traffic through attach,
close, reattach and crash passed. Runtime identity remained stable; off/quit
cleanup passed. This does not prove crash re-open or current-source update recovery.
Root reviewed checkpoint50/Linux/summary.json and retained guest receipt.

New fc82 pair source fingerprint
65378a4ad1d4951020d0e059ab73bebdac91fa1bb53b8303b3587525e2961635;
pinned Linux runtime1.13.4 SHA
fdf44dd63aa9d04668f37629067aa6bd008e04b993dd3825ea829f17919af765.
Guest Temurin17 and binutils are installed. Current pair path:
/home/vpnfixture/fc82-linux-pair-retry3; build PID31868 / Gradle child31888 were
verified live, then terminated with packageDeb rejecting unsupported DEB because
dpkg-deb/fakeroot/rpmbuild were absent. Guest-only dependencies are now installed;
retry3 evidence remains intact. The new immutable retry4 produced base2.1.10/target2.1.11 DEB/RPM/Arch artifacts
and a fixture receipt. Installing an already-present2.1.10 was a package-manager
no-op, leaving old source inputs; exact frozen-base reinstall is assigned before
public target recovery. No source identity guard is weakened.

The first build failed because objcopy was absent. A second attempt correctly
rejected existing immutable stage outputs. A worker then improperly removed the
old pair directory; its contained base-build log/stage was lost, while the outer
failure logs survived. No packages or final receipt had existed. Preserve all
remaining records and do not repeat that cleanup pattern.

### Windows

Owned nativeAMD64 Windows guest:
/home/kardinal/vpn-control-windows-msi-native-20260907 on Arch. Manual MSI from
source1b, version2.1.10, SHA
1c16fa37459ff95a784c205275e889234d0896dbbc1fa1347ed9b3f1873f7aee replaced the prior
2.1.9 launcher in place. Installer exit0, engine exit0 and ordinary-user public CLI
version2.1.10/exit0 passed. Actual launcher is under parityagent LocalAppData.
Remote checkpoint50-manual-msi-receipt.txt SHA
f143f6ec821287059fa0c0743fe04072f908e250e1bed96958b485d38162461b.
This is manual installed-package proof, not public update-adapter recovery.
Later read-only reconciliation found SYSTEM msiexec8744 absent; its original outcome
remains unknown. Preserve the related historical records.

Ordinary InteractiveToken/LeastPrivilege static and missing-owner checks passed
on that older installed package. Current-source lifecycle and runtime evidence
remain required; the earlier package cannot certify the new source.

Local ARM64 guest / AMD64-emulation component evidence remains separate: scoped
broker/TUN and UAC denial preserved traffic; original-user bootstrap fixture ran
three tests with no skips/failures. Current-package/nativeAMD64 broker and full
MSI adapter scenarios remain required. The production factory already enables the
scoped broker on eligible Windows processes; preflight is read-only and UAC occurs
at explicit VPN preparation. Old HIGHEST autostart migration is active: it checks
owned XML under a local lock, rechecks, then lowers run level with schtasks /Change
and validates the result. It does not delete/recreate the task. Native DACL,
foreign-task rejection and reboot evidence remain open. Task Scheduler offers no
atomic compare-and-swap against a concurrently replaced same-name task; repeated
reads do not prove such a guarantee. Preserve this limitation without inventing a
new privileged service or disabling requested migration as an interim substitute.

### macOS

Tart fixture43 uses the clean fc82-compatible base2.1.10/target2.1.11 pair at
/private/tmp/vpn-control-macos-pair-bbb7b046, identical executable fingerprint
bfb60629266d1050c2f66e44746112d3cfaf7f638f04ec4183670e0f7daeac0a.
Base DMG SHA23d0fe05cd764fc8c8c49f8a35d3f73702c27df1fe230b25a44c9b2251b24dfa;
target SHAb73cd188fbd2b0d4c01126355bceedb603796697943baf18d4a21179f97f7cd7.

Account access is resolved. Creation records showed the original Tart image
credential authenticated at setup; it again worked through SSH and normal guest
UI. The separately generated VNC password is not the account password. No user
credential or account reset is required.

Public check/download succeeded, followed by actual authorization of job
2958cf24-59fc-45ae-8c39-60f1b785b093, operation
c9e66967-1282-4a9f-a8e3-d1179f8ca7e3. Native copyfile logged output EIO before any
rename. Protected status.json directly confirms FAILED/PERSISTENCE_FAILED seq1;
installed remains unknown. Original app and protected receipt/correlation survive;
terminal input cleanup removed only inputs. The partial stage remains under
/Applications/.vpn-control-stage-2958cf24-59fc-45ae-8c39-60f1b785b093.app.
Underlying I/O cause is unproven; do not infer host capacity as its cause.
Receipt checkpoint50/macos/receipt.json retains the native log and identities.
Older job49a33fcf-cecd-4d19-a233-47b6cc1dcf69 and its base remain untouched.

The fresh machine-install retry is now successful on the frozen fc82-compatible
pair: job9d328c5c-3bc8-4da5-9b91-6f6ee7e6e14f, operation
57b93ace-d01a-468d-a7ff-98659d09ecfb. Protected receipt seq4 is SUCCEEDED/OK;
public target recovery reports installed=true and cleanupCode=OK. Target2.1.11
main JAR SHA86425c0aa6d970798410bd631de5124f20651bf6adda41ca835980b62af70ef4
matches the frozen target. Root copied and hash-verified summary and three raw
public responses under checkpoint51/macos-success; summary SHA
2109ccbcf2fd923292d2ea91122b9b6f375a36c4bc41aaac5b19a39736cafb9d.
No stage/backup remains for this successful job. Old failed and unknown evidence
remains. Guest-only Tart Automation permission was test setup, not a product
requirement. This closes this machine replacement/recovery scenario, not local
installation, denial, rollback, GUI-return or final-delivered-helper coverage.

## Capacity And Artifact Preservation

Verified lossless offload restored10,826,780KiB host free space. Three additional
cold evidence trees (checkpoint26 macOS host source, checkpoint30 Android pair,
checkpoint33 macOS archive) were archived remotely and verified before local
relocation. Restore pointers remain. See checkpoint50/capacity/RECONCILE_RESTORE.md
and earlier RESTORE.md. Current APK/DMG pairs, VM disks, failed/unknown installer
records and required JDK/runtime inputs were preserved. Serialize host builds and
reserve headroom for VM sparse-disk growth; a single free-space observation is not
proof of sufficient peak capacity.

## Remaining Implementation And Acceptance

1. Windows public MSI update and original-user/elevated/different-approver recovery,
   protected receipt/lock handling and current nativeAMD64 public lifecycle.
2. Current-package Windows broker/configuration coverage, denial preserving activeA
   and pendingB, TUN/child cleanup, ordinary GUI/autostart and safe legacy migration.
3. Finish remaining RPM failure cases and final-source package revalidation. Fresh
   DEB dependency acquisition and exact Arch replacement/rollback are proven in
   checkpoint63 and checkpoint68 respectively. macOS machine rollback, interrupted recovery
   and automatic GUI return remain open; user-local rollback/recovery now passes
   on the checkpoint105 frozen pair.
   Current ae926016 user-local synchronous/asynchronous and machine grant/denial
   recovery are proven above;
   the3d RPM success and earlier Mac machine success apply only to their artifacts.
4. Android API29/API35 action/SSH/refresh/consent/foreground-service/process-loss and
   installer permission/cancel/corruption/retention/reconciliation matrix.
5. Remaining document expiry/principal/owner/hash/interruption/resource/persistence
   failures and GUI/private export paths; cold-read success does not close these.
6. All desktop one-owner/traffic lifecycle and scheduled-refresh scenarios through
   installed launchers, including missing-owner and transient-owner behavior.
7. GUI-versus-CLI effect comparison and remaining changed-scene capture/review.
   Six Android installer baselines passed local review and checks; their delivered
   source attestation and the broader platform inventory remain open.
8. Final metadata, full current prepush, reviewed commits/push and all five required
   workflows for the exact SHA; match final packaged evidence to delivered inputs.

Do not label skipped native checks, component-only tests, older launchers with new
JARs, mounted images or in-progress jobs as full installed-package acceptance.

Checkpoint97 Android shell preflight now proves fast and stalled SOCKS replies
through an owned ADB reverse mapping, using device127.0.0.1. The earlier probe
used nc -q1 and could end after stdin EOF before proving a handshake; it did not
prove a broken reverse route. Exact runnable probe scripts and a self-excluding
manifest are retained in checkpoint97/android-endpoint-preflight. A single
subsequent cancellation attempt is assigned to android_cancel97 with frozen
fixture copies; no result is claimed yet.

Checkpoint98 Android cancellation is now proven on the frozen nondebuggable
API35 ARM64 APK through the public legacy provider: operation
178ed42b-f3d8-4281-9c00-167930ffc2ac was accepted nonfinal, produced a new
benchmark-side stalled SOCKS event, then cancelled and waited as CANCELLED.
The relay stayed owned by one persistent Python context throughout. Cleanup
leaves revision22, only CP89, runtime OFF/unselected, no owned reverse or relay,
and all10 transfers discarded. Root verified its evidence manifest. This does
not certify the default desktop CLI document transport or API29 cancellation.

Checkpoint98 source freeze: scheduled/manual refresh outcome regressions retain
causal RED XML/logs and the70-test GREEN selection in checkpoint98. Final narrow
independent review found no blocking concern. Python focused selections pass:
provider11, SOCKS14, combined HTTPS/relay4, benchmark/probe10. Full pre-push,
metadata and a new checkpoint push remain required.

Windows CP95 base installation completed through the ordinary parity95 desktop
with MSI exit0 and the expected per-user directory. Original installer process
10172 is terminal; the Windows Installer service process1952 remains owned by
Windows and is preserved. The immutable same-source fixture and reviewed base
launcher were verified by hash/ACL. This is base installation, not public update
replacement or next-owner recovery. Evidence: checkpoint95/windows-fresh/base97-result.json.
