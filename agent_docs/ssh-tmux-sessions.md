# Owned tmux sessions

## Network changes and temporary outages

The coordinator's host frequently changes networks and the router may be
temporarily disconnected. Transport handling must tolerate these conditions:

- Distinguish a stale/refusing control socket, unavailable network, unavailable
  configured session and an actual authentication rejection. A generic failed
  probe or an old socket refusal must not be reported as broken credentials.
- Revalidate connection health, then use a bounded fresh connection to the same
  configured trusted route when its cached transport fails. Preserve foreign
  sockets and sessions. Connection recovery must not replay a submitted task.
- Bound connection attempts and backoff, report their actual outcome promptly,
  and retain the original remote job identity across reconnection. Resume
  read-only observation or collection of that job when connectivity returns.
- Keep long-running work in the owned remote session with durable receipts.
  Losing a local SSH client proves neither remote termination nor task failure.

These are required transport behaviors. Current acceptance remains incomplete.
Direct15e614eb reaches the gateway through outer3c9 but the configured nested
socket refuses. A separate fresh direct0a4d90 test through the user's port2228
route succeeds: Arch UID1000, original SSH63191 exit0, complete dual EOF,
stdout62 and stderr0. The configured passphrase and fresh route work. Public
receipt manifest16416255 closes at root without opening private raw streams.
Historical generic authentication_failed receipts remain historical
classifications, without a proved authentication cause. A strict probe-only
classification repair has19 local passes and independent LOCAL CLEAR
(review979c506e). The equivalent MCP diagnostic reports socketState=refused,
nestedState=unknown and failurePhase=socket_parser; it does not claim an
authentication failure.

The old local outer3c9 is subsequently positively absent and retired by MCP;
new outer146bf14f is ready. This proves a new outer connection, not restoration
of the nested cached socket. A separate admitted fresh nested channel is being
implemented so canonical socket cleanup does not delay connection recovery.
No native VM/app job is replayed by these transport observations.

New independent nested test channels use `ControlPersist=18000`, allowing five
hours without an active client session. An active command keeps the connection
in use. This setting avoids idle expiry during long preparation pauses; it does
not change command deadlines or guarantee remote process survival after an
unexpected active SSH disconnection. Expired channels remain ended; prepare a
new identity rather than restoring one. The separate foreground tmux master below
continues to have its own lifecycle.

## Current channel546 trust and recovery boundary

The channel546 generic small/oversized DIRECT and actual fresh-SDK MCP proof
completed four programs, with original source closing and keeper absence. Its
receipt is `.runtime/windows-parity-20261019/program-tool-native/final-748-638/native-direct-mcp-qualification.private.json`
(SHA-256 `55b5b9302d8e5bc6f6e1f0f3c1e712fc26e1c5e9b5155b38bea4e91153edf612`).
Subsequent `known_hosts` drift makes the old READY authority stale; five-hour idle
persistence does not extend source or trust authority. Do not adopt old READY,
restore inferred trust bytes, or replay an unknown program to recover the route.

The once-only original PID4120 status query has completed and observed its create
terminal result. The full original ba962 probe remains `unknown-unverified`:
local owner57875 and SSH58163 are absent, original outer custody is lost, and
original dual EOF/source closing remain unproved. The new status carrier's closure
cannot recover those original facts. Keep the status result and original full
probe as separate records; do not repeat the consumptive query.

Stage A's exact helper/fixture/policy adoption passed 37 canonical methods while
retaining the sixteen original DIRECT sources. Its actual fixed546 retirement is
now complete: root joined retained outer/exit-client known-zero and dual EOF,
independent absence and authentic original546 ENDED publication/readback. Receipt
`.runtime/windows-parity-20261019/stage-a-native-retirement-546-v1/root-retirement-adjudication.private.json`
has SHA-256 `a405c991fac3d7f6f872d1ec12d1c2820454968a7da91569cf29b6c7562c9fad`.
This closes only the admitted channel; original ba962 UNKNOWN and lost original
custody remain unchanged, and historical trust equivalence is not claimed.

Stage B's thirty exact reviewed source overrides and policy `b2041052` are now
applied against accepted Stage A. All 203 distinct methods in the seven-module
focused slice pass; its one MCP dependency skip was rerun successfully in the
project environment. Root's post-check code/policy closure is
`.runtime/windows-parity-20261019/stage-b-canonical-adoption-v1/root-canonical-adoption.private.json`
(SHA-256 `df8f3de570f416e399af17b1b41a778e7c0a3b9471f33412ed689c51a5fb4470`).
At that post-check checkpoint, documentation/version freeze and NEW normal
prepare/select were still pending. Channel267 has since reached READY/SELECTED and
qualified its DIRECT small program. Its oversized c79 failed before job creation
with `SelectionUnknown`; the original cause remains unresolved and unreplayed.
Later distinct DIRECT-large and actual fresh-SDK MCP small/large operations complete
all four pre-Stage-C b204/0b0d SSH tool proofs, retaining the earlier small result without rerun.
Root adjudication is
`.runtime/windows-parity-20261019/program-tool-native/stage-b-b204-remaining-proof-v1/root-four-program-adjudication.private.json`
(SHA-256 `fba549716ff1d11e5accd09f22a24af79bf7c59be26da58840b6df7249ab8671`).
Four actual programs and 41 RPC servers are distinct counts. Original c79 and LOST
diagnostic1 remain unchanged. Those SSH tool proofs made zero Windows guest actions.

The first later bf05 prerequisite b7 left its original operator UNKNOWN across a
terminal-publication gap. One pure LOCAL status recovered the original component
terminal/owner-close and qualified inner/source closing; root adjudication89b4
preserves original observation98/exec73992 exit1, adds no starts/remote queries and
leaves the remaining six callers held. This is component recovery, not promotion
of the original operator or authority to replay it. The final private e286 worker
candidate has actual whole-before/current UNKNOWN-to-redacted-PENDING causal proof
and a foreign-operation false-PENDING-to-UNKNOWN counterfactual; its37-method
private slice passed and is now adopted. The initial aggregate88 remains failed
with two recipe source-inspection setup errors caused by a stale staged guest
alias in the test fixture. Stage D's boundary41806/helper0a51 restore exact module
and parent aliases; actual old-boundary RED3 failures/0 errors and current five-
method GREEN retain the causal fixture proof. Final source-current88 PASS16.885s
(program37+retirement/diagnostic46+recipe5), fresh platform2import/7capability PASS,
and all43 held full-generation/hash source closings are joined in
`.runtime/windows-parity-20261019/stage-d-canonical-isolation-adoption-v1/joined-validation.private.json`
(SHA-256 `e0d15f8f9224e060b5b3381c19a9089e96c121bbb671e72d3b8543f973b72e37`).
Routine enrollment is closed. At that checkpoint, fixed-source native first fresh
T and the remaining six callers had not run; original caller identity/outcome
remains unchanged. The later first caller4835 below adds no successful native result.
Recipe S's five local cases and UAC31/13 controls give no native visual acceptance
or successor launch authority. All64 Windows/shared memberships and58 scenes remain
open, with no app installed and no current prepush or push.
The later post-adoption caller `4835b6ea-e758-44b0-b024-0972f8fe6594` remains
UNKNOWN: automatic b9 staged a130341-byte wrapper carrying114293 source bytes, then selected-channel guard
refused `master_closing` / `fd_changed` before program loader admission. Exact
changed FD/master type and original cause remain UNRESOLVED; original capture
has no program bytes/EOF proof. Preservation `86702dc6` and journal complement
`b6c8df1f` retain the original result and absent execution-intent/submission-returned.
The separate private FD-enumeration candidate179c97 has actual whole-beforefb8dfa
RED/current GREEN plus strict missing-listener/birth/stat/permission controls:
private59 PASS16.824s, handoff009c4f96/qualification523eda03, including natural
same-case old-CURRENT `fd_changed` ERROR/exit1 versus current GREEN. It skips only per-entry disappeared readlinks
while still positively joining the unique expected listener. This does not identify
the original4835 FD/type/cause, and supplies no native-acceptance result.
Retirement-profile/gateway Stage A's twelve sources are adopted (helper18ab,
testcf8/gatewaya854/policy21df); canonical retirement50+source-stage52 pass102 in
36.782s. Pure LOCAL real-original17/50 preflight and both absent execution markers
pass under receipt4ec358ff, with zero native calls/exit claims/source16 changes.
That preflight is separate from the later once-only actual retirement3f7beb36:
originalexec11155 natural0, normal publisher/final original status ENDED, complete
native exit, dual EOF and independent absence. Root qualificationf49f564a joins98
held records/all50 historical proofs/16 sources unchanged. Original267 is
closed without changing old unknown outcomes or granting native action. FD Stage B
then adopted exactly four reviewed sources (provider179c/teste5b5/fixturea3ab), no
policy write/21df unchanged, receipt6ed71d3b. Fresh109 (provider59+retirement50)
PASS14.526s on originalsession7246 natural0, retained outputeeebbd4e, closing this
source-current routine-enrollment gate. At that checkpoint, four-tool proof/native-
seven successor plans were private and no new channel had been created. No replay
or remaining-six start is claimed.
Original prepush90637/frozen8e55 naturally failed one gateway writer-alive assertion;
all workers closed/root exit1. Separate owned Event-release fixture correction has
actual controlled late-observation RED/current GREEN,14 private cases and the
adopted52-method canonical slice (handofff0d24c0a). Original scheduling specifics
and4835 FD/type/cause remain unresolved. No passing current prepush or push exists;
app,64native memberships and58visual scenes remain unfinished.

Subsequently fresh11dda7ac was prepared/READY/selected (receipt3af388db,idle18000),
and four current DIRECT/fresh-SDK MCP small/large programs qualified under held
engineering21's finally loader, root closinge1840795/full proofe85c9f44. Four program
starts differ from66 SDK RPC servers; all33 source generations/hashes close unchanged,
608 held records/141 local actors absent. Stage F then adopted the reusable
SystemExit guard/getter fix and its existing five-case family (receipt9e20ef17,
policy688 last); canonical5 PASS5.678s closes this live-source unit gate. Metadata
renews only two pins/three scope edges; selected source16/core/e286 remain unchanged,
so consumed-runtime-source tool proofs stay valid. Windows-seven rebinding/runs,
app installation,64 memberships/58 scenes, fresh prepush and push remain OPEN.
These tool proofs make zero Windows guest actions; no replay is authorized.

Preparing a fresh channel before Stage B and subsequently changing its bound
sources would make that authority stale again. The old selection pointer is not
rewritten as a shortcut. None of this authorizes foreign cleanup, trust-file changes
or replay of unknown work or the consumed original-status query.

## Gateway connection

The dedicated gateway companion retains one foreground nested SSH master in a
private tmux server. It uses the configured Arch profile and verified key/trust
metadata, with the existing private credential channel. It exposes no arbitrary
command or path. The master uses `-M -N`, without daemonization or an idle
ControlPersist timeout. It does not reconnect automatically after failure.

`ssh_workflow` exposes `gateway-tmux-availability`, `gateway-tmux-prepare`,
`gateway-tmux-release` and `gateway-tmux-status` for host `archlinux`.
Preparation retains an external anchor before a separately fenced release;
lost replies are observed rather than retried. Existing configured sockets and
foreign tmux sessions are preserved. A ready owner is not inventory adoption or
VM/product acceptance. The coordinator must separately publish a reviewed
canonical recovery intent, adopt it and verify the configured route.

The gateway's Debian tmux3.5a-3 prerequisite is installed. Worker/adapter/route
tests and independent review pass; fresh MCP availability reports available.
Native d606 preparation and its single release completed. Separate read-only
checks prove the original SSH child is alive, its master answers, and an Arch
command succeeds. The original worker missed readiness after its five-second
startup window; its unknown status remains preserved. Canonical readiness
reconciliatione5bc754e and adoption5db13851 completed. New outer session
c5015dce is ready; fresh MCP session status and the configured Arch probe pass
e7f4cbc3. The read-only reconciliation status route passes fresh MCP observation1a04102e
and reports adopted. It makes no writes or remote queries and does not claim
current master readiness. The
original gateway status still truthfully reports its missing readiness record.
Direct inert disconnect acceptance passes on both hops: gateway7dd0f8e6 and
Archab06da02 each completed20 heartbeats after the submitting local SSH client
was deliberately stopped. Fresh clients observed the same original remote job.
MCP integration exposes the fixed `tmux-disconnect-probe` action with hop and a
new correlation only. Independent17-case route review passes; true fresh MCP
retest f57ea080 completes both gateway226c88c0 and Archcb7c4308 with20
heartbeats and held source pins unchanged.
This proves inert job persistence, not interrupted package-output or product
acceptance. Arch package sessions below remain a separate fixed purpose.

## Arch packaging

This companion is for the fixed Linux package fixture build on the owned Arch
build host. Direct build86fcac2e persisted after the submitting SSH call ended and was
observed running from separate SSH calls. Its immutable collection verified ten
artifacts and twelve timing receipts. The reusable MCP adapter is reviewed;
registered MCP status observes the same job ready. Equivalent MCP collectionff31ffb3 completed ready with the same ten
artifacts and twelve timing receipts. Current frozen product packages remain authoritative.

`vm_workflow` exposes `linux-package-tmux-availability`, `-preflight`, `-start`,
`-status`, and `-collect`. Availability takes an empty object. Preflight/start
take the coordinator's exact sourceSha/baseVersion/targetVersion/correlationId;
an optional local sourceRoot must be a clean managed worktree of the same Git
repository. Status/collect take only correlationId. There is no public release,
attach, arbitrary command, or remote path override.

New jobs require `linux-package-tmux-resource-prepare` first. It takes the same
four build fields plus a required clean managed local `sourceRoot`. The root
operator must already have reserved a distinct8GiB row for
`owned-linux-package-build-<correlationId>` with operator `root-tmux-build`.
The route derives its identity from the protected inventory; tokens are never
public inputs or outputs. It measures current host boot, complete QEMU identities,
capacity and disk identity, counting all existing pending/running reservations.
Start/preflight require the sealed admission; staging and release recheck it.
Legacy86 status/collection remain available through the original adapter.
The historical unbound8GiB row remains counted and cannot be released from a
completed build's claim closure. New-start/disconnect native acceptance is pending.

The narrowly scoped `arch-tmux-install-preflight`, `-start`, and `-status` actions
take host=archlinux, correlationId and exact sourceSha, plus optional bounded
timeoutSeconds. They install only the currently admitted signed extra/tmux
candidate, using the ignored private sudo credential through SSH stdin.
The one-time209dd37d installation and fresh MCP status both verified3.7_c-1 and
package integrity. A consumed installation is observed, never resubmitted.

First native build02f4a070 failed while the original full Git clone reached its
60-second limit, before tmux preparation or build release. Its raw receipt and
claim remain preserved. A separately reviewed source-staging recovery and
shallow exact-source fetch are required before another correlation is admitted.

## Why this purpose

Native scenario and Android installer dispatch already detach their workers,
record process generations before release, and resume by observation. They do
not need tmux. The Linux package fixture coordinator detaches locally, but its
remote build remains foreground and its tar result streams over SSH stdout.
A disconnect can lose that stream. This companion saves `result.tar`, private
`build.log`, and a terminal receipt on the remote host before collection.

## Admission and source authority

The caller owns host authentication, build-host admission, sole environment
claim, transfer, and source staging. The local-host companion does not establish
those facts and must not be exposed as an arbitrary path or command API. It
accepts exactly the `linux-package-fixture-build` purpose, `archlinux` host,
`owned-linux-package-build` environment, canonical UUID, source SHA, and ordered
versions. Only the fixed reviewed packaging helper is executed.

Product source remains bound to its exact Git HEAD and clean tracked files.
A reviewed tooling overlay is permitted only at
`agent_tools/linux_package_fixture_build.py`, whose separate SHA256 is fixed in
the companion. Any other tracked modification is refused. This separation does
not relabel the tooling overlay as product source. The public adapter stages a shallow fetch of the exact source SHA before
preparation; it never substitutes branch-latest source.

The existing source job and its parent must be owned private directories. The
socket pathname must be shorter than 100 bytes. No shared/default tmux server,
configuration, interactive shell, attach UI, or arbitrary command is exposed.
The authority model is one authorized operator in a private owned build job;
it does not promise atomic exclusion of arbitrary hostile same-UID writers.

## One submit and reconnect

1. Read-only `preflight` checks tmux availability, source, private job identity,
   and absence of a launch fence and socket.
2. `start` fsyncs a create-only launch fence and fixed worker source before one
   dedicated-server submission. The pane waits for release.
3. The original server and pane PID/start ticks, socket generation, source,
   worker, and job proof are durably anchored. `start` returns `prepared` and the
   original full anchor pin WITHOUT releasing the build. Preserve it durably
   outside the remote job, then call one-shot `release`. The preparation gate
   expires after five minutes without release; expiry is unknown and never
   retried. Lost release responses can be observed using the retained pin.
4. `status` and `collect` require that external pin. They never launch or restart
   a session. A lost submit response leaves a consumed fence; do not retry.
   Without the original external anchor pin, no running authority is claimed.
5. Status exposes finite metadata only. Build logs remain private. A terminal
   means the wrapper finished; exit code zero is not artifact acceptance.
6. Collection reads only `result.tar`. The first chunk hashes the complete
   archive and returns a full generation/digest pin; subsequent chunks reuse
   that external pin and reject generation changes. Chunk size is bounded at
   1 MiB. Preserve the exact terminal pin throughout. For production large-file
   transfer, the root adapter may implement a fixed streamed transfer under
   the same proof and must verify the full digest after transfer.
7. Run the existing package artifact verifier on the collected complete archive.
   Its receipts remain authoritative for source, versions, package bytes, and
   build timing. No tmux status promotes package readiness.

There is no close/kill API. Packaging can leave Gradle descendants, so pane exit
alone does not prove no child runtime. No foreign session, server, VPN, or
runtime is stopped. The normal dedicated tmux server may exit when its pane
ends; immutable spool and terminal collection do not require a live server.

## Routine regression

`python3 -m unittest agent_tools.tests.test_ssh_tmux_session`

Tests use inert subprocess/tmux stand-ins and real private local files/sockets.
They cover lost response/no duplicate, reconnect identity, source replacement,
foreign sessions/socket, missing tmux, strict inputs, private output, and actual
generated wrapper spool/terminal ordering. They do not constitute a native
Arch/tmux acceptance result.
