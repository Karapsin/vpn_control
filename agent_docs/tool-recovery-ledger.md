# Automatic tool readiness and recovery ledger

## Scope and custody

This infrastructure task started on 2026-10-20 in the independent clone
`/Users/karapsin_de/projects/vpn_control_tool_recovery`, from verified
`origin/dev` `d24c19047ec15689948404ede40f50c5ec284e77`. Its own project
configuration was generated and the normal `prepare_start`, `docs` and
`change_impact` CLI workflows completed. The session's original MCP server is
bound to the paused checkout; do not use that server to modify this clone.

Windows product parity, product acceptance and visual review remain paused.
Do not change the paused checkout, its prepared packets, evidence, remote VM
or unresolved operations. Request `820e102a-12a9-4e5d-9a9d-f8071b729cc0`
remains UNKNOWN and its helper must be retained. Display dismissal
`88b307ca-2d01-421e-88f0-6d6388d931b7` was completed before this task;
this task does not authorize further inspection or sign-in in that fixture.

The user authorized copying transport access only into this clone's private
inventory. VM profiles, Android mappings, fixture paths, operation history and
Windows input/credential profiles were excluded. The original inventory bytes
were verified unchanged. Private inventory and evidence are never committed.

The user subsequently explicitly authorized deleting existing VMs on this
MacBook to free storage. The stopped local Tart VM
`vpn-control-boot-control53` was deleted using `tart delete`; `tart list`
then showed no VMs and available storage rose from about 400 MiB to 48 GiB.
This authorization does not extend to the paused remote Windows fixture.
The user also authorized deleting Colima's persistent container data and unused
local VM assets. Colima VM/data and an unused Android API29 system image were
removed; the active task fixtures and all original evidence were retained.

The user explicitly replaced the original real five-hour idle qualification
with accelerated testing. Production calls retain 18,000-second SSH idle
persistence. Do not wait five hours as an acceptance gate.

Local/SSH transport parity was audited and then explicitly deferred by the
user. No provider-host executor or new transport envelope was implemented.
The current task covers automatic recovery in existing supported modes:
Android and Tart on a local provider host; raw QEMU and libvirt through SSH.
DIRECT native, MCP and CLI coverage is required within those modes. Do not
claim two transport modes from a single-mode result.

## Implementation ownership

| Area | Owner | Scope |
| --- | --- | --- |
| Coordinator and delivery | Root agent | Readiness admission, integration, dependency mapping, ledger, checks and exact-SHA delivery |
| SSH prerequisites and readiness | Transport worker | Reviewed five-hour persistence, proven-prelaunch E2BIG, generated-program dependencies, owned transport recovery |
| Durable jobs | Durable-job worker | Detached owner, atomic admission, retained streams and original-operation reconciliation |
| Action policy / Windows fixtures | Catalog worker | Frozen exposure audit; new raw QEMU/libvirt Windows acceptance and adapters |
| Provider fixtures | Provider worker | Independent Android fixture, capacity gate, provider observations and qualified lifecycle adapters |
| Keep-awake | Lease worker | Expiring, cancellable owned leases and original-setting restoration |
| QEMU Linux | QEMU worker | Headless guest, positive idle proof, lifecycle and registered adapter |
| Tart | Tart worker | Sequential Linux/macOS fixtures within aggregate memory/disk reservations |

## Admission and non-replay boundaries

`ensure_ready(context, requirements, operation_identity)` binds target,
machine, connection, boot, account and session. Call it before constructing
commands; call `revalidate` immediately before dispatch and GUI input.
Unsubmitted stale preparations may be regenerated. Submitted or uncertain
operations retain their original identity and observation route.

Requirements distinguish transport, running guest, guest agent, ordinary
session and interactive desktop. Intentional disconnected, locked, signed-out,
sleeping, paused, suspended and stopped phases are not repaired. Local metadata
and existing local-only status/collection do not acquire a connection. Remote
original-operation observation may restore transport, never wake its VM.

Recovery has a stable per-target private journal and cooperative lock. Power
and credential submissions have create-only identities; a lost acknowledgement
causes observation. A later positively closed phase may admit a new transition.
Graceful reboot is limited to one per original admission and requires complete
positive visibility of reservations, running and UNKNOWN jobs, installers,
lifecycle phases, operators and protected processes. Missing visibility blocks.
The coordinator host cannot receive guest power/session recovery.

The user additionally requires explicit target selection for every VM-affecting
entrypoint. New readiness calls require `fixtureId`; original-operation status
and reconciliation retain that original target. Legacy visual lifecycle routes
now require explicit provider targets and reject mismatches before mutation.
Controlled whole-before callers reproduced default-target power, wrong-QMP-peer
power, foreign-AVD settings changes and default Windows bootstrap; all four
fixed callers reject before effects. Low-level Android leases also reject a
declared-machine/AVD conflict. The Android permission reset now selects explicit
host/device, and new Mac server-stop requests require a matching `vmName`.
New credential probe/recovery starts now require an explicit environment bound
to the configured VM descriptor before private input, reservations or transport.
Four legacy VM-associated mutation phases now also require the explicit original
process generation. Controlled causal checks pass for these gates and the two
credential routes. The scoped audit covers all 407 VM routes; final native
source qualification remains required before a delivery claim.

Normal readiness budget is 180 seconds, cold start/reboot 600 seconds, bounded
by a shorter caller deadline. Transport attempts are limited to three with
1/2/4-second backoff. Trust, ownership, credential and integrity failures remain
specific blockers. No rebuild, force reset or disk restoration is authorized.

## Evidence and acceptance status

These are partial, source-bound observations, not completion claims.

| Lane | Direct evidence | MCP/CLI equivalence | Remaining gate |
| --- | --- | --- | --- |
| Direct and explicit nested SSH / durable jobs | Earlier native short-expiry, network-loss and client/server-loss cases preserve original execution and retained output. Current channel custody and protected sudo carriers pass; current saved-script sentinel `3ba29293` is healthy-path proof only | Earlier fresh MCP reconciliation and exact CLI collection pass; current-source direct and nested interruption campaigns are being prepared on separate controls | Repeat faults against the final source without touching shared connection `3ec9cdaeb`, then managed checks and exact-SHA delivery |
| Android emulator | Independent API35 fixture passed wake, pause/resume, graceful reboot and persisted stopped/start; complete native-owner inventory blocks UNKNOWN work; a counter progressed 44→80 through private ADB daemon loss and collected the same terminal result after a second loss. Direct lease expiry across daemon loss restored the captured original setting through one retained restoration owner | Fresh MCP healthy, server-loss and client-loss jobs each retained all 80 lines with one execution; CLI collection matched and all ten server/relay actors closed. Fresh MCP/CLI lease expiry, cancellation and daemon-loss restoration passed; all 37 client/server actors closed with 1,381 source inputs unchanged | Direct guards and fresh MCP/CLI idle reboot passed once under operation `7b874295-68d1-4909-9ead-c25fff5ff6d5`; positive closure `7b02dcdf-8fdb-40cf-8799-61fd6239a62b` retired only the completed independent fixture. The staged API35 update worker no longer re-admits through an unstaged import; rerun the native installer update scenario. Final managed checks |
| Raw QEMU Windows | New secured fixture `942cca12-3296-4363-a5bb-e4df996883dd` passed direct retained counter; older fixture `21b29aa0` remains quarantined with its original UNKNOWN login. Pause/resume, display wake and native display/system leases passed separately | Current fresh MCP counter `f761f1c5` retained one execution and all 240 values through client/server and actual SSH-channel loss; automatic same-request recovery passed, and complete CLI collection matched | Protected current-protocol unlock, signed-out recovery, supported S3, qualified start/reboot and complete facade equivalence |
| Raw QEMU Linux | Current direct and normal-route pause/resume, S3 wake, positive-idle reboot and same-persisted stopped/start passed. Strict census blocks actual unmanaged ordinary work. Current fixture `0f559886` remains running and retained | Fresh MCP/CLI lifecycle equivalence passed. Counter `15e956d7` retained one execution and all 120 values through client/server loss. Final S3 operation `2105` resumed the same actor and boot once; CLI matched | Final source qualification after shared edits, managed checks and exact-SHA delivery |
| libvirt Windows | Fixture `6e848ad1-8078-4435-9abc-e3a24c6556cd`; exact daemon socket proves active domain. Earlier protected ordinary sign-in and native leases passed, but do not qualify the replacement login protocol | Current fresh MCP counter `7caab074` retained one execution and all 240 values through server and actual SSH-channel loss; same-request observer recovery and complete CLI equivalence passed | Positive full idle, current protected login, supported S3 and lifecycle startup/reboot proofs; start/reboot qualification remains open. The creator pre-VM claim of `7e8b2dcd` now has a reviewed closure (stage-1 source, Stage 2b route fence, root rulings); after exact-SHA CI including the root-census step, run its runbook R1–R3 once, then linked attempt 2 for fixture `a3aec884` |
| Tart macOS | Same 25 GB disk/run `2d933a39`; protected ordinary desktop is verified as UID 502/session 100237. Guest agent, fixed root probe and source-qualified factory passed. Canonical counter `2c129a5f` retained all 80 values and one execution after an uncertain initial acknowledgement and fresh-client observation | Normal lease expiry and active cancellation pass fresh MCP servers and exact CLI collection; counter fault cases remain open | Generic protected session recovery, positive full idle and supported lifecycle recovery; locked/sleeping background probes do not unlock or wake |
| Tart Linux | Pinned Ubuntu existing-instance start and current-source idle reboot passed; canonical retained counter survives client loss; collected legacy jobs close automatically after verified reboot and root absence. Positive shutdown, actor absence and owned resource retirement completed | Fresh MCP/CLI persisted start, canonical guest counter with client/server loss, and same-operation idle reboot passed; reboot operation `f5311b9f-8ea9-4c7e-9c9e-67d58fe05c37` produced one effect | Final managed checks |
| SSH idle persistence | Production 18,000 seconds; accelerated real 2-second expiry and daemon ownership join passed | Generated callers retain five-hour defaults | No five-hour dwell required under explicit user override |
| Policy / routine coverage | Exhaustive action catalog and physical source custody; shared reboot admission requires all seven idle categories and preserves same-operation recovery | 660 actions across 28 surfaces audited; 407 VM routes and current target source pins pass | Exact literal routes keep the catalogue finite; 259 VM actions fence every pure refusal before readiness (255 exact, 4 reviewed residual) under an AST contract test. The TEST-006 frozen full audit ran all 855 modules (9,657 tests); every failure was fixed and rerun first. Final managed prepush, commit/push and exact-SHA five-workflow verification remain |


Private evidence is under `.runtime/tool-recovery/` and
`.rag_index/tool-recovery/` in this clone. The durable gateway sentinel's
original operation is `a0e0b122-c24c-444f-9d58-08e6141f81ab`; its custody
record contains its task-only remote root, machine/boot/account, owner generation
and source digest. Never use an SSH disconnect as authority to run a replacement.

## Encountered failure types

| Failure | Cause or boundary | Causal regression and native limit |
| --- | --- | --- |
| Recovery fixture checkout bytes | Windows Git conversion changed four raw-hashed reflection PS1/native JSON payloads | Authentic old attributes reproduce all four mismatches through real Git checkout; explicit byte-preserving policies pass the same test and native-evidence readers |
| Running reservation double count | Post-start bookkeeping counted its exact already-live VM twice | Whole before helper reproduces 62 GiB refusal versus correct 60 GiB projection; same original `48c16ebf` reconciled its reservation without another VM start. Adjacent journal/inventory crash-gap causal coverage also passes |
| Concurrent lock initialization | A competing caller can see a newly created empty lock before its writer finishes | Whole-before real-process barrier reproduces empty publication; atomic complete-inode no-replace publication passes locally and on the Linux host |
| Actual kernel E2BIG | Inline launch was conclusively refused before child creation | Preserved transport/program beforeimages; actual RED/GREEN saved-file execution while retaining 60,000-byte boundary |
| Short idle persistence | Fresh/recovery generated callers used shorter persistence | Preserved generated callers; actual executed RED/GREEN; production default remains five hours, accelerated expiry accepted by user |
| Generated-program dependencies/custody | Missing loader/client dependencies and stale-source boundaries | Preserved causal fixtures and focused suites, including actual SDK initialization |
| Detached owner reaping | Popen handle could be discarded without reaping | Preserved original owner and warnings-as-errors RED/GREEN; original child is reaped without replacing work |
| Disk exhaustion | Initial dependency install failed ENOSPC; original emulator exited before boot with hasSufficientDiskSpace refusal | Original stderr/actor/terminal evidence retained; capacity admission must fail before bootstrap/launch, causal RED/GREEN in visual tests |
| Master lifecycle / network blackhole | OpenSSH daemonizes ControlPersist parent; a live socket can outlast connectivity | Exact owned daemon join and independent successor retain history; real short-expiry and controlled native blackhole RED/GREEN |
| Source execution custody | Timestamp-valid foreign bytecode, missing closure dependencies and list-subclass escape | Verified captured-byte execution and retained saved-plan custody; authentic beforeimage RED/current GREEN |
| Android installer/power observations | Idle PackageInstaller process was not an active install; full power dump exceeded bound | Session-specific installation census and bounded streaming power projection; original native evidence and causal regressions retained |
| Storage / memory aggregation | Separate sparse-disk growth and retained provider reservations were not summed | Durable shared plans and aggregate admission; concurrent and native causal RED/GREEN |
| Exited writer observation | Unreaped original child still answered kill(0) | Kernel terminal observation and original-owner reaping; real-process regression and preserved driver evidence |
| Windows provider preflight | Unrelated pacman repository warning; remote clock briefly ahead of local | Local installed-package database query and bounded clock catch-up preserve original guards; actual RED/GREEN and new original admitted installer |
| Native endpoint refusal | Private-master loss followed by three new connections hit gateway resets; cause unproved | Original jobs independently completed once with retained output; bounded controlled caller preserves UNKNOWN and specific transport blocker |
| Android durable-owner bootstrap | Native SELinux denied named FIFOs in the private shell directory; the initial unsupported-flag diagnosis was disproved | Authentic beforeimage and actual denial retained; anonymous-pipe capture and bounded overflow regressions pass. New direct/MCP/CLI counters passed real daemon/client/server losses; the original legacy operation remains UNKNOWN |
| Client closing receipt after source change | Relay discarded the closing receipt when server source changed, masking the integrity result as a missing file | Whole relay/client RED and GREEN plus an isolated real gateway source-change scenario pass; original job collected once with complete retained output |
| Background action policy | New guest counter policies unnecessarily permitted login/display recovery despite requiring only a guest agent | Policy RED and GREEN preserve the no-login/no-display-wake invariant; current catalog and VM source audit pass |
| Shared dispatch deadlines and closing guards | Saved-source preparation repeatedly performed remote checks outside the target timeout; a closing connection-generation refusal could hide an already returned original result | Preserved whole beforeimages and real delayed socket RED/GREEN cover the absolute budget. Current native 108,911-byte saved program completed in 10.06 seconds; independent transport loss recovered once. One-use returned-result custody prevents target replay; provider consumers still need final acceptance |
| Linux idle admission gaps | Detached ordinary-account work and the acknowledgement-to-poweroff interval were missing admission coverage | Preserved whole beforeimages, causal controller tests and actual unmanaged-job refusal passed; complete emitted Linux protocol suite passed 26 cases. Final normal lifecycle acceptance remains required |
| Android initial lease acknowledgement | A valid admitted detached owner could remain temporarily unobservable before its first acknowledgement | Preserved complete facade RED/GREEN now returns bounded original-only observation guidance; native UNKNOWN→starting→ACTIVE→terminal passed. Separate harness baseline assumptions were corrected without changing or relabeling retained original settings |
| Android final reboot facade admission | Direct lifecycle proof did not cover projecting idle visibility and consistent guest-agent identities through the normal coordinator route | The normal-route causal refusal and focused adapter fix passed; later direct and fresh MCP/CLI reboot `7b874295` admitted all seven categories and completed once. The independent fixture was positively retired; final managed checks remain |
| Legacy raw Windows login uncertainty | Original controller did not retain the lock inode used before credential effects; current absence and wall-clock chronology cannot exclude historical replacement | Preserve raw operation `3be5067e` as UNKNOWN with its original helper and fixture. Do not replay credentials or power that fixture. Future protocol needs retained lock identity and separate native qualification |
| Native CI selector enrollment | Adding readiness selectors to the historical CP117 step violated its exact retained-selector contract | Actual existing guard failed on the preserved full workflow. Readiness now has its own unconditional native step; the same guard and a retained-beforeimage causal test pass. Real CLI enrollment confirms unaffected includes run; actual Git CRLF checkout preserves the new fixture bytes |
| Windows bootstrap private output | The existing gateway could retain and hash unexpected private payload echoes before semantic validation | Deployment-only gateway now retains metadata instead of raw private streams and emits only exact public mode/operation-bound projections. Complete real-socket echo, malformed, overflow, timeout, base64, extra-field and partial-prefix counterfactuals passed; native new-fixture use remains pending |
| Windows owner directory security | SYSTEM-created directories inherited an Administrators owner that failed the durable owner's explicit security contract | Original `d82c6b3b` remains UNKNOWN. Atomic explicit SYSTEM security-descriptor creation passed actual Windows kernel checks and independent retained counters; no repair or replay of the original directory |
| Windows original-owner observation | A brief initial acknowledgement gap and a disconnected observer channel exposed transport identity instead of continuing the original job | Whole before callers reproduce the failure over real sockets; bounded read-only retry passes. Current raw QEMU and libvirt MCP cases recovered automatically and collected one complete 240-value execution each |
| Apple VNC and keyboard dialect | Raw-only framebuffer negotiation crashed the first run; physical Shift and Apple-specific modifier mapping affected public setup typing | Original crash/terminal and complete unfixed sources retained. Controlled protocol causal tests and native second-run public typing pass. This does not qualify account recovery or an unfinished Mac backend |
| Historical Android dependency closure | Frozen diagnostic fixtures accidentally loaded current private helpers; staged installer imports lacked two current dependencies and action pins | Exact historical helper custody and finite current installer staging have focused causal RED/GREEN. Full affected rerun remains required; historical receipts and operation identities are not relabeled |
| Snapshot observation mutation | Reading a consumed admission snapshot recreated a missing journal lock | Whole before source causes an actual filesystem mutation; existing-only locking refuses with unchanged filesystem and preserves healthy consumed-snapshot checks. No remote packet changes |
| Native source catalogue closure | Current SSH readiness added finite dynamic dependencies; the channel keeper also began consuming a previously excluded retention helper | Complete old catalogue rejects the actual current callers. The fixed catalogue holds all new source bytes, accepts only matching package fallbacks and exact reviewed standard-library edges, and still rejects missing or unclassified dependencies; 25 focused Git/custody checks pass |
| Unbounded action routes after a table hoist | Moving the Windows fixture lifecycle table to module level, plus a prefix-matched Setup recovery gate, left `action.startswith` routing that the catalogue audit cannot bound; an extracted-closure route test also lost its module-level helpers | Exact literal action sets restore the finite bound (no unbounded routes; 660 actions across 28 surfaces audited). The audit's guard-weakening checks now cover the synthetic prefix join and the real lifecycle gate. Component-only; no native scenario |
| Pure request refusals after readiness | 153 readiness-requiring VM routes refused malformed input only inside the dispatcher, after transport readiness; for two Android `-start` routes readiness could start, resume, log in or reboot a guest first | Shared pure predicates fence every pure refusal before the first effect (259 actions). An AST contract test (drift pins, exact equivalence, dynamic differential) is actually RED on the unfixed source (273 subtests) and GREEN; 1,039,534 generated requests showed unchanged dispatcher behaviour. The strict HEAD CP117 rejected-input tests pass unchanged |
| Test isolation after the transport migration | `subprocess.run` fakes stopped intercepting `ssh_transport.run_ssh` (real `ssh <alias>` launches); routing tests reached real admission (a persistent ControlMaster when an inventory exists); tests wrote the native-failure ledger, GUI leases, the TEST-006 failure set and `.runtime` evidence, or read the private inventory | Two reviewed fix rounds over more than 40 test files. Each fix reproduced the leak with direct and nested TEST-NET decoy inventories under a host-tool sandbox, passed a mutation check, and four whole-suite sweeps found no remaining real-host reach or unneeded inventory read |
| Inherited stdin in managed runners | `mcp_server._run`, runner workers and the selector loop let child tests inherit stdin; under the MCP stdio transport a stdin-reading test could consume the client's JSON-RPC stream, and on a terminal it blocked | `stdin=DEVNULL` at all three launch points. Preserved whole beforeimages give actual RED (sentinel consumed, timeout) through each launch point and GREEN on the fix |
| Android staged update re-admission | The staged API35 update worker compiled the lifecycle main's new readiness tail unchanged, so it re-admitted through an unstaged import and failed with ImportError | A third finite, reviewed substitution binds the actor's outer guard instead of re-admitting; whole-before RED and GREEN, plus both Android whole-entry suites. The native installer update scenario must be rerun |
| Creator pre-VM refusal claim | Attempt 1 of `7e8b2dcd` stopped in the credential-listener phase before any VM existed and left its prepared resource claim UNKNOWN; no existing API could close it without a fabricated unsubmitted or clean-stop proof | A read-only observer proof, a journaled once-only closure with explicit resume authorization, a Stage 2b fence on the generic environment routes and linked attempt custody. RED on the unfixed tree and on the stage-1 writer, GREEN, and 21 killed mutants. Real-kernel root-census RED/GREEN runs in a new Fast Checks sudo step; native R1–R3 and attempt 2 follow exact-SHA CI |
| Historical source pins after the migration | Moving CP117 modules onto `ssh_transport` changed source hashes pinned across 25 modules and in reviewed selector declarations, so replays stopped at their first pin check | One cascade re-pin with exact, count-checked reverse deltas for the owner diagnostic, d24c1904 copies authenticated by provenance and no frozen fixture changed; 151 of 159 breadth modules green, the rest sandbox-only or the separately fixed ordering tests |
| Managed prepush agent-stage timeout | The complete managed pre-push ran the whole 808-module agent selection as one command, which outgrew the 50-minute per-command bound (the original run timed out with no per-module results); a failed-first rerun of that whole command would time out again | The planner runs the SSH-close gate alone first, then the two hosted CI shards from `shard_selection` without it, each with its own bound. Failed-level reruns do not run the gate first unless it was recorded: a timed-out, unparsed or import-failed command reruns once, never split recursively, without its removed modules (a row whose modules were all removed is skipped, single-module rows included), grouped by index parity in the sorted union of the current selection and its remaining modules, so for an unchanged selection a recorded shard reruns as itself. On timeout the launcher sends SIGTERM, so the runner stops its worker sessions before the next command, then SIGKILL after a 30-second grace; only the original timeout is reported, even for undecodable text output. `agent_tools.tests.test_mcp_failed_first_reruns` gives actual RED on the whole recovery-tree beforeimage (one unbounded command, an unchanged rerun that keeps removed modules, an immediate SIGKILL that orphans a worker session) and GREEN on the fix; the original timeout receipt is retained |
| Hosted agent shard timeout | Fast Checks run 40187427911 at `cc2873b5` split the 815-module affected selection into two hosted shards, and both 50-minute agent steps timed out: shard 0 after 4,543 tests and 2,870 s of runner time while still relaying public events, shard 1 with 105 assigned modules never started. Shard 0's selection and runner alone took 49.8 minutes; charging each unstarted module the mean measured module time, shard 1's share was 65 minutes. Above 256 modules per shard each relayed event also recompiled every module pattern, past Python's 512-entry regex cache, so shard 0's relay lagged about 1,000 events | Fast Checks runs the same sorted alternating partition as six hosted shard jobs (`CI_SHARD_COUNT`, at most 136 modules each), and the coverage job verifies all six current-attempt receipts; the managed halves stay exactly the hosted shards of each index parity. `test_agent_ci_shards`, `test_fast_workflow_budget`, `test_fast_agent_shards` and `test_agent_ci_evidence` are actually RED on the whole `cc2873b5` workflow, selector and verifier and GREEN with the slowest measured share at 25.8 of 50 minutes. Only the next hosted Linux run confirms each new shard's actual wall time |
| Durable status read across owner completion | Under the two-worker managed pre-push, `ssh_program_execution.status()` found no `terminal.json`, then observed the owner already gone, because the owner publishes its terminal and closing receipt and exits in between. It reported `unknown`/`original_owner_terminal_unproved` for a completed, verified job, and `reconcile()`, with the same order, started a redundant network reconciliation | After an owner-gone observation, both re-check `terminal.json`. An arrived terminal takes the unchanged binding, capture and stream validation, and one never published stays UNKNOWN. `agent_tools.tests.test_ssh_program_status_terminal_race` is actually RED on the whole beforeimage (13 subtests, including exited and reused owner pids) and GREEN; the 18 controller fixtures that pin the old source stay frozen evidence. Component-only; prepared SSH acceptance controller generations must be regenerated before their next native run |
| Gateway fixture registry wait shadowed | This task's leak fix added a registry-waiting `GatewayOwnerTests.finish()`, but the existing `ReadyReconciliationTests.finish()` overrode it, so its cases and `ReconciliationStatusTests` never waited for their fake-tmux jobs, and a late `.done.json` broke temp removal under load | The override now always delegates to `super().finish()`, which keeps the home on registry failure, and the archived late-ready replay asserts one registry wait. `agent_tools.tests.test_ssh_gateway_ready_registry_cleanup` is actually RED on the whole beforeimage (the original `Directory not empty`) and GREEN, with a delegation guard over every override. Test fixtures only; no native scenario |
| macOS stage child bound on a directory-bound host | The wrong-account subtest of `test_macos_fixture_stage` runs the real guest bootstrap, which looks up the absent account; on this Active Directory-bound Mac an uncached absent-account lookup takes about 10 s, just past the harness's 10 s child bound, so the managed pre-push saw `TimeoutExpired`. A real guest or CI runner resolves it at once | The harness bound is 60 s and the subtest is unchanged. `agent_tools.tests.test_macos_fixture_stage_child_bound` runs the actual `run_guest` of the whole beforeimage and the fix against an owned wrapper that delays past the old bound: actually RED (`TimeoutExpired`) and GREEN (the guest's identity refusal), independent of the directory service. Test harness only; no native scenario |
| Partial worker stderr read | `test_original_route_order_failure_and_fixed_actual_worker` asserted the original worker's complete route-order error as soon as its stderr file was non-empty; the traceback arrives in several writes, so under load it saw only the first line | The test waits for the asserted error text itself within its deadline. `agent_tools.tests.test_ssh_program_route_stderr_completion` drives the actual test from the whole beforeimage and the fix with a controlled partial-then-complete observation: actually RED with the original assertion and GREEN with and without coloured tracebacks. Test only; unrelated to the status fix |
| Darwin zombie-only group in runner cleanup | On Darwin, `killpg` on a process group that still exists but holds only unreaped zombies returns EPERM, not ESRCH. `agent_test_runner.close_session` probed right after SIGTERM and every 20 ms, and `_stop_workers` signalled, catching only `ProcessLookupError`; a probe that landed between the SIGTERMed orphan's exit and launchd reaping it let `PermissionError` escape, so the runner CLI refused with exit code 2 and wrote no report. The session observer tests fed that original refusal into their assertions (`1 != 2 : Agent unittest runner refused: PermissionError`, or `PermissionError` at the original `close_session` line 526) and into their orphan cleanup | `close_session` treats EPERM as a present group and waits for ESRCH within its bounds, now also after SIGKILL, returning an incomplete result instead of raising; `_stop_workers` tolerates EPERM. The observer tests clean orphans with the current runner and give only the original-runner observations up to three fresh orphans on exactly that refusal. `agent_tools.tests.test_agent_test_runner_zombie_group` (Darwin only) keeps a group member as an unreaped zombie with an owned holder outside the group: actually RED on both whole beforeimages and GREEN, with 22 killed mutants. Local processes only; no native scenario |
| Tart registry harness read a finishing owner | The `terminal()` helper of `test_readiness_tart_macos_registry` called `OriginalOwner.observe()` as soon as the owner record existed. The frozen `durable_remote_job.observe()` checks `terminal.json` before it checks the owner's birth, and the owner publishes its receipt and then exits, so a finish between the two checks reported `original_owner_missing` for a completed job and the original two tests raised `macos_original_owner_unknown` (3 of 6 loaded sweeps) | The helper waits observation-only through the three transient durable states until the receipt exists, then reads through the original owner once; other states still fail at once. `agent_tools.tests.test_tart_macos_registry_terminal_race` runs both original tests of the whole beforeimage and the fix with owned launch and program gates, so the owner finishes during the second observation of its live record: actually RED (the original `MacBlocked` trace) and GREEN. Test harness only; durable observe and the registry are unchanged and no native scenario. The same order remains a fail-safe product defect in the frozen `durable_remote_job.observe()` (a finished job can read UNKNOWN once); its fix waits until the Windows creator closure no longer pins that source |
| Control-check observation deadline | `test_ssh_nested_control_crlf` gave its real `/usr/bin/ssh -O check` child of an owned absent socket a 5 s deadline. The child normally exits in milliseconds, but on this Active Directory-bound Mac its service lookup waits for `opendirectoryd`, whose directory reconnect times out after 10 s several times an hour. In managed pre-push run 5 the child had not finished by the deadline, so the capture was unfinished, the unfixed `_failure()` returned `unavailable` and the case failed with `AdapterBlocked not raised`; a later loaded run logged both copies' ssh children held 10 s by that reconnect | Each actual observation is bounded at 60 s and every assertion is unchanged. `agent_tools.tests.test_ssh_nested_control_crlf_deadline` runs the actual case of the whole beforeimage and the fix while an owned wrapper delays only that control-check launch by 11 s and then execs the real ssh: actually RED (the original message at 5 s) and GREEN (the exact CRLF answer after both delays). Test harness only; no native scenario |
| Creator listener identity on Linux | Fast Checks run 40187427911 at `cc2873b5`: `CredentialWireTests.test_fixed_generated_sender_original_owner_lost_ack_never_resends` read `listenerReady` false. The unix-address fix binds `credentials.sock` through the creator's held job descriptor, Linux `/proc/net/unix` keeps that sun_path verbatim, and `_creator_status` accepted only a listening row at the canonical job pathname, so no Linux HOST, attempt 2's included, could report the listener ready | `_creator_status` joins the creator's own `socket:[inode]` descriptor links to exactly one listening stream row at the canonical path or at `/proc/self/fd/<d>/credentials.sock` whose descriptor resolves, by path and identity, to the held job directory; foreign, other-directory, aliased, overmounted, stale, replaced, non-listening and second listeners stay false. Review of the first fix (`39f54981`, never landed) found that the kernel ends a row only at a newline and prints names verbatim, so a local socket name could carry a row naming a creator socket that was not its live listener; the join now splits the bytes only at `\n`, needs the matched inode in exactly one row, and re-reads the creator's descriptors, which must still hold that socket and the named job descriptor. `agent_tools.tests.test_windows_managed_creator_listener_identity` runs the actual status code of the whole `6ad3dae7` beforeimage and of the fix over a kernel-format synthetic `/proc` on every host and over the actual kernel on Linux: actually RED and GREEN on 3.14 and 3.12, its carried-row, closed-descriptor and line-end cases also RED on the first fix in a review clone, with 25 of 26 mutants killed (the survivor is equivalent here). The Linux wire test now prints complete listener facts on failure, and its once-fence comparison no longer includes the access time its own repeat read moves under relatime. A carried row naming a creator socket that has no row of its own (not AF_UNIX, or in another network namespace) stays undetected; the creator's own code opens none before its listener closes, and the handoff still checks its peer. The fix re-pins `readiness_windows_managed_create.py` in the creator pre-VM closure writer, so that source epoch changes before R1; the real kernel is covered only on the hosted Linux runner |
| Windows-absent POSIX test APIs | At `cc2873b5` the Windows Desktop Package release-hygiene step failed 17 cases in `scripts/test_visual_platform.py` and `scripts/test_visual_target.py`: they reached `socketserver.UnixStreamServer`, `socket.AF_UNIX`, the POSIX storage-plan lock, direct `#!` launches and `/bin/bash`, which Windows CPython and CreateProcess lack; every product path involved is POSIX-host-only | Each case skips on the exact missing API or launch semantics, and portable siblings keep running. A new executable capability probe in `scripts/check_python_platform_contracts.py` removes those APIs and models the two CreateProcess launch shapes: actually RED on the whole `cc2873b5` test beforeimages (all 17 CI outcomes) and GREEN. Real CreateProcess, PATHEXT and Git Bash remain Windows-runner only |
| Windows PowerShell 5.1 stdin harnesses | The first run of the new Windows causal step failed two harnesses that piped programs to `powershell.exe -Command -`: a multi-line function put the console host in block mode, and without a blank line the pending block was discarded at end of input (exit 0, no output); `Add-Type` raised its terminating compiler error after the non-terminating diagnostics, so it reached stderr | Both harnesses run the exact program from an owner-only `.ps1` with `-File`, and the compile harness catches the terminating error into its diagnostics; failures print complete output. A documented console-host and Add-Type model gives actual RED on the whole `cc2873b5` harnesses and GREEN locally; the real 5.1 behaviour is confirmed only by the Windows runner |
| Interpreter-dependent AST digests | `readiness_windows_host_work._source` hashed `ast.dump(node)` per function, and Python 3.13 changed that text, so digests reviewed on this host's 3.14 refused every authentic source on CI's 3.12 (`windows_host_work_source_unreviewed`, 8 errors) | A canonical `_syntax` rendering reproduces the reviewed digests unchanged on Python 3.10 to 3.15. `agent_tools.tests.test_windows_host_work_ast_digest` is actually RED on the whole beforeimage under the 3.12 text and GREEN under both |
| Linux-only test assumptions | Linux CI ran tests that this macOS host never had: the fixture SSH daemon was named `ssh` in `ps`, ext4 reused a freed inode number for a same-size replacement, host births read `linux:<ticks>` where macOS guest actors were expected, the runner's descriptor limit let an 8,200-descriptor holder outlive its scenario, and the stand-in qemu interpreter lived under a world-writable path | Test-side fixes for each cause, with quick regressions that are actually RED on the whole beforeimages (emulated where the platform differs) and GREEN; every touched Linux test prints complete diagnostics. Only the next Linux run confirms the real kernel, filesystem and runner behaviour |
| Proxy drop observation race | `ProxyObservationTests.test_exact_owned_drop_once_receipt_and_no_live_pair_replay` timed out on Linux CI: the selector candidate's `drop_once` closed sockets that the forward thread kept registered in a persistent selector, and closing a registered descriptor drops its queued readiness, so the forwarder never observed the drop and a second drop was accepted | `drop_once` only shuts the sockets down and the owning forwarder closes them. A new whole candidate source carries the fix, the original stays frozen evidence, and a controlled regression holds the forwarder outside its wait during the drop: actually RED (lost drop, replay accepted) and GREEN. Epoll itself runs only on Linux CI |
| Android owned-descendant child program syntax and timeout report | `OwnedDescendantLinuxTests.test_actual_separate_session_descendants_reaped_and_flag_restored` failed after 13 ms in Fast Checks run 40187427911 with no surviving traceback. With the added diagnostics, run 40232090301 at `005852a2` showed its `python -I -B -c` child exiting 1 with `SyntaxError: unterminated string literal (detected at line 22)`: the case wrote the program in a non-raw triple-quoted literal, so the escape child's newline pid terminator reached the child as a real line break inside a one-line string. The child compiles the whole program before running it, so the case failed this way on every Linux run since `60bb1a26` and is skipped elsewhere; the program was byte-identical in both runs. Review of that fix found that a child outliving the case's 8 s timeout failed it as a bare `TimeoutExpired`: the separate-session sleepers that `cleanup_selftest` forks inherit the child's output pipes, so a refusal before they were killed left the child's error unprinted and reported no host facts | The program literal is raw, as in its descriptor sibling; the authenticated owned-descendant fixture and its self-test were already escaped correctly and are unchanged. `agent_tools.tests.test_android_owned_descendant_child_syntax` runs the original case of the whole `005852a2` beforeimage, which fails with the exact CI message on any host, and hands both cases' exact child argv to the real interpreter with only the fixture argument replaced by an owned probe: actually RED (exit 1, the SyntaxError at line 22, the probe never runs) and GREEN (the probe runs) on 3.14 and 3.12. The case now fails from that timeout with the child's captured output and the host facts. The module's timeout control runs both cases' exact call under a real 2 s timeout, with only the fixture replaced by an owned probe whose separate-session descendant holds the output pipes until released: actually RED (a bare timeout) on the beforeimage with only the raw fix, which is the reviewed syntax-fix module, and GREEN on 3.10 to 3.14. Test only; the subreaper, PIDfd and `/proc` behaviour of the fixed case is confirmed only by the Linux case on the next Fast Checks run |
| Descriptor counts disturbed by earlier garbage | At `005852a2`, `ProviderEndedClosureHistoryTests.test_actual_equal_source_ended_then_new_intent` saw `43 != 7` open descriptors on Linux CI. Earlier modules in the same serial worker leave cyclic garbage whose private-config owners hold descriptors until collected, so a collection inside a later global `/dev/fd` count moves it; the measured code opens and closes all of its own descriptors | A shared `descriptor_window` helper finalizes pending garbage, keeps the collector off for the measured window and compares exact descriptor identities, printing both tables on failure; it is applied to every test with the same global count. A controlled regression is actually RED on the whole beforeimages and GREEN, and a real descriptor kept by the measured code still fails |
| Worker traceback read before its exit | `test_direct_source_session_lazy_dependency_before_red_current_green` failed on Linux CI with a traceback cut off at an import frame: the shared `terminal()` helper reported a legacy worker's stderr at its first non-empty observation, while CPython 3.12 was still writing the traceback line by line | `terminal()` reports the stderr only after the exact recorded worker has exited, and reports it whole. A regression drives the actual case from the whole beforeimage with a controlled partial-then-complete write: actually RED and GREEN on Python 3.11 to 3.14 |
| CPython 3.15 suggestion in probe comparison | The macOS runner's CPython 3.15 adds nested-attribute suggestions, so the simulated AF_UNIX absence ended with `Did you mean '.AF_APPLETALK.AF_UNIX' instead of '.AF_UNIX'?` and no longer equalled the five recorded Windows lines | The probe comparison strips the interpreter's trailing suggestion from both sides; every recorded Windows outcome stays exact. A regression with the exact CI line is actually RED on the whole beforeimage and GREEN on CPython 3.10 to 3.15 |

Additional retained failure classes include lost connection-readiness publication,
terminal failed connection generations, old failed history hidden by a changed
current pointer, stale saved-transfer non-submission claims, Android implicit
ADB daemon startup, libvirt's wrong default session socket, APFS clone capacity
accounting, UNKNOWN guest roots with no process, Windows Session 0 display leases,
and Windows token-restoration acknowledgement failure. Their owned beforeimages,
original evidence and same-scenario causal tests remain in this clone. Native
qualification of a component does not qualify an unfinished provider facade.

Normal SSH and VM readiness status also exposes a pure local recovery projection: original recovery and operation IDs, actions, attempts and retained outcomes. It creates no directory or lock, contacts no provider and grants no replay authority. Fourteen focused tests cover shared reboot callers, malformed records, concurrent publication and protected metadata.

Current component validation includes 101 coordinator, admission, original-operation,
public-route and guidance tests passing together. The normal affected selector
accepts the finite source mappings (577 of 644 modules at that snapshot); this
is a selection result, not a final test or managed pre-push receipt.

The normal finite `readiness-reboot` action uses `idle_reboot(context, operation)`.
It requires an already running guest and complete positive idle proof. It shares
pending recovery across callers, retains each caller's original association and
observes repeated operation identities after a changed boot. It never starts or
resumes a guest merely to reboot it. Normal readiness continues to perform no
power recovery for a healthy guest. Readiness completion can reconcile retained
original resource-owner bookkeeping; a failure or changed generation blocks
packet admission rather than launching another guest.

## Resume procedure

Read the [fresh-agent handoff](tool-recovery-resume.md) for original job identities,
active UNKNOWN custody and the remaining native acceptance sequence.

1. Continue only in this clone. Run its CLI `workflow-status`; inspect this ledger
   and the private evidence, never the paused checkout's tool server.
2. Reconcile task-created native actors, leases and remote jobs from their
   original receipts. Do not replay an uncertain submit or repurpose the paused VM.
3. Preserve each newly encountered failure and unfixed beforeimage; implement
   actual causal RED/GREEN and retain its native scenario under TEST-001/002.
4. Complete every provider's direct scenarios, then matching fresh MCP and CLI
   cases. Keep unsupported/unqualified capabilities explicit. Use short expiry
   tests and retain five-hour production defaults. Mock results cannot fill the matrix.
5. Review scope, call `version_bump` after final edits, run affected tests and
   fresh managed prepush, commit explicit paths, push dev, and verify all five
   required workflows for the exact SHA. No release is authorized.

## Current integration checkpoint

### Source integration checkpoint (2026-10-24)

The recovery clone now carries one reviewed source set for delivery. The CP117
re-pin cascade, exact literal action routes, pure request fences before readiness,
two rounds of test-isolation fixes, the managed-runner stdin fix, the Android
staged update substitution and the stage-1 creator pre-VM closure are integrated
with whole beforeimages, actual RED/GREEN where a defect was causal, and appended
reviewed-loader pins. Each fix was implemented in sandboxed clones without the
private inventory and passed an independent adversarial review; decoy-inventory
sweeps of the whole suite found no remaining real-host reach.

The TEST-006 frozen-snapshot audit ran all 855 modules (9,657 tests). Its eleven
real failures came from two shared-worker causes, both now fixed in tests: three
modules left umask 077 behind for later suites, and master-socket fixtures built
socket parents under the runner's private TMPDIR, which the production provenance
rule correctly refuses. The failed-first rerun through the actual runner passed;
the two local OpenSSH probes pass with real OpenSSH. The remote Claude Code project
configuration commit is merged (HEAD `2dfa2f2e`) and the version bump is recorded.
The first managed prepush timed out in its single agent-test command. Its
failed-first rerun passed in two bounded commands, and the agent stage now runs the
SSH-close gate alone, then the two hosted CI shards. Before publication, the
committed Spotlight lock-screen frame had its location-derived weather card filled
with the card's own colour, outside every gate crop; the original native frame
stays in private local evidence. The next complete pre-push passed everything
except three agent tests with two causes, both now fixed with causal regressions: the
durable program status race and the shadowed gateway fixture registry wait. The
following complete pre-push hit two test-timing flakes, an absent-account lookup on
this directory-bound host and a partial worker stderr read, both fixed with quick
causal regressions. A third run hit a control-check deadline, so two concurrent
full-selection sweeps under extra load, three rounds, looked for the rest: they found
the runner's Darwin zombie-group cleanup defect and a Tart registry harness race, both
fixed with causal regressions with the deadline, and a confirmation pass showed only
host-stub artifacts of the sweep harness. Still unfixed and seen only under heavier
than managed load or with concurrent full runs: a worker-order pairing assertion in
`test_agent_test_runner`, ancestor-generation pins over shared temporary or home
directories, and the frozen durable observe race above. The delivery commit
`cc2873b5` passed the Android, Linux and macOS package workflows, but exact-SHA CI
failed on Windows (POSIX-only test APIs and two PowerShell 5.1 stdin harnesses) and in
Fast Checks (interpreter-dependent AST digests, Linux-only test assumptions, a proxy
drop race, the creator listener identity defect in the pinned managed-create source,
and a hosted shard timeout). All are fixed with regressions; the creator closure was
re-pinned before its first proof, and its R0.1 to R1 steps restart against the new
digests. The follow-up `005852a2` passed the Android, Linux and Windows package
workflows, including both PowerShell harnesses, and every Linux runbook gate ran
without skips; Fast Checks and the macOS package then showed four test-side types
(the Android child program, garbage-disturbed descriptor counts, an early worker
stderr read and a CPython 3.15 suggestion), all fixed with regressions. Next: the
failed-first rerun, a fresh managed prepush, the commit, push and exact-SHA
verification. The creator closure's native runbook and the remaining provider lanes
follow that delivery; no native step ran in this checkpoint.

Local/SSH transport parity remains deferred. The latest narrow integration fixes
preserve finite backend credential/trust/identity blockers, remove discarded
Windows packet construction before readiness, and publish complete private Windows
admission records atomically. Whole retained beforeimages reproduce each failure;
focused suites pass. Native Windows counter acceptance passed on both current
raw QEMU and libvirt fixtures: initial owner acknowledgement and an actual lost
observer SSH channel recover automatically within the original request,
preserving one execution, all 240 values and complete retained output.
Fresh MCP and actual CLI collection are equal. The earlier `d82c6b3b` result stays UNKNOWN; a separate,
authenticated pre-execution rejection proof grants no replay or cleanup authority.

Raw QEMU Linux direct and fresh MCP/CLI S3 recovery pass on the same actor and kernel boot.
The original `cont` failure is retained; suspended guests require supported
`system_wakeup`, while paused guests retain `cont`. Current normal-route lifecycle
and continuous-counter acceptance are closed. Two earlier S3 incidents woke
automatically; their cause remains unproved and no production fix is claimed.

The macOS fixture's same 25 GB disk and existing run `2d933a39` now have
an authenticated ordinary UID 502 desktop, guest agent, fixed root probe and
source-qualified factory. Counter `2c129a5f` retained exactly one execution and
all 80 values through initial acknowledgement uncertainty and fresh-client
observation. Its canonical namespace uses `/private/var/tmp`; whole generated
callers reproduce the original Darwin `/var` symlink refusal and the fix.
Linux namespace fields and job identities remain unchanged. The ordinary
session later locked and its display slept; background probes continue without
input. Native v2 keep-awake expiry `2855d3d4`, cancellation `e78679a5` and
submitter death `4547` now have terminal originals, full retained streams and
verified assertion absence/restoration. The fresh observer saw the client-death
case after termination; continuous activity after client death is not claimed.
The old failed release receipt and failed cancellation observation remain
retained. Exact original assertion ownership and OS timeout evidence qualify
the narrow release fix. A new known-state wake and ordinary-account unlock
passed: `bff007a4` submitted the password once and Return once, then an independent
privileged probe confirmed UID 502, the same boot/session and an unlocked desktop.
Its internal 180-second lease `a7727061` was acquired once and cancelled once;
original owner/assertion absence, restoration and full streams are collected.
No filled field was retained or hashed. Normal MCP/CLI admission, signed-out
recovery and power acceptance remain open. The earlier bounded Shift exception
has expired; new wake incidents require authenticated state and journals.
The current v7 factory passed two source-held read-only guest observations under
the original operator lock. Its normal background lease requirement is guest-agent
access: locked or sleeping sessions do not trigger display wake or login. A
preserved whole-facade TCP regression proves the old unnecessary wake and the
fixed single background execution. Normal direct lease `6d4e3edd` now passes:
an initial registration-reference refusal is retained, a new source epoch proved
host and guest admission absence, and the same operation was admitted once.
An uncertain acknowledgement was followed by fresh ACTIVE observation, natural
expiry, restoration, complete original streams and kernel/IOPM assertion absence.
Cancellation arrived after expiry and is not an active-cancellation proof.
Typed client guidance now follows uncertain acknowledgements and running cleanup
by observing the original operation. Normal fresh MCP/CLI lease cancellation
`076cd86e` and expiry `afc2d9fe` pass with complete retained streams, restored
settings and independent owner/assertion absence. Cancellation was submitted
once after ACTIVE; each case used new MCP servers and exact CLI result equality.
All client/server contexts closed. The current alias is
`tart-macos-independent-v9`; no generic unlock or power capability is implied.
The finite network census found three active tunnel interfaces without complete
ownership/activity proof; the ordinary idle getter also returned an unavailable
result. Both retain reboot blockers. No Mac power action has been submitted.

Current Windows unlock `eeb329b5` stopped before credential admission because
19 selected-tile edge pixels changed. A host-only original-owner collector
proved its wake/dismiss phases ended and credential intent/phase were absent.
The blocked terminal remains immutable; this is no whole-attempt replay
permission. Exact interior-region recognition has actual-frame causal coverage;
a separately fenced, same-original credential-only continuation is undergoing
implementation and review. TPM ownership now passes a real privileged full
metadata census without connecting the live TPM socket. Lifecycle capabilities
stay disabled until original-host ownership and clean-stop/start acceptance pass.
The current full libvirt observation `f472276f` clears exactly two lifecycle
records backed by authenticated phase proofs and preserves twenty genuine legacy
gaps. A separate managed-first fixture `cc1092b6` is planned; no allocation has
occurred. Its creator and seed-detachment gates must pass source and native
review before ordinary sign-in or lifecycle qualification.
A fresh current-source read-only Windows probe `68ce6760` passed the original
phase, account and session gates, then stopped at an unrecognized screen.
It retained complete before/after source manifests and sent no input. Historical
`a24b` has reviewed source/output association but lacks a transitive closing
manifest; it has not been promoted to current native qualification.
The subsequent HOST-only cache observer `9199d361` failed on a missing `pathlib`
global before its first metadata read. Complete source and failure streams are
retained; no frame, guest call or input was produced. Its correction is private
caller preparation and grants no current-screen or credential authority.
The corrected new cache observation `e8593493` read an all-black retained frame;
that establishes neither original frame custody nor current desktop state.
Separate current typed read-only observation `035c093b` verified an asleep display
and the same locked ordinary session, boot and absent credential intent. It sent
no input and grants no known-empty-field or credential authority.

Integration testing also exposed and repaired portable readiness imports,
source-owned context-manager custody, isolated direct-CLI imports, and the
private-capture retention schema. A private SSH capture accepted a credential
prefix inside valid JSON before semantic validation; whole-before real-child
RED and closed public-validator GREEN now cover this boundary. Private input
lengths are no longer retained. Legacy transport snapshots and historical
helper pins are not upgraded to reopen private-hash paths.
Normal SSH recovery now qualifies a fresh connection `3ec9cdaeb` under operation
`22d0c803` while preserving all original connection and UNKNOWN campaign bytes.
The only accepted historical intent difference was directory membership
metadata; file contents, credentials, ownership, boot and source identity remain
strict. The new gateway-v2 operation `244ba7ec` passed real prepare/release,
readiness and owned orderly closure. Its original CRLF publication failure is
preserved with causal native RED/GREEN. Legacy tmux transport snapshots still
block; they do not acquire v2 authority by updating a hash.
Current automatic transport and tmux adapters also hold private keys without
content hashes. Four intent boundaries validate retained public bytes before
hashing and never reopen a private pathname afterward. Sixty-seven focused
tests pass; native `3ba29293` verified adapter availability and a 65 KiB saved
program with one three-value execution. Original history and the selected
connection were unchanged. Fresh MCP/CLI and original-job recovery coverage
remain separate acceptance gates.

A separate current durable-program path still hashed private SSH key contents
in its connection intent. Its complete unfixed producer and original records
are preserved. The schema-two private-custody fix passes 83 combined checks,
including real-socket durable jobs and private-generation race refusals. Native
normal-client qualification remains open.
Legacy intents are not rewritten or admitted by weakening the privacy boundary.
Original direct job `61bd241b` was recovered through a separately reviewed
read-only observer, without importing that legacy reader or submitting a job.
It collected exit zero, all 1,600 counter lines and the exact retained stderr;
source custody and observer cleanup closed. This does not qualify the unfinished
normal-client disconnect campaign. Its independent transport master was closed
gracefully, with positive daemon, launcher and socket absence.

Real Git checkout tests now cover raw Windows counter/background native JSON and
explicit visual-target script beforeimages. Authentic prior attributes produce
sixteen additional byte mismatches; a further ten finite dependency/provenance
files also have actual Git conversion RED/GREEN coverage.
The Windows package workflow explicitly enrolls directory-security, desktop
background and Defender service causal native checks. These checks do not replace final managed
prepush, versioning, commit/push or exact-SHA CI, all of which remain pending.

The broad affected run was cancelled after preserving 74 errors and ten failures,
mostly historical Android consumers of changed dependencies. It is not a valid
check receipt. Focused repairs preserve historical private-helper identities,
stage the finite current installer dependencies and retain direct-entrypoint
readiness guards. Complete affected and managed prepush runs remain required.
Fresh Android explicit-target native qualification also needs a new fixture:
the retained UNKNOWN emulator and active Mac currently consume the qualified
local slots and storage budget. Do not weaken capacity limits or repurpose the
UNKNOWN fixture to close that gate.

The independent 109-module diagnostic finished with 1,574 tests, 52 failures,
24 errors and three skips. Failures are preserved and grouped; several source
and historical-fixture repairs have focused GREEN results. This diagnostic is
not a managed check receipt. Final affected selection, complete managed prepush,
version bump, commit, push and exact-SHA CI have not completed.
Release hygiene now passes after causal test-harness portability repairs. A new
128-module SSH/native diagnostic ended with 1,707 tests, 72 failures, 117 errors
and four skips while source files changed; many refusals correctly detected
stale loaded code. It is not a check receipt. Confirmed catalogue, close and
captured-dependency defects have fresh focused causal GREEN results. Windows import
and collection probes pass all twenty-one selected targets. Current source
mapping still awaits the active login, Mac facade and tmux checkpoints before
another complete affected run.
The current reviewed metadata batch selects 733 of 785 modules, with 2,250 source
versions audited and no unexplained dependency inputs. All 407 VM routes and
247 source nodes pass the source audit. This is selection evidence, not a test
receipt. A focused 20-test cohort exposed a stale test expectation at the
`foreign_adapter_context` boundary. Its beforeimages and trace are preserved;
the test now expects rejection of the foreign fragment and closes its unused
generator. The strict production guard is unchanged. All twenty original tests
and twenty-two related tests pass. New provider integration edits still require
a fresh reviewed selection.

Managed Windows fixture seed observation passed the new controlled Linux ROOT
qualification `2d88d6a6`: the preserved FD-only observer missed a real mmap-only
holder (causal RED), the current observer detected it, and the nondumpable-holder
case passed. All three owned child processes were reaped. This grants no VM
allocation, seed ejection or lifecycle acceptance; the actual selected-VM
bootstrap and durable fresh-agent proof remain open.
Mac suspend is blocked on a safe enforced save-state allocation bound; unmodified
Tart supplies no estimator and exits on save failure. No suspend was attempted.
A bounded, separate save-volume and minimal future Tart-owner fork are being
qualified. They cannot adopt the live VM object or imply a safe snapshot size.
Same-persisted-instance start uses Tart's native per-VM lock and authenticated
original-manager/work closure. It does not claim blanket absence of arbitrary
host FD mappings. A distinct known-off admission must preserve an unknown stop
cause, prove actual provider OFF and original terminal streams/actor absence,
reject retained uncertain work and unknown saved state, retain disk/NVRAM
metadata custody, and recheck resources under the target's power fence. This
path remains unqualified; no stop or new start has been submitted on the Mac.

The separate public-source capture for the proposed Tart owner fork is terminal
and source-closed: 34 bounded requests produced a 43,499,520-byte private bundle.
The first capture's strict NAK framing failure and partial artifact are retained;
the new producer preserves actual HTTP bodies before parsing both valid counted
NAK forms. No source extraction, build, signing or VM action occurred. Dependency,
manifest and PACK-object inspection is a separate read-only step; capture alone
does not establish an offline SwiftPM build or safe suspend support.

The provider-specific lease catalog and its live resolver pass 75 focused tests
(two native platform skips) and the 660-action exposure audit. Mac background
leases declare guest-agent access without wake/login; Android and Windows keep
their previous requirements. Unknown provider lanes fail before effects. The
new four exact raw fixture byte rules pass real Git checkout causals: four
failures with the complete old attributes and 27 passing checkout tests now.

Windows display-phase qualification `b81bbc0f` passes all seven controlled Linux
socket cases, including the complete emitted old/current programs. The old
program blocks its own once intent; the fix wakes the fake endpoint once and
then observes the same phase without another input. Owned test actors are
positively absent. Real phase `304443da` subsequently woke the selected Windows
fixture with one pointer event and verified the same boot, account and session;
all 157 source records closed unchanged. A later current-field observation
`8be1abbe` safely stopped before capture because the display was no longer awake.
No credential continuation was submitted. A new combined wake-and-field packet
passed its four actual controlled Linux socket/process cases as `da0a7a3b`,
with complete output, all 158 source records unchanged and nine owned actors
absent. It made no real VM or credential request. Real protected input remains
blocked on independent recipient-helper qualification; historical wake success
is never current input authority.

Mac catalog GET `34fa7297` is source-closed with all nine observed host actors
absent. It independently proves a sealed, read-only root volume; service catalog
construction fails on a source-custody check. Its stable 767-file shape scan
retains 38 protected-read failures and several inactive-source schema/account
cases. Follow-up `3e988548` closed with the same volume and agent identity:
the 38 failures are 29 hard-link counts and nine symlinks, with zero source-file
permission failures. A guarded SSV reader/index prototype passes 13 controlled
checks and awaits native qualification. The separate all-UID process permission
gap still requires the minimal privileged helper. These results grant no idle
or reboot authority. The old root probe and permissions remain unchanged, and
the new helper is uninstalled.

A fresh, source-stable 128-module diagnostic ran 1,710 tests: 1,703 passed,
four skipped and three errored. Two errors were outdated explicit-environment
test fixtures (41 focused checks now pass); the third was a synthetic tmux
driver fixture (60 focused checks now pass). The runner also detected and
cleaned an owned leftover child, so this is an incomplete diagnostic, not a
passing receipt. Its original child identity was not retained; the new observer
addresses that evidence gap without relabelling the original diagnostic.

The integrated session observer now passes 33 focused checks. It retains bounded
kernel process identities before cleanup and observations afterward; existing
cleanup and signalling functions are unchanged. The next original 128-module
diagnostic awaits a coherent dependency-map checkpoint and source freeze.

Mac public nonce/TIS qualification `689a01c1` passed all 136 checks in 18.45
seconds after one state-bound wake `2dd616c6`. The same locked ordinary account,
boot, agent and session were verified. Its normal MCP lease `5e5e51db` was
cancelled once, with complete retained output, assertion restoration and owner
absence; all five servers and three producer processes closed. No ordinary
credential, framebuffer artifact or unlock was involved. The private parent
caller's earlier name-shadowing failure now has two passing routine controls,
including actual whole-before failure before SDK entry and fixed caller entry
through guarded source custody. The nonce benchmark did not exercise the newer
legacy-input closure and observer-namespace guards; their expanded public
preflight remains required before protected input.

Mac source-index GET `f349e695` verified all 729 single-link files and 29 hard
links. Nine symlinks remain outside the qualified source namespace. The index
and active-domain stages correctly did not run. Metadata-only target diagnosis
is separate from granting content-read, idle or lifecycle authority.

Failure-aware metadata GET `2e635cce` subsequently identified all nine first
rejected components as stable root-owned directories with mode `0777`, on a
different device from the qualified sealed system volume. All nine diagnostic
actors are absent and source custody closed. Actual paths and readlink chains
remain private. No child traversal or target-content read followed rejection.
The sealed-root policy cannot qualify these other-device components; their
mount and namespace integrity require a separate bounded observation.
Metadata GET `6f1c359a` has now closed with all nine observed actors absent.
The single deduplicated directory is on writable APFS, with no observed
immutable, restricted or no-unlink flags. It remains outside the qualified
namespace. No permission exception or target-content read was introduced.

Windows bootstrap qualification `d04a540c` passed all 13 actual Linux tests with
no skips, including retained original-owner observation after sign-in/reboot
endpoint changes. Its predecessor encountered a controlled carrier's Linux
argument-size limit; the authentic failure and whole source remain covered by
causal RED/GREEN tests. Managed VM allocation and native bootstrap remain open.
Expanded native cohort `127c473b` ran 28 tests: 26 passed and two failed on
a missing function-local dependency in its nested test fixture. Full output,
the whole unfixed test and failed-closing receipt are preserved. The dispatcher
retained output correctly and source custody closed; missing aggregate
helper-birth records are not reconstructed retrospectively. A test-only closure
and failure-recording fix passes controlled regressions. The expanded sealed
cohort `d568f676` then exceeded its foreground caller deadline. Its partial-output
callback and failed-closing receipt are preserved, with source custody closed.
The original automatic stage is identified, but no loader PID/birth, terminal
streams or nested-child closure was captured. It remains UNKNOWN, with no replay
or replacement. Future whole-cohort callers require a durable top-level owner.

The offline-confinement preparation's original `58a90aca` failed before compilation
on an overly strict disk-image attachment schema. Actual replies and complete
beforeimages are preserved. Original-only cleanup `accf8427` detached the exact
owned image without force, closed its actors, and settled only its own working
claim; all ten other plans remained unchanged. A new bounded qualifier is a
separate operation. This work has not qualified an offline Swift build or suspend.

The next original qualifier `ae56281a` passed image attachment, then its compiler
aborted before creating a binary. Its exact crash and native denial log are
retained. Original-only non-forced detach `72d901c5` closed all owned actors and
settled only that operation's working claim. A candidate adding only the three
observed public read permissions subsequently passed native compiler startup:
the authentic old profile aborted and the candidate returned version output.
Compilation and baseline/constrained child and grandchild canaries are still
required; startup alone does not prove confinement.
Canary operation `463c6425` then stopped at fresh storage admission, before
creating any image, mount, claim or native command. Source closure and original
owner absence are verified. A later read-only calculation measured a 1.31 GB
shortfall against existing growth reservations and headroom. A separate lossless archive of one positively closed blank image followed;
its phase-specific proof is recorded below.
Original archive attempt `b3d46903` stopped before reading image data: APFS
updated its output directory's link count on the attempt's own file creation.
The original image is unchanged, the empty partial and conservative claim are
retained, and all observed actors are absent. Six routine controls reproduce
the actual APFS failure and verify stable directory identity without weakening
full regular-file generation and link-count checks. A separate archive operation
`325d1d6e` completed: the 2 GiB raw image and fully decoded gzip have the same
SHA-256, with complete CRC/EOF validation. The gzip is 2,092,398 bytes. A separate
reviewed retirement removed only that original raw image and retired its own
claim; the archive and all thirteen other plans stayed unchanged.

New canary `8c4ddcf2` passed capacity admission, image creation and attachment,
then failed in the linker with an alignment assertion. Exact sources and complete
diagnostics are retained; the cause remains unresolved. No binary or confinement
canary ran. Original-only cleanup `a316eddb` detached the image without force,
retained it and closed complete streams. All thirteen launch-observed original
and cleanup actors are absent; a separately sampled linker PID/birth was never
captured, so no all-descendant absence is claimed. All fourteen other claims
remain unchanged. A separate settlement changed only that operation’s claim to retained with
zero working growth; the image and all fourteen other claims remain unchanged.

The SSH acceptance helper now passes twelve routine controls covering the
observed-running gate and private output custody. It preserves completed public
results before assertion or closing-source failures, including one-use carried
results. Its live normal-SDK controller and new direct/nested campaigns remain
pending. Original `61bd241b` remains the same independently collected terminal
job; it is never replayed.

The next dependency checkpoint preserves all historical source pins and maps
the new finite fixtures explicitly. A fresh plan selects 751 of 803 modules.
Its initial focused selector run exposed three miniature-repository fixtures
that omitted the runner's new observer dependency. The complete old test
reproduces those failures; the corrected shared fixture passes all 94 tests.
Twenty additional raw-SHA fixture paths also have actual Windows-style Git
checkout RED/GREEN coverage and exact-path byte rules; parse-only manifests
retain normal text handling. Later source edits still require renewed selection
and the complete managed pre-push checks.

The Mac observer index source passes 101 focused controls, including authentic
reservation and guest-boot admission failures. Its namespace qualifier now
retains bounded public output immediately through held descriptors; eleven
controlled-child tests include the whole old caller reproducing timeout and
cleanup output loss. Native namespace qualification `a9935f53` passed on the same persisted VM:
one enrollment, two status reads and an empty inventory; healthy repeat caused
no dispatch. All four RPC actors and its controller are absent. It starts no
observer job and grants no credential or full-idle authority.
Four later raw-SHA fixtures extend the checkout suite to thirteen passing tests;
all earlier twenty fixture byte rules and causal coverage remain intact.

The next closed dependency epoch selects 754 of 806 modules without unresolved
mappings. Six finite loader-row changes preserve all historical pins and scopes;
archive and namespace fixtures resolve naturally. New direct/nested SSH capsules
are source-only. Their directory-permission audit caught inherited default modes
before native execution; the owned preparation fix and durable whole-controller
admission remain prerequisites. Production persistence stays five hours; native
qualification uses accelerated intervals and does not wait five hours.

## Latest diagnostic checkpoint

Work remains incomplete on base `d24c19047ec15689948404ede40f50c5ec284e77`.
The current manifest is `64345819` after HOME promotion; attributes are `0e62cf9c`.
Source holds have closed. No final version bump, pre-push receipt, commit, push or
five exact-SHA workflow results exist. Product parity remains paused, transport
parity deferred, production persistence 18,000 seconds and test expiry accelerated.

Direct `8a468b28`/`e8cd093d` and nested `63e0bf1f`/`f99584f3` now each pass all four
faults: one original execution, all 1,600 values, exact 6,890-byte stdout and
47-byte stderr, fresh SDK/CLI equivalence and lost terminal acknowledgement.
Direct closure `328ab017` proves 37 local actor absences and all streams/proxy
threads closed. Nested closure `083d0f33` proves 1,397 source bindings, 32 local
actor absences, eight client stream pairs closed and both owned test channels
ended. Shared masters and remote job owners were never signalled. Nested cleanup
in a fresh macOS environment exposed a current-TMPDIR provenance mismatch;
original-environment guarded cleanup passed. A strict production provenance fix
and real separate-process causal coverage remain pending.

The exact CRLF dead-socket fix is integrated with thirteen generated-caller/socket
causal controls, plus ten polling/final-audit controls. All 23 pass. The corrected
same twelve-module SSH fixture cohort passed 116 tests in 537.898 seconds, with
full streams, 3,157-source closure, empty worker session and positive actor absence
(`15617149`). Earlier failure evidence and unproven late-readiness causes remain.
The 43-path finite routine union and Windows native compile check are integrated;
46 tests passed with one expected Windows-only skip. The latest global planner
passed 782/833 selection before the subsequent HOME correction. Full execution
and managed pre-push are still pending.

The managed Windows creator now inherits only an existing HOME instead of
inventing one from the fixture path. Four actual subprocess/source regressions
pass. Separate new libvirt preparation selects supported 4 GiB RAM and 8 GiB
headroom, with the normal conservative capacity gate; production default
headroom remains 16 GiB. Capacity-dedup prototypes are parked. Fresh namespace,
resource, asset/WIM and source admissions precede any creator dispatch.
Existing Windows fixture `942cca12` is signed out; original UNKNOWN jobs and
unclassified work still block idle/reboot. QGA capability-only `fa2a01ce` passed,
but source-only VNC/listener/endpoint controls supply no input authority. Actual
WTS cadence, keyboard/profile, protected material and native lifecycle are open.

Mac known-session wake/public-region original `3bd29e00`/`10e1be2b` completed with
lease restoration and source/actor closure `77427d5e`. White account glyphs match
exactly across the retained public images; their backgrounds differ. A narrow
label profile, per-event guard and readonly native-enrollment procedure are under
final review. Empty-field checks are unchanged and native stability is unproven.
No ordinary credentials were entered. Active-work/installer/lease-deadline
candidates have controlled checks, but actual source-alias publication, helper
installation, 501/502 visibility, protected activity, full idle and lifecycle
remain native gates. Preserve prior mismatch and sleeping refusal receipts.

Linux retirement `8042e683` acknowledged asynchronous guest poweroff queuing,
while its same QEMU actor remains running. The original command streams were
not retained, so the stall cause is unknown. Exact original-only read-only serial
classification is under investigation; no power replay, force stop, terminal
inference or claim release is authorized. The final raw-byte roundtrip must
extend the prepared 133-path inventory for all subsequent promotions.

## Retained diagnostic history

The entries below preserve earlier source epochs and their then-current blockers;
the checkpoint above governs current work. No later pass rewrites an original
UNKNOWN operation or supplies missing historical evidence.

The isolated checkout remains based on `d24c19047ec15689948404ede40f50c5ec284e77`.
No final version bump, managed pre-push receipt, commit or push is complete.
Windows product parity remains paused; provider-host local/SSH parity is deferred.
Production SSH persistence remains 18,000 seconds; qualification uses accelerated
intervals, as the user instructed. No five-hour test dwell is required.

Original diagnostic `170ee960` retains its 1,713 tests, 94 failures and four
skips. A representative failure was causally traced to the inert SSH/tmux helper
selecting a broken system Python under the durable owner's sanitized PATH.
The exact interpreter-binding correction passed actual old/current bootstrap
checks. Focused operation `264404df` then passed all 97 tests from the nine
failing families plus the interpreter regression, with complete streams,
unchanged sources and an empty worker session.

The exact original 128-module repetition `6c62f323` subsequently ran 1,713 tests:
15 failures, one error and four skips in 1,157.539 seconds. All 3,049 captured
sources closed unchanged. Its report remains incomplete because a sleep child
was present before cleanup; afterwards the session was empty, the worker reaped
and the root removed, with all recorded process generations absent. The four
remaining families are dispatch retry, bound carrier, owner v2 and ready
reconciliation. Their full tracebacks and original source snapshot are retained.
A three-second fixture release wait is a lead, not a proven cause. The next
small diagnostic preserves phase/output evidence before test cleanup; no new
full repetition is authorized until the causes are understood and covered.
Focused diagnostic `ffc7f648` passed all 38 inner tests against the preserved
3,049-file snapshot in 157.982 seconds. Its single outer harness passed with
complete streams and unchanged sources; both worker-session inventories were
empty, cleanup reaped the worker and removed its root. Project imports were
restricted to the snapshot, and 78 phase captures retained evidence before
cleanup. This isolated pass does not reproduce or fix the original full-suite
failure; its cause and causal coverage remain open.

Direct SSH acceptance controller `9e3d91aa` failed during initial readiness:
all three owned connections reset before authentication. No counter request or
counter source was generated. All owned masters, proxy sockets and threads
closed, with shared connections untouched. The reset origin is unknown. A
metadata-only proxy observer passes seven real-loopback checks; a new
readiness-only campaign is prepared but unsubmitted. The nested campaign is
also unsubmitted. Neither the original controller nor its planned counter is
replayed.

Windows original compiler parent `687d2609` failed at its first file ACL update,
before compilation. Its original partial namespace is retained. Native causal
probe `e4ca2ae8` reproduced the write-only-handle denial and verified atomic
ACL-at-creation, held ACL inspection, exact readback and duplicate refusal.
The corresponding routine regression uses owned current-token files on Windows
and is explicitly included in the Windows workflow; its actual SYSTEM/session0
qualification remains the separate retained native probe.

New compiler parent `8e6c74d8` failed after child waiting and stream completion:
a PowerShell branch pipeline turned an empty byte array into null before Write.
An unsuppressed awaited write also emitted VoidTaskResult. Whole beforeimages
and complete 39-byte/412-byte original output are retained. The minimal stream
correction is source-only; actual Windows interpreter RED/GREEN remains required.
Original diagnostic `7c3cffa6` retained 15 running replies but no terminal frame.
One original-only reader `5bd979e6` later found no QGA PID record. Fixed HOST-only
wire inspection recovered no lost terminal frame. These facts establish neither
its historical outcome nor the compiler result: both remain UNKNOWN and are
never replayed. Further collection must inspect original retained records,
without manufacturing a successful terminal receipt.

Interpreter probe `5e4df85b` stopped at its guest-epoch guard before running any
causal cases. Independent public probe `fb237dc9` confirmed the same machine
UUID with a new boot at `2026-10-21T00:28:33.5000000Z`; the boot-change cause is
unproven. The old session and recipient profiles are stale. A new interpreter
probe needs a fresh operation and current boot admission. Original-result readers
must distinguish their current observer boot from the old original-job boot;
they must not rewrite the original job's identity or infer a successful exit.

Mac public parent `dc9d6e03`/child `07110b57` failed during SessionObserver startup.
The prior file-mode preparation fault is fixed by validated offline preparation.
For the new attempt, lease `847bc27d` acquired once and cancelled with restoration;
known-state wake `084e1c45` reached the same ordinary session once. All recorded
host callers closed. The failed observer discarded its initial exception and
startup streams, so the original cause and historical guest exit remain unknown.
Read-only census `fbba7fe9` subsequently proved a current absence barrier for the
selected interpreter class using two complete stable ordinary-account snapshots.
Its three callers, exact durable owner and source closure are verified. This
narrow absence proof grants no input, power or full-idle authority.

Startup diagnostics are now integrated in the Mac unlock owner: the original
host process identity and bounded public startup output are retained before
cleanup, capture stops before credential access, and diagnostic I/O failures
cannot skip process/pipe cleanup. The three-second startup cap and native
qualification flags are unchanged. Nine new regressions and the existing
unlock/nonce cohort pass all 34 tests. A fresh source packet and native
qualification of this change remain required.

Fresh public-only parent `8d424161` and child `d0441a6c` both ended with exit one.
The missing initial acknowledgement was reconciled to the same running owner,
without a replacement. Lease `7910c2e2` acquired once, cancelled once and retained
restoration evidence. Wake `5bf63389` used one Shift group to restore the known
sleeping display in the same ordinary session. No credential handle was opened.
The outer child failure is `macos_operation_unknown`. Retained startup evidence
identifies `ValueError` at the payload-write `select.select`, with complete host
EOF and fixed guest gate failure `guest_source_changed`. Original descriptor
numbers were not retained. A controlled whole-constructor run with 1,098 held
descriptors reproduces this phase and error. The minimal kernel-selector fix
passes all three pipe sites, EOF and cleanup controls, preserving the write/read
caps and credential boundary. The combined cohort passes 39 tests. This proves
the controlled defect, without inventing historical native descriptor evidence;
fresh native verification remains required. Preserve both original terminal
streams and do not replay either operation.

Mac service-shape diagnostic `e3376ee1` completed with exit zero, full streams,
13 closed callers and unchanged sources. All 165 system and 162 caller-domain
active rows matched their single-job PID/label queries. Four unknown system
field occurrences remain unclassified. Actor/source/account joins, installers,
protected activity and the complete seven-category inventory remain blockers;
no all-UID, disk-origin or idle authority is inferred. ACL diagnostic `9143d37e`
likewise remains diagnostic only: unavailable ACL visibility and an unsealed
volume do not authenticate a namespace. Compiler/fork work stays parked;
`395a1e0c` invoked clang -### only, with no compile or link.

The seven-file caller deadline change passes 77 focused tests. Its reviewed
lease-workflow pin is now updated, and the VM audit passes 407 routes and 247
source nodes. The action audit covers all 660 actions across 28 surfaces.
Routine coverage also passes 52 SSH preparation/owner tests, 20 Mac parent tests,
20 Mac ACL tests, and six Windows harness tests executing 29 current controls
and nine preserved causal failures. Capability reporting passes 95 platform and
12 target tests. Git byte-custody now passes 16 tests, including actual old/new
checkout of both preserved PowerShell ACL sources and three authenticated proxy
JSON inputs. The old policy corrupts those three inputs; the current policy
preserves their original bytes. The preceding aggregate
byte roundtrip passed all 64 raw fixture paths with no mismatch and a converting
text control. The current affected planner selects 769 of 821 modules with no unresolved
mapping; this is selection, not a completed test run. The actual affected run,
native provider matrix, managed pre-push, versioning, explicit commit/push and all
five exact-SHA workflows remain open.

Controlled release-gate operation `965ffdc2` reproduced exit 72 after 3.199 seconds
when release was held for 3.5 seconds. Removing only the fixture's shortening
accepted the same hold, with unchanged three-second readiness checks. Complete
streams, source closure and empty sessions are retained. Production's
300-second release budget is unchanged. The candidate fixture cleanup passes nine
controls for V1/V2 workers, source-bound stop records and unresolved publication;
its focused public integration remains in progress. This does not establish the earlier full
suite's cause.

Readiness-only SSH operation `687c35f4` closed with all three proxies connected
but failing at local select before traffic. Real high-FD whole-class tests
reproduce the failure; the selector correction passes nine routine tests. The
earlier `9e3d91aa` cause remains unknown. Corrected readiness-only operation
`dfbba244` completed with exit zero, complete streams and closure of all owned
actors, proxy sockets and held sources. No counter or nested campaign has been
submitted by these readiness-only controllers; their fresh successors are
prepared as source only.

Native PowerShell operation `aa0d394e` passed all old/current empty-stream and
awaiter cases. Original getter `839ad09d` recovered a concrete C# unassigned-local
error, while original compiler `8e6c74d8` remains UNKNOWN without its final
receipt. New compiler `ce76d780` has an authenticated failed terminal; getter
`c359fe5d` retained all 1,933 diagnostic bytes and identified an object passed to
a dictionary parameter. New compile-only operation `13323c59` preserves bounded
diagnostic output before validation and collects every compiler error. It completed with authenticated exit zero, all child EOFs, the exact
`COMPILE_ONLY_OK` output and no stderr. No compiled method was invoked; input
and idle authority remain unqualified. The two whole-source compiler failures
and fixed source are now routine causal fixtures, with the actual compiler case
explicitly selected by Windows CI. Local coverage passes six tests with one
expected Windows-only skip.

Mac `3f0be95c`/`cd476c22` passed native observer startup and stopped at the VNC
protected-FD reader. Its lease cancelled/restored and host actors closed. The
reader correction passes seven additional controls, including real high-FD files,
pipes and auth-only clients; the combined Mac cohort passes 61 tests. Source-only
V14 refresh preserved the same VM, native receipts and namespaces and passed its
bounded read-only qualification. New `09ef9bab`/`2ce082d3` then stopped at a legacy
dependency pin before observer construction, with lease cancellation/restoration
retained. The compatibility correction must preserve historical transport source
claims explicitly. No ordinary credential input occurred in these attempts.

The reviewed Windows public-output and SSH proxy regressions are now copied into
routine checks: 19 tests ran, 18 passed and the actual Framework test skipped on
this Mac; its real VM interpreter qualification is retained separately. The
Windows workflow explicitly includes that native test. Raw-byte rules cover the
three new SHA-authenticated proxy JSON files. A new aggregate byte roundtrip and
the full affected/pre-push tiers remain required.
