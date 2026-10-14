# Tool guide migration manifest

Baseline: `3944739d3f33983dbd7a23ac0b8cf00aa20107aa`; original Git blob `29fdab6fa68b41be2789357ba006981bdc99d1ab`.
Original SHA256 `ffaee225a96344a6dcbf728fbbe615de02d8644e3b371398252ba04e2a5bce11`; 2548 lines / 173535 bytes.

All source lines are preserved exactly once in focused references. Private byte-exact copy and mechanical report:
.runtime/docs-cleanup-2026-10-14/tool-routing/ (ignored; evidence stays in place).

The [historical snapshot](tool-guide-original.md) preserves the complete original with an explicit historical wrapper
and one relative-link repair. The recipe wrappers classify fixed CP117 operations as historical, not commands to replay.

| Original lines | Focused destination / lines |
| --- | --- |
| 1–74 | [agent_docs/tools/lifecycle-and-api.md](../../../tools/lifecycle-and-api.md), 11–84 |
| 289–592 | [agent_docs/tools/lifecycle-and-api.md](../../../tools/lifecycle-and-api.md), 85–388 |
| 75–288 | [agent_docs/tools/visual-and-platform-evidence.md](../../../tools/visual-and-platform-evidence.md), 16–229 |
| 593–1099 | [agent_docs/tools/visual-and-platform-evidence.md](../../../tools/visual-and-platform-evidence.md), 230–736 |
| 1100–2548 | [agent_docs/tools/parity-worker-recipes.md](../../../tools/parity-worker-recipes.md), 23–1471 |

Every original heading/anchor is retained in the focused destination and redirected in the entry guide.
The private machine-readable manifest maps each heading to its exact destination/range; the full snapshot preserves original anchor order.
Payload reversal, 36 original headings/anchors, original UUID/SHA pins, and line partition: PASS.

## Original heading and anchor destinations

| Original line / heading | Original anchor | Focused destination |
| --- | --- | --- |
| 1: VPN Control Agent Tools | <code>vpn-control-agent-tools</code> | [record](../../../tools/lifecycle-and-api.md#vpn-control-agent-tools) |
| 5: Automatic MCP Setup | <code>automatic-mcp-setup</code> | [record](../../../tools/lifecycle-and-api.md#automatic-mcp-setup) |
| 26: Mandatory Lifecycle | <code>mandatory-lifecycle</code> | [record](../../../tools/lifecycle-and-api.md#mandatory-lifecycle) |
| 75: Windows retained input observer | <code>windows-retained-input-observer</code> | [record](../../../tools/visual-and-platform-evidence.md#windows-retained-input-observer) |
| 118: Native Acceptance Execution | <code>native-acceptance-execution</code> | [record](../../../tools/visual-and-platform-evidence.md#native-acceptance-execution) |
| 135: Fixed Linux engineering source context | <code>fixed-linux-engineering-source-context</code> | [record](../../../tools/visual-and-platform-evidence.md#fixed-linux-engineering-source-context) |
| 187: Collector uncertainty and local observer loss | <code>collector-uncertainty-and-local-observer-loss</code> | [record](../../../tools/visual-and-platform-evidence.md#collector-uncertainty-and-local-observer-loss) |
| 201: Early SSH close dependency check | <code>early-ssh-close-dependency-check</code> | [record](../../../tools/visual-and-platform-evidence.md#early-ssh-close-dependency-check) |
| 211: Selected Arch route for nested guests | <code>selected-arch-route-for-nested-guests</code> | [record](../../../tools/visual-and-platform-evidence.md#selected-arch-route-for-nested-guests) |
| 220: Fixed Linux GUI lifecycle recipe | <code>fixed-linux-gui-lifecycle-recipe</code> | [record](../../../tools/visual-and-platform-evidence.md#fixed-linux-gui-lifecycle-recipe) |
| 259: Installer collection diagnostics | <code>installer-collection-diagnostics</code> | [record](../../../tools/visual-and-platform-evidence.md#installer-collection-diagnostics) |
| 289: MCP Tools | <code>mcp-tools</code> | [record](../../../tools/lifecycle-and-api.md#mcp-tools) |
| 347: Receipt-bound channel keeper | <code>receipt-bound-channel-keeper</code> | [record](../../../tools/lifecycle-and-api.md#receipt-bound-channel-keeper) |
| 383: Shared keeper helpers and routine promotion | <code>shared-keeper-helpers-and-routine-promotion</code> | [record](../../../tools/lifecycle-and-api.md#shared-keeper-helpers-and-routine-promotion) |
| 409: Other MCP tools | <code>other-mcp-tools</code> | [record](../../../tools/lifecycle-and-api.md#other-mcp-tools) |
| 514: Command-Line Fallback | <code>command-line-fallback</code> | [record](../../../tools/lifecycle-and-api.md#command-line-fallback) |
| 533: Documentation RAG | <code>documentation-rag</code> | [record](../../../tools/lifecycle-and-api.md#documentation-rag) |
| 547: Tests | <code>tests</code> | [record](../../../tools/lifecycle-and-api.md#tests) |
| 593: Private Native Hosts And VM Workflows | <code>private-native-hosts-and-vm-workflows</code> | [record](../../../tools/visual-and-platform-evidence.md#private-native-hosts-and-vm-workflows) |
| 628: Fixed Secure Boot firmware prerequisite | <code>fixed-secure-boot-firmware-prerequisite</code> | [record](../../../tools/visual-and-platform-evidence.md#fixed-secure-boot-firmware-prerequisite) |
| 679: Fixed swtpm integrity repair for the Windows fixture | <code>fixed-swtpm-integrity-repair-for-the-windows-fixture</code> | [record](../../../tools/visual-and-platform-evidence.md#fixed-swtpm-integrity-repair-for-the-windows-fixture) |
| 760: Fixed Windows credential-validity probe | <code>fixed-windows-credential-validity-probe</code> | [record](../../../tools/visual-and-platform-evidence.md#fixed-windows-credential-validity-probe) |
| 840: Fixed Windows credential recovery | <code>fixed-windows-credential-recovery</code> | [record](../../../tools/visual-and-platform-evidence.md#fixed-windows-credential-recovery) |
| 903: Owned Android stale-proxy recovery | <code>owned-android-stale-proxy-recovery</code> | [record](../../../tools/visual-and-platform-evidence.md#owned-android-stale-proxy-recovery) |
| 920: Configured guest routes | <code>configured-guest-routes</code> | [record](../../../tools/visual-and-platform-evidence.md#configured-guest-routes) |
| 938: Native artifact, bundle, and environment helpers | <code>native-artifact-bundle-and-environment-helpers</code> | [record](../../../tools/visual-and-platform-evidence.md#native-artifact-bundle-and-environment-helpers) |
| 1050: Fixed CP117 loopback forward | <code>fixed-cp117-loopback-forward</code> | [record](../../../tools/visual-and-platform-evidence.md#fixed-cp117-loopback-forward) |
| 1078: Durable fixed-scenario execution | <code>durable-fixed-scenario-execution</code> | [record](../../../tools/visual-and-platform-evidence.md#durable-fixed-scenario-execution) |
| 1100: Reusable native acceptance orchestration | <code>reusable-native-acceptance-orchestration</code> | [record](../../../tools/parity-worker-recipes.md#reusable-native-acceptance-orchestration) |
| 2218: Compact guidance and failure evidence | <code>compact-guidance-and-failure-evidence</code> | [record](../../../tools/parity-worker-recipes.md#compact-guidance-and-failure-evidence) |
| 2253: Nested SSH connection recovery | <code>nested-ssh-connection-recovery</code> | [record](../../../tools/parity-worker-recipes.md#nested-ssh-connection-recovery) |
| 2276: Read-only Android observation | <code>read-only-android-observation</code> | [record](../../../tools/parity-worker-recipes.md#read-only-android-observation) |
| 2304: Verified fixture staging | <code>verified-fixture-staging</code> | [record](../../../tools/parity-worker-recipes.md#verified-fixture-staging) |
| 2333: Fixed continuation acceptance adapters | <code>fixed-continuation-acceptance-adapters</code> | [record](../../../tools/parity-worker-recipes.md#fixed-continuation-acceptance-adapters) |
| 2485: Fixed CP117 retirement recovery | <code>fixed-cp117-retirement-recovery</code> | [record](../../../tools/parity-worker-recipes.md#fixed-cp117-retirement-recovery) |
| 2503: Fixed c32 historical baseline admission | <code>fixed-c32-historical-baseline-admission</code> | [record](../../../tools/parity-worker-recipes.md#fixed-c32-historical-baseline-admission) |

Coordinator addition to the compact tool entry: current agent startup/commit/exact-SHA CI routing paragraph
under Mandatory Lifecycle. Focused source payload and historical snapshot remain unchanged.

The compact tool entry also adds the current historical-classification/index refresh explanation
under Documentation RAG; the original detailed source text remains preserved.
