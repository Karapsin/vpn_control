package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.ControlOperationId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs

class ControlCliParserTest {
    @Test
    fun subscriptionNameCanBeExplicitlyClearedWithoutAcceptingEmptyInputs() {
        val invocation = assertIs<ControlCliParseResult.Invocation>(ControlCliParser.parse(
            listOf("subscriptions", "update", "id", "--name", "")))
        assertEquals("", invocation.options["--name"])
        assertIs<ControlCliParseResult.Invalid>(ControlCliParser.parse(
            listOf("subscriptions", "add", "--input", "")))
        assertIs<ControlCliParseResult.Invalid>(ControlCliParser.parse(
            listOf("subscriptions", "update", "id", "--source", "")))
    }

    @Test
    fun emptyAndKnownGuiArgumentsRemainGuiButUnknownFlagsNeverDo() {
        assertIs<ControlCliParseResult.Gui>(ControlCliParser.parse(emptyList()))
        assertIs<ControlCliParseResult.Gui>(ControlCliParser.parse(listOf("--autostart", "--minimized")))
        for (args in listOf(listOf("--typo"), listOf("--autostart", "--typo"), listOf("--json"))) {
            assertIs<ControlCliParseResult.Invalid>(ControlCliParser.parse(args))
        }
    }

    @Test
    fun helpAndVersionAreExplicitNonOperationalResults() {
        assertIs<ControlCliParseResult.Help>(ControlCliParser.parse(listOf("--help")))
        assertIs<ControlCliParseResult.Help>(ControlCliParser.parse(listOf("help")))
        assertEquals(ControlOperationId.LOCATIONS_ADD,
            assertIs<ControlCliParseResult.Help>(ControlCliParser.parse(listOf("locations", "add", "--help"))).operation)
        assertIs<ControlCliParseResult.Version>(ControlCliParser.parse(listOf("--version")))
        assertIs<ControlCliParseResult.Invalid>(ControlCliParser.parse(listOf("--help", "--unknown")))
        assertIs<ControlCliParseResult.Invalid>(ControlCliParser.parse(listOf("--version", "on")))
    }

    @Test
    fun unicodeNamesPathsAndLiteralOptionLikeNamesSurviveTokenization() {
        val invocation = parse("--state-dir", "/tmp/東京 workspace", "locations", "update", "東京 office", "--input", "C:\\VPN files\\quoted \"name\".json")
        assertEquals("/tmp/東京 workspace", invocation.client.stateDirectory)
        assertEquals(listOf("東京 office"), invocation.positional)
        assertEquals("C:\\VPN files\\quoted \"name\".json", invocation.options["--input"])
        assertEquals(listOf("--json"), parse("select", "--", "--json").positional)
        assertEquals(listOf("Office east"), parse("select", "Office", "east").positional)
        assertEquals(listOf("17"), parse("locations", "select", "17").positional)
    }

    @Test
    fun globalsValidateTargetAndRangesBeforeAnyOperation() {
        val invocation = parse("--android", "--serial", "emulator-5554", "--json", "subscriptions", "refresh", "all", "--async", "--timeout-seconds", "0", "--if-revision", "9", "--controller-id", "owner-epoch")
        assertEquals(0, invocation.client.timeoutSeconds)
        assertEquals(9, invocation.client.ifRevision)
        assertEquals("owner-epoch", invocation.client.controllerId)
        assertEquals("emulator-5554", invocation.client.serial)
        for (args in listOf(
            listOf("--serial", "one", "status"),
            listOf("--android", "--state-dir", "/tmp/state", "status"),
            listOf("--timeout-seconds", "-1", "status"),
            listOf("--timeout-seconds", Long.MAX_VALUE.toString(), "status"),
            listOf("--timeout-seconds", "1.5", "status"),
            listOf("--if-revision", "-1", "on"),
            listOf("--if-revision", "1", "status"),
            listOf("--async", "status"),
            listOf("--json", "--json", "on"),
        )) assertIs<ControlCliParseResult.Invalid>(ControlCliParser.parse(args))
    }

    @Test
    fun publicRevisionIsAlwaysBoundToAnExplicitOwnerEpoch() {
        assertIs<ControlCliParseResult.Invalid>(ControlCliParser.parse(listOf(
            "settings", "set", "language", "en", "--if-revision", "0")))
        val guarded = parse("settings", "set", "language", "en", "--controller-id", "owner-epoch", "--if-revision", "0")
        assertEquals("owner-epoch", guarded.client.controllerId)
        assertEquals(0L, guarded.client.ifRevision)
        assertIs<ControlCliParseResult.Invalid>(ControlCliParser.parse(listOf(
            "settings", "set", "language", "en", "--controller-id", " ", "--if-revision", "0")))
    }

    @Test
    fun everyOperationHasAnExecutableGrammarExample() {
        val examples = listOf(
            listOf("on"), listOf("off"), listOf("status", "--watch"), listOf("restart"), listOf("find-best"),
            listOf("source", "show"), listOf("source", "set", "subscription", "id"),
            listOf("subscriptions", "list"), listOf("subscriptions", "show", "id"),
            listOf("subscriptions", "add", "--source", "https://example.test/sub", "--name", "Office"),
            listOf("subscriptions", "update", "id", "--name", "New"), listOf("subscriptions", "delete", "id"),
            listOf("subscriptions", "refresh", "all"), listOf("locations", "list"), listOf("locations", "show", "1"),
            listOf("locations", "add", "--input", "-"), listOf("locations", "update", "1", "--input", "-"),
            listOf("locations", "delete", "1"), listOf("locations", "select", "1"), listOf("locations", "benchmark", "1"),
            listOf("locations", "import", "--qr-image", "qr.png"), listOf("locations", "export", "--output", "-"),
            listOf("routing", "show"), listOf("routing", "set", "direct-domains", "[\"example.test\"]"),
            listOf("routing", "import", "--input", "-"), listOf("routing", "export", "--output", "qr.png", "--format", "qr-png"),
            listOf("routing", "apps", "list", "--search", "browser"), listOf("routing", "apps", "set", "--input", "-"),
            listOf("routing", "apps", "add", "org.test.app"), listOf("routing", "apps", "remove", "org.test.app"),
            listOf("routing", "apps", "select-all"), listOf("routing", "apps", "clear"), listOf("settings", "show"),
            listOf("settings", "set", "mode", "proxy-only"), listOf("settings", "apply", "--input", "-"),
            listOf("settings", "languages"), listOf("ssh", "key", "status"), listOf("ssh", "key", "import", "--input", "-"),
            listOf("stats", "--watch"), listOf("logs", "--follow", "--limit", "10"),
            listOf("diagnostics", "export", "--output", "-"), listOf("operations", "list"),
            listOf("operations", "status", "id"), listOf("operations", "wait", "id"), listOf("operations", "cancel", "id"),
            listOf("updates", "status"), listOf("updates", "check"), listOf("updates", "download"),
            listOf("updates", "install"), listOf("updates", "cancel"), listOf("updates", "dismiss"),
            listOf("serve"), listOf("gui", "show"), listOf("gui", "hide"), listOf("quit"), listOf("capabilities"),
        )
        val parsed = examples.map { assertIs<ControlCliParseResult.Invocation>(ControlCliParser.parse(it), it.first()) }
        assertEquals(ControlOperationId.entries.toSet(), parsed.map { it.operation }.toSet())
        assertEquals(ControlOperationId.entries.size, parsed.size)
    }

    @Test
    fun contradictoryAndIncompleteInputsFailWithoutEchoingSecretData() {
        for (args in listOf(
            listOf("locations", "add"),
            listOf("locations", "add", "--input", "-", "--qr-image", "secret.png"),
            listOf("subscriptions", "update", "id"),
            listOf("subscriptions", "add", "--source", "https://SECRET.test", "--input", "-"),
            listOf("source", "set", "subscription"),
            listOf("source", "set", "all", "SECRET"),
            listOf("routing", "set", "rule-sets", "SECRET"),
            listOf("routing", "export", "--output", "-", "--json"),
            listOf("locations", "export", "--output", "secret", "--format", "bad"),
            listOf("locations", "add", "--input", "--json"),
            listOf("locations", "add", "--input", "secret", "--input", "other"),
            listOf("logs", "--limit", "-1"), listOf("logs", "--follow", "--follow"),
            listOf("ssh", "key", "import", "--secret", "SECRET"),
        )) {
            val error = assertIs<ControlCliParseResult.Invalid>(ControlCliParser.parse(args))
            assertFalse(error.reason.contains("SECRET"))
        }
    }

    private fun parse(vararg args: String) = assertIs<ControlCliParseResult.Invocation>(ControlCliParser.parse(args.toList()))
}
