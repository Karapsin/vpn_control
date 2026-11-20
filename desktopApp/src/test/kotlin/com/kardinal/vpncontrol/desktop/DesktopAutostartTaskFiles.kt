package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.nio.file.Path

/**
 * The definition a `schtasks /Create /XML <file>` call hands Task Scheduler, read as schtasks reads it: a UTF-16
 * little-endian document with its BOM. Null for any other command. Test worlds call this while the command runs,
 * because the product deletes the file once schtasks has ended.
 */
internal fun registeredTaskXml(argv: List<String>): String? {
    val index = argv.indexOf("/XML")
    if (argv.take(2) != listOf("schtasks", "/Create") || index < 0 || index + 1 >= argv.size) return null
    val bytes = Files.readAllBytes(Path.of(argv[index + 1]))
    check(bytes.size >= 2 && bytes[0] == 0xFF.toByte() && bytes[1] == 0xFE.toByte()) { "not a UTF-16LE task document" }
    return String(bytes, 2, bytes.size - 2, Charsets.UTF_16LE)
}

/** The text of every element of this local name in a task document, in document order (no nested markup). */
internal fun taskElementTexts(xml: String, name: String): List<String> =
    Regex("<(?:[A-Za-z0-9]+:)?$name(?:\\s[^>]*)?>([^<]*)</(?:[A-Za-z0-9]+:)?$name>").findAll(xml)
        .map { it.groupValues[1] }.toList()

/** The one LogonTrigger element of a task document, as text. */
internal fun logonTriggerText(xml: String): String =
    Regex("<(?:[A-Za-z0-9]+:)?LogonTrigger(?:\\s[^>]*)?(?:/>|>.*?</(?:[A-Za-z0-9]+:)?LogonTrigger>)", RegexOption.DOT_MATCHES_ALL)
        .findAll(xml).single().value
