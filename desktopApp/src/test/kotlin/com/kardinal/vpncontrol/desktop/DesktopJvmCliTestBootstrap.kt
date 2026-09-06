package com.kardinal.vpncontrol.desktop

import java.io.File
import java.nio.file.Path
import java.util.Base64

/** Only bypasses Java17's ANSI argv conversion in JVM fixtures, not application parsing/IO.
 * Public packaged-launcher Unicode admission is verified separately by test_packaged_cli.py.
 */
object DesktopJvmCliTestBootstrap {
    fun encode(arguments: List<String>) = arguments.map { Base64.getEncoder().encodeToString(it.toByteArray(Charsets.UTF_8)) }
    fun classpath(main: String) = Path.of(DesktopJvmCliTestBootstrap::class.java.protectionDomain.codeSource.location.toURI()).toString() + File.pathSeparator + main
    @JvmStatic fun main(arguments: Array<String>) {
        main(arguments.map { Base64.getDecoder().decode(it).toString(Charsets.UTF_8) }.toTypedArray(), true)
    }
    private fun main(arguments: Array<String>, @Suppress("UNUSED_PARAMETER") decoded: Boolean) {
        // Reflection avoids resolving this object's main recursively instead of the top-level entry.
        Class.forName("com.kardinal.vpncontrol.desktop.MainKt").getMethod("main", Array<String>::class.java)
            .invoke(null, arguments as Any)
    }
}
