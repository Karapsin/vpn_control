package com.kardinal.vpncontrol.desktop

import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.zip.GZIPOutputStream

/** Only fixed bundled code and opaque correlation identifiers cross the process command line. */
internal object DesktopWindowsCapturedInstallWorker {
    enum class Role(val resource: String) {
        ORIGINAL_USER("windows-install-user.ps1"), COORDINATOR("windows-install-coordinator.ps1"),
    }

    fun arguments(role: Role, jobId: String, ownerPid: Long): List<String> {
        require(DesktopInstallJobNames.validJob(jobId) && ownerPid in 1..0xffffffffL)
        fun resource(name: String) = requireNotNull(javaClass.getResourceAsStream("/$name")).use {
            val bytes = it.readNBytes(262145)
            require(bytes.size <= 262144)
            bytes
        }
        fun compressed(bytes: ByteArray): String {
            val output = ByteArrayOutputStream()
            GZIPOutputStream(output).use { it.write(bytes) }
            return Base64.getEncoder().encodeToString(output.toByteArray())
        }
        val native = compressed(resource("windows-install-native.cs"))
        val worker = compressed(("param([string]${'$'}JobId,[uint32]${'$'}OwnerPid)\n".encodeToByteArray() +
            resource("windows-install-common.ps1") + "\n".encodeToByteArray() + resource(role.resource)))
        val script = """
            ${'$'}ErrorActionPreference='Stop'
            function Expand-Fixed([string]${'$'}value) {
                ${'$'}stream=[IO.Compression.GZipStream]::new([IO.MemoryStream]::new([Convert]::FromBase64String(${'$'}value)),[IO.Compression.CompressionMode]::Decompress)
                ${'$'}reader=[IO.StreamReader]::new(${'$'}stream,[Text.UTF8Encoding]::new(${'$'}false,${'$'}true))
                try { ${'$'}reader.ReadToEnd() } finally { ${'$'}reader.Dispose() }
            }
            Add-Type -TypeDefinition (Expand-Fixed '$native')
            & ([ScriptBlock]::Create((Expand-Fixed '$worker'))) '$jobId' ([uint32]$ownerPid)
        """.trimIndent()
        // Leave room for the trusted OS executable path and fixed switches below CreateProcess's limit.
        // The operand contains only fixed ASCII code/base64 and validated UUID/numeric identifiers.
        // Pass it as ONE ProcessBuilder token; ShellExecute callers must use Windows argv quoting.
        // UTF-16 -EncodedCommand would inflate captured source past Windows' command-line limit.
        require(script.length < 30000 && script.all { it.code < 128 }) {
            "Captured installer worker exceeds Windows command-line bound"
        }
        return listOf("-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
    }
}
