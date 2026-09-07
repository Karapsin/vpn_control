package com.kardinal.vpncontrol.desktop

internal object DesktopLinuxCapturedInstallWorker {
    private fun source(name: String) = requireNotNull(javaClass.getResourceAsStream("/$name")).use {
        it.readNBytes(65537).also { bytes -> require(bytes.size <= 65536) }.decodeToString(throwOnInvalidSequence = true)
    }
    /** Only fixed captured code and validated correlation identifiers cross the privileged argv boundary. */
    fun arguments(jobId: String, ownerPid: Long): List<String> {
        require(DesktopInstallJobNames.validJob(jobId) && ownerPid in 1..Int.MAX_VALUE)
        val captured = source("linux-install-arch.sh") + "\n" + source("linux-install-worker.sh")
        require(captured.encodeToByteArray().size <= 65536)
        // pkexec reserves 126/127 for rejected/cancelled authorization, but also
        // returns its command's exit status. Keep those codes exclusive to the
        // authorization boundary. A separate shell preserves the worker's $$
        // identity for its retained /proc descriptors; a (...) subshell would not.
        val wrapper = """
            unset ENV BASH_ENV CDPATH
            /bin/sh -c "${'$'}1" vpn-control-install-worker "${'$'}2" "${'$'}3"
            worker_exit=${'$'}?
            case "${'$'}worker_exit" in
                126|127) exit 125 ;;
                *) exit "${'$'}worker_exit" ;;
            esac
        """.trimIndent()
        return listOf("/bin/sh", "-c", wrapper, "vpn-control-install-admission", captured, jobId, ownerPid.toString())
    }

    fun watcherArguments(jobId: String, ownerPid: Long): List<String> {
        require(DesktopInstallJobNames.validJob(jobId) && ownerPid in 1..Int.MAX_VALUE)
        return listOf("/bin/sh", "-c", source("linux-install-user.sh"), "vpn-control-install-user", jobId, ownerPid.toString())
    }
}
