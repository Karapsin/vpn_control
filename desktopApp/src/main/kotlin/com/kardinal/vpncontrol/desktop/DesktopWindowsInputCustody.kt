package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlValue

/** Fixed original objects only. Names are protocol constants, never caller paths. */
internal enum class DesktopWindowsInputCustodyLeaf(val nameOnDisk: String) {
    REQUEST("request.json"), PACKAGE("package.msi"), COMMIT("commit.json"),
    WORKER_READY("worker-ready.json"), WORKER_RESULT("worker-result.json"),
}

/** Native FILE_ID_INFO text is data until compared with an inspected original handle. */
internal data class DesktopWindowsInputCustodyFile(
    val leaf: DesktopWindowsInputCustodyLeaf,
    val nativeId: String,
    val size: Long,
    val sha256: String,
) {
    val name get() = leaf.nameOnDisk
    init {
        requireCustodyNativeId(nativeId)
        require(size > 0)
        requireCustodySha256(sha256)
    }
    override fun toString() = "DesktopWindowsInputCustodyFile(leaf=$leaf, identity=<private>)"
}

/** Native creation FILETIME remains an integer, never milliseconds or floating point. */
internal data class DesktopWindowsInputCustodyProcess(
    val pid: Long,
    val creationFileTime: Long,
    val helperSha256: String,
) {
    init {
        require(pid in 1..0xffffffffL && creationFileTime > 0)
        requireCustodySha256(helperSha256)
    }
    override fun toString() = "DesktopWindowsInputCustodyProcess(identity=<private>)"
}

/**
 * Immutable data contract matching InputCustodyContract.final.cs exactly.
 * Decoding/binding does not admit protected file custody, actor closure, cleanup or replay.
 * The native reader independently retains and checks the protected chain and all originals.
 */
internal data class DesktopWindowsInputCustody(
    val jobId: String,
    val principalSid: String,
    val workspaceSha256: String,
    val inputRootNativeId: String,
    val inputJobNativeId: String,
    val protectedMachineNativeId: String,
    val protectedJobNativeId: String,
    val worker: DesktopWindowsInputCustodyProcess,
    val coordinator: DesktopWindowsInputCustodyProcess,
    val request: DesktopWindowsInputCustodyFile,
    val packageFile: DesktopWindowsInputCustodyFile,
    val commit: DesktopWindowsInputCustodyFile,
    val workerReady: DesktopWindowsInputCustodyFile,
    val workerResult: DesktopWindowsInputCustodyFile,
) {
    // A new view is returned each time; mutating a cast of this list cannot change the record.
    val files get() = listOf(request, packageFile, commit, workerReady, workerResult)

    init {
        require(DesktopInstallJobNames.validJob(jobId))
        requireCustodySid(principalSid)
        requireCustodySha256(workspaceSha256)
        require(worker.pid != coordinator.pid && worker.helperSha256 == coordinator.helperSha256)
        val directories = listOf(inputRootNativeId, inputJobNativeId, protectedMachineNativeId, protectedJobNativeId)
        directories.forEach(::requireCustodyNativeId)
        require(files.map { it.leaf } == DesktopWindowsInputCustodyLeaf.entries)
        val identities = directories + files.map { it.nativeId }
        require(identities.distinct().size == 9)
    }

    fun file(leaf: DesktopWindowsInputCustodyLeaf): DesktopWindowsInputCustodyFile = when (leaf) {
        DesktopWindowsInputCustodyLeaf.REQUEST -> request
        DesktopWindowsInputCustodyLeaf.PACKAGE -> packageFile
        DesktopWindowsInputCustodyLeaf.COMMIT -> commit
        DesktopWindowsInputCustodyLeaf.WORKER_READY -> workerReady
        DesktopWindowsInputCustodyLeaf.WORKER_RESULT -> workerResult
    }

    fun encode(): ByteArray {
        val values = linkedMapOf<String, ControlValue>(
            "version" to ControlValue.IntegerValue(1),
            "jobId" to ControlValue.Text(jobId),
            "principalSid" to ControlValue.Text(principalSid),
            "workspaceSha256" to ControlValue.Text(workspaceSha256),
            "inputRootNativeId" to ControlValue.Text(inputRootNativeId),
            "inputJobNativeId" to ControlValue.Text(inputJobNativeId),
            "protectedMachineNativeId" to ControlValue.Text(protectedMachineNativeId),
            "protectedJobNativeId" to ControlValue.Text(protectedJobNativeId),
        )
        fun process(prefix: String, value: DesktopWindowsInputCustodyProcess) {
            values[prefix + "Pid"] = ControlValue.IntegerValue(value.pid)
            values[prefix + "CreationFileTime"] = ControlValue.IntegerValue(value.creationFileTime)
            values[prefix + "HelperSha256"] = ControlValue.Text(value.helperSha256)
        }
        process("worker", worker)
        process("coordinator", coordinator)
        for (file in files) {
            values[file.name + ".nativeId"] = ControlValue.Text(file.nativeId)
            values[file.name + ".size"] = ControlValue.IntegerValue(file.size)
            values[file.name + ".sha256"] = ControlValue.Text(file.sha256)
        }
        return ControlProtocolCodec.encodeValues(values).encodeToByteArray().also {
            require(it.size <= MAX_BYTES)
            require(decode(it) == this)
        }
    }

    /** Data matching only: receipt must arrive from the independent protected native reader. */
    fun requireBinding(
        binding: DesktopInstallCorrelationRecord,
        receipt: DesktopInstallJobReceipt,
        currentSid: String,
        workspaceSHA: String,
    ) {
        requireCustodySid(currentSid)
        requireCustodySha256(workspaceSHA)
        require(binding.receiptAuthority == DesktopInstallReceiptAuthority.MACHINE)
        require(binding.jobId == jobId && receipt.jobId == jobId)
        require(binding.workspaceKey == workspaceSha256 && workspaceSHA == workspaceSha256)
        require(currentSid == principalSid)
        require(receipt.phase == DesktopInstallJobPhase.SUCCEEDED && receipt.code == ControlCode.OK)
    }

    fun requireSame(observed: DesktopWindowsInputCustody) { require(this == observed) }

    override fun toString() = "DesktopWindowsInputCustody(data=<private>)"

    companion object {
        const val NAME = "input-custody.json"
        const val MAX_BYTES = 4096
        private val baseFields = setOf(
            "version", "jobId", "principalSid", "workspaceSha256", "inputRootNativeId", "inputJobNativeId",
            "protectedMachineNativeId", "protectedJobNativeId", "workerPid", "workerCreationFileTime",
            "workerHelperSha256", "coordinatorPid", "coordinatorCreationFileTime", "coordinatorHelperSha256",
        )
        private val fields = baseFields + DesktopWindowsInputCustodyLeaf.entries.flatMap { leaf ->
            listOf(leaf.nameOnDisk + ".nativeId", leaf.nameOnDisk + ".size", leaf.nameOnDisk + ".sha256")
        }

        fun decode(bytes: ByteArray): DesktopWindowsInputCustody {
            require(bytes.size <= MAX_BYTES)
            val frame = bytes.decodeToString(throwOnInvalidSequence = true)
            requireCustodyFlatScalarWire(frame)
            val values = ControlProtocolCodec.decodeValues(frame)
            require(values.keys == fields && values["version"] == ControlValue.IntegerValue(1))
            fun text(name: String) = requireNotNull(values[name] as? ControlValue.Text).value
            fun number(name: String) = requireNotNull(values[name] as? ControlValue.IntegerValue).value
            fun process(prefix: String) = DesktopWindowsInputCustodyProcess(
                number(prefix + "Pid"), number(prefix + "CreationFileTime"), text(prefix + "HelperSha256"),
            )
            fun file(leaf: DesktopWindowsInputCustodyLeaf) = DesktopWindowsInputCustodyFile(
                leaf, text(leaf.nameOnDisk + ".nativeId"), number(leaf.nameOnDisk + ".size"), text(leaf.nameOnDisk + ".sha256"),
            )
            return DesktopWindowsInputCustody(
                text("jobId"), text("principalSid"), text("workspaceSha256"),
                text("inputRootNativeId"), text("inputJobNativeId"), text("protectedMachineNativeId"), text("protectedJobNativeId"),
                process("worker"), process("coordinator"), file(DesktopWindowsInputCustodyLeaf.REQUEST),
                file(DesktopWindowsInputCustodyLeaf.PACKAGE), file(DesktopWindowsInputCustodyLeaf.COMMIT),
                file(DesktopWindowsInputCustodyLeaf.WORKER_READY), file(DesktopWindowsInputCustodyLeaf.WORKER_RESULT),
            )
        }
    }
}

private fun requireCustodySha256(value: String) {
    require(value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' })
}

private fun requireCustodyNativeId(value: String) {
    require(value.length == 48 && value.all { it in '0'..'9' || it in 'a'..'f' } && value.any { it != '0' })
}

private fun requireCustodySid(value: String) {
    val parts = value.split('-')
    require(parts.size in 4..18 && parts[0] == "S" && parts[1] == "1")
    parts.drop(2).forEachIndexed { index, text ->
        require(text.isNotEmpty() && text.all { it in '0'..'9' })
        val number = requireNotNull(text.toLongOrNull())
        require(text == number.toString() && number in 0..if (index == 0) 0xffffffffffffL else 0xffffffffL)
    }
}

/**
 * The shared JSON decoder supplies duplicate/escape/object parsing. This small wire guard
 * preserves the native flat parser's scalar/nonnegative canonical integer grammar before
 * a general JSON codec can normalize numeric representations. It is not a JSON parser.
 */
private fun requireCustodyFlatScalarWire(frame: String) {
    var quoted = false
    var escaped = false
    var index = 0
    while (index < frame.length) {
        val char = frame[index]
        if (quoted) {
            require(char.code >= 32)
            if (escaped) escaped = false
            else if (char == '\\') escaped = true
            else if (char == '"') quoted = false
            index++
        } else when {
            char == '"' -> { quoted = true; index++ }
            char in "{}:, \t\r\n" -> index++
            char in '0'..'9' -> {
                val start = index
                while (index < frame.length && frame[index] in '0'..'9') index++
                require(index - start == 1 || frame[start] != '0')
            }
            else -> throw IllegalArgumentException("INVALID_INPUT_CUSTODY")
        }
    }
    require(!quoted && !escaped)
}
