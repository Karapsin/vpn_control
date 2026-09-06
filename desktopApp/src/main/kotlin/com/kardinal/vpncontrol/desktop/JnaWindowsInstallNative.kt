package com.kardinal.vpncontrol.desktop

import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Platform
import com.sun.jna.Pointer
import com.sun.jna.WString
import com.sun.jna.platform.win32.*
import com.sun.jna.ptr.IntByReference
import com.sun.jna.ptr.LongByReference
import com.sun.jna.ptr.PointerByReference
import com.sun.jna.win32.StdCallLibrary
import com.sun.jna.win32.W32APIOptions
import java.io.ByteArrayOutputStream

/** Lazy bindings: constructing a backend or running fake-native tests never loads Windows DLLs. */
internal class JnaWindowsInstallNative : WindowsInstallNative {
    private val kernel by lazy { check(Platform.isWindows()); Native.load("kernel32", Kernel32::class.java, W32APIOptions.UNICODE_OPTIONS) }
    private val advapi by lazy { check(Platform.isWindows()); Native.load("advapi32", Advapi32::class.java, W32APIOptions.UNICODE_OPTIONS) }
    private val extraKernel by lazy { check(Platform.isWindows()); Native.load("kernel32", ExtraKernel::class.java) }
    private val extraSecurity by lazy { check(Platform.isWindows()); Native.load("advapi32", ExtraSecurity::class.java) }
    private class Handle(val value: WinNT.HANDLE, val restrictedWriter: Boolean) : WindowsInstallNative.Handle
    private fun handle(value: WindowsInstallNative.Handle) = (value as Handle).value
    private fun checked(ok: Boolean) { if (!ok) throw WindowsInstallNativeFailure(kernel.GetLastError()) }

    override fun programData(): String {
        check(Platform.isWindows())
        val pointer = PointerByReference()
        val result = Shell32.INSTANCE.SHGetKnownFolderPath(KnownFolders.FOLDERID_ProgramData, 0, null, pointer)
        if (result.toInt() != 0) throw WindowsInstallNativeFailure(result.toInt())
        return try { requireNotNull(pointer.value).getWideString(0) }
        finally { Ole32.INSTANCE.CoTaskMemFree(pointer.value) }
    }

    override fun open(path: String, access: Int, shareDelete: Boolean, createSddl: String?): WindowsInstallNative.Handle {
        // FILE_FLAG_OPEN_REPARSE_POINT classifies the object itself, including junctions/mountpoints.
        // Every ancestor was opened separately and remains pinned without FILE_SHARE_DELETE.
        val options = windowsInstallOpenOptions(access, shareDelete, createSddl != null)
        fun opened(attributes: WinBase.SECURITY_ATTRIBUTES?): WindowsInstallNative.Handle {
            val opened = kernel.CreateFile(path, options.rights, options.share, attributes, options.creation,
                options.flags, null)
            if (opened == WinBase.INVALID_HANDLE_VALUE || opened.pointer == WinBase.INVALID_HANDLE_VALUE.pointer)
                throw WindowsInstallNativeFailure(kernel.GetLastError())
            return Handle(opened, access == WindowsInstallNative.READ_WRITE && createSddl == null)
        }
        return if (createSddl == null) opened(null) else withSecurity(createSddl, ::opened)
    }

    override fun createDirectory(path: String, sddl: String, allowExisting: Boolean) = withSecurity(sddl) { attributes ->
        if (!kernel.CreateDirectory(path, attributes)) {
            val code = kernel.GetLastError()
            if (!allowExisting || code != 183) throw WindowsInstallNativeFailure(code)
        }
    }

    private fun <T> withSecurity(sddl: String, action: (WinBase.SECURITY_ATTRIBUTES) -> T): T {
        val descriptor = PointerByReference()
        checked(extraSecurity.ConvertStringSecurityDescriptorToSecurityDescriptorW(WString(sddl), 1, descriptor, null))
        try {
            val attributes = WinBase.SECURITY_ATTRIBUTES()
            attributes.lpSecurityDescriptor = descriptor.value
            attributes.bInheritHandle = false
            attributes.write()
            return action(attributes)
        } finally { kernel.LocalFree(descriptor.value) }
    }

    override fun inspect(handle: WindowsInstallNative.Handle): WindowsInstallInfo {
        val opened = handle(handle)
        val attributes = Memory(8)
        checked(kernel.GetFileInformationByHandleEx(opened, 9, attributes, WinDef.DWORD(8))) // FileAttributeTagInfo
        val standard = Memory(24)
        checked(kernel.GetFileInformationByHandleEx(opened, 1, standard, WinDef.DWORD(24))) // FileStandardInfo
        val owner = PointerByReference()
        val dacl = PointerByReference()
        val descriptor = PointerByReference()
        val code = advapi.GetSecurityInfo(opened, 1, 0x5, owner, null, dacl, null, descriptor)
        if (code != 0) throw WindowsInstallNativeFailure(code)
        try {
            require(advapi.IsValidSecurityDescriptor(descriptor.value))
            val ownerSid = sid(requireNotNull(owner.value))
            val entries = dacl.value?.let { aclPointer ->
                require(advapi.IsValidAcl(aclPointer))
                val acl = WinNT.ACL(aclPointer)
                val count = aclPointer.getShort(4).toInt() and 0xffff
                require(count <= 4096)
                (0 until count).map { index ->
                    val ace = PointerByReference()
                    checked(advapi.GetAce(acl, index, ace))
                    val pointer = requireNotNull(ace.value)
                    val type = pointer.getByte(0).toInt() and 0xff
                    val flags = pointer.getByte(1).toInt() and 0xff
                    require(type == 0 || type == 1) { "Unsupported installer ACE" }
                    require((pointer.getShort(2).toInt() and 0xffff) >= 16)
                    WindowsInstallAce(type, flags, pointer.getInt(4), sid(pointer.share(8)))
                }
            }
            return WindowsInstallInfo(standard.getByte(21).toInt() != 0, attributes.getInt(0), attributes.getInt(4),
                ownerSid, entries, standard.getLong(8), standard.getInt(16), kernel.GetFileType(opened) == 1)
        } finally { kernel.LocalFree(descriptor.value) }
    }

    private fun sid(pointer: Pointer): String {
        val sid = WinNT.PSID(pointer)
        require(advapi.IsValidSid(sid))
        val string = PointerByReference()
        checked(advapi.ConvertSidToStringSid(sid, string))
        return try { requireNotNull(string.value).getWideString(0) } finally { kernel.LocalFree(string.value) }
    }

    override fun read(handle: WindowsInstallNative.Handle, limit: Int): ByteArray {
        require(limit in 1..1_048_577)
        val opened = handle(handle)
        checked(extraKernel.SetFilePointerEx(opened, 0, null, 0))
        val output = ByteArrayOutputStream()
        while (output.size() < limit) {
            val bytes = ByteArray(minOf(8192, limit - output.size()))
            val received = IntByReference()
            checked(kernel.ReadFile(opened, bytes, bytes.size, received, null))
            require(received.value in 0..bytes.size)
            if (received.value == 0) break
            output.write(bytes, 0, received.value)
        }
        return output.toByteArray()
    }

    override fun writeAndSync(handle: WindowsInstallNative.Handle, bytes: ByteArray) {
        val opened = handle(handle)
        val restricted = (handle as Handle).restrictedWriter
        if (restricted) require(bytes.contentEquals(byteArrayOf(1)) && inspect(handle).size == 1L)
        checked(extraKernel.SetFilePointerEx(opened, 0, null, 0))
        var offset = 0
        while (offset < bytes.size) {
            val chunk = bytes.copyOfRange(offset, minOf(offset + 8192, bytes.size))
            val written = IntByReference()
            checked(kernel.WriteFile(opened, chunk, chunk.size, written, null))
            require(written.value in 1..chunk.size)
            offset += written.value
        }
        if (!restricted) {
            val length = Memory(8).also { it.setLong(0, bytes.size.toLong()) }
            checked(kernel.SetFileInformationByHandle(opened, 6, length, WinDef.DWORD(8))) // FileEndOfFileInfo
            checked(kernel.FlushFileBuffers(opened))
        }
        // Existing cancellation writers have FILE_WRITE_DATA, not GENERIC_WRITE (required by
        // FlushFileBuffers). Their fixed-size write uses FILE_FLAG_WRITE_THROUGH instead;
        // both data and metadata are flushed by that documented caching mode.
    }

    internal fun requirePrivateExport(handle: WindowsInstallNative.Handle, owner: String) {
        val flags = IntByReference()
        checked(extraKernel.GetVolumeInformationByHandleW(handle(handle), null, 0, null, null, flags, null, 0))
        requireWindowsPrivateExport(flags.value, inspect(handle), owner)
    }

    override fun rename(handle: WindowsInstallNative.Handle, directory: WindowsInstallNative.Handle, name: String) {
        require(name == DesktopInstallJobNames.STATUS)
        // Win32 rejects the relative RootDirectory form on supported native hosts.
        // Resolve the retained directory handle, not a caller path. Every ancestor
        // stays pinned against rename/reparse mutation until this call completes.
        // A volume GUID also avoids per-user DOS drive-letter remapping.
        val buffer = CharArray(32768)
        val length = extraKernel.GetFinalPathNameByHandleW(handle(directory), buffer, buffer.size, 1)
        if (length == 0) throw WindowsInstallNativeFailure(kernel.GetLastError())
        require(length in 1 until buffer.size) { "Installer directory path exceeds native bound" }
        val info = windowsInstallRenameInfo(String(buffer, 0, length), Native.POINTER_SIZE)
        checked(kernel.SetFileInformationByHandle(handle(handle), 3, info, WinDef.DWORD(info.size())))
    }

    override fun delete(handle: WindowsInstallNative.Handle) {
        val info = Memory(1).also { it.setByte(0, 1) }
        checked(kernel.SetFileInformationByHandle(handle(handle), 4, info, WinDef.DWORD(1)))
    }
    override fun close(handle: WindowsInstallNative.Handle) { checked(kernel.CloseHandle(handle(handle))) }

    private interface ExtraKernel : StdCallLibrary {
        fun GetVolumeInformationByHandleW(handle: WinNT.HANDLE, volumeName: CharArray?, volumeSize: Int,
            serial: IntByReference?, componentLength: IntByReference?, flags: IntByReference,
            fileSystemName: CharArray?, fileSystemSize: Int): Boolean
        fun SetFilePointerEx(handle: WinNT.HANDLE, distance: Long, position: LongByReference?, method: Int): Boolean
        fun GetFinalPathNameByHandleW(handle: WinNT.HANDLE, path: CharArray, size: Int, flags: Int): Int
    }
    private interface ExtraSecurity : StdCallLibrary {
        fun ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl: WString, revision: Int,
            descriptor: PointerByReference, size: IntByReference?): Boolean
    }
}

internal fun requireWindowsPrivateExport(volumeFlags: Int, info: WindowsInstallInfo, owner: String) {
    require(volumeFlags and 8 != 0) { "Export volume does not enforce ACLs" }
    require(info.disk && !info.directory && info.attributes and 0x400 == 0 && info.reparseTag == 0 && info.links == 1)
    require(info.owner == owner)
    val acl = requireNotNull(info.dacl)
    require(acl.isNotEmpty() && acl.all { it.type == 0 && it.sid == owner && it.flags and 0x18 == 0 })
}

/** FILE_RENAME_INFO with a null RootDirectory and a handle-resolved absolute UTF-16 path. */
internal fun windowsInstallRenameInfo(directory: String, pointerSize: Int): Memory {
    require(pointerSize == 4 || pointerSize == 8)
    val prefix = "\\\\?\\Volume{"
    require(directory.startsWith(prefix) && directory.length > prefix.length + 37)
    val id = directory.substring(prefix.length, prefix.length + 36)
    require(java.util.UUID.fromString(id).toString().equals(id, ignoreCase = true))
    require(directory.substring(prefix.length + 36).startsWith("}\\"))
    require('\u0000' !in directory && '/' !in directory)
    val target = directory.trimEnd('\\') + "\\" + DesktopInstallJobNames.STATUS
    require(target.length < 32768)
    val bytes = target.toByteArray(Charsets.UTF_16LE)
    val rootOffset = if (pointerSize == 8) 8L else 4L
    val lengthOffset = rootOffset + pointerSize
    val nameOffset = lengthOffset + 4
    return Memory(nameOffset + bytes.size + 2).also { info ->
        info.clear() // RootDirectory must remain NULL.
        info.setByte(0, 1)
        info.setInt(lengthOffset, bytes.size)
        info.write(nameOffset, bytes, 0, bytes.size)
    }
}

internal data class WindowsInstallOpenOptions(val rights: Int, val share: Int, val creation: Int, val flags: Int)
internal fun windowsInstallOpenOptions(access: Int, shareDelete: Boolean, create: Boolean): WindowsInstallOpenOptions {
    val rights = 0x00120080 or when (access) {
        WindowsInstallNative.INSPECT -> 0
        WindowsInstallNative.READ -> 1
        WindowsInstallNative.READ_WRITE -> if (create) 0x40000003 else 3
        WindowsInstallNative.DELETE -> 0x00010000
        else -> error("Invalid installer access")
    }
    // Directory pins additionally deny direct write handles (including reparse mutation).
    // Cancellation readers/writers must share data writes with their cooperating retained handle.
    return WindowsInstallOpenOptions(rights, 1 or (if (access == WindowsInstallNative.INSPECT) 0 else 2) or
        (if (shareDelete) 4 else 0), if (create) 1 else 3,
        0x02200000 or if (access == WindowsInstallNative.READ_WRITE) 0x80000000.toInt() else 0)
}
