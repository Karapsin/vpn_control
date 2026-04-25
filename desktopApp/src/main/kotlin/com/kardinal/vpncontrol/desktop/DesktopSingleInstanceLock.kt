package com.kardinal.vpncontrol.desktop

import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.channels.OverlappingFileLockException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption

internal class DesktopSingleInstanceLock private constructor(
    private val channel: FileChannel,
    private val lock: FileLock,
) : AutoCloseable {
    override fun close() {
        runCatching { lock.release() }
        runCatching { channel.close() }
    }

    companion object {
        fun acquire(
            lockFile: Path = Path.of(
                System.getProperty("user.home"),
                ".vpn-control-desktop",
                "vpn-control.lock",
            ),
        ): DesktopSingleInstanceLock? {
            Files.createDirectories(lockFile.parent)
            val channel = FileChannel.open(
                lockFile,
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
            )
            val lock = try {
                channel.tryLock()
            } catch (_: OverlappingFileLockException) {
                null
            }
            if (lock == null) {
                channel.close()
                return null
            }
            channel.truncate(0)
            channel.write(java.nio.ByteBuffer.wrap(ProcessHandle.current().pid().toString().toByteArray()))
            return DesktopSingleInstanceLock(channel, lock)
        }
    }
}
