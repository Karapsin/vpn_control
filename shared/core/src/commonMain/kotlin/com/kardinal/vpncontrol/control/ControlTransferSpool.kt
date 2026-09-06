package com.kardinal.vpncontrol.control

/**
 * Private owner-controlled storage, never a client path. Calls are serialized by the store;
 * adapters must invoke that store on an appropriate IO dispatcher. append/read are <=64KiB.
 * sha256 returns a lowercase digest snapshot without finalizing/resetting incremental state.
 * erase is idempotent and releases resources. Failed append may be partial: store invalidates it.
 */
interface ControlTransferSpool {
    fun append(bytes: ByteArray)
    fun read(offset: Long, length: Int): ByteArray
    fun sha256(): String
    fun erase()
}
