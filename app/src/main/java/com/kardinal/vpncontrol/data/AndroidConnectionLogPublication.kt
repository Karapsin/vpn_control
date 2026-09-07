package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ConnectionLogEntry
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** Delivers each durable bounded log list in write order, including rollover between reads. */
internal class AndroidConnectionLogPublication {
    private val writes = Mutex()
    @Volatile private var observer: ((List<ConnectionLogEntry>) -> Unit)? = null

    fun observe(observer: (List<ConnectionLogEntry>) -> Unit) { this.observer = observer }

    suspend fun commit(write: suspend () -> List<ConnectionLogEntry>) = writes.withLock {
        // A service/GUI coroutine may disappear after DataStore commits. Finish the
        // publication before releasing write order so the next status cannot pass it.
        withContext(NonCancellable) {
            val committed = write()
            observer?.invoke(committed)
            Unit
        }
    }
}
