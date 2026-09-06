package com.kardinal.vpncontrol

import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.Assert.*
import org.junit.Test

class AndroidApplicationOwnerInstrumentedTest {
    @Test
    fun recreatedFrontendSharesCommandOwnerButNotGuiDrafts() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val owner = AndroidApplicationOwner.get(context)
        assertSame(owner, AndroidApplicationOwner.get(context.applicationContext))
        val firstStore = ViewModelStore()
        val secondStore = ViewModelStore()
        val release = CompletableDeferred<Unit>()
        try {
            withContext(Dispatchers.Main) {
                val first = ViewModelProvider(firstStore, MainViewModel.factory(context))[MainViewModel::class.java]
                val second = ViewModelProvider(secondStore, MainViewModel.factory(context))[MainViewModel::class.java]
                first.onProfileDraftChanged("frontend-local-draft")
                assertNotEquals(first.uiState.value.profileDraft, second.uiState.value.profileDraft)
                val command = requireNotNull(owner.commands.launchTracked { release.await() })
                assertTrue(first.uiState.value.isBusy)
                assertTrue(second.uiState.value.isBusy)
                firstStore.clear()
                assertTrue(command.isActive)
                second.cancelActiveOperation()
                command.join()
                assertFalse(owner.commands.busy.value)
            }
        } finally {
            release.complete(Unit)
            withContext(Dispatchers.Main) {
                firstStore.clear()
                secondStore.clear()
            }
        }
    }
}
