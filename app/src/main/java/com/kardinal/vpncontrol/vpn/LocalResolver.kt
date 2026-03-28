package com.kardinal.vpncontrol.vpn

import android.net.DnsResolver
import android.os.CancellationSignal
import android.system.ErrnoException
import io.nekohasekai.libbox.ExchangeContext
import io.nekohasekai.libbox.Func
import io.nekohasekai.libbox.LocalDNSTransport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asExecutor
import kotlinx.coroutines.runBlocking
import java.net.InetAddress
import java.net.UnknownHostException
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

object LocalResolver : LocalDNSTransport {
    private const val RCODE_SERVFAIL = 2
    private const val RCODE_NXDOMAIN = 3

    override fun raw(): Boolean = true

    override fun exchange(ctx: ExchangeContext, message: ByteArray) {
        runBlocking {
            val network = DefaultNetworkMonitor.requireNetwork()
            suspendCoroutine { continuation ->
                val signal = CancellationSignal()
                ctx.onCancel(Func { signal.cancel() })
                DnsResolver.getInstance().rawQuery(
                    network,
                    message,
                    DnsResolver.FLAG_NO_RETRY,
                    Dispatchers.IO.asExecutor(),
                    signal,
                    object : DnsResolver.Callback<ByteArray> {
                        override fun onAnswer(answer: ByteArray, rcode: Int) {
                            if (rcode == 0) {
                                ctx.rawSuccess(answer)
                            } else {
                                ctx.errorCode(rcode)
                            }
                            continuation.resume(Unit)
                        }

                        override fun onError(error: DnsResolver.DnsException) {
                            val cause = error.cause
                            if (cause is ErrnoException) {
                                ctx.errnoCode(cause.errno)
                            } else {
                                ctx.errorCode(RCODE_SERVFAIL)
                            }
                            continuation.resume(Unit)
                        }
                    },
                )
            }
        }
    }

    override fun lookup(ctx: ExchangeContext, network: String, domain: String) {
        runBlocking {
            val defaultNetwork = DefaultNetworkMonitor.requireNetwork()
            suspendCoroutine { continuation ->
                val signal = CancellationSignal()
                ctx.onCancel(Func { signal.cancel() })
                val callback = object : DnsResolver.Callback<Collection<InetAddress>> {
                    override fun onAnswer(answer: Collection<InetAddress>, rcode: Int) {
                        if (rcode == 0) {
                            ctx.success(answer.mapNotNull { it.hostAddress }.joinToString("\n"))
                        } else {
                            ctx.errorCode(rcode)
                        }
                        continuation.resume(Unit)
                    }

                    override fun onError(error: DnsResolver.DnsException) {
                        val cause = error.cause
                        if (cause is ErrnoException) {
                            ctx.errnoCode(cause.errno)
                        } else {
                            ctx.errorCode(RCODE_SERVFAIL)
                        }
                        continuation.resume(Unit)
                    }
                }
                val type = when {
                    network.endsWith("4") -> DnsResolver.TYPE_A
                    network.endsWith("6") -> DnsResolver.TYPE_AAAA
                    else -> null
                }
                if (type != null) {
                    DnsResolver.getInstance().query(
                        defaultNetwork,
                        domain,
                        type,
                        DnsResolver.FLAG_NO_RETRY,
                        Dispatchers.IO.asExecutor(),
                        signal,
                        callback,
                    )
                } else {
                    DnsResolver.getInstance().query(
                        defaultNetwork,
                        domain,
                        DnsResolver.FLAG_NO_RETRY,
                        Dispatchers.IO.asExecutor(),
                        signal,
                        callback,
                    )
                }
            }
        }
    }

    fun fallbackLookup(domain: String): List<InetAddress> {
        return try {
            InetAddress.getAllByName(domain).toList()
        } catch (_: UnknownHostException) {
            emptyList()
        }
    }
}
