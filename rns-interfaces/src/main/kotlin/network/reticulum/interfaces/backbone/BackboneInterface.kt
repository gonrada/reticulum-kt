package network.reticulum.interfaces.backbone

import network.reticulum.common.RnsConstants
import network.reticulum.common.RnsLog
import network.reticulum.interfaces.Interface
import network.reticulum.interfaces.framing.HDLC
import network.reticulum.interfaces.framing.HdlcReceiveBuffer
import network.reticulum.interfaces.toRef
import network.reticulum.interfaces.util.TcpKeepalive
import network.reticulum.interfaces.util.TransmitBuffer
import network.reticulum.transport.Transport
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * High-throughput TCP backbone interface — Kotlin port of Python RNS's
 * `BackboneInterface`. A single [Selector] event loop accepts client connections and
 * drives all of their I/O, spawning one [BackboneClientInterface] per client that
 * deframes with [HdlcReceiveBuffer] and transmits through a coalescing [TransmitBuffer].
 *
 * The Python original is `epoll`-based and therefore Linux/Android-only; this port uses
 * Java NIO, so it is cross-platform. The dataplane ingress/egress burst-control aggregation
 * from the Python version is deferred (a separate increment); this is the transport core.
 *
 * Threading: the selector loop is the sole consumer of each client's [TransmitBuffer] and
 * the sole reader. `processOutgoing` runs on Transport's outbound thread (the producer);
 * it appends to the client's buffer and enqueues a write-interest request that the loop
 * applies — so `interestOps` is never touched off-thread mid-`select`.
 */
class BackboneInterface(
    name: String,
    private val bindIp: String,
    private val bindPort: Int,
    override val ifacNetname: String? = null,
    override val ifacNetkey: String? = null,
    /** Configured `ifac_size` in bits, as the config expresses it; null keeps the class default (python Reticulum.py:950 applies it to every interface, Backbone included). */
    private val ifacSizeBits: Int? = null,
) : Interface(name) {

    override val configuredIfacSizeBits: Int?
        get() = ifacSizeBits

    companion object {
        /**
         * python `BackboneInterface.HW_MTU` (BackboneInterface.py:43). This was 262144 —
         * TCPInterface's value — which is a quarter of what the reference uses. HW_MTU
         * bounds the largest frame the interface will carry and feeds link MTU discovery,
         * so a python backbone peer negotiating up to 1 MiB would have its larger frames
         * rejected here.
         */
        const val HW_MTU = 1048576
        const val BITRATE_GUESS = 1_000_000_000

        /** Per-client outbound high-water mark. Bounds buffered-unsent bytes so a slow
         *  or stalled client cannot grow its transmit buffer without limit. */
        const val TX_HWM = 16 * 1024 * 1024

        /** Cap on concurrently spawned client interfaces, so a connection flood cannot
         *  exhaust memory/Transport state with unbounded spawned interfaces. */
        const val MAX_CLIENTS = 1024

        private const val READ_BUFSIZE = 65536
        private const val SELECT_TIMEOUT_MS = 1000L
    }

    override val hwMtu: Int = HW_MTU

    // IFAC credentials are derived in the Interface base from ifacNetname/ifacNetkey and
    // delegated to every spawned BackboneClientInterface, as python
    // BackboneInterface.py:722-730 copies ifac_size/netname/netkey to each spawned
    // interface and derives its ifac_key from them.

    private var serverChannel: ServerSocketChannel? = null
    private var selector: Selector? = null
    private var loopThread: Thread? = null
    private val running = AtomicBoolean(false)
    private val pendingWrites = ConcurrentLinkedQueue<BackboneClientInterface>()

    init { spawnedInterfaces = CopyOnWriteArrayList() }

    /** The actual bound port (useful when [bindPort] is 0 for an ephemeral port). */
    val boundPort: Int
        get() = (serverChannel?.localAddress as? InetSocketAddress)?.port ?: bindPort

    override fun start() {
        val sel = Selector.open()
        val server = ServerSocketChannel.open()
        server.configureBlocking(false)
        server.bind(InetSocketAddress(bindIp, bindPort))
        server.register(sel, SelectionKey.OP_ACCEPT)
        selector = sel
        serverChannel = server
        running.set(true)
        setOnline(true)
        loopThread = thread(name = "BackboneInterface-$name", isDaemon = true) { loop(sel, server) }
    }

    /** Producer side: enqueue a write-interest request for [client]; the loop applies it. */
    internal fun requestWrite(client: BackboneClientInterface) {
        pendingWrites.add(client)
        selector?.wakeup()
    }

    private fun loop(sel: Selector, server: ServerSocketChannel) {
        val readBuf = ByteBuffer.allocate(READ_BUFSIZE)
        while (running.get() && !detached.get()) {
            try { sel.select(SELECT_TIMEOUT_MS) } catch (e: Exception) {
                if (running.get()) continue else break
            }
            if (!running.get() || detached.get()) break

            // Apply queued write-interest requests on the loop thread.
            while (true) {
                val c = pendingWrites.poll() ?: break
                val k = c.selectionKey
                if (k != null && k.isValid) k.interestOps(k.interestOps() or SelectionKey.OP_WRITE)
            }

            val it = sel.selectedKeys().iterator()
            while (it.hasNext()) {
                val key = it.next()
                it.remove()
                if (!key.isValid) continue
                if (key.isAcceptable) {
                    // A failed accept() (EMFILE, a peer that reset mid-handshake, ...) is
                    // logged and the listener kept, as python BackboneInterface.py:652-663
                    // does. The server key must never reach closeClient(): that would close
                    // the ServerSocketChannel and stop accepting for the process lifetime.
                    try {
                        accept(sel, server)
                    } catch (e: Exception) {
                        RnsLog.log(RnsLog.WARNING, name) { "Accepting socket failed for incoming connection: $e" }
                    }
                    continue
                }
                try {
                    if (key.isReadable) read(key, readBuf)
                    if (key.isValid && key.isWritable) write(key)
                } catch (e: Exception) {
                    closeClient(key)
                }
            }
        }
    }

    private fun accept(sel: Selector, server: ServerSocketChannel) {
        val ch = server.accept() ?: return
        if ((spawnedInterfaces?.size ?: 0) >= MAX_CLIENTS) {
            // Refuse past the cap rather than spawn unbounded client interfaces.
            try { ch.close() } catch (_: Exception) {}
            return
        }
        try {
            ch.configureBlocking(false)
            // Dead-peer detection on every accepted client (python BackboneInterface.py:891
            // calls set_timeouts_linux on each connected_socket; :920-922 sets
            // SO_KEEPALIVE, TCP_KEEPIDLE=5, TCP_KEEPINTVL=2, TCP_KEEPCNT=12), so a
            // vanished peer cannot hold one of the MAX_CLIENTS slots indefinitely.
            TcpKeepalive.apply(ch)
            val remote = ch.remoteAddress as? InetSocketAddress
            val clientName = remote?.let { "${it.address.hostAddress}:${it.port}" } ?: "backbone-client"
            val client = BackboneClientInterface(clientName, ch, this)
            val key = ch.register(sel, SelectionKey.OP_READ, client)
            client.attach(key)
            client.onPacketReceived = { data, iface -> onPacketReceived?.invoke(data, iface) }
            client.setOnline(true)
            spawnedInterfaces?.add(client)
            try { Transport.registerInterface(client.toRef()) } catch (_: Exception) {}
        } catch (e: Exception) {
            // Failed after accept(): drop only the client channel (python
            // BackboneInterface.py:657-659 closes client_socket on a failed
            // incoming_connection), never the listener.
            try { ch.close() } catch (_: Exception) {}
            throw e
        }
    }

    private fun read(key: SelectionKey, readBuf: ByteBuffer) {
        val ch = key.channel() as SocketChannel
        val client = key.attachment() as BackboneClientInterface
        readBuf.clear()
        val n = ch.read(readBuf)
        if (n == -1) { closeClient(key); return }
        if (n > 0) {
            readBuf.flip()
            val bytes = ByteArray(n)
            readBuf.get(bytes)
            client.receiveBuffer.feed(bytes) // deframes -> onFrame -> client.processIncoming
        }
    }

    private fun write(key: SelectionKey) {
        val ch = key.channel() as SocketChannel
        val client = key.attachment() as BackboneClientInterface
        // A channel write returning 0 (would-block) makes drainTo stop; an IOException
        // propagates to the loop's catch and closes the client.
        client.transmitBuffer.drainTo { b, off, len -> ch.write(ByteBuffer.wrap(b, off, len)) }
        if (client.transmitBuffer.sendable == 0L) {
            key.interestOps(key.interestOps() and SelectionKey.OP_WRITE.inv())
        }
    }

    private fun closeClient(key: SelectionKey) {
        val client = key.attachment() as? BackboneClientInterface
        try { key.channel().close() } catch (_: Exception) {}
        key.cancel()
        if (client != null) {
            client.setOnline(false)
            spawnedInterfaces?.remove(client)
            try { Transport.deregisterInterface(client.toRef()) } catch (_: Exception) {}
        }
    }

    /**
     * Parent-level outbound is a no-op — python `BackboneInterface.process_outgoing`
     * is `pass` (RNS/Interfaces/BackboneInterface.py:776-777), exactly like
     * `TCPServerInterface`. Every spawned [BackboneClientInterface] is registered
     * with Transport in [accept], so Transport.transmit addresses the child directly.
     * Fanning out here as well would egress every broadcast twice per client (once
     * via this parent, once via the child Transport iterates independently).
     */
    override fun processOutgoing(data: ByteArray) {
        // Intentionally empty.
    }

    override fun detach() {
        running.set(false)
        detached.set(true)
        setOnline(false)
        val sel = selector
        sel?.wakeup()
        try { serverChannel?.close() } catch (_: Exception) {}
        // Take the spawned clients down in their own right before the selector goes.
        // Closing the selector's keys below closes their channels, so a client left
        // registered would be a Transport-visible interface whose writes can never be
        // drained: findInterfaceByHash does not filter on `online`, so a path-table entry
        // naming it still resolves and processOutbound transmits into a TransmitBuffer no
        // loop reads. The child's own processOutgoing guard does not catch it either,
        // because nothing had cleared its `online`/`detached` state. This is the same
        // teardown closeClient performs per connection, and the same order
        // LocalServerInterface.detach uses. python reaches the identical end state by a
        // different route: BackboneInterface.py:779-792 shuts down only the listener
        // sockets, and each spawned client is detached in its own right by
        // Transport.py:3625-3687, whose per-interface detach call lands in
        // BackboneInterface.py:927-945 and leaves the child online=False/detached=True,
        // so python's outbound (which tests interface.online) skips it. python has no
        // Transport.deregister_interface at all; in this port deregistration is what
        // produces that same "not a send candidate" state.
        // ArrayList copy, not toList(): the size==1 fast path races with a concurrent
        // removal from closeClient on the CopyOnWriteArrayList during teardown.
        val clients = spawnedInterfaces?.let { ArrayList(it) } ?: emptyList<Interface>()
        spawnedInterfaces?.clear()
        for (client in clients) {
            try { Transport.deregisterInterface(client.toRef()) } catch (_: Exception) {}
            try { client.detach() } catch (_: Exception) {}
        }
        try {
            sel?.keys()?.forEach {
                try { it.channel().close() } catch (_: Exception) {}
                it.cancel()
            }
        } catch (_: Exception) {}
        try { sel?.close() } catch (_: Exception) {}
        loopThread?.join(2000)
    }
}

/**
 * A single client connection spawned by [BackboneInterface]. It owns no thread — the
 * parent's selector loop reads into [receiveBuffer] and drains [transmitBuffer].
 */
class BackboneClientInterface(
    name: String,
    private val channel: SocketChannel,
    private val parent: BackboneInterface,
) : Interface(name) {

    init {
        parentInterface = parent
    }

    override val hwMtu: Int = BackboneInterface.HW_MTU

    // IFAC: same network as the parent. Credentials derive in the Interface base from
    // the delegated netname/netkey (identical bytes to the parent's); the tag size
    // follows the parent (python BackboneInterface.py:722-730).
    override val ifacNetname: String? get() = parent.ifacNetname
    override val ifacNetkey: String? get() = parent.ifacNetkey
    override val ifacSize: Int get() = parent.ifacSize

    @Volatile var selectionKey: SelectionKey? = null
        private set

    val receiveBuffer = HdlcReceiveBuffer(
        mtu = { hwMtu },
        minFrameLen = RnsConstants.HEADER_MIN_SIZE,
        // python BackboneInterface.py:876-877 passes max_frame_len = HW_MTU + ifac_size, so an
        // oversize frame is refused in the framer; without it the Transport MTU gate still
        // dropped the frame, but only after it was unescaped and counted.
        maxFrameLen = { hwMtu + ifacSize },
        onFrame = { frame -> processIncoming(frame) },
    )
    val transmitBuffer = TransmitBuffer()

    internal fun attach(key: SelectionKey) {
        this.selectionKey = key
    }

    override fun start() { setOnline(true) }

    override fun processOutgoing(data: ByteArray) {
        if (!online.value || detached.get()) return
        // Bound the per-client outbound buffer: if full, drop rather than grow unbounded.
        if (!transmitBuffer.append(HDLC.frame(data), BackboneInterface.TX_HWM)) return
        txBytes.addAndGet(data.size.toLong())
        parent.requestWrite(this)
    }

    override fun detach() {
        detached.set(true)
        setOnline(false)
        try { channel.close() } catch (_: Exception) {}
        selectionKey?.cancel()
    }
}
