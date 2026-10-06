package com.capi.webscan

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.Executors

private fun ByteArray.u(i: Int) = this[i].toInt() and 255

/**
 * VPN local : seul le trafic DNS (vers une fausse adresse) passe dans l'appli.
 * Les noms de domaine bloqués reçoivent "n'existe pas" ; les autres sont transmis au DNS réel.
 * Le reste du trafic (pages, vidéos...) ne transite PAS par l'appli.
 */
class BlockService : VpnService() {
    companion object { const val STOP = "STOP"; const val ADDR = "10.111.222.1"; const val DNS = "10.111.222.2" }

    private var tun: ParcelFileDescriptor? = null
    private var worker: Thread? = null
    private val pool = Executors.newFixedThreadPool(8)
    private val lock = Any()
    @Volatile private var running = false
    private var out: FileOutputStream? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == STOP) { stopSelf(); return START_NOT_STICKY }
        if (running) return START_STICKY
        Blocker.load(this)
        val pfd = try {
            Builder().setSession("Web Scan - Blocage").addAddress(ADDR, 32)
                .addDnsServer(DNS).addRoute(DNS, 32).setBlocking(true).establish()
        } catch (_: Exception) { null }
        if (pfd == null) { stopSelf(); return START_NOT_STICKY }
        tun = pfd; running = true
        out = FileOutputStream(pfd.fileDescriptor)
        worker = Thread { loop(FileInputStream(pfd.fileDescriptor)) }.also { it.start() }
        BlockState.active.value = true
        return START_STICKY
    }

    private fun loop(inp: FileInputStream) {
        val buf = ByteArray(32767)
        while (running) {
            val n = try { inp.read(buf) } catch (_: Exception) { -1 }
            if (n < 0) break
            if (n > 0) handle(buf.copyOf(n))
        }
    }

    private fun handle(p: ByteArray) {
        if (p.size < 28 || (p.u(0) shr 4) != 4 || p.u(9) != 17) return
        val ihl = (p.u(0) and 15) * 4
        if (p.size < ihl + 8) return
        if (((p.u(ihl + 2) shl 8) or p.u(ihl + 3)) != 53) return
        val udpLen = (p.u(ihl + 4) shl 8) or p.u(ihl + 5)
        val end = minOf(p.size, ihl + udpLen)
        if (end < ihl + 8 + 17) return
        val dns = p.copyOfRange(ihl + 8, end)
        val srcIp = p.copyOfRange(12, 16)
        val dstIp = p.copyOfRange(16, 20)
        val srcPort = (p.u(ihl) shl 8) or p.u(ihl + 1)
        pool.execute { try { answer(dns, srcIp, dstIp, srcPort) } catch (_: Exception) {} }
    }

    private fun answer(dns: ByteArray, srcIp: ByteArray, dstIp: ByteArray, srcPort: Int) {
        val q = parseQuestion(dns)
        val resp: ByteArray? = if (q != null && Blocker.isBlocked(q.first)) {
            BlockState.record(q.first, true)
            nxdomain(dns, q.second)
        } else {
            if (q != null) BlockState.record(q.first, false)
            forward(dns)
        }
        if (resp != null) {
            val pkt = build(dstIp, srcIp, 53, srcPort, resp)
            synchronized(lock) { try { out?.write(pkt) } catch (_: Exception) {} }
        }
    }

    /** Retourne (nom de domaine, fin de la question) */
    private fun parseQuestion(d: ByteArray): Pair<String, Int>? {
        var i = 12
        val sb = StringBuilder()
        while (i < d.size) {
            val l = d.u(i)
            if (l == 0) {
                val e = i + 5
                return if (sb.isEmpty() || e > d.size) null else sb.toString().lowercase() to e
            }
            if ((l and 0xC0) != 0 || i + 1 + l > d.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(d, i + 1, l, Charsets.US_ASCII))
            i += l + 1
        }
        return null
    }

    private fun nxdomain(d: ByteArray, qEnd: Int): ByteArray {
        val r = d.copyOf(qEnd)
        r[2] = (0x80 or (d.u(2) and 0x01)).toByte()   // réponse, on garde "recursion desired"
        r[3] = 0x83.toByte()                            // recursion available + NXDOMAIN
        for (k in 6..11) r[k] = 0                       // aucune réponse / autorité / additionnel
        return r
    }

    private fun forward(dns: ByteArray): ByteArray? {
        for (server in Blocker.upstream(Blocker.settings.value.level)) {
            try {
                DatagramSocket().use { s ->
                    protect(s)   // ce socket sort hors du VPN, sinon boucle infinie
                    s.soTimeout = 3000
                    s.send(DatagramPacket(dns, dns.size, InetAddress.getByName(server), 53))
                    val rb = ByteArray(4096)
                    val rp = DatagramPacket(rb, rb.size)
                    s.receive(rp)
                    return rb.copyOf(rp.length)
                }
            } catch (_: Exception) {}
        }
        return null
    }

    private fun build(src: ByteArray, dst: ByteArray, sport: Int, dport: Int, payload: ByteArray): ByteArray {
        val total = 28 + payload.size
        val b = ByteArray(total)
        b[0] = 0x45; b[2] = (total shr 8).toByte(); b[3] = total.toByte()
        b[8] = 64; b[9] = 17
        System.arraycopy(src, 0, b, 12, 4); System.arraycopy(dst, 0, b, 16, 4)
        val c = checksum(b, 0, 20)
        b[10] = (c shr 8).toByte(); b[11] = c.toByte()
        b[20] = (sport shr 8).toByte(); b[21] = sport.toByte()
        b[22] = (dport shr 8).toByte(); b[23] = dport.toByte()
        val ul = 8 + payload.size
        b[24] = (ul shr 8).toByte(); b[25] = ul.toByte()   // somme UDP à 0 = non utilisée (autorisé en IPv4)
        System.arraycopy(payload, 0, b, 28, payload.size)
        return b
    }

    private fun checksum(b: ByteArray, off: Int, len: Int): Int {
        var s = 0
        var i = off
        while (i < off + len) { s += (b.u(i) shl 8) or b.u(i + 1); i += 2 }
        while ((s shr 16) != 0) s = (s and 0xFFFF) + (s shr 16)
        return s.inv() and 0xFFFF
    }

    override fun onRevoke() { stopSelf() }

    override fun onDestroy() {
        running = false
        try { tun?.close() } catch (_: Exception) {}
        tun = null
        pool.shutdownNow()
        BlockState.active.value = false
        super.onDestroy()
    }
}
