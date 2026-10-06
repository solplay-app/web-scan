package com.capi.webscan

import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.temporal.ChronoUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

data class HttpResult(val status: Int, val body: String)
data class DomainAge(val ageDays: Long, val registered: String, val expiry: String?, val registrar: String, val masked: Boolean)
data class CertInfo(val issuer: String, val ageDays: Long, val lifetimeDays: Long)

object Net {
    private const val UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/124 Mobile Safari/537.36"

    private fun readLimited(s: InputStream, max: Int = 2_000_000): String {
        val out = ByteArrayOutputStream(); val buf = ByteArray(8192); var total = 0
        while (true) {
            val n = s.read(buf)
            if (n < 0 || total >= max) break
            out.write(buf, 0, n); total += n
        }
        return out.toString("UTF-8")
    }

    fun get(url: String, headers: Map<String, String> = emptyMap(), timeoutMs: Int = 10_000): HttpResult? = try {
        val c = URL(url).openConnection() as HttpURLConnection
        c.connectTimeout = timeoutMs; c.readTimeout = timeoutMs; c.instanceFollowRedirects = true
        c.setRequestProperty("User-Agent", UA)
        headers.forEach { (k, v) -> c.setRequestProperty(k, v) }
        val status = c.responseCode
        val stream = if (status >= 400) c.errorStream else c.inputStream
        HttpResult(status, stream?.use { readLimited(it) } ?: "")
    } catch (_: Exception) { null }

    private fun JSONArray?.objs(): List<JSONObject> =
        if (this == null) emptyList() else (0 until length()).mapNotNull { optJSONObject(it) }

    fun domainAge(domain: String): DomainAge? {
        val endpoints = listOf(
            "https://rdap.org/domain/$domain",
            "https://rdap.identitydigital.services/rdap/domain/$domain"
        )
        for (ep in endpoints) {
            try {
                val r = get(ep, mapOf("Accept" to "application/rdap+json")) ?: continue
                if (r.status != 200) continue
                val j = JSONObject(r.body)
                val events = j.optJSONArray("events").objs()
                val reg = events.firstOrNull { it.optString("eventAction") == "registration" } ?: continue
                val exp = events.firstOrNull { it.optString("eventAction") == "expiration" }
                val entities = j.optJSONArray("entities").objs()
                fun hasRole(e: JSONObject, role: String) =
                    (0 until (e.optJSONArray("roles")?.length() ?: 0)).any { e.optJSONArray("roles")!!.optString(it) == role }
                var registrar = "inconnu"
                entities.firstOrNull { hasRole(it, "registrar") }?.optJSONArray("vcardArray")?.optJSONArray(1)?.let { props ->
                    for (i in 0 until props.length()) {
                        val f = props.optJSONArray(i) ?: continue
                        if (f.optString(0) == "fn") registrar = f.optString(3, "inconnu")
                    }
                }
                val date = reg.getString("eventDate")
                return DomainAge(
                    ageDays = ChronoUnit.DAYS.between(Instant.parse(date), Instant.now()),
                    registered = date,
                    expiry = exp?.optString("eventDate"),
                    registrar = registrar,
                    masked = entities.none { hasRole(it, "registrant") }
                )
            } catch (_: Exception) { }
        }
        return null
    }

    /** Lit le certificat même invalide (trust-all) : on ne transmet AUCUNE donnée, on lit seulement le cert. */
    fun cert(host: String): CertInfo? = try {
        val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(c: Array<X509Certificate>?, a: String?) {}
            override fun checkServerTrusted(c: Array<X509Certificate>?, a: String?) {}
            override fun getAcceptedIssuers() = arrayOf<X509Certificate>()
        })
        val ctx = SSLContext.getInstance("TLS").apply { init(null, trustAll, null) }
        val raw = Socket().apply { connect(InetSocketAddress(host, 443), 8000) }
        val s = ctx.socketFactory.createSocket(raw, host, 443, true) as SSLSocket
        s.soTimeout = 8000
        s.startHandshake()
        val c = s.session.peerCertificates[0] as X509Certificate
        s.close()
        CertInfo(
            issuer = Regex("O=([^,]+)").find(c.issuerX500Principal.name)?.groupValues?.get(1) ?: "inconnu",
            ageDays = ChronoUnit.DAYS.between(c.notBefore.toInstant(), Instant.now()),
            lifetimeDays = ChronoUnit.DAYS.between(c.notBefore.toInstant(), c.notAfter.toInstant())
        )
    } catch (_: Exception) { null }

    fun virusTotal(domain: String, key: String?): Int? {
        if (key.isNullOrBlank()) return null
        return try {
            val r = get("https://www.virustotal.com/api/v3/domains/$domain", mapOf("x-apikey" to key.trim())) ?: return null
            if (r.status != 200) return null
            val s = JSONObject(r.body).getJSONObject("data").getJSONObject("attributes").optJSONObject("last_analysis_stats")
            (s?.optInt("malicious") ?: 0) + (s?.optInt("phishing") ?: 0) + (s?.optInt("suspicious") ?: 0)
        } catch (_: Exception) { null }
    }
}
