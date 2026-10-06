package com.capi.webscan

import android.content.Context
import java.io.File
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update

/** level : 0 = standard, 1 = + malware/phishing (DNS Cloudflare 1.1.1.2), 2 = + contenu adulte (1.1.1.3) */
data class BlockCfg(
    val ads: Boolean = true,
    val trackers: Boolean = true,
    val level: Int = 1,
    val custom: Set<String> = emptySet()
)

object BlockState {
    val active = MutableStateFlow(false)
    val blocked = MutableStateFlow(0)
    val total = MutableStateFlow(0)
    val recent = MutableStateFlow<List<String>>(emptyList())
    fun record(name: String, wasBlocked: Boolean) {
        total.update { it + 1 }
        if (wasBlocked) {
            blocked.update { it + 1 }
            recent.update { (listOf(name) + it.filter { n -> n != name }).take(30) }
        }
    }
}

object Blocker {
    val settings = MutableStateFlow(BlockCfg())
    private var loaded = false
    @Volatile private var remote: Set<String> = emptySet()
    val remoteInfo = MutableStateFlow("Liste intégrée uniquement")
    private const val LIST_URL = "https://adaway.org/hosts.txt"

    private fun info(ctx: Context, n: Int) {
        val t = ctx.getSharedPreferences("block", Context.MODE_PRIVATE).getLong("listTime", 0L)
        remoteInfo.value = if (n == 0) "Liste intégrée uniquement"
        else "$n domaines téléchargés" + if (t > 0) " le " + java.text.SimpleDateFormat("dd/MM/yyyy", java.util.Locale.getDefault()).format(java.util.Date(t)) else ""
    }

    /** Télécharge une liste publique au format hosts (AdAway) et la garde sur l'appareil. Retourne le nombre de domaines, ou null si échec. */
    fun refresh(ctx: Context): Int? {
        val res = Net.get(LIST_URL, timeoutMs = 20_000) ?: return null
        if (res.status !in 200..299) return null
        val set = HashSet<String>()
        res.body.lineSequence().forEach { l ->
            val t = l.substringBefore('#').trim()
            if (t.isEmpty()) return@forEach
            val parts = t.split(Regex("\\s+"))
            if (parts.size >= 2 && (parts[0] == "127.0.0.1" || parts[0] == "0.0.0.0")) {
                val d = parts[1].lowercase()
                if (d != "localhost" && d.contains('.')) set.add(d)
            }
        }
        if (set.size < 100) return null
        File(ctx.filesDir, "blocklist.txt").writeText(set.joinToString("\n"))
        remote = set
        ctx.getSharedPreferences("block", Context.MODE_PRIVATE).edit().putLong("listTime", System.currentTimeMillis()).apply()
        info(ctx, set.size)
        return set.size
    }

    fun load(ctx: Context) {
        if (loaded) return
        loaded = true
        val p = ctx.getSharedPreferences("block", Context.MODE_PRIVATE)
        try {
            val f = File(ctx.filesDir, "blocklist.txt")
            if (f.exists()) remote = f.readLines().filter { it.isNotBlank() }.toSet()
        } catch (_: Exception) {}
        info(ctx, remote.size)
        settings.value = BlockCfg(
            ads = p.getBoolean("ads", true),
            trackers = p.getBoolean("trackers", true),
            level = p.getInt("level", 1),
            custom = p.getStringSet("custom", emptySet()).orEmpty().toSet()
        )
    }

    fun update(ctx: Context, f: (BlockCfg) -> BlockCfg) {
        load(ctx)
        val c = f(settings.value)
        settings.value = c
        ctx.getSharedPreferences("block", Context.MODE_PRIVATE).edit()
            .putBoolean("ads", c.ads).putBoolean("trackers", c.trackers)
            .putInt("level", c.level).putStringSet("custom", c.custom).apply()
    }

    /** Nettoie une saisie : "https://www.exemple.com/page" -> "exemple.com". Retourne null si invalide. */
    fun clean(input: String): String? {
        val d = input.trim().lowercase().removePrefix("https://").removePrefix("http://")
            .substringBefore('/').substringBefore('?').substringBefore(':').removePrefix("www.")
        return if (d.contains('.') && Regex("^[a-z0-9.-]+$").matches(d) && !d.startsWith(".") && !d.endsWith(".")) d else null
    }

    fun upstream(level: Int): List<String> = when (level) {
        1 -> listOf("1.1.1.2", "1.0.0.2")
        2 -> listOf("1.1.1.3", "1.0.0.3")
        else -> listOf("1.1.1.1", "1.0.0.1")
    }

    /** Un domaine est bloqué si lui ou l'un de ses parents est dans une liste active. */
    fun isBlocked(name: String): Boolean {
        val s = settings.value
        var d = name
        while (true) {
            if (d in s.custom) return true
            if (s.ads && (d in ADS || d in remote)) return true
            if (s.trackers && d in TRACKERS) return true
            val i = d.indexOf('.')
            if (i < 0) return false
            d = d.substring(i + 1)
        }
    }

    // Liste intégrée volontairement compacte : les régies publicitaires les plus répandues.
    private val ADS = setOf(
        "doubleclick.net", "googlesyndication.com", "googleadservices.com", "adservice.google.com",
        "pagead2.googlesyndication.com", "adsystem.com", "amazon-adsystem.com", "adnxs.com",
        "adsrvr.org", "taboola.com", "outbrain.com", "criteo.com", "criteo.net", "rubiconproject.com",
        "pubmatic.com", "openx.net", "casalemedia.com", "moatads.com", "advertising.com",
        "adcolony.com", "applovin.com", "unityads.unity3d.com", "mopub.com", "inmobi.com",
        "vungle.com", "chartboost.com", "ironsrc.com", "supersonicads.com", "smaato.net",
        "tapjoy.com", "startappservice.com", "an.facebook.com", "ads.twitter.com",
        "static.ads-twitter.com", "ads.linkedin.com", "ads.pinterest.com", "ads.tiktok.com",
        "ads.youtube.com", "ads.yahoo.com", "popads.net", "popcash.net", "propellerads.com",
        "adsterra.com", "exoclick.com", "juicyads.com", "trafficjunky.net", "clickadu.com",
        "mgid.com", "revcontent.com", "zedo.com", "yieldmo.com", "teads.tv", "smartadserver.com",
        "33across.com", "bidswitch.net", "lijit.com", "sharethrough.com", "indexww.com",
        "contextweb.com", "serving-sys.com", "adform.net", "adition.com", "adtech.com",
        "media.net", "yandexadexchange.net", "an.yandex.ru", "mc.yandex.ru"
    )

    private val TRACKERS = setOf(
        "google-analytics.com", "ssl.google-analytics.com", "stats.g.doubleclick.net",
        "app-measurement.com", "scorecardresearch.com", "quantserve.com", "hotjar.com",
        "mixpanel.com", "flurry.com", "appsflyer.com", "adjust.com", "adjust.io", "kochava.com",
        "singular.net", "amplitude.com", "fullstory.com", "mouseflow.com", "crazyegg.com",
        "bat.bing.com", "analytics.twitter.com", "analytics.tiktok.com", "segment.io",
        "bugsnag.com", "optimizely.com", "chartbeat.com", "newrelic.com"
    )
}
