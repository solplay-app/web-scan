package com.capi.webscan

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URL

object Analyzer {
    private fun rootOf(u: String): String = try { registrable(URL(u).host.lowercase().removePrefix("www.")) } catch (_: Exception) { "" }

    suspend fun analyze(ctx: Context, input: String, deep: Boolean, vtKey: String?, step: (String) -> Unit): Report =
        withContext(Dispatchers.IO) {
            val raw = input.trim()
            val full = if (raw.startsWith("http://", true) || raw.startsWith("https://", true)) raw else "https://$raw"
            val url = try { URL(full) } catch (_: Exception) { throw IllegalArgumentException("URL invalide") }
            val host = url.host.lowercase().removePrefix("www.")
            if (!host.contains(".")) throw IllegalArgumentException("URL invalide")

            val reg = registrable(host)
            val parts = reg.split(".")
            val label = parts.first(); val tldFull = parts.drop(1).joinToString("."); val tldLast = parts.last()
            val tokens = label.split("-")

            val findings = mutableListOf<Finding>()
            fun add(p: Int, m: String, strong: Boolean = false) { if (findings.none { it.message == m }) findings.add(Finding(p, m, strong)) }

            // 1. Nom de domaine
            step("Analyse du nom de domaine…")
            val norm = normalizeDomain(label)
            for (brand in Rules.BRANDS) {
                if (label == brand) continue
                val b = normalizeDomain(brand)
                if (brand.length >= 5) {
                    val dist = levenshtein(norm, b)
                    val maxD = if (brand.length <= 6) 1 else 2
                    when {
                        norm == b -> add(35, "Homoglyphes de « $brand » ($label)", true)
                        dist <= maxD -> add(35, "Ressemblance avec « $brand » (distance $dist)", true)
                        norm.contains(b) -> add(30, "Marque « $brand » contenue dans le domaine", true)
                    }
                } else if (brand in tokens) add(10, "Segment « $brand » dans le domaine (marque courte, à vérifier)")
            }
            val sub = if (host.length > reg.length) host.substring(0, host.length - reg.length - 1) else ""
            if (sub.isNotEmpty()) {
                val st = sub.split(Regex("[.-]"))
                Rules.BRANDS.filter { it.length >= 4 && it in st }
                    .forEach { add(30, "Marque « $it » utilisée en sous-domaine d'un domaine tiers ($reg)", true) }
            }
            if (tldLast in Rules.HIGH_TLDS) add(10, "TLD à risque : .$tldFull")
            else if (tldLast in Rules.MID_TLDS) add(4, "TLD fréquent chez les arnaqueurs : .$tldFull")
            if (Rules.KW_WHITELIST.none { reg.contains(it) }) {
                val hits = keywordHits(label)
                if (hits.isNotEmpty()) add(minOf(8 * hits.size, 20), "Mots-clés suspects dans le domaine : ${hits.joinToString(", ")}")
            }
            if (label.count { it == '-' } >= 2) add(8, "Domaine multi-tirets (typique du bulk-scam)")

            // 2. Page
            var html = ""; var title: String? = null; var finalUrl: String? = null; var unknown3rd: Int? = null
            if (deep) {
                step("Chargement de la page (WebView isolée)…")
                val r = renderPage(ctx, url.toString())
                if (r != null) {
                    html = r.html; title = r.title; finalUrl = r.finalUrl
                    val fr = rootOf(r.finalUrl)
                    if (fr.isNotEmpty() && fr != reg) add(10, "Redirection vers un autre domaine : ${r.finalUrl}")
                    if (r.sslError) add(10, "Certificat TLS invalide ou non fiable")
                    if (r.forms.any { it.sensitive }) add(10, "Formulaire demandant des données sensibles")
                    r.forms.firstOrNull { it.sensitive && it.action.isNotBlank() && rootOf(it.action) != fr }
                        ?.let { add(20, "Formulaire sensible envoyé vers un autre domaine : ${it.action.take(80)}", true) }
                    if (r.dialogs > 0) add(5 * minOf(r.dialogs, 5), "${r.dialogs} alert()/confirm() déclenchés au chargement")
                    if (r.popups > 0) add(10, "${r.popups} popup(s) ouvert(s) automatiquement")
                    val third = r.hosts.filter { it != reg && !it.endsWith(".$reg") }
                    third.filter { Rules.AD_NET.containsMatchIn(it) }.take(5).takeIf { it.isNotEmpty() }
                        ?.let { add(5, "Réseau de pub/track suspect : ${it.joinToString(", ")}") }
                    unknown3rd = third.count { !Rules.KNOWN_CDN.containsMatchIn(it) }
                    if (unknown3rd > 25) add(5, "$unknown3rd domaines tiers inconnus (tracking massif)")
                } else add(5, "Navigation impossible ou délai dépassé")
            }
            if (html.isEmpty()) {
                step("Lecture du HTML…")
                Net.get(url.toString())?.let {
                    html = it.body
                    title = Regex("<title[^>]*>(.*?)</title>", setOf(RegexOption.DOT_MATCHES_ALL, RegexOption.IGNORE_CASE))
                        .find(html)?.groupValues?.get(1)?.trim()
                }
            }

            // 3. Contenu
            title?.takeIf { it.isNotBlank() }?.let { t ->
                Rules.BRANDS.filter { it.length >= 5 && !label.contains(it) }
                    .filter { Regex("\\b${Regex.escape(it)}\\b", RegexOption.IGNORE_CASE).containsMatchIn(t) }
                    .forEach { add(20, "Titre de la page mentionne « $it » (domaine non affilié)") }
            }
            if (html.isNotEmpty()) {
                val text = html.lowercase()
                val strongHits = Rules.PROMISE_STRONG.filter { text.contains(it) }
                if (strongHits.isNotEmpty()) add(minOf(10 * strongHits.size, 40),
                    "Promesses trompeuses (${strongHits.size}) : ${strongHits.take(8).joinToString(" | ")}", strongHits.size >= 2)
                val weakHits = Rules.PROMISE_WEAK.filter { text.contains(it) }
                if (weakHits.isNotEmpty()) add(minOf(3 * weakHits.size, 9),
                    "Formules d'urgence/pression (${weakHits.size}) : ${weakHits.take(5).joinToString(" | ")}")
                Rules.JS_PATTERNS.forEach { (re, msg, strong) -> if (re.containsMatchIn(html)) add(10, msg, strong) }
                val dl = Regex("href=[\"']([^\"']+?\\.(apk|xapk|exe|msi|scr|bat|jar|dmg|vbs|ps1))(\\?[^\"']*)?[\"']", RegexOption.IGNORE_CASE)
                    .findAll(html).map { it.groupValues[2].lowercase() }.toSet()
                if (dl.isNotEmpty()) add(if ("apk" in dl || "xapk" in dl) 15 else 10,
                    "Le site propose le téléchargement de fichier(s) exécutable(s) : ${dl.joinToString(", ")} (analysez-les dans l'onglet Fichier)")
                val imgs = Regex("<img[^>]+src=[\"']([^\"']+)[\"']", RegexOption.IGNORE_CASE).findAll(html).map { it.groupValues[1].lowercase() }.toList()
                for (b in Rules.BRANDS) {
                    if (b.length < 5 || label.contains(b)) continue
                    val own = Regex("//[^/]*${Regex.escape(b)}\\.")
                    imgs.firstOrNull { it.contains("logo") && it.contains(b) && !own.containsMatchIn(it) }
                        ?.let { add(10, "Logo « $b » servi hors du domaine officiel (site imité ?)") }
                }
            }

            // 4. Âge du domaine, certificat, VirusTotal
            step("Âge du domaine (RDAP)…")
            val shared = Rules.isShared(reg)
            val age = if (shared) null else Net.domainAge(reg)
            val young = age != null && age.ageDays < 90
            if (shared) add(8, "Hébergé sur une plateforme gratuite ($tldFull) : n'importe qui peut y publier, l'âge du domaine n'est pas significatif")
            else if (age != null) {
                when {
                    age.ageDays < 30 -> add(40, "Domaine enregistré il y a ${age.ageDays} jours (< 30 j)", true)
                    age.ageDays < 90 -> add(30, "Domaine récent : ${age.ageDays} jours (< 90 j)", true)
                    age.ageDays < 365 -> add(10, "Domaine de ${age.ageDays} jours (< 1 an)")
                }
                if (age.masked) add(3, "Registrant masqué (courant, y compris chez les sites légitimes)")
                age.expiry?.let { e ->
                    val d = try { java.time.temporal.ChronoUnit.DAYS.between(java.time.Instant.now(), java.time.Instant.parse(e)) } catch (_: Exception) { null }
                    if (d != null && d < 200 && age.ageDays < 365) add(5, "Domaine payé pour seulement $d jours de plus")
                }
            } else add(3, "RDAP inaccessible (vérifiez manuellement who.is)")

            step("Certificat TLS…")
            val cert = Net.cert(host)
            if (cert != null && cert.ageDays < 14) {
                if (young) add(20, "Certificat TLS émis il y a ${cert.ageDays} jours + domaine récent", true)
                else add(3, "Certificat TLS récent (${cert.ageDays} j) — banal seul")
            }

            step("VirusTotal…")
            val vt = Net.virusTotal(if (shared) host else reg, vtKey)
            if (vt != null && vt.flagged > 0) add(minOf(40, vt.flagged * 10), "VirusTotal : ${vt.flagged} moteur(s) sur ${vt.total} le signalent", true)

            // 5. Score
            val rawSum = findings.sumOf { it.points }
            val capped = findings.none { it.strong } && rawSum > 39
            val score = minOf(if (capped) 39 else rawSum, 100)
            Report(
                target = url.toString(), score = score, raw = rawSum, capped = capped, level = Level.of(score),
                findings = findings.sortedByDescending { it.points },
                tech = Tech(host, reg, title, finalUrl, age, cert, unknown3rd, vt, deep, shared)
            )
        }
}
