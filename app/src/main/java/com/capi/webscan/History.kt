package com.capi.webscan

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Lien reçu depuis le menu « Partager » d'une autre appli. */
object Incoming { val url = MutableStateFlow<String?>(null) }

data class HistItem(val time: String, val kind: String, val title: String, val summary: String)

/** Historique des analyses, chiffré par le Keystore (SecureStore). */
object History {
    val items = MutableStateFlow<List<HistItem>>(emptyList())
    private var loaded = false

    fun load(ctx: Context) {
        if (loaded) return
        loaded = true
        try {
            val a = JSONArray(SecureStore.get(ctx, "history") ?: return)
            items.value = (0 until a.length()).map { val o = a.getJSONObject(it)
                HistItem(o.getString("t"), o.getString("k"), o.getString("n"), o.getString("s")) }
        } catch (_: Exception) {}
    }

    private fun save(ctx: Context) {
        val a = JSONArray()
        items.value.forEach { a.put(JSONObject().put("t", it.time).put("k", it.kind).put("n", it.title).put("s", it.summary)) }
        SecureStore.put(ctx, "history", if (items.value.isEmpty()) "" else a.toString())
    }

    fun add(ctx: Context, kind: String, title: String, summary: String) {
        load(ctx)
        val t = SimpleDateFormat("dd/MM HH:mm", Locale.getDefault()).format(Date())
        items.value = (listOf(HistItem(t, kind, title, summary)) + items.value).take(50)
        save(ctx)
    }

    fun clear(ctx: Context) { items.value = emptyList(); save(ctx) }

    fun verdict(r: FileReport): String = when (val v = r.vt) {
        is VtFile.Found -> when { v.flagged >= 5 -> "DANGEREUX (${v.flagged} moteurs)"; v.flagged >= 1 -> "SUSPECT (${v.flagged} moteurs)"; else -> "AUCUNE DÉTECTION" }
        is VtFile.NotFound -> "INCONNU DE VIRUSTOTAL"
        is VtFile.Err -> "VirusTotal indisponible"
        null -> if (r.error != null) "Erreur de lecture" else "Non vérifié sur VirusTotal"
    }
}
