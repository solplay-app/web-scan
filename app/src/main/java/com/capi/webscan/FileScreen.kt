package com.capi.webscan

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch

private fun fmtSize(b: Long) = when {
    b >= 1_048_576 -> "%.1f Mo".format(b / 1_048_576.0)
    b >= 1024 -> "%.0f Ko".format(b / 1024.0)
    else -> "$b o"
}

private data class Verdict(val title: String, val color: Long, val text: String)

private fun verdictOf(r: FileReport): Verdict {
    val v = r.vt
    return when {
        r.error != null -> Verdict("ERREUR", 0xFF616161, r.error)
        v == null -> Verdict("EMPREINTE CALCULÉE", 0xFF616161, "Ajoutez une clé VirusTotal pour rechercher cette empreinte.")
        v is VtFile.Err -> Verdict("RECHERCHE IMPOSSIBLE", 0xFF616161, v.msg)
        v is VtFile.NotFound -> Verdict("INCONNU DE VIRUSTOTAL", 0xFF616161,
            "Aucun moteur ne l'a encore analysé : fichier rare, récent ou modifié. Ce n'est pas un signe de sécurité.")
        v is VtFile.Found && v.flagged >= 5 -> Verdict("DANGEREUX", 0xFFC62828,
            "${v.flagged} moteurs sur ${v.total} le détectent. N'installez pas et n'ouvrez pas ce fichier.")
        v is VtFile.Found && v.flagged > 0 -> Verdict("SUSPECT", 0xFFEF6C00,
            "${v.flagged} moteur(s) sur ${v.total} le signalent. Faux positif possible, mais ne l'installez pas sans vérifier la source.")
        else -> Verdict("AUCUNE DÉTECTION", 0xFF2E7D32,
            "Connu de VirusTotal et non signalé. Cela ne prouve pas qu'il est sûr, surtout s'il est récent.")
    }
}

@Composable
fun FileScanScreen(vtKey: String, onVtKey: (String) -> Unit, result: FileReport?, onResult: (FileReport?) -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var step by remember { mutableStateOf("") }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            busy = true; onResult(null)
            scope.launch { val fr = FileScanner.scan(ctx, uri, vtKey) { step = it }; onResult(fr); History.add(ctx, "file", fr.name, History.verdict(fr)); busy = false }
        }
    }

    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item { Text("Analyser un fichier", fontSize = 26.sp, fontWeight = FontWeight.Bold) }
        item {
            Card(Modifier.fillMaxWidth()) {
                Text("Votre fichier ne quitte jamais votre téléphone. Seule son empreinte SHA-256 (sa « carte d'identité ») est envoyée à VirusTotal.",
                    Modifier.padding(16.dp), fontSize = 14.sp)
            }
        }
        item {
            OutlinedTextField(vtKey, { onVtKey(it) }, Modifier.fillMaxWidth(), singleLine = true,
                label = { Text("Clé VirusTotal (nécessaire pour la recherche)") }, visualTransformation = PasswordVisualTransformation())
        }
        item {
            Button(onClick = { picker.launch(arrayOf("*/*")) }, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                Text(if (busy) "Analyse en cours…" else "Choisir un fichier (APK, ZIP, EXE, PDF…)")
            }
        }
        if (busy) item { Column { LinearProgressIndicator(Modifier.fillMaxWidth()); Text(step, fontSize = 12.sp, color = Color.Gray) } }

        result?.let { r ->
            val vd = verdictOf(r)
            val vc = Color(vd.color)
            item {
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(vd.title, fontWeight = FontWeight.Bold, fontSize = 20.sp, color = vc)
                        Text(vd.text)
                        if (r.sha256.isNotEmpty()) {
                            Text("${r.name} — ${fmtSize(r.size)}", fontWeight = FontWeight.Medium, modifier = Modifier.padding(top = 8.dp))
                            r.pkg?.let { Text("Paquet : $it", fontSize = 12.sp, color = Color.Gray) }
                            SelectionContainer { Text("SHA-256 : ${r.sha256}", fontSize = 11.sp, color = Color.Gray) }
                        }
                    }
                }
            }
            val f = r.vt as? VtFile.Found
            if (f != null) {
                item {
                    Card(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text("Informations VirusTotal", fontWeight = FontWeight.Bold, fontSize = 18.sp)
                            f.type?.let { Text("Type : $it", fontSize = 13.sp) }
                            f.firstSeen?.let { Text("Première analyse : $it", fontSize = 13.sp) }
                            f.threatLabel?.let { Text("Famille probable : $it", fontSize = 13.sp, fontWeight = FontWeight.Medium) }
                            if (f.threatNames.isNotEmpty()) Text("Noms : ${f.threatNames.joinToString(", ")}", fontSize = 13.sp)
                            if (f.categories.isNotEmpty()) Text("Catégories : ${f.categories.joinToString(", ")}", fontSize = 13.sp)
                            if (f.tags.isNotEmpty()) Text("Étiquettes : ${f.tags.take(8).joinToString(", ")}", fontSize = 12.sp, color = Color.Gray)
                        }
                    }
                }
                if (f.flagged > 0) {
                    val threats = matchFileThreats(f)
                    items(threats.size) { i ->
                        val t = threats[i]
                        Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = Color(0xFFFDECEA))) {
                            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text(t.title, fontWeight = FontWeight.Bold, color = Color(0xFFC62828))
                                Text(t.summary, fontSize = 14.sp)
                                Text("Ce que ça peut faire :", fontWeight = FontWeight.Medium, fontSize = 13.sp)
                                t.capabilities.forEach { Text("• $it", fontSize = 13.sp) }
                            }
                        }
                    }
                    item {
                        Card(Modifier.fillMaxWidth()) {
                            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                Text("Moteurs qui le détectent (${f.detections.size})", fontWeight = FontWeight.Bold, fontSize = 16.sp)
                                f.detections.take(12).forEach { Text("• ${it.engine} : ${it.result.ifBlank { it.category }}", fontSize = 12.sp) }
                                if (f.detections.size > 12) Text("… et ${f.detections.size - 12} autres", fontSize = 12.sp, color = Color.Gray)
                            }
                        }
                    }
                }
            }
            if (r.pkg != null) {
                item {
                    Card(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            val high = r.perms.count { it.level == 2 }
                            Text("Permissions de l'APK", fontWeight = FontWeight.Bold, fontSize = 18.sp)
                            Text(when { high >= 3 -> "Profil ÉLEVÉ : plusieurs permissions typiques des malwares."
                                high >= 1 -> "Profil MOYEN : au moins une permission très sensible."
                                r.perms.isNotEmpty() -> "Profil modéré : permissions sensibles courantes."
                                else -> "Aucune permission sensible repérée." },
                                fontWeight = FontWeight.Medium, color = if (high >= 3) Color(0xFFC62828) else Color.DarkGray)
                            r.perms.forEach { p ->
                                Column {
                                    Text("${if (p.level == 2) "⚠️" else "•"} ${p.label}", fontWeight = FontWeight.Medium, fontSize = 14.sp)
                                    Text(p.why, fontSize = 12.sp, color = Color.Gray)
                                }
                            }
                            Text("Les permissions montrent ce que l'appli PEUT faire, pas ce qu'elle fait.", fontSize = 12.sp, color = Color.Gray)
                        }
                    }
                }
            }
            if (r.sha256.isNotEmpty()) item {
                OutlinedButton(onClick = { ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(r.link))) }, Modifier.fillMaxWidth()) {
                    Text("Voir sur VirusTotal")
                }
            }
        }
    }
}
