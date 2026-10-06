package com.capi.webscan

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MaterialTheme(colorScheme = lightColorScheme()) { Surface(Modifier.fillMaxSize()) { ScannerScreen() } } }
    }
}

@Composable
fun ScannerScreen() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var url by rememberSaveable { mutableStateOf("") }
    var deep by rememberSaveable { mutableStateOf(true) }
    var vtKey by rememberSaveable { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var stepText by remember { mutableStateOf("") }
    var report by remember { mutableStateOf<Report?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    LazyColumn(
        Modifier.systemBarsPadding().fillMaxSize(),
        contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item { Text("Web Scan", fontSize = 26.sp, fontWeight = FontWeight.Bold) }
        item {
            OutlinedTextField(url, { url = it }, Modifier.fillMaxWidth(), singleLine = true,
                label = { Text("URL du site à analyser") }, placeholder = { Text("https://exemple.com") })
        }
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Switch(deep, { deep = it })
                Spacer(Modifier.width(8.dp))
                Column {
                    Text("Analyse approfondie", fontWeight = FontWeight.Medium)
                    Text(if (deep) "Charge la page dans une WebView isolée (JS exécuté)" else "Lit seulement le HTML, sans l'exécuter (plus sûr)",
                        fontSize = 12.sp, color = Color.Gray)
                }
            }
        }
        item {
            OutlinedTextField(vtKey, { vtKey = it }, Modifier.fillMaxWidth(), singleLine = true,
                label = { Text("Clé VirusTotal (optionnel)") }, visualTransformation = PasswordVisualTransformation())
        }
        item {
            Button(
                onClick = {
                    error = null; report = null; busy = true
                    scope.launch {
                        try { report = Analyzer.analyze(ctx, url, deep, vtKey) { stepText = it } }
                        catch (e: Exception) { error = e.message ?: "Erreur d'analyse" }
                        busy = false
                    }
                },
                enabled = !busy && url.isNotBlank(), modifier = Modifier.fillMaxWidth()
            ) { Text(if (busy) "Analyse en cours…" else "Analyser") }
        }
        if (busy) item { Column { LinearProgressIndicator(Modifier.fillMaxWidth()); Text(stepText, fontSize = 12.sp, color = Color.Gray) } }
        error?.let { e -> item { Text(e, color = Color(0xFFC62828)) } }

        report?.let { r ->
            val c = Color(r.level.color)
            item { ScoreCard(r, c) }
            item {
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text("En clair", fontWeight = FontWeight.Bold, fontSize = 18.sp)
                        Text(r.headline)
                        Text("Que faire ?", fontWeight = FontWeight.Medium, modifier = Modifier.padding(top = 6.dp))
                        r.advice.forEach { Text("• $it") }
                    }
                }
            }
            item { Text("Signaux détectés (${r.findings.size})", fontWeight = FontWeight.Bold, fontSize = 18.sp) }
            if (r.findings.isEmpty()) item { Text("Aucun signal détecté.") }
            items(r.findings) { f ->
                Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(
                    containerColor = if (f.strong) Color(0xFFFDECEA) else MaterialTheme.colorScheme.surfaceVariant)) {
                    Row(Modifier.padding(12.dp), verticalAlignment = Alignment.Top) {
                        Text("+${f.points}", fontWeight = FontWeight.Bold, color = if (f.strong) Color(0xFFC62828) else Color.DarkGray,
                            modifier = Modifier.width(44.dp))
                        Column {
                            if (f.strong) Text("★ SIGNAL FORT", fontSize = 11.sp, color = Color(0xFFC62828), fontWeight = FontWeight.Bold)
                            Text(f.message)
                        }
                    }
                }
            }
            if (r.capped) item { Text("Score brut ${r.raw} plafonné à 39 : aucun signal fort ★, donc pas de verdict élevé.", fontSize = 12.sp, color = Color.Gray) }
            item { TechCard(r.tech) }
            item {
                OutlinedButton(onClick = {
                    ctx.startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
                        type = "text/plain"; putExtra(Intent.EXTRA_TEXT, r.shareText())
                    }, "Partager le rapport"))
                }, Modifier.fillMaxWidth()) { Text("Partager le rapport") }
            }
            item { Text("Score indicatif : ce n'est pas une preuve. Vérifiez toujours manuellement.", fontSize = 12.sp, color = Color.Gray) }
        }
    }
}

@Composable
fun ScoreCard(r: Report, c: Color) {
    Card(Modifier.fillMaxWidth()) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(110.dp), contentAlignment = Alignment.Center) {
                Canvas(Modifier.fillMaxSize()) {
                    val s = Stroke(14.dp.toPx(), cap = StrokeCap.Round); val pad = 7.dp.toPx()
                    val sz = Size(size.width - 2 * pad, size.height - 2 * pad)
                    drawArc(Color(0x22000000), 135f, 270f, false, Offset(pad, pad), sz, style = s)
                    drawArc(c, 135f, 270f * r.score / 100f, false, Offset(pad, pad), sz, style = s)
                }
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text("${r.score}", fontSize = 30.sp, fontWeight = FontWeight.Bold, color = c); Text("/100", fontSize = 12.sp)
                }
            }
            Spacer(Modifier.width(16.dp))
            Column {
                Text(r.level.label, fontWeight = FontWeight.Bold, fontSize = 18.sp, color = c)
                Text(r.tech.registrable, fontSize = 13.sp, color = Color.Gray)
            }
        }
    }
}

@Composable
fun TechCard(t: Tech) {
    fun row(k: String, v: String?) = v?.let { k to it }
    val rows = listOfNotNull(
        row("Domaine", t.registrable),
        row("Mode", if (t.deep) "Approfondi (WebView)" else "HTML seul"),
        row("Titre de la page", t.title?.takeIf { it.isNotBlank() }),
        row("URL finale", t.finalUrl),
        row("Enregistré le", t.domain?.registered?.take(10)),
        row("Âge du domaine", t.domain?.let { "${it.ageDays} jours" }),
        row("Expire le", t.domain?.expiry?.take(10)),
        row("Registrar", t.domain?.registrar),
        row("Certificat", t.cert?.let { "${it.issuer} — émis il y a ${it.ageDays} j (durée ${it.lifetimeDays} j)" }),
        row("Domaines tiers inconnus", t.unknownThirdParties?.toString()),
        row("VirusTotal", t.vtMalicious?.let { "$it détection(s)" })
    )
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(12.dp)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("Détails techniques", fontWeight = FontWeight.Bold, fontSize = 18.sp)
            rows.forEach { (k, v) -> Row { Text(k, Modifier.width(130.dp), color = Color.Gray, fontSize = 13.sp); Text(v, fontSize = 13.sp) } }
        }
    }
}
