package com.capi.webscan

data class Finding(val points: Int, val message: String, val strong: Boolean = false)

enum class Level(val label: String, val color: Long) {
    HIGH("FORT RISQUE", 0xFFC62828),
    ELEVATED("RISQUE ÉLEVÉ", 0xFFEF6C00),
    MODERATE("RISQUE MODÉRÉ", 0xFFF9A825),
    LOW("AUCUN SIGNAL FORT", 0xFF2E7D32);
    companion object {
        fun of(score: Int) = when { score >= 70 -> HIGH; score >= 40 -> ELEVATED; score >= 20 -> MODERATE; else -> LOW }
    }
}

data class Tech(
    val host: String, val registrable: String, val title: String?, val finalUrl: String?,
    val domain: DomainAge?, val cert: CertInfo?, val unknownThirdParties: Int?, val vt: VtResult?, val deep: Boolean, val shared: Boolean
)

data class Report(
    val target: String, val score: Int, val raw: Int, val capped: Boolean,
    val level: Level, val findings: List<Finding>, val tech: Tech
) {
    val threats: List<ThreatGroup> get() = groupThreats(tech.vt)
    val headline: String get() = when (level) {
        Level.HIGH -> "Ce site présente de nombreux signaux typiques des faux sites et arnaques."
        Level.ELEVATED -> "Plusieurs signaux d'alerte : ce site demande une vérification sérieuse avant toute action."
        Level.MODERATE -> "Quelques signaux isolés : rien de décisif, mais une vérification manuelle est conseillée."
        Level.LOW -> "Aucun signal fort détecté. Cela ne garantit pas que le site est fiable."
    }
    val advice: List<String> get() = when (level) {
        Level.HIGH -> listOf("Ne saisissez aucun mot de passe, carte bancaire ou pièce d'identité.",
            "Ne faites aucun dépôt ni paiement.", "Fermez la page et signalez le site aux autorités de votre pays.")
        Level.ELEVATED -> listOf("Cherchez des avis indépendants (Trustpilot, Reddit, Scamadviser).",
            "Vérifiez les mentions légales : société, adresse, numéro d'immatriculation.",
            "Ne réutilisez aucun mot de passe existant et ne déposez pas d'argent.")
        Level.MODERATE -> listOf("Vérifiez les mentions légales et les avis indépendants.", "Méfiez-vous des promesses de gains rapides.")
        Level.LOW -> listOf("Restez prudent : un site récent ou bien fait peut quand même être frauduleux.")
    }
}

fun Report.shareText(): String = buildString {
    appendLine("Rapport Web Scan — ${target}")
    appendLine("Score : $score/100 — ${level.label}")
    appendLine(headline); appendLine()
    findings.sortedByDescending { it.points }.forEach { appendLine("[+${it.points}]${if (it.strong) " ★" else ""} ${it.message}") }
    if (capped) appendLine("\n(Score brut $raw plafonné à 39 : aucun signal fort.)")
    threats.forEach { g -> appendLine("\nMenace : ${g.info.title} (${g.engines.size} moteur(s) : ${g.engines.joinToString(", ")})")
        g.info.capabilities.forEach { appendLine(" - $it") } }
    appendLine("\nScore indicatif, pas une preuve.")
}
