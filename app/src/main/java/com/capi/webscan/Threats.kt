package com.capi.webscan

enum class ThreatType { PHISHING, MALWARE, C2, SCAM, MINER, SPAM, GENERIC, SUSPICIOUS }

data class ThreatInfo(val type: ThreatType, val title: String, val summary: String, val capabilities: List<String>, val advice: String)
data class ThreatGroup(val info: ThreatInfo, val engines: List<String>)

object ThreatCatalog {
    val all = mapOf(
        ThreatType.PHISHING to ThreatInfo(ThreatType.PHISHING, "Hameçonnage (phishing)",
            "Le site imite un service connu pour vous faire saisir vos identifiants ou vos données bancaires.",
            listOf("Voler mots de passe et codes de double authentification", "Collecter numéro de carte, IBAN, pièce d'identité",
                "Rediriger vers de fausses pages de paiement"),
            "Si vous avez saisi un mot de passe, changez-le tout de suite (et partout où vous l'utilisez) et activez la double authentification."),
        ThreatType.MALWARE to ThreatInfo(ThreatType.MALWARE, "Logiciel malveillant (malware)",
            "Le site héberge ou distribue des fichiers ou des scripts dangereux.",
            listOf("Installer virus, chevaux de Troie ou logiciels espions", "Voler fichiers, contacts et mots de passe enregistrés",
                "Chiffrer vos données contre rançon (rançongiciel)", "Pousser de fausses applis ou extensions"),
            "Ne téléchargez ni n'installez rien depuis ce site. Si c'est fait, désinstallez l'appli concernée et lancez une analyse Play Protect."),
        ThreatType.C2 to ThreatInfo(ThreatType.C2, "Serveur de contrôle (botnet / C2)",
            "Le domaine sert de relais à des appareils infectés par un logiciel malveillant.",
            listOf("Envoyer des ordres aux appareils infectés", "Récupérer les données volées", "Servir de relais pour d'autres attaques"),
            "Si vous voyez ce domaine dans le trafic de votre appareil ou de votre réseau, considérez l'appareil comme potentiellement infecté."),
        ThreatType.SCAM to ThreatInfo(ThreatType.SCAM, "Arnaque / fraude",
            "Le site cherche à vous soutirer de l'argent par tromperie.",
            listOf("Promettre des gains ou investissements fictifs", "Exiger dépôts, frais ou « mise à niveau » payante",
                "Bloquer les retraits puis disparaître", "Revendre vos données personnelles"),
            "Ne déposez rien. Si vous avez déjà payé, contactez votre banque (contestation de paiement) et signalez le site."),
        ThreatType.MINER to ThreatInfo(ThreatType.MINER, "Cryptominage caché",
            "Le site utilise la puissance de votre appareil pour miner de la cryptomonnaie à votre insu.",
            listOf("Saturer le processeur de l'appareil", "Vider la batterie et le faire chauffer", "Ralentir fortement le téléphone"),
            "Fermez la page. Les effets disparaissent dès que le site est quitté."),
        ThreatType.SPAM to ThreatInfo(ThreatType.SPAM, "Spam / publicité abusive",
            "Le site est lié à du spam ou à de la publicité intrusive.",
            listOf("Redirections et pop-ups à répétition", "Abonnements ou notifications non désirés", "Collecte d'e-mails et de numéros"),
            "N'acceptez pas les notifications et ne laissez pas votre numéro."),
        ThreatType.GENERIC to ThreatInfo(ThreatType.GENERIC, "Site jugé malveillant (type non précisé)",
            "Des moteurs le classent « malveillant » sans dire de quel type de menace il s'agit.",
            listOf("Selon les cas : hameçonnage, distribution de malwares ou fraude"),
            "Traitez-le comme dangereux : pas de saisie de données, pas de téléchargement. Consultez le détail sur VirusTotal."),
        ThreatType.SUSPICIOUS to ThreatInfo(ThreatType.SUSPICIOUS, "Comportement suspect (non confirmé)",
            "Des moteurs le jugent suspect sans certitude : faux positifs possibles.",
            listOf("Signal faible à croiser avec les autres indices de l'analyse"),
            "Vérifiez avec les autres signaux de ce rapport avant de décider.")
    )

    fun classify(result: String, category: String): ThreatType {
        val r = result.lowercase()
        return when {
            r.contains("phish") -> ThreatType.PHISHING
            listOf("malware", "trojan", "virus", "ransom", "exploit").any { r.contains(it) } -> ThreatType.MALWARE
            listOf("botnet", "c2", "c&c", "command").any { r.contains(it) } -> ThreatType.C2
            listOf("scam", "fraud", "fake").any { r.contains(it) } -> ThreatType.SCAM
            listOf("mining", "miner", "cryptojack").any { r.contains(it) } -> ThreatType.MINER
            r.contains("spam") -> ThreatType.SPAM
            category == "suspicious" || r.contains("suspicious") -> ThreatType.SUSPICIOUS
            else -> ThreatType.GENERIC
        }
    }
}

fun groupThreats(vt: VtResult?): List<ThreatGroup> =
    vt?.detections.orEmpty()
        .groupBy { ThreatCatalog.classify(it.result, it.category) }
        .map { (t, d) -> ThreatGroup(ThreatCatalog.all.getValue(t), d.map { it.engine }.distinct().sorted()) }
        .sortedBy { it.info.type.ordinal }
