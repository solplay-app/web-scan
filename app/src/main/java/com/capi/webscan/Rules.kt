package com.capi.webscan

object Rules {
    val BRANDS = listOf(
        "paypal","google","facebook","amazon","apple","microsoft","netflix","binance","coinbase","kucoin",
        "bybit","kraken","revolut","wise","bnp","creditagricole","societegenerale","ing","wellsfargo","hsbc",
        "chase","dhl","fedex","ups","steam","instagram","whatsapp","tiktok","telegram","orange","free","sfr",
        "bouygues","n26"
    )
    val SCAM_KW = listOf(
        "crypto","invest","profit","money","cash","gain","earn","riche","trading","bonus","giveaway","airdrop",
        "fast","win","winner","jackpot","rich","double","mine","stake","token","pay","wallet","lottery","prize",
        "gift","claim","ptc","faucet"
    )
    val KW_WHITELIST = listOf(
        "coinmarketcap","freelance","windowsupdate","freewheel","fastly","windev","payfit","tokeneo",
        "doubleclick","winmail","gaindesign","coinbasehelp","mineos","stakelattice"
    )
    val PROMISE_STRONG = listOf(
        "double your money","doublez votre argent","rendement garanti","guaranteed profit","profit garanti",
        "risk-free","sans risque","get rich quick","devenir riche","earn money fast","watch ads and earn",
        "regarder des pubs","click and earn","clic et gagne","daily earnings","gains quotidiens","1000% return",
        "100% return","passive income guaranteed","revenu passif garanti","free crypto","crypto gratuite",
        "bitcoin doubler","double your bitcoin","claim your airdrop","pump signal","you have won","vous avez gagné",
        "claim your prize","réclamez votre gain","lottery winner","free gift card","carte cadeau gratuite",
        "iphone giveaway","congratulations you","verify your identity now","suspended account","compte suspendu"
    )
    val PROMISE_WEAK = listOf(
        "earn fast","welcome bonus","bonus de bienvenue","sign up bonus","limited slots","places limitées",
        "act now","agissez maintenant","only today","last chance","dernière chance","hurry","dépêchez-vous",
        "your account has been","votre compte a été","unusual activity","activité inhabituelle"
    )
    val HIGH_TLDS = setOf("tk","ml","ga","cf","gq","zip","mov","icu","top","buzz","click","rest","xyz")
    val MID_TLDS = setOf("live","shop","pro","online","site","store","club","fun")
    val KNOWN_CDN = Regex(
        "(^|\\.)(google|gstatic|googleapis|googletagmanager|google-analytics|googlesyndication|doubleclick|cloudflare|" +
        "cloudflareinsights|jquery|facebook|fbcdn|fontawesome|bootstrapcdn|unpkg|jsdelivr|amazon-adsystem|hotjar|" +
        "matomo|sentry|recaptcha|hcaptcha|akamai|akamaized|cloudfront|azureedge|github|w3)\\.[a-z.]+$",
        RegexOption.IGNORE_CASE
    )
    val AD_NET = Regex("bit\\.ly|shorte|adfly|onclick|propeller|popads|adcash|exoclick", RegexOption.IGNORE_CASE)
    val SECOND_LEVEL = setOf(
        "co.uk","org.uk","ac.uk","com.br","com.au","co.jp","co.za","com.tr","com.cn","co.in","co.ci",
        "com.ng","com.mx","co.nz","com.ar"
    )
    // (regex, message, fort ?)
    val JS_PATTERNS = listOf(
        Triple(Regex("eval\\s*\\(\\s*atob\\s*\\(", RegexOption.IGNORE_CASE), "eval(atob()) — code obfusqué", true),
        Triple(Regex("(String\\.fromCharCode\\s*\\([^)]*\\)[^;]{0,40}){5,}", RegexOption.IGNORE_CASE), "String.fromCharCode répété — obfuscation", false),
        Triple(Regex("(login|verify|account|update|secure)[-_.]?\\d*\\.php", RegexOption.IGNORE_CASE), "Page PHP typique de phishing kit", false),
        Triple(Regex("<iframe[^>]+(width\\s*=\\s*[\"']?0|display\\s*:\\s*none)", RegexOption.IGNORE_CASE), "iframe cachée", false),
        Triple(Regex("keylog|stealer|grabber", RegexOption.IGNORE_CASE), "Terminologie de malware", false)
    )
}

fun levenshtein(a: String, b: String): Int {
    val m = Array(a.length + 1) { IntArray(b.length + 1) }
    for (i in 0..a.length) m[i][0] = i
    for (j in 0..b.length) m[0][j] = j
    for (i in 1..a.length) for (j in 1..b.length)
        m[i][j] = minOf(m[i - 1][j] + 1, m[i][j - 1] + 1, m[i - 1][j - 1] + if (a[i - 1] == b[j - 1]) 0 else 1)
    return m[a.length][b.length]
}

fun normalizeDomain(d: String) = d.lowercase()
    .replace("0", "o").replace("1", "l").replace("3", "e").replace("5", "s")
    .replace("rn", "m").replace("vv", "w").replace("-", "").replace(".", "")

fun registrable(host: String): String {
    val p = host.lowercase().split(".")
    if (p.size <= 2) return host.lowercase()
    val l2 = p.takeLast(2).joinToString(".")
    return if (l2 in Rules.SECOND_LEVEL) p.takeLast(3).joinToString(".") else l2
}

/** Mots-clés longs : sous-chaîne. Mots courts : segment entier OU mots collés (earnfast = earn+fast). */
fun keywordHits(label: String): List<String> {
    val tokens = label.split("-")
    return Rules.SCAM_KW.filter { k ->
        if (k.length >= 5) label.contains(k)
        else tokens.any { t ->
            t == k ||
                (t.startsWith(k) && t.removePrefix(k) in Rules.SCAM_KW) ||
                (t.endsWith(k) && t.removeSuffix(k) in Rules.SCAM_KW)
        }
    }
}
