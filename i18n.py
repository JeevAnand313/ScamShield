"""i18n.py - local language detection (no AI) + UI text for English / Hindi / Marathi."""
import re

LANGS = {"en", "hi", "mr", "hinglish"}
LANG_NAME = {
    "en": "English",
    "hi": "Hindi (Devanagari script)",
    "mr": "Marathi (Devanagari script, NOT Hindi)",
    "hinglish": "Hinglish (Hindi written in English letters)",
}

_DEV = re.compile(r"[\u0900-\u097F]")
_LATIN = re.compile(r"[A-Za-z]")
_WORD = re.compile(r"[\u0900-\u0963\u0966-\u097F]+|[A-Za-z]+")

MARATHI_WORDS = {"आहे", "आहेत", "आणि", "नका", "तुम्ही", "तुमचे", "तुमचा", "तुमची", "तुमच्या",
                 "करा", "आपले", "आपल्या", "आपला", "आपली", "आपण", "झाले", "होईल", "मध्ये",
                 "साठी", "नाही", "लगेच", "ताबडतोब"}
HINDI_WORDS = {"है", "हैं", "और", "नहीं", "आप", "आपका", "आपकी", "आपके", "करें", "में",
               "तुरंत", "गया", "जाएगा", "जायेगा", "कीजिए", "भेजें", "बताएं", "आपको"}
ROMAN_HINDI = {"aapka", "aapki", "aap", "apka", "apna", "nahi", "nahin", "karein", "kare", "karo",
               "bhejo", "bhejiye", "turant", "jaldi", "paisa", "paise", "hai", "hain", "abhi",
               "khata", "band", "jayega", "jaega", "kripya", "batao", "kijiye", "dijiye", "aapko"}


def detect_language(text: str) -> str:
    """Return 'en' | 'hi' | 'mr' | 'hinglish'. Pure script + word-marker check."""
    text = text or ""
    dev, lat = len(_DEV.findall(text)), len(_LATIN.findall(text))
    if dev + lat == 0:
        return "en"
    words = set(_WORD.findall(text.lower()))
    if dev / (dev + lat) > 0.3:                       # mostly Devanagari
        mr, hi = len(words & MARATHI_WORDS), len(words & HINDI_WORDS)
        return "mr" if mr > hi else "hi"
    return "hinglish" if len(words & ROMAN_HINDI) >= 2 else "en"


def ui_lang(lang: str) -> str:
    """Which UI text set to use. Hinglish reads the English UI."""
    return lang if lang in ("hi", "mr") else "en"


# ---------- UI strings ----------
STRINGS = {
    "en": {
        "scam": "🚨 SCAM", "scam_sub": "Do NOT reply, click, or pay anything.",
        "suspicious": "⚠️ SUSPICIOUS", "suspicious_sub": "Be careful. Verify before you do anything.",
        "safe": "✅ LOOKS SAFE", "safe_sub": "No signs of fraud found. Stay alert anyway.",
        "risk": "Risk score", "scale": ("Safe", "Suspicious", "Scam"),
        "why": "Why", "quick": "⚡ Quick signals (rule checks, no AI)",
        "flags": "🚩 Red flags (AI)", "todo": "✅ What to do now",
        "none_signals": "No rule-based signals found.", "none_flags": "No red flags found.",
        "none_todo": "Nothing specific. Stay alert and never share OTP or PIN.",
        "ondevice": "Analysed on-device in {s:.1f}s. Nothing was sent to the internet.",
        "score_line": "AI score {ai} · Quick-signal score {rs} · Combined {c}",
        "raised": "Quick signals raised this from {a} to {b}.",
        "ai_down": "⚡ AI is unavailable. Rule checks only:",
        "instant": "⚡ Quick signals (instant)",
    },
    "hi": {
        "scam": "🚨 स्कैम", "scam_sub": "जवाब न दें, लिंक न खोलें, पैसे न भेजें।",
        "suspicious": "⚠️ संदिग्ध", "suspicious_sub": "सावधान रहें। कुछ भी करने से पहले जाँच लें।",
        "safe": "✅ सुरक्षित लगता है", "safe_sub": "धोखाधड़ी के संकेत नहीं मिले। फिर भी सतर्क रहें।",
        "risk": "जोखिम स्कोर", "scale": ("सुरक्षित", "संदिग्ध", "स्कैम"),
        "why": "क्यों", "quick": "⚡ क्विक सिग्नल (नियम-आधारित, बिना AI)",
        "flags": "🚩 रेड फ्लैग (AI)", "todo": "✅ अभी क्या करें",
        "none_signals": "कोई नियम-आधारित संकेत नहीं मिला।", "none_flags": "कोई रेड फ्लैग नहीं मिला।",
        "none_todo": "कुछ खास नहीं। सतर्क रहें और OTP या PIN कभी साझा न करें।",
        "ondevice": "{s:.1f} सेकंड में डिवाइस पर जाँचा गया। इंटरनेट पर कुछ नहीं भेजा गया।",
        "score_line": "AI स्कोर {ai} · क्विक-सिग्नल स्कोर {rs} · कुल {c}",
        "raised": "क्विक सिग्नल ने नतीजा {a} से बढ़ाकर {b} किया।",
        "ai_down": "⚡ AI उपलब्ध नहीं है। सिर्फ़ नियम-आधारित जाँच:",
        "instant": "⚡ क्विक सिग्नल (तुरंत)",
    },
    "mr": {
        "scam": "🚨 फसवणूक", "scam_sub": "उत्तर देऊ नका, लिंक उघडू नका, पैसे पाठवू नका.",
        "suspicious": "⚠️ संशयास्पद", "suspicious_sub": "सावध रहा. काहीही करण्यापूर्वी खात्री करा.",
        "safe": "✅ सुरक्षित दिसते", "safe_sub": "फसवणुकीची चिन्हे आढळली नाहीत. तरीही सावध रहा.",
        "risk": "धोका स्कोअर", "scale": ("सुरक्षित", "संशयास्पद", "फसवणूक"),
        "why": "कारण", "quick": "⚡ क्विक सिग्नल (नियम-आधारित, AI नाही)",
        "flags": "🚩 रेड फ्लॅग (AI)", "todo": "✅ आता काय करावे",
        "none_signals": "नियम-आधारित कोणतेही संकेत आढळले नाहीत.", "none_flags": "कोणतेही रेड फ्लॅग आढळले नाहीत.",
        "none_todo": "विशेष काही नाही. सावध रहा आणि OTP किंवा PIN कधीही शेअर करू नका.",
        "ondevice": "{s:.1f} सेकंदात डिव्हाइसवरच तपासले. इंटरनेटवर काहीही पाठवले नाही.",
        "score_line": "AI स्कोअर {ai} · क्विक-सिग्नल स्कोअर {rs} · एकूण {c}",
        "raised": "क्विक सिग्नलने निकाल {a} वरून {b} केला.",
        "ai_down": "⚡ AI उपलब्ध नाही. फक्त नियम-आधारित तपासणी:",
        "instant": "⚡ क्विक सिग्नल (तात्काळ)",
    },
}

VERDICT_WORD = {
    "en": {"SCAM": "SCAM", "SUSPICIOUS": "SUSPICIOUS", "SAFE": "SAFE"},
    "hi": {"SCAM": "स्कैम", "SUSPICIOUS": "संदिग्ध", "SAFE": "सुरक्षित"},
    "mr": {"SCAM": "फसवणूक", "SUSPICIOUS": "संशयास्पद", "SAFE": "सुरक्षित"},
}

# scam_type labels (English keys must match SCAM_KNOWLEDGE in analyzer.py)
LABELS = {
    "hi": {
        "UPI / Collect-request fraud": "UPI / कलेक्ट-रिक्वेस्ट धोखाधड़ी",
        "Fake KYC / Bank account block": "नकली KYC / बैंक अकाउंट ब्लॉक",
        "OTP / PIN theft": "OTP / PIN चोरी",
        "Digital arrest": "डिजिटल अरेस्ट",
        "Fake courier / Customs": "नकली कूरियर / कस्टम्स",
        "Job / Task scam": "नौकरी / टास्क स्कैम",
        "Lottery / KBC prize": "लॉटरी / KBC इनाम",
        "Loan app harassment": "लोन ऐप उत्पीड़न",
        "Electricity bill disconnection": "बिजली बिल कनेक्शन कटने की धमकी",
        "Other": "अन्य धोखाधड़ी",
    },
    "mr": {
        "UPI / Collect-request fraud": "UPI / कलेक्ट-रिक्वेस्ट फसवणूक",
        "Fake KYC / Bank account block": "बनावट KYC / बँक अकाउंट ब्लॉक",
        "OTP / PIN theft": "OTP / PIN चोरी",
        "Digital arrest": "डिजिटल अरेस्ट",
        "Fake courier / Customs": "बनावट कुरिअर / कस्टम्स",
        "Job / Task scam": "नोकरी / टास्क स्कॅम",
        "Lottery / KBC prize": "लॉटरी / KBC बक्षीस",
        "Loan app harassment": "लोन अ‍ॅप छळवणूक",
        "Electricity bill disconnection": "वीज बिल कनेक्शन तोडण्याची धमकी",
        "Other": "इतर फसवणूक",
    },
}

# Quick-signal labels (keys are the exact English labels from rules.py).
# Dynamic ones ("...: host") are matched by the part before the first ": ".
SIGNALS = {
    "hi": {
        "Shortened link hides the real site": "छोटा लिंक असली वेबसाइट छिपाता है",
        "Unusual website ending": "अजीब वेबसाइट एंडिंग",
        "Link is a raw IP address, not a real brand site": "लिंक सिर्फ़ IP एड्रेस है, असली ब्रांड साइट नहीं",
        "Link uses '@' trick to hide the real site": "लिंक '@' चाल से असली साइट छिपाता है",
        "Look-alike (punycode) domain": "नकली जैसा दिखने वाला डोमेन (punycode)",
        "Link downloads an APK app file": "लिंक APK ऐप फ़ाइल डाउनलोड कराता है",
        "Pretends to be a government site": "सरकारी साइट होने का नाटक",
        "Pressure / urgency words": "जल्दबाज़ी / दबाव वाले शब्द",
        "Threatens account block / KYC": "अकाउंट ब्लॉक / KYC की धमकी",
        "Money bait: refund, prize, easy income or a fee": "पैसे का लालच: रिफंड, इनाम, आसान कमाई या फ़ीस",
        "Asks you to share OTP / PIN / password": "OTP / PIN / पासवर्ड माँगता है",
        "Collect request: approving it sends money OUT": "कलेक्ट रिक्वेस्ट: मंज़ूर करने पर पैसे कट जाते हैं",
        "Asks for remote-access / screen-share app": "रिमोट-एक्सेस / स्क्रीन-शेयर ऐप माँगता है",
        "Asks you to install an app / APK": "ऐप / APK इंस्टॉल करने को कहता है",
        "Digital arrest threat. No agency does this": "डिजिटल अरेस्ट की धमकी। कोई एजेंसी ऐसा नहीं करती",
        "Tells you to keep it secret": "इसे राज़ रखने को कहता है",
    },
    "mr": {
        "Shortened link hides the real site": "छोटी लिंक खरी वेबसाइट लपवते",
        "Unusual website ending": "संशयास्पद वेबसाइट शेवट",
        "Link is a raw IP address, not a real brand site": "लिंक फक्त IP अ‍ॅड्रेस आहे, खरी ब्रँड साइट नाही",
        "Link uses '@' trick to hide the real site": "लिंक '@' युक्तीने खरी साइट लपवते",
        "Look-alike (punycode) domain": "हुबेहूब दिसणारे बनावट डोमेन (punycode)",
        "Link downloads an APK app file": "लिंक APK अ‍ॅप फाइल डाउनलोड करते",
        "Pretends to be a government site": "सरकारी साइट असल्याचे भासवते",
        "Pressure / urgency words": "घाई / दबाव आणणारे शब्द",
        "Threatens account block / KYC": "अकाउंट ब्लॉक / KYC ची धमकी",
        "Money bait: refund, prize, easy income or a fee": "पैशाचे आमिष: रिफंड, बक्षीस, सोपी कमाई किंवा फी",
        "Asks you to share OTP / PIN / password": "OTP / PIN / पासवर्ड मागतो",
        "Collect request: approving it sends money OUT": "कलेक्ट रिक्वेस्ट: मंजूर केल्यास पैसे जातात",
        "Asks for remote-access / screen-share app": "रिमोट-अ‍ॅक्सेस / स्क्रीन-शेअर अ‍ॅप मागतो",
        "Asks you to install an app / APK": "अ‍ॅप / APK इन्स्टॉल करायला सांगतो",
        "Digital arrest threat. No agency does this": "डिजिटल अरेस्टची धमकी. कोणतीही एजन्सी असे करत नाही",
        "Tells you to keep it secret": "हे गुप्त ठेवायला सांगतो",
    },
}
BRAND_TPL = {
    "hi": "{b} बनने का नाटक, पर आधिकारिक साइट नहीं: {h}",
    "mr": "{b} असल्याचे भासवते, पण अधिकृत साइट नाही: {h}",
}
_BRAND_RE = re.compile(r"^Pretends to be (\w+) but is not an official site: (.*)$")


def translate_label(label: str, lang: str) -> str:
    return LABELS.get(ui_lang(lang), {}).get(label, label)


def translate_signal(label: str, lang: str) -> str:
    lang = ui_lang(lang)
    if lang == "en":
        return label
    table = SIGNALS[lang]
    if label in table:
        return table[label]
    m = _BRAND_RE.match(label)
    if m:
        return BRAND_TPL[lang].format(b=m.group(1), h=m.group(2))
    head, sep, tail = label.partition(": ")
    if sep and head in table:
        return f"{table[head]}: {tail}"
    return label