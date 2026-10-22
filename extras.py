"""extras.py - report box text, share-warning builder, history entries. Pure Python, offline."""
import re
import time

from i18n import VERDICT_WORD, translate_label, ui_lang

MAX_HISTORY = 20
ICON = {"SCAM": "🚨", "SUSPICIOUS": "⚠️", "SAFE": "✅"}

TEXT = {
    "en": {
        "report_title": "🚨 Report this scam",
        "report_md": (
            "- **Lost money? Call 1930 right now.** National Cyber Crime Helpline. "
            "The faster you report, the better the chance the money can be frozen.\n"
            "- Report online: [cybercrime.gov.in](https://cybercrime.gov.in)\n"
            "- Before reporting: keep the screenshot, note the sender's number or link, "
            "transaction ID, date and time. Do not delete the chat.\n"
            "- Call your bank at once to block the card / UPI.\n"
            "- No money lost? Still report it and block the sender."
        ),
        "share_title": "📤 Share warning with family",
        "share_hint": "Tap the copy icon, then paste in WhatsApp. The scam message and links are not included.",
        "head_scam": "🚨 SCAM ALERT",
        "head_susp": "⚠️ BE CAREFUL",
        "intro": "I checked this message with ScamShield. Result: {verdict} ({type}), risk {score}/100.",
        "todo": "What to do:",
        "footer": ("Never share your OTP or UPI PIN with anyone. If money was lost, call 1930 right away "
                   "or report at cybercrime.gov.in. Please forward this to family and friends."),
    },
    "hi": {
        "report_title": "🚨 इस स्कैम की रिपोर्ट करें",
        "report_md": (
            "- **पैसे कट गए? अभी 1930 पर कॉल करें।** (राष्ट्रीय साइबर क्राइम हेल्पलाइन) "
            "जितनी जल्दी शिकायत, पैसे रुकने की उतनी ज़्यादा उम्मीद।\n"
            "- ऑनलाइन शिकायत: [cybercrime.gov.in](https://cybercrime.gov.in)\n"
            "- शिकायत से पहले: स्क्रीनशॉट रखें, भेजने वाले का नंबर या लिंक, ट्रांज़ैक्शन ID, "
            "तारीख और समय नोट करें। चैट डिलीट न करें।\n"
            "- तुरंत अपने बैंक को फ़ोन करके कार्ड / UPI ब्लॉक कराएं।\n"
            "- पैसे नहीं गए? फिर भी रिपोर्ट करें और नंबर ब्लॉक करें।"
        ),
        "share_title": "📤 परिवार को चेतावनी भेजें",
        "share_hint": "कॉपी आइकन दबाएं, फिर WhatsApp में पेस्ट करें। स्कैम मैसेज और लिंक इसमें शामिल नहीं हैं।",
        "head_scam": "🚨 स्कैम से सावधान",
        "head_susp": "⚠️ सावधान रहें",
        "intro": "मैंने ScamShield से यह मैसेज जाँचा। नतीजा: {verdict} ({type}), जोखिम {score}/100।",
        "todo": "क्या करें:",
        "footer": ("OTP या UPI PIN कभी किसी को न बताएं। पैसे कट गए हों तो तुरंत 1930 पर कॉल करें "
                   "या cybercrime.gov.in पर शिकायत करें। यह संदेश परिवार और दोस्तों को भेजें।"),
    },
    "mr": {
        "report_title": "🚨 या फसवणुकीची तक्रार करा",
        "report_md": (
            "- **पैसे गेले? आत्ताच 1930 वर कॉल करा.** (राष्ट्रीय सायबर क्राइम हेल्पलाइन) "
            "जितकी लवकर तक्रार, तितकी पैसे थांबवण्याची शक्यता जास्त.\n"
            "- ऑनलाइन तक्रार: [cybercrime.gov.in](https://cybercrime.gov.in)\n"
            "- तक्रारीपूर्वी: स्क्रीनशॉट जपून ठेवा, पाठवणाऱ्याचा नंबर किंवा लिंक, ट्रान्झॅक्शन ID, "
            "तारीख आणि वेळ लिहून ठेवा. चॅट डिलीट करू नका.\n"
            "- लगेच तुमच्या बँकेला फोन करून कार्ड / UPI ब्लॉक करा.\n"
            "- पैसे गेले नाहीत? तरीही तक्रार करा आणि नंबर ब्लॉक करा."
        ),
        "share_title": "📤 कुटुंबाला इशारा पाठवा",
        "share_hint": "कॉपी आयकॉन दाबा, मग WhatsApp मध्ये पेस्ट करा. फसवणुकीचा मेसेज आणि लिंक यात नाहीत.",
        "head_scam": "🚨 फसवणुकीपासून सावध रहा",
        "head_susp": "⚠️ सावध रहा",
        "intro": "मी ScamShield ने हा मेसेज तपासला. निकाल: {verdict} ({type}), धोका {score}/100.",
        "todo": "काय करावे:",
        "footer": ("OTP किंवा UPI PIN कधीही कोणाला सांगू नका. पैसे गेले असल्यास लगेच 1930 वर कॉल करा "
                   "किंवा cybercrime.gov.in वर तक्रार करा. हा संदेश कुटुंब आणि मित्रांना पाठवा."),
    },
}


def build_share_text(r: dict, lang: str) -> str:
    """WhatsApp-ready warning in the result language. No scam text, no links."""
    ui = ui_lang(lang)
    T = TEXT[ui]
    head = T["head_scam"] if r["verdict"] == "SCAM" else T["head_susp"]
    intro = T["intro"].format(verdict=VERDICT_WORD[ui][r["verdict"]],
                              type=translate_label(r["scam_type"], ui), score=r["risk_score"])
    lines = [head, "", intro]
    if r["explanation"]:
        lines += ["", r["explanation"]]
    steps = r["what_to_do"][:3]
    if steps:
        lines += ["", T["todo"]] + [f"{i}. {s}" for i, s in enumerate(steps, 1)]
    lines += ["", T["footer"]]
    return "\n".join(lines)


def make_entry(r: dict, text: str | None, filename: str | None, seconds: float | None) -> dict:
    """One history row. Label is stripped of markdown chars so button text stays safe."""
    snippet = (text or r.get("extracted_text") or filename or "Screenshot")
    snippet = re.sub(r"\s+", " ", snippet).strip()[:38]
    snippet = re.sub(r"[*_`~$\[\]()#<>:\\|]", "", snippet)
    return {
        "label": f"{ICON[r['verdict']]} {r['risk_score']} · {snippet}",
        "time": time.strftime("%H:%M"),
        "result": r,
        "seconds": seconds,
    }