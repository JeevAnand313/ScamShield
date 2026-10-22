"""rules.py - rule-based scam signals. No AI. Runs in milliseconds, fully offline."""
import re
from urllib.parse import urlparse

# Type labels. Must match SCAM_KNOWLEDGE keys in analyzer.py.
T_UPI = "UPI / Collect-request fraud"
T_KYC = "Fake KYC / Bank account block"
T_OTP = "OTP / PIN theft"
T_ARREST = "Digital arrest"

# ---------- link data ----------
TLDS = {"com", "in", "org", "net", "gov", "edu", "io", "co", "me", "ly", "app", "info",
        "biz", "xyz", "top", "click", "icu", "buzz", "live", "site", "online", "club",
        "link", "shop", "store", "vip", "cc", "tk", "ml", "ga", "cf", "gq", "sbi", "pw"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "cutt.ly", "rb.gy", "is.gd", "shorturl.at",
              "tiny.cc", "goo.gl", "ow.ly", "buff.ly", "bitly.com", "s.id"}
RISKY_TLDS = (".xyz", ".top", ".click", ".icu", ".buzz", ".live", ".site", ".online",
              ".club", ".link", ".vip", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw")
# brand keyword -> official domains. Add more here. Wrong list = false alarms.
BRANDS = {
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com"},
    "hdfc": {"hdfcbank.com", "hdfc.com", "hdfclife.com"},
    "icici": {"icicibank.com", "icicilombard.com", "iciciprulife.com"},
    "axis": {"axisbank.com"},
    "kotak": {"kotak.com"},
    "pnb": {"pnbindia.in"},
    "paytm": {"paytm.com", "paytm.in", "paytmbank.com"},
    "phonepe": {"phonepe.com", "phon.pe"},
    "amazon": {"amazon.in", "amazon.com", "amazon.co.in", "amazonaws.com", "amzn.in"},
    "flipkart": {"flipkart.com", "fkrt.it"},
    "irctc": {"irctc.co.in"},
    "incometax": {"incometax.gov.in"},
    "uidai": {"uidai.gov.in"},
    "indiapost": {"indiapost.gov.in"},
    "fedex": {"fedex.com"},
    "dhl": {"dhl.com"},
    "bluedart": {"bluedart.com"},
}
OFFICIAL_GOV = (".gov.in", ".nic.in")

_TLD_ALT = "|".join(sorted(TLDS, key=len, reverse=True))
URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"']+"                                   # with scheme / www
    r"|(?<![\w@.-])(?:[a-z0-9-]+\.)+(?:" + _TLD_ALT + r")(?![a-z0-9-])(?:/[^\s<>\"']*)?"  # bare domain
    r"|(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.])(?:/[^\s<>\"']*)?",   # bare IP
    re.I,
)
IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")

# ---------- text patterns ----------
URGENCY_EN = [r"\burgent(?:ly)?\b", r"\bimmediately\b", r"\bwithin\s+\d+\s*(?:hours?|hrs?|minutes?|mins?)\b",
              r"\blast\s+chance\b", r"\bact\s+now\b", r"\bfinal\s+notice\b", r"\bexpires?\b",
              r"\btoday\s+only\b", r"\bturant\b", r"\babhi\b", r"\bjaldi\b"]
URGENCY_LOCAL = ["तुरंत", "अभी", "जल्दी", "आजच", "लगेच", "ताबडतोब"]
ACCOUNT_RE = re.compile(
    r"\bkyc\b|(?:account|card|sim|upi|wallet|pan|aadhaar).{0,25}(?:block|suspend|freez|deactivat|clos|expire)"
    r"|\bblocked\b|ब्लॉक|बंद", re.I | re.S)
MONEY_RE = re.compile(
    r"\brefund\b|\bcashback\b|\blottery\b|\bprize\b|\bkbc\b|lucky\s*draw|work\s*from\s*home|part[- ]?time"
    r"|\bper\s+day\b|registration\s+fee|processing\s+fee|customs\s+fee|you\s+(?:have\s+)?won\b|claim\s+your"
    r"|इनाम|लॉटरी|बक्षीस", re.I)
OTP_WORDS = r"(?:otp|upi\s*pin|atm\s*pin|pin|cvv|password|passcode|card\s*number)"
VERBS = r"(?:share|send|enter|tell|give|provide|forward|reply|submit|batao|bhejo|bhejiye|dijiye)"
OTP_ASK_RE = re.compile(rf"\b{VERBS}\b.{{0,40}}\b{OTP_WORDS}\b", re.I | re.S)
NEGATION_RE = re.compile(
    r"\b(?:do\s*not|don'?t|dont|never|not|mat|nahi|nahin|kabhi)\b|delivery\s+(?:agent|partner|executive|person)"
    r"|नहीं|कभी|नका", re.I)
COLLECT_RE = re.compile(r"collect\s*request|(?:approve|accept).{0,40}(?:receive|refund|cashback)", re.I | re.S)
REMOTE_RE = re.compile(r"anydesk|teamviewer|quick\s*support|rustdesk|airdroid|alpemix|screen\s*shar", re.I)
APK_RE = re.compile(r"\.apk\b|download\s+(?:the\s+)?apk|install\s+(?:this\s+)?app", re.I)
ARREST_RE = re.compile(
    r"digital\s*arrest|डिजिटल\s*अरेस्ट"
    r"|(?:cbi|narcotics|enforcement\s+directorate|trai|customs).{0,100}(?:arrest|warrant|illegal|drugs)"
    r".{0,100}(?:transfer|pay|deposit|verif)", re.I | re.S)
SECRECY_RE = re.compile(
    r"(?:do\s*not|don'?t|dont)\s+(?:tell|inform)\s+(?:any|your|family|bank|police)|keep\s+(?:this\s+)?secret"
    r"|kisi\s+ko\s+mat\s+bata|किसी\s+को\s+न\s+बता", re.I)


# ---------- helpers ----------
def _sig(label: str, points: int, critical: bool = False, type_: str | None = None) -> dict:
    return {"label": label, "points": points, "critical": critical, "type": type_}


def _host(url: str) -> tuple[str, str]:
    try:
        p = urlparse(url if "://" in url else "//" + url)
        return (p.hostname or "").lower(), p.netloc.lower()
    except ValueError:
        return "", ""


def find_links(text: str) -> list[str]:
    seen, out = set(), []
    for m in URL_RE.finditer(text or ""):
        u = m.group(0).rstrip(".,;:!?)\"'")
        if u and u.lower() not in seen:
            seen.add(u.lower())
            out.append(u)
    return out


_MAP_L = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s"})
_MAP_I = str.maketrans({"0": "o", "1": "i", "3": "e", "5": "s"})


def _variants(host: str) -> set[str]:
    """Undo digit tricks: sb1 -> sbi, paytrn -> paytm."""
    base = {host, host.translate(_MAP_L), host.translate(_MAP_I)}
    return base | {v.replace("rn", "m") for v in base}


def _mentions_brand(host: str, brand: str) -> bool:
    for v in _variants(host):
        if len(brand) <= 4:
            if any(t.startswith(brand) for t in re.split(r"[.\-_]", v)):
                return True
        elif brand in v:
            return True
    return False


def _is_official(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for ds in BRANDS.values() for d in ds)


def link_signals(url: str) -> list[dict]:
    host, netloc = _host(url)
    if not host:
        return []
    out = []
    if host in SHORTENERS:
        out.append(_sig(f"Shortened link hides the real site: {host}", 20))
    if host.endswith(RISKY_TLDS):
        out.append(_sig(f"Unusual website ending: {host}", 15))
    if IP_RE.fullmatch(host):
        out.append(_sig(f"Link is a raw IP address, not a real brand site: {host}", 30, True))
    if "@" in netloc:
        out.append(_sig(f"Link uses '@' trick to hide the real site: {url}", 25))
    if "xn--" in host:
        out.append(_sig(f"Look-alike (punycode) domain: {host}", 25, True))
    if url.lower().split("?")[0].endswith(".apk"):
        out.append(_sig("Link downloads an APK app file", 35, True))
    if not _is_official(host):
        for brand in BRANDS:
            if _mentions_brand(host, brand):
                out.append(_sig(f"Pretends to be {brand.upper()} but is not an official site: {host}",
                                35, True, T_KYC))
                break
        else:
            toks = re.split(r"[.\-_]", host)
            if ("gov" in toks or "govt" in toks) and not host.endswith(OFFICIAL_GOV):
                out.append(_sig(f"Pretends to be a government site: {host}", 30, True))
    return out


def _count(patterns: list[str], low: str) -> int:
    return sum(1 for p in patterns if re.search(p, low))


def _has_request(rx: re.Pattern, text: str) -> bool:
    """True if rx matches somewhere NOT preceded by a negation ('never share OTP')."""
    for m in rx.finditer(text):
        window = text[max(0, m.start() - 35): m.end()]
        if not NEGATION_RE.search(window):
            return True
    return False


# ---------- main entry ----------
def run_rules(text: str) -> dict:
    """Return {'signals': [...], 'score': 0-100, 'critical': int, 'links': [...]}."""
    text = text or ""
    low = text.lower()
    links = find_links(text)
    sigs: list[dict] = []
    for u in links:
        sigs += link_signals(u)

    hits = _count(URGENCY_EN, low) + sum(1 for w in URGENCY_LOCAL if w in text)
    if hits:
        sigs.append(_sig("Pressure / urgency words", 20 if hits >= 2 else 10))
    if ACCOUNT_RE.search(text):
        sigs.append(_sig("Threatens account block / KYC", 15, type_=T_KYC))
    if MONEY_RE.search(text):
        sigs.append(_sig("Money bait: refund, prize, easy income or a fee", 15))
    if _has_request(OTP_ASK_RE, text):
        sigs.append(_sig("Asks you to share OTP / PIN / password", 40, True, T_OTP))
    if _has_request(COLLECT_RE, text):
        sigs.append(_sig("Collect request: approving it sends money OUT", 35, True, T_UPI))
    if REMOTE_RE.search(text):
        sigs.append(_sig("Asks for remote-access / screen-share app", 35, True, T_OTP))
    if APK_RE.search(text):
        sigs.append(_sig("Asks you to install an app / APK", 30, True))
    if ARREST_RE.search(text):
        sigs.append(_sig("Digital arrest threat. No agency does this", 45, True, T_ARREST))
    if SECRECY_RE.search(text):
        sigs.append(_sig("Tells you to keep it secret", 15))

    # dedupe by label, strongest first
    uniq = {s["label"]: s for s in sigs}
    sigs = sorted(uniq.values(), key=lambda s: -s["points"])
    return {
        "signals": sigs,
        "score": min(100, sum(s["points"] for s in sigs)),
        "critical": sum(1 for s in sigs if s["critical"]),
        "links": links,
    }