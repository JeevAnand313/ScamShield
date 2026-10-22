"""analyzer.py - Gemma 4 E4B via Ollama (fully local) + combine with rule signals."""
import io
import json
import re

import httpx
import ollama
from PIL import Image

from i18n import LANG_NAME, LANGS, detect_language
from rules import run_rules

# ---------- CONFIG ----------
MODEL = "gemma4:e4b"
OLLAMA_HOST = "http://localhost:11434"
TEMPERATURE = 0.1
TIMEOUT_SEC = 120          # first call is slow (model load); keep generous
MAX_IMAGE_SIDE = 1280      # downscale big screenshots for speed
MAX_RETRIES = 1            # retry once on bad JSON or wrong language script
KEEP_ALIVE = "30m"         # keep model in RAM between checks
NUM_CTX = 8192             # long prompt + image tokens need room

# how rules mix into the AI score
RULE_WEIGHT = 0.3          # final = max(ai, 0.7*ai + 0.3*rules)
FLOOR_ONE_CRITICAL = 40    # 1 critical signal -> at least SUSPICIOUS
FLOOR_TWO_CRITICAL = 75    # 2+ critical signals -> SCAM

VERDICTS = {"SCAM", "SUSPICIOUS", "SAFE"}
SCORE_BANDS = {"SAFE": (0, 30), "SUSPICIOUS": (31, 70), "SCAM": (71, 100)}
RANK = {"SAFE": 0, "SUSPICIOUS": 1, "SCAM": 2}

# ---------- INDIA SCAM KNOWLEDGE ----------
SCAM_KNOWLEDGE = {
    "UPI / Collect-request fraud":
        "Fake 'refund', 'cashback' or 'payment received' that sends a COLLECT request. "
        "Approving a collect request or entering UPI PIN sends money OUT. "
        "UPI PIN is never needed to receive money. Also: wrong-payment-sent, 'please return my money'.",
    "Fake KYC / Bank account block":
        "SMS/WhatsApp saying account, card, PAN, Aadhaar or wallet will be blocked unless "
        "KYC is updated NOW. Link or APK to 'update'. Banks do not do KYC via random links. "
        "Brands often faked: SBI, HDFC, ICICI, Paytm, PhonePe.",
    "OTP / PIN theft":
        "Any request for OTP, PIN, CVV, card number, password or screen-share app "
        "(AnyDesk, TeamViewer, QuickSupport). Fake 'bank officer', 'customer care', "
        "'lucky draw' callers. Real banks NEVER ask for OTP or PIN.",
    "Digital arrest":
        "Caller or message claims to be CBI, police, ED, customs, TRAI or narcotics. Says "
        "you are linked to a crime, parcel or SIM misuse. Demands you stay on video call, "
        "'digital arrest', and transfer money for 'verification'. No agency arrests on video "
        "call or takes money to clear you. Always a scam.",
    "Fake courier / Customs":
        "Parcel stuck at customs or delivery failed. Pay small fee, redeem or "
        "'reschedule' via link. Often FedEx, DHL, India Post, Blue Dart. "
        "Check: did you actually order or expect a parcel?",
    "Job / Task scam":
        "Work-from-home, part-time, 'like YouTube videos / rate hotels and earn per day'. "
        "Small first payout to build trust, then asks deposit, registration fee or "
        "'prepaid task' money. Contact starts on WhatsApp or Telegram from unknown number.",
    "Lottery / KBC prize":
        "You 'won' lottery, KBC, lucky draw, car or iPhone. Must pay tax, processing or "
        "delivery fee first. You never entered any contest.",
    "Loan app harassment":
        "Instant loan app, no documents, asks access to contacts, gallery and SMS. "
        "Takes huge interest and processing fee. Then threatens to send morphed photos "
        "or shame you to your contacts. Unregistered with RBI.",
    "Electricity bill disconnection":
        "Message says power will be cut tonight because last bill unpaid. Gives a mobile "
        "number to call or link to pay. Real boards do not threaten same-day cut-off from "
        "a personal mobile number.",
    "Other":
        "Fraud that fits none of the above (fake investment or stock tips, romance, "
        "matrimonial, fake customer care number, OLX or marketplace buyer scam, etc).",
}
SCAM_LABELS = list(SCAM_KNOWLEDGE)

LABEL_HINTS = {
    "upi": SCAM_LABELS[0], "collect": SCAM_LABELS[0], "refund": SCAM_LABELS[0],
    "kyc": SCAM_LABELS[1], "account block": SCAM_LABELS[1], "bank": SCAM_LABELS[1],
    "otp": SCAM_LABELS[2], "pin": SCAM_LABELS[2], "phishing": SCAM_LABELS[2],
    "arrest": SCAM_LABELS[3], "cbi": SCAM_LABELS[3], "police": SCAM_LABELS[3],
    "courier": SCAM_LABELS[4], "customs": SCAM_LABELS[4], "parcel": SCAM_LABELS[4],
    "job": SCAM_LABELS[5], "task": SCAM_LABELS[5], "work from home": SCAM_LABELS[5],
    "lottery": SCAM_LABELS[6], "kbc": SCAM_LABELS[6], "prize": SCAM_LABELS[6],
    "loan": SCAM_LABELS[7],
    "electric": SCAM_LABELS[8], "power": SCAM_LABELS[8], "bill": SCAM_LABELS[8],
}


def build_system_prompt() -> str:
    types = "\n".join(f"- {label}: {desc}" for label, desc in SCAM_KNOWLEDGE.items())
    labels = " | ".join(f'"{l}"' for l in SCAM_LABELS)
    return (
        "You are ScamShield, a scam-detection assistant for everyday users in India.\n"
        "You receive a screenshot or text of a message (SMS, WhatsApp, email, payment request).\n"
        "Respond with ONLY one JSON object. No markdown, no code fences, no text before or after.\n"
        "Exact schema:\n"
        "{\n"
        '  "verdict": "SCAM" | "SUSPICIOUS" | "SAFE",\n'
        '  "risk_score": <integer 0-100>,\n'
        f'  "scam_type": {labels} | "None",\n'
        '  "language": "en" | "hi" | "mr" | "hinglish",\n'
        '  "red_flags": ["<short specific reason, quote the message where useful>"],\n'
        '  "explanation": "<2-3 simple sentences a non-technical person understands>",\n'
        '  "what_to_do": ["<2-4 concrete actions>"],\n'
        '  "extracted_text": "<for a screenshot: all message text you can read, copied exactly, '
        "including links and sender. For plain text input: ''>\"\n"
        "}\n\n"
        "COMMON SCAM TYPES IN INDIA (use these exact labels for scam_type):\n"
        f"{types}\n\n"
        "FACTS YOU MUST USE:\n"
        "- Real banks, RBI, police, courts and government NEVER ask for OTP, UPI PIN, CVV, "
        "card number or password by message or call.\n"
        "- UPI PIN is only needed to SEND money. Receiving money never needs a PIN.\n"
        "- A collect request means YOU will pay. 'Approve to get refund' is always a scam.\n"
        "- No agency does 'digital arrest' or takes money on a video call to close a case.\n"
        "- Official sites end in .gov.in, .nic.in, or the bank's real domain. Lookalike spellings, "
        "shortened links, odd endings (.xyz, .top, .click) and APK downloads are red flags.\n"
        "- Scammers use fear, urgency, big rewards and secrecy ('do not tell anyone').\n\n"
        "WHAT LEGIT LOOKS LIKE (do not over-flag):\n"
        "- A bank OTP SMS for a transaction the user started, with 'do not share' warning.\n"
        "- Debit/credit alerts with masked account numbers and no link asking for action.\n"
        "- A delivery or order update that asks for nothing and matches normal shopping.\n"
        "- A message that only WARNS people not to share OTP is SAFE.\n"
        "- Ordinary chat between friends or family with no money or link request.\n\n"
        "LANGUAGE RULES:\n"
        "- The user message gives OUTPUT LANGUAGE. Write explanation, red_flags and what_to_do "
        "ONLY in that language, in simple everyday words.\n"
        "- If OUTPUT LANGUAGE is auto, use the language of the message itself and set "
        '"language" to its code: en, hi (Hindi), mr (Marathi), hinglish (Hindi in English letters).\n'
        "- Hindi and Marathi must be written in Devanagari script. Marathi is NOT Hindi: use "
        "Marathi grammar (आहे, नका, करा).\n"
        "- Keep JSON keys, verdict and scam_type labels in English. Copy quoted scam text, links, "
        "numbers, 1930 and cybercrime.gov.in exactly as they are.\n\n"
        "RULES:\n"
        "- Base everything only on what is in the message. Never invent facts.\n"
        "- If unsure, choose \"SUSPICIOUS\". Use \"SAFE\" only when there is no sign of fraud.\n"
        "- risk_score must match verdict: SAFE 0-30, SUSPICIOUS 31-70, SCAM 71-100.\n"
        "- If SAFE, scam_type is \"None\".\n"
        "- If message asks for OTP, PIN, password, or to click a strange link, never say SAFE.\n"
        "- red_flags: 2-5 items, each quoting the exact risky words when possible.\n"
        "- what_to_do: concrete steps. For money loss mention calling 1930."
    )


SYSTEM_PROMPT = build_system_prompt()

RETRY_NUDGE = ("Your last reply was not valid JSON. Reply again with ONLY the JSON object "
               "in the exact schema. No extra text.")


class AnalysisError(Exception):
    """Friendly, user-showable error."""


# ---------- helpers ----------
def prepare_image(raw: bytes) -> bytes:
    """Downscale + normalize to PNG so big screenshots do not slow the model."""
    try:
        img = Image.open(io.BytesIO(raw)).convert("RGB")
        img.thumbnail((MAX_IMAGE_SIDE, MAX_IMAGE_SIDE))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except Exception:
        raise AnalysisError("Could not read that image. Try a PNG or JPG screenshot.")


def extract_json(raw: str) -> dict:
    """Pull the first balanced {...} object out of model text. Raises ValueError."""
    text = re.sub(r"```(?:json)?", "", raw or "").strip()
    start = text.find("{")
    if start == -1:
        raise ValueError("no JSON object found")
    depth, in_str, esc = 0, False, False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start:i + 1])
    raise ValueError("unbalanced JSON")


def as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [str(value)]


def clean_scam_type(raw: str, verdict: str) -> str:
    """Map whatever the model wrote to one of our fixed labels."""
    if verdict == "SAFE":
        return "None"
    low = (raw or "").strip().lower()
    for label in SCAM_LABELS:
        if low == label.lower():
            return label
    for key, label in LABEL_HINTS.items():
        if key in low:
            return label
    return "Other"


def verdict_from_score(score: int) -> str:
    return "SCAM" if score >= 71 else "SUSPICIOUS" if score >= 31 else "SAFE"


def normalize(d: dict) -> dict:
    """Make sure every field exists and has the right type. Never trust the model."""
    verdict = str(d.get("verdict", "SUSPICIOUS")).strip().upper().replace(" ", "_")
    if verdict in {"LIKELY_SAFE", "LEGIT", "LEGITIMATE"}:
        verdict = "SAFE"
    if verdict not in VERDICTS:
        verdict = "SUSPICIOUS"
    try:
        score = int(float(d.get("risk_score", 50)))
    except (TypeError, ValueError):
        score = 50
    lo, hi = SCORE_BANDS[verdict]          # keep meter and banner consistent
    score = max(lo, min(hi, score))
    lang = str(d.get("language") or "").strip().lower()
    return {
        "verdict": verdict,
        "risk_score": score,
        "scam_type": clean_scam_type(str(d.get("scam_type") or ""), verdict),
        "language": lang if lang in LANGS else "",
        "red_flags": as_list(d.get("red_flags")),
        "explanation": str(d.get("explanation") or "").strip(),
        "what_to_do": as_list(d.get("what_to_do")),
        "extracted_text": str(d.get("extracted_text") or "").strip(),
    }


def wrong_script(result: dict, lang: str | None) -> bool:
    """True if Hindi/Marathi was requested but the answer is mostly Latin letters."""
    if lang not in ("hi", "mr"):
        return False
    body = result["explanation"] + " " + " ".join(result["what_to_do"])
    dev = len(re.findall(r"[\u0900-\u097F]", body))
    lat = len(re.findall(r"[A-Za-z]", body))
    return dev + lat > 0 and dev / (dev + lat) < 0.3


# ---------- model call ----------
def analyze(text: str | None = None, image_bytes: bytes | None = None,
            lang: str | None = None) -> dict:
    """Call Gemma 4 locally. lang = en/hi/mr/hinglish, or None for 'same as the message'.
    Returns normalized dict or raises AnalysisError."""
    if not text and not image_bytes:
        raise AnalysisError("Give me a screenshot or some message text first.")

    out_lang = LANG_NAME[lang] if lang in LANG_NAME else "auto (same language as the message)"
    content = f"Analyze this message for scams.\nOUTPUT LANGUAGE: {out_lang}"
    if text:
        content += f"\n\nMessage text:\n{text}"
    user_msg = {"role": "user", "content": content}
    if image_bytes:
        user_msg["images"] = [prepare_image(image_bytes)]

    client = ollama.Client(host=OLLAMA_HOST, timeout=TIMEOUT_SEC)
    messages = [{"role": "system", "content": SYSTEM_PROMPT}, user_msg]
    last_result = None                       # best answer so far, used if retry also fails

    for attempt in range(MAX_RETRIES + 1):
        try:
            resp = client.chat(
                model=MODEL,
                messages=messages,
                format="json",
                options={"temperature": TEMPERATURE, "num_ctx": NUM_CTX},
                keep_alive=KEEP_ALIVE,
            )
        except (ConnectionError, httpx.ConnectError):
            raise AnalysisError("Cannot reach Ollama. Start it with `ollama serve` (or open the Ollama app) and try again.")
        except httpx.TimeoutException:
            raise AnalysisError("The model took too long. First run loads the model; wait a bit and try again.")
        except ollama.ResponseError as e:
            if getattr(e, "status_code", None) == 404:
                raise AnalysisError(f"Model not found. Run: `ollama pull {MODEL}`")
            raise AnalysisError(f"Ollama error: {e}")
        except Exception as e:  # last-resort guard so demo never shows a traceback
            raise AnalysisError(f"Unexpected problem talking to the model: {e}")

        last_raw = resp["message"]["content"] or ""
        try:
            result = normalize(extract_json(last_raw))
        except (ValueError, json.JSONDecodeError):
            messages = messages + [{"role": "assistant", "content": last_raw},
                                   {"role": "user", "content": RETRY_NUDGE}]
            continue

        if wrong_script(result, lang):       # asked for Hindi/Marathi, got English
            last_result = result
            messages = messages + [
                {"role": "assistant", "content": last_raw},
                {"role": "user", "content": f"Rewrite the JSON. explanation, red_flags and what_to_do "
                                            f"MUST be in {LANG_NAME[lang]}. Same schema, ONLY JSON."},
            ]
            continue
        return result

    if last_result:                          # language retry failed: still show something useful
        return last_result
    raise AnalysisError("The model gave a garbled answer twice. Please press Check again.")


# ---------- combine AI + rules ----------
def combine(model: dict, rules: dict) -> dict:
    """Rules can only RAISE risk, never lower it."""
    ai, rs = model["risk_score"], rules["score"]
    score = max(ai, round((1 - RULE_WEIGHT) * ai + RULE_WEIGHT * rs))
    if rules["critical"] >= 2:
        score = max(score, FLOOR_TWO_CRITICAL)
    elif rules["critical"] == 1:
        score = max(score, FLOOR_ONE_CRITICAL)
    score = min(100, score)
    verdict = verdict_from_score(score)
    if RANK[model["verdict"]] > RANK[verdict]:     # safety: never downgrade the AI verdict
        verdict = model["verdict"]
        lo, hi = SCORE_BANDS[verdict]
        score = max(lo, min(hi, score))

    scam_type = model["scam_type"]
    if verdict == "SAFE":
        scam_type = "None"
    elif scam_type == "None":                      # rules raised a SAFE result: pick a type
        hinted = next((s["type"] for s in rules["signals"] if s.get("type") in SCAM_LABELS), None)
        scam_type = hinted or "Other"

    return {
        **model,
        "verdict": verdict,
        "risk_score": score,
        "scam_type": scam_type,
        "model_verdict": model["verdict"],
        "model_score": ai,
        "rule_score": rs,
        "signals": rules["signals"],
        "links": rules["links"],
    }


def pick_language(text: str | None, lang_choice: str) -> str | None:
    """Forced choice > detected from pasted text > None (screenshot: model decides)."""
    if lang_choice in LANGS:
        return lang_choice
    if text:
        return detect_language(text)
    return None


def check(text: str | None, image_bytes: bytes | None, lang_choice: str = "auto") -> dict:
    """Full pipeline: model, then rules on pasted text + text the model read from the image."""
    lang = pick_language(text, lang_choice)
    model = analyze(text, image_bytes, lang)
    seen = "\n".join(t for t in (text or "", model["extracted_text"]) if t.strip())
    result = combine(model, run_rules(seen))
    result["language"] = lang or model["language"] or detect_language(model["extracted_text"])
    return result