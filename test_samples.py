"""test_samples.py - quick accuracy check.
Run:  python test_samples.py              (full: rules + Gemma, needs Ollama)
      python test_samples.py --rules-only (no AI, instant)"""
import sys
import time

from analyzer import AnalysisError, check
from rules import run_rules

SAMPLES = [
    {"name": "Fake SBI KYC link", "expect": {"SCAM"}, "lang": "en",
     "text": "Dear customer, your SBI account will be blocked today. Update KYC at "
             "http://sbi-kyc-update.xyz or share OTP."},
    {"name": "UPI collect 'refund'", "expect": {"SCAM"}, "lang": "en",
     "text": "Refund of Rs 4,999 pending. Approve the collect request in your PhonePe "
             "and enter UPI PIN to receive."},
    {"name": "Hindi digital arrest", "expect": {"SCAM"}, "lang": "hi",
     "text": "यह CBI अधिकारी है। आपके नाम के पार्सल में ड्रग्स मिले हैं। आप डिजिटल अरेस्ट में हैं। "
             "वीडियो कॉल पर रहें और वेरिफिकेशन के लिए 50,000 रुपये ट्रांसफर करें।"},
    {"name": "Legit Amazon OTP", "expect": {"SAFE"}, "lang": "en",
     "text": "123456 is your OTP for Amazon login. Do not share it with anyone."},
    {"name": "Legit delivery update", "expect": {"SAFE"}, "lang": "en",
     "text": "Your order #408-1234567 has been delivered. Thank you for shopping with us."},
]


def run_rules_only() -> int:
    fails = 0
    for s in SAMPLES:
        r = run_rules(s["text"])
        want_safe = s["expect"] == {"SAFE"}
        ok = (r["score"] == 0) if want_safe else (r["critical"] >= 1)
        fails += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {s['name']:<24} rules score={r['score']:<3} "
              f"critical={r['critical']} signals={len(r['signals'])}")
    return fails


def run_full() -> int:
    fails, total = 0, 0.0
    for s in SAMPLES:
        t0 = time.perf_counter()
        try:
            r = check(s["text"], None, "auto")
        except AnalysisError as e:
            print(f"FAIL  {s['name']:<24} error: {e}")
            fails += 1
            continue
        dt = time.perf_counter() - t0
        total += dt
        ok = r["verdict"] in s["expect"] and r["language"] == s["lang"]
        fails += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {s['name']:<24} got={r['verdict']:<10} "
              f"score={r['risk_score']:<3} type={r['scam_type']!r} lang={r['language']} {dt:.1f}s")
    print(f"avg {total / len(SAMPLES):.1f}s per check")
    return fails


if __name__ == "__main__":
    f = run_rules_only() if "--rules-only" in sys.argv else run_full()
    print(f"\n{len(SAMPLES) - f}/{len(SAMPLES)} passed")
    sys.exit(1 if f else 0)