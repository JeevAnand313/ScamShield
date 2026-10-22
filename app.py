"""ScamShield - Step 6 (final): AI + quick signals + languages + history, report, share.
Run: streamlit run app.py"""
import html
import re
import time

import streamlit as st

from analyzer import MODEL, AnalysisError, check, pick_language
from extras import MAX_HISTORY, TEXT, build_share_text, make_entry
from i18n import STRINGS, VERDICT_WORD, translate_label, translate_signal, ui_lang
from rules import run_rules

# verdict -> (accent colour, string key)
THEME = {"SCAM": ("#d93025", "scam"), "SUSPICIOUS": ("#f29900", "suspicious"), "SAFE": ("#1e8e3e", "safe")}
RANK = {"SAFE": 0, "SUSPICIOUS": 1, "SCAM": 2}
LANG_CHOICES = {"Auto (same as message)": "auto", "English": "en", "हिन्दी": "hi", "मराठी": "mr"}

CSS = """
<style>
.ss-banner{border-radius:16px;padding:22px 26px;margin:8px 0 18px 0;border-left:10px solid var(--c);
  background:color-mix(in srgb,var(--c) 14%,transparent);}
.ss-banner h1{margin:0;font-size:2.6rem;line-height:1.1;color:var(--c);}
.ss-banner p{margin:6px 0 0 0;font-size:1.1rem;opacity:.9;}
.ss-type{display:inline-block;margin-top:10px;padding:3px 12px;border-radius:999px;
  background:var(--c);color:#fff;font-weight:600;font-size:.85rem;}
.ss-meter-label{display:flex;justify-content:space-between;font-weight:600;margin-bottom:4px;}
.ss-track{position:relative;height:16px;border-radius:999px;
  background:linear-gradient(90deg,#1e8e3e 0%,#f2c200 50%,#d93025 100%);}
.ss-marker{position:absolute;top:-6px;width:6px;height:28px;border-radius:3px;
  background:#222;border:2px solid #fff;transform:translateX(-50%);}
.ss-scale{display:flex;justify-content:space-between;font-size:.75rem;opacity:.65;margin-top:4px;}
.ss-card{padding:10px 14px;margin:6px 0;border-radius:10px;border-left:5px solid var(--c);
  background:color-mix(in srgb,var(--c) 10%,transparent);}
.ss-card mark{background:#ffe066;color:#000;padding:0 3px;border-radius:3px;}
.ss-step{display:flex;gap:12px;align-items:flex-start;padding:10px 14px;margin:6px 0;
  border-radius:10px;background:color-mix(in srgb,#1e8e3e 10%,transparent);}
.ss-num{flex:none;width:26px;height:26px;border-radius:50%;background:#1e8e3e;color:#fff;
  text-align:center;line-height:26px;font-weight:700;font-size:.85rem;}
</style>
"""


def esc(s) -> str:
    """Escape model/user text so it can never break our HTML."""
    return html.escape(str(s))


def highlight_quotes(escaped: str) -> str:
    return re.sub(r"(&quot;|“|‘|&#x27;)(.{2,}?)(&quot;|”|’|&#x27;)", r"<mark>\2</mark>", escaped)


def signals_html(signals: list[dict], lang: str) -> str:
    """Quick-signal cards. Red dot = critical, orange = warning."""
    return "".join(
        f'<div class="ss-card" style="--c:{"#d93025" if s["critical"] else "#f29900"}">'
        f'{"🔴" if s["critical"] else "🟠"} {esc(translate_signal(s["label"], lang))}</div>'
        for s in signals
    )


def render_result(r: dict, seconds: float | None) -> None:
    ui = ui_lang(r.get("language", "en"))
    S = STRINGS[ui]
    X = TEXT[ui]
    colour, key = THEME[r["verdict"]]
    st.markdown(CSS, unsafe_allow_html=True)

    pill = (f'<span class="ss-type">{esc(translate_label(r["scam_type"], ui))}</span>'
            if r["scam_type"] != "None" else "")
    st.markdown(
        f'<div class="ss-banner" style="--c:{colour}"><h1>{esc(S[key])}</h1>'
        f'<p>{esc(S[key + "_sub"])}</p>{pill}</div>',
        unsafe_allow_html=True,
    )

    score = r["risk_score"]
    a, b, c = S["scale"]
    st.markdown(
        f'<div class="ss-meter-label"><span>{esc(S["risk"])}</span>'
        f'<span style="color:{colour}">{score}/100</span></div>'
        f'<div class="ss-track"><div class="ss-marker" style="left:{score}%"></div></div>'
        f'<div class="ss-scale"><span>{esc(a)}</span><span>{esc(b)}</span><span>{esc(c)}</span></div>',
        unsafe_allow_html=True,
    )
    st.caption(S["score_line"].format(ai=r["model_score"], rs=r["rule_score"], c=score))

    if RANK[r["verdict"]] > RANK[r["model_verdict"]]:
        vw = VERDICT_WORD[ui]
        st.warning(S["raised"].format(a=vw[r["model_verdict"]], b=vw[r["verdict"]]))

    if r["explanation"]:
        st.markdown(f"#### {S['why']}")
        st.write(r["explanation"])

    st.markdown(f"#### {S['quick']}")
    if r["signals"]:
        st.markdown(signals_html(r["signals"], ui), unsafe_allow_html=True)
    else:
        st.write(S["none_signals"])

    st.markdown(f"#### {S['flags']}")
    if r["red_flags"]:
        cards = "".join(
            f'<div class="ss-card" style="--c:{colour}">{highlight_quotes(esc(f))}</div>'
            for f in r["red_flags"]
        )
        st.markdown(cards, unsafe_allow_html=True)
    else:
        st.write(S["none_flags"])

    st.markdown(f"#### {S['todo']}")
    if r["what_to_do"]:
        steps = "".join(
            f'<div class="ss-step"><div class="ss-num">{i}</div><div>{esc(x)}</div></div>'
            for i, x in enumerate(r["what_to_do"], 1)
        )
        st.markdown(steps, unsafe_allow_html=True)
    else:
        st.write(S["none_todo"])

    # Report + share: only when something looks wrong
    if r["verdict"] != "SAFE":
        with st.container(border=True):
            st.markdown(f"#### {X['report_title']}")
            st.markdown(X["report_md"])
        with st.container(border=True):
            st.markdown(f"#### {X['share_title']}")
            st.caption(X["share_hint"])
            st.code(build_share_text(r, ui), language=None, wrap_lines=True)

    if seconds is not None:
        st.caption(S["ondevice"].format(s=seconds))
    with st.expander("Raw parsed output"):
        st.json(r)


# ---------- state ----------
st.set_page_config(page_title="ScamShield", page_icon="🛡️")
for _k, _v in (("result", None), ("error", None), ("seconds", None),
               ("fallback", None), ("fallback_lang", None), ("history", [])):
    st.session_state.setdefault(_k, _v)

# ---------- UI ----------
st.title("🛡️ ScamShield")
st.caption(f"Runs 100% on this device with {MODEL}. Your messages never leave it.")

tab_img, tab_txt = st.tabs(["📷 Screenshot", "✍️ Paste text"])
with tab_img:
    file = st.file_uploader("Upload a screenshot", type=["png", "jpg", "jpeg"])
    if file:
        st.image(file.getvalue(), width=320)
with tab_txt:
    pasted = st.text_area("Paste the message here", height=150)

lang_label = st.radio("Explain in / भाषा", list(LANG_CHOICES), horizontal=True)
lang_choice = LANG_CHOICES[lang_label]

col_check, col_clear, _ = st.columns([1, 1, 4])
check_clicked = col_check.button("Check it", type="primary")
if col_clear.button("Clear"):
    for k in ("result", "error", "seconds", "fallback", "fallback_lang"):
        st.session_state[k] = None

if check_clicked:
    text = pasted.strip() or None
    start = time.perf_counter()
    pre_lang = pick_language(text, lang_choice) or "en"
    pre = run_rules(text or "")              # instant, before the model
    live = st.empty()
    if pre["signals"]:                       # show quick signals while the model thinks
        live.markdown(CSS + f"#### {STRINGS[ui_lang(pre_lang)]['instant']}\n"
                      + signals_html(pre["signals"], pre_lang), unsafe_allow_html=True)
    with st.spinner("Analysing locally..."):
        try:
            result = check(text, file.getvalue() if file else None, lang_choice)
            secs = time.perf_counter() - start
            st.session_state["result"] = result
            st.session_state["seconds"] = secs
            st.session_state["error"] = None
            st.session_state["fallback"] = None
            entry = make_entry(result, text, file.name if file else None, secs)
            st.session_state["history"] = ([entry] + st.session_state["history"])[:MAX_HISTORY]
        except AnalysisError as e:
            st.session_state["error"] = str(e)
            st.session_state["result"] = None
            st.session_state["fallback"] = pre["signals"] or None   # rules-only safety net
            st.session_state["fallback_lang"] = pre_lang
        except Exception as e:               # last guard: never show a traceback on stage
            st.session_state["error"] = f"Something went wrong: {e}"
            st.session_state["result"] = None
            st.session_state["fallback"] = pre["signals"] or None
            st.session_state["fallback_lang"] = pre_lang
    live.empty()

# ---------- sidebar history (after check logic so new rows show at once) ----------
with st.sidebar:
    st.subheader("🕘 History (this session)")
    hist = st.session_state["history"]
    if not hist:
        st.caption("No checks yet.")
    for i, h in enumerate(hist):
        if st.button(h["label"], key=f"hist_{i}", help=f"Checked at {h['time']}"):
            st.session_state["result"] = h["result"]
            st.session_state["seconds"] = h["seconds"]
            st.session_state["error"] = None
            st.session_state["fallback"] = None
    if hist and st.button("Clear history"):
        st.session_state["history"] = []
        st.rerun()
    st.caption("Kept in memory only. Gone when you close the app.")

# ---------- output ----------
if st.session_state.get("error"):
    st.error(st.session_state["error"])
    if st.session_state.get("fallback"):
        fl = st.session_state.get("fallback_lang") or "en"
        st.markdown(CSS + f"#### {STRINGS[ui_lang(fl)]['ai_down']}\n"
                    + signals_html(st.session_state["fallback"], fl), unsafe_allow_html=True)

if st.session_state.get("result"):
    render_result(st.session_state["result"], st.session_state.get("seconds"))