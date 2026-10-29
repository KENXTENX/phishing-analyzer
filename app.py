"""Phishing Email Analyzer: upload an email, get red flags and an AI verdict."""
import os

import pandas as pd
import streamlit as st

from email_parser import parse_email
from rules import check_email

st.set_page_config(page_title="Phishing Email Analyzer", page_icon="🎣", layout="wide")

# On Streamlit Cloud the API key lives in Secrets; locally it comes from .env
try:
    if "ANTHROPIC_API_KEY" in st.secrets:
        os.environ["ANTHROPIC_API_KEY"] = st.secrets["ANTHROPIC_API_KEY"]
except Exception:
    pass

MAX_AI_CHECKS = 10        # per visitor session, so a public app can't drain API credit
MAX_FILE_MB = 2
COLORS = {"Phishing": "red", "Suspicious": "orange", "Likely safe": "green"}

st.title("🎣 Phishing Email Analyzer")
st.caption("Rule-based red flags plus an AI second opinion, with defenses against prompt injection. "
           "The tool reads links but never opens them.")

with st.expander("How do I get a .eml file?"):
    st.markdown("**Gmail:** open the email → **⋮** → **Download message**.  \n"
                "**Outlook:** open the email → **File** → **Save As**.  \n"
                "Uploaded emails are sent to Anthropic's API for the AI check. "
                "Don't upload anything confidential.")

# ---------- Pick an email ----------
left, right = st.columns([3, 1])
uploaded = left.file_uploader("Upload an email (.eml)", type=["eml"])
use_demo = right.button("Try a demo phishing email", width="stretch")

if use_demo:
    st.session_state["raw"] = open("demo/fake_paypal_phish.eml", "rb").read()
    st.session_state["name"] = "Demo: fake PayPal email"
    st.session_state.pop("ai", None)
elif uploaded is not None and uploaded.name != st.session_state.get("name"):
    if uploaded.size > MAX_FILE_MB * 1024 * 1024:
        st.error(f"That file is over {MAX_FILE_MB} MB. Try a different email.")
        st.stop()
    st.session_state["raw"] = uploaded.getvalue()
    st.session_state["name"] = uploaded.name
    st.session_state.pop("ai", None)

if "raw" not in st.session_state:
    st.info("Upload a .eml file or try the demo to get started.")
    st.stop()

info = parse_email(st.session_state["raw"])
result = check_email(info)

# ---------- Summary ----------
st.subheader(st.session_state["name"])
c1, c2, c3, c4 = st.columns(4)
c1.metric("Rule score", f"{result['score']}/100")
c2.markdown(f"**Rule verdict**  \n:{COLORS[result['verdict']]}[**{result['verdict']}**]")
c3.metric("Links found", len(info["links"]))
c4.metric("SPF / DKIM / DMARC", f"{info['spf']} / {info['dkim']} / {info['dmarc']}")

# Backticks keep addresses as plain text, so nothing from the email becomes clickable
st.markdown(f"**From:** {info['from_name']} `{info['from_address']}`  \n"
            f"**Reply-To:** `{info['reply_to'] or '(none)'}`  \n"
            f"**Subject:** {info['subject']}")

# ---------- AI verdict ----------
st.divider()
st.subheader("AI verdict")
used = st.session_state.get("ai_checks", 0)

if "ai" in st.session_state:
    ai = st.session_state["ai"]
    st.markdown(f"### :{COLORS[ai['verdict']]}[{ai['verdict']}] · {ai['confidence']}% confident")
    if ai.get("overridden"):
        st.warning("The AI said Likely safe, but the rule checks found strong red flags, "
                   "so the verdict was raised to Suspicious.")
    st.write(ai["summary"])
    for reason in ai["reasons"]:
        st.markdown(f"- {reason}")
elif used >= MAX_AI_CHECKS:
    st.info(f"You've used all {MAX_AI_CHECKS} AI checks for this session. The rule checks below still work.")
elif st.button("Get AI verdict", type="primary"):
    with st.spinner("Asking Claude..."):
        try:
            from llm import analyze_with_llm
            st.session_state["ai"] = analyze_with_llm(info, result)
            st.session_state["ai_checks"] = used + 1
            st.rerun()
        except Exception as error:
            st.error(f"The AI check didn't work: {error}")

# ---------- Red flags ----------
st.divider()
st.subheader(f"Red flags ({len(result['flags'])})")
if result["flags"]:
    flags = pd.DataFrame(result["flags"])
    flags["severity"] = flags["severity"].str.upper()
    st.dataframe(flags.rename(columns={"severity": "Severity", "flag": "Flag", "detail": "Detail"}),
                 hide_index=True, width="stretch")
else:
    st.success("No rule-based red flags found.")

# ---------- Links ----------
with st.expander(f"All links in the email ({len(info['links'])}). Not clickable, on purpose."):
    if info["links"]:
        links = pd.DataFrame(info["links"]).rename(columns={"url": "Destination", "text": "Shown as"})
        st.dataframe(links, hide_index=True, width="stretch")
    else:
        st.write("No links.")

with st.expander("Email text"):
    st.text(info["body"][:3000] or "(empty)")