"""Interface web de Log Sentinel. Lancer avec : streamlit run app.py"""
from __future__ import annotations

import hashlib
from collections import Counter
from pathlib import Path

import pandas as pd
import streamlit as st

from sentinel import AnalysisResult, Config, analyze_text
from sentinel.llm import LLMError, generate_report
from sentinel.models import SEVERITIES, SEVERITY_ICONS, SEVERITY_LABELS
from sentinel.report import escape_md, strip_images, to_json, to_markdown

ROOT = Path(__file__).parent
REPO_URL = "https://github.com/heumbia2002/log-sentinel"
SAMPLES = {
    "Exemple : serveur SSH (auth.log)": ROOT / "samples" / "auth.log",
    "Exemple : serveur web (access.log)": ROOT / "samples" / "access.log",
}
UPLOAD, PASTE = "Téléverser un fichier", "Coller du texte"
SHARED_KEY_LIMIT = 3  # rapports IA par session lorsque la clé de démonstration est utilisée

st.set_page_config(page_title="Log Sentinel", page_icon="🛡️", layout="wide")


@st.cache_data(show_spinner=False, max_entries=20)
def run_analysis(text: str, cfg_values: tuple) -> AnalysisResult:
    return analyze_text(text, Config(*cfg_values))


def shared_key() -> str | None:
    """Clé facultative du propriétaire de la démo, définie dans les secrets Streamlit."""
    try:
        return st.secrets.get("ANTHROPIC_API_KEY")
    except Exception:  # aucun fichier secrets.toml
        return None


def fmt_ts(ts) -> str:
    return ts.strftime("%d/%m %H:%M:%S") if ts else "?"


# ---------- Barre latérale ----------
with st.sidebar:
    st.header("Journaux")
    choice = st.radio("Source", [*SAMPLES, UPLOAD, PASTE], label_visibility="collapsed")

    st.header("Seuils de détection")
    bf = st.slider("Échecs SSH avant alerte", 3, 30, 5)
    bf_window = st.slider("Fenêtre de force brute (minutes)", 1, 60, 10)
    spray = st.slider("Comptes différents visés (pulvérisation)", 3, 20, 5)
    w404 = st.slider("Erreurs 404 avant alerte", 5, 100, 20)

    st.header("Rapport IA")
    user_key = st.text_input(
        "Clé API Anthropic (facultative)", type="password",
        help="Utilisée seulement pendant votre session, jamais enregistrée. "
             "Obtenez-en une sur console.anthropic.com.")
    lang = st.selectbox("Langue du rapport", ["Français", "English"])
    mask_ips = st.toggle("Masquer les adresses IP avant l'envoi", value=True,
                         help="Les IP sont remplacées par [IP-01], [IP-02]… avant d'être envoyées "
                              "à l'IA, puis rétablies dans le rapport affiché.")
    st.caption(f"[Code source sur GitHub]({REPO_URL})")

# ---------- Choix des journaux ----------
st.title("🛡️ Log Sentinel")
st.write("Repère les attaques dans vos journaux SSH (auth.log) et web (Apache, Nginx), "
         "les relie aux techniques MITRE ATT&CK et propose les actions à prendre.")

text = ""
if choice in SAMPLES:
    text = SAMPLES[choice].read_text(encoding="utf-8")
    st.caption("Journal d'exemple. Les adresses IP proviennent des plages réservées à la "
               "documentation et n'appartiennent à personne.")
    with st.expander("Voir le journal brut"):
        st.code(text, language=None)
else:
    if choice == UPLOAD:
        uploaded = st.file_uploader("Fichier .log ou .txt (5 Mo maximum)", type=["log", "txt"])
        if uploaded:
            text = uploaded.getvalue().decode("utf-8", errors="replace")
    else:
        text = st.text_area(
            "Lignes de journaux", height=200,
            placeholder="Oct 24 10:15:02 web01 sshd[2211]: Failed password for root "
                        "from 203.0.113.45 port 52344 ssh2")
    st.caption("Les journaux sont analysés en mémoire et ne sont pas conservés. Retirez les "
               "données confidentielles avant de soumettre des journaux de production.")

if not text.strip():
    st.info("Choisissez un exemple dans la barre latérale ou ajoutez vos journaux pour lancer l'analyse.")
    st.stop()

cfg = (bf, bf_window, spray, 3, w404, 5)
result = run_analysis(text, cfg)
stats, findings = result.stats, result.findings

# ---------- Vue d'ensemble ----------
cols = st.columns(4)
cols[0].metric("Lignes lues", stats["lines"])
cols[1].metric("Événements reconnus", stats["recognized"])
cols[2].metric("Adresses IP", stats["unique_ips"])
cols[3].metric("Alertes", len(findings))

if stats["truncated"]:
    st.warning("Seules les 50 000 premières lignes ont été analysées.")
if stats["recognized"] == 0:
    st.warning("Aucune ligne reconnue. Formats pris en charge : auth.log / syslog (sshd, sudo) "
               "et journaux d'accès Apache ou Nginx au format « combined ».")
    st.stop()

left, right = st.columns([2, 1], gap="large")

with left:
    st.subheader("Alertes")
    if not findings:
        st.success("Aucune activité suspecte avec les seuils actuels.")
    else:
        present = [s for s in SEVERITIES if any(f.severity == s for f in findings)]
        selected = st.multiselect(
            "Gravité", present, default=present,
            format_func=lambda s: f"{SEVERITY_ICONS[s]} {SEVERITY_LABELS[s]}")
        for f in (f for f in findings if f.severity in selected):
            where = f" ({escape_md(f.ip)})" if f.ip else ""
            label = f"{SEVERITY_ICONS[f.severity]} {SEVERITY_LABELS[f.severity]} — {f.title}{where}"
            with st.expander(label, expanded=f.severity == "critical"):
                st.markdown(f"**MITRE ATT&CK :** [{f.mitre_id} – {f.mitre_name}]({f.mitre_url})  \n"
                            f"**Occurrences :** {f.count}  \n"
                            f"**Période :** {fmt_ts(f.first_seen)} → {fmt_ts(f.last_seen)}")
                st.markdown(escape_md(f.description))
                st.markdown(f"**Recommandation :** {f.recommendation}")
                st.code("\n".join(f.evidence), language=None)

with right:
    if stats["top_ips"]:
        st.subheader("IP les plus actives")
        df = pd.DataFrame(stats["top_ips"], columns=["IP", "Événements"]).set_index("IP")
        st.bar_chart(df, horizontal=True)
    if findings:
        st.subheader("Techniques MITRE ATT&CK")
        techniques = Counter((f.mitre_id, f.mitre_name, f.mitre_url) for f in findings)
        st.markdown("\n".join(f"- [{tid}]({url}) {name} ({n})"
                              for (tid, name, url), n in techniques.most_common()))

# ---------- Rapport IA ----------
st.divider()
st.subheader("Rapport d'incident rédigé par l'IA")
lang_code = "fr" if lang == "Français" else "en"
digest = hashlib.sha256(f"{text}|{cfg}|{lang_code}|{mask_ips}".encode()).hexdigest()
api_key = user_key or shared_key()
using_shared = not user_key and api_key is not None
st.session_state.setdefault("ai_calls", 0)

if not findings:
    st.caption("Aucune alerte à résumer.")
elif not api_key:
    st.caption("Ajoutez une clé API Anthropic dans la barre latérale pour obtenir un rapport rédigé : "
               "résumé pour la direction, chronologie, actions prioritaires et indicateurs de "
               "compromission. La détection ci-dessus fonctionne sans clé.")
elif using_shared and st.session_state.ai_calls >= SHARED_KEY_LIMIT:
    st.warning(f"Limite de {SHARED_KEY_LIMIT} rapports atteinte avec la clé de démonstration. "
               "Ajoutez votre propre clé pour continuer.")
elif st.button("Générer le rapport d'incident", type="primary"):
    with st.spinner("Rédaction du rapport…"):
        try:
            report = generate_report(api_key, findings, stats, lang=lang_code, mask_ips=mask_ips)
            st.session_state.ai_report = {"digest": digest, "text": report}
            st.session_state.ai_calls += 1
        except LLMError as exc:
            st.error(str(exc))

saved = st.session_state.get("ai_report")
ai_text = saved["text"] if saved and saved["digest"] == digest else None
if ai_text:
    # Le rapport peut citer du contenu contrôlé par l'attaquant : pas d'HTML ni d'images.
    st.markdown(strip_images(ai_text))

# ---------- Export ----------
st.divider()
c1, c2 = st.columns(2)
c1.download_button("Télécharger le rapport (Markdown)", to_markdown(result, ai_text),
                   file_name="rapport-log-sentinel.md", mime="text/markdown")
c2.download_button("Télécharger les alertes (JSON)", to_json(result),
                   file_name="alertes-log-sentinel.json", mime="application/json")
