"""Export des résultats en Markdown et en JSON."""
from __future__ import annotations

import json
import re
from datetime import datetime

from .models import SEVERITY_ICONS, SEVERITY_LABELS

# Caractères ayant un sens en Markdown (et dans le Markdown de Streamlit : $ pour LaTeX, : pour
# les émojis). Le contenu des journaux est contrôlé par l'attaquant : on l'échappe avant affichage
# pour empêcher l'injection de liens ou d'images.
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|<>~$:])")
_MD_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")


def escape_md(value: str) -> str:
    return _MD_SPECIAL.sub(r"\\\1", value)


def strip_images(markdown: str) -> str:
    """Retire les images d'un texte Markdown (une image distante ferait une requête réseau)."""
    return _MD_IMAGE.sub("[image retirée]", markdown)


def _fmt(ts: datetime | None) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "inconnue"


def to_markdown(result, ai_report: str | None = None) -> str:
    s = result.stats
    out = [
        "# Rapport d'analyse — Log Sentinel",
        "",
        f"Généré le {datetime.now():%Y-%m-%d %H:%M}.",
        "",
        "## Résumé",
        "",
        f"- Lignes lues : {s['lines']}",
        f"- Événements reconnus : {s['recognized']}",
        f"- Adresses IP distinctes : {s['unique_ips']}",
        f"- Période couverte : {s['start'] or 'inconnue'} → {s['end'] or 'inconnue'}",
        f"- Alertes : {len(result.findings)}",
        "",
        f"## Alertes ({len(result.findings)})",
        "",
    ]
    if not result.findings:
        out.append("Aucune activité suspecte détectée.")
    for f in result.findings:
        where = f" ({escape_md(f.ip)})" if f.ip else ""
        evidence = "\n".join(line.replace("~~~", "~ ~ ~") for line in f.evidence)
        out += [
            f"### {SEVERITY_ICONS[f.severity]} {SEVERITY_LABELS[f.severity]} — {f.title}{where}",
            "",
            f"- MITRE ATT&CK : [{f.mitre_id} – {f.mitre_name}]({f.mitre_url})",
            f"- Occurrences : {f.count}",
            f"- Période : {_fmt(f.first_seen)} → {_fmt(f.last_seen)}",
            "",
            escape_md(f.description),
            "",
            f"**Recommandation :** {f.recommendation}",
            "",
            "~~~",
            evidence,
            "~~~",
            "",
        ]
    if ai_report:
        out += ["## Rapport d'incident (généré par IA)", "", strip_images(ai_report), ""]
    return "\n".join(out)


def to_json(result) -> str:
    return json.dumps(
        {"stats": result.stats, "findings": [f.to_dict() for f in result.findings]},
        ensure_ascii=False, indent=2)
