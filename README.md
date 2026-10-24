# 🛡️ Log Sentinel

![Tests](https://github.com/heumbia2002/log-sentinel/actions/workflows/tests.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)
![Licence](https://img.shields.io/badge/licence-MIT-green)

**[Essayer la démo en ligne](https://VOTRE-APP.streamlit.app)** · [English version below](#english)

Log Sentinel analyse des journaux SSH (`auth.log`) et web (Apache, Nginx), repère les attaques, les relie aux techniques **MITRE ATT&CK** et propose les actions à prendre. Avec une clé API, il rédige aussi un rapport d'incident complet grâce à l'IA (Claude).

La détection fonctionne **sans clé API et sans installation** : ouvrez la démo, choisissez un journal d'exemple et les alertes s'affichent.

## Ce qui est détecté

| Règle | Attaque | MITRE ATT&CK | Gravité |
|---|---|---|---|
| `SSH-COMPROMISE` | Connexion réussie après une série d'échecs | [T1078](https://attack.mitre.org/techniques/T1078/) | Critique |
| `SSH-BRUTE` | Force brute SSH (fenêtre glissante) | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Élevée |
| `SSH-SPRAY` | Pulvérisation de mots de passe | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Élevée |
| `SSH-ROOT` | Connexion directe en root | [T1078.003](https://attack.mitre.org/techniques/T1078/003/) | Moyenne |
| `SUDO-FAIL` | Échecs d'élévation de privilèges | [T1548.003](https://attack.mitre.org/techniques/T1548/003/) | Moyenne |
| `WEB-RCE` | Injection de commande, Log4Shell | [T1190](https://attack.mitre.org/techniques/T1190/) | Élevée* |
| `WEB-SQLI` | Injection SQL | [T1190](https://attack.mitre.org/techniques/T1190/) | Élevée* |
| `WEB-TRAVERSAL` | Traversée de répertoires (y compris double encodage) | [T1190](https://attack.mitre.org/techniques/T1190/) | Élevée* |
| `WEB-XSS` | Script intersite | [T1190](https://attack.mitre.org/techniques/T1190/) | Moyenne |
| `WEB-PROBE` | Recherche de `.env`, `.git`, sauvegardes… | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) | Moyenne |
| `WEB-SCANNER` | sqlmap, Nikto, Nuclei, gobuster… | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | Moyenne |
| `WEB-404-FLOOD` | Rafale d'erreurs 404 (énumération) | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) | Moyenne |

\* Passe à **Critique** si le serveur a répondu 2xx : la requête malveillante a été traitée.

## Lancer le projet

**En local**

```bash
git clone https://github.com/heumbia2002/log-sentinel.git
cd log-sentinel
python -m venv .venv && source .venv/bin/activate   # Windows : .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

**Avec Docker**

```bash
docker build -t log-sentinel .
docker run -p 8501:8501 log-sentinel
```

Puis ouvrir http://localhost:8501.

**Tests**

```bash
python -m unittest discover -s tests -v
```

## Sécurité de l'outil lui-même

Un outil qui lit des journaux lit du contenu écrit par des attaquants. Plusieurs protections en tiennent compte :

- **Injection de prompt** : les extraits de journaux envoyés à l'IA sont isolés entre balises `<logs>`, présentés comme des données non fiables, et une ligne contenant `</logs>` ne peut pas sortir de cette zone.
- **Injection Markdown** : les valeurs issues des journaux (IP, noms d'utilisateur) sont échappées avant affichage, et les images sont retirées du rapport IA, pour empêcher un attaquant de faire charger une ressource externe.
- **Confidentialité** : les adresses IP peuvent être masquées (`[IP-01]`) avant l'envoi à l'IA, puis rétablies localement. Les journaux ne sont jamais enregistrés sur disque.
- **Clés API** : la clé saisie reste dans la session ; `.streamlit/secrets.toml` est exclu de Git.
- **Ressources** : 5 Mo par fichier et 50 000 lignes maximum ; le conteneur Docker ne tourne pas en root.

## Déployer sa propre démo (gratuit)

1. Publier le dépôt sur GitHub.
2. Sur [share.streamlit.io](https://share.streamlit.io), choisir le dépôt et `app.py`.
3. Facultatif : dans *Settings → Secrets*, ajouter `ANTHROPIC_API_KEY = "..."` pour offrir le rapport IA aux visiteurs (limité à 3 rapports par session). **Fixez une limite de dépenses dans la console Anthropic** : la limite par session se contourne en rechargeant la page.

## Structure

```
app.py                  Interface Streamlit
sentinel/parsers.py     Lecture d'auth.log (classique et ISO) et des journaux d'accès
sentinel/detectors.py   Règles de détection et correspondance MITRE ATT&CK
sentinel/llm.py         Rapport d'incident par IA, masquage des IP
sentinel/report.py      Export Markdown / JSON, échappement
samples/                Journaux d'exemple (IP fictives, RFC 5737)
scripts/                Générateur des exemples
tests/                  Tests unitaires (exécutés par GitHub Actions)
```

## Pistes d'amélioration

- Journaux Windows (événements 4625, 4624) et pare-feu
- Géolocalisation et réputation des IP (AbuseIPDB)
- Export des règles au format Sigma
- Règles fail2ban générées automatiquement

---

<a id="english"></a>

## English

Log Sentinel analyzes SSH (`auth.log`) and web server (Apache, Nginx) logs, detects attacks, maps them to **MITRE ATT&CK** techniques and recommends next steps. With an API key, it also writes a full incident report using AI (Claude).

Detection works **without an API key or installation**: open the demo, pick a sample log and the alerts appear. The interface is in French; AI reports can be generated in English.

**Detected:** successful login after brute force (critical), SSH brute force and password spraying, direct root logins, sudo failures, command injection and Log4Shell, SQL injection, path traversal (including double encoding), XSS, sensitive file probing, vulnerability scanners and 404 bursts. Exploitation attempts are escalated to *critical* when the server answered 2xx. See the table above for rules and ATT&CK IDs.

**Run locally:** `pip install -r requirements.txt` then `streamlit run app.py`, or use Docker (`docker build -t log-sentinel . && docker run -p 8501:8501 log-sentinel`). Tests: `python -m unittest discover -s tests -v`.

**Securing the tool itself:** log lines are attacker-controlled, so they are fenced as untrusted data in the AI prompt (with tag-escape protection), escaped before Markdown rendering, and images are stripped from AI output. IP addresses can be masked before leaving the machine and restored locally. Logs are never written to disk, and the container runs as a non-root user.

## Licence

MIT. Auteur : Romaric Heumbia Mbuetang.
