"""Règles de détection. Chaque règle est associée à une technique MITRE ATT&CK."""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import timedelta
from urllib.parse import unquote_plus

from .models import SEVERITIES, Finding, LogEvent

MAX_EVIDENCE = 5
MAX_EVIDENCE_CHARS = 400


@dataclass
class Config:
    brute_force_threshold: int = 5      # échecs SSH depuis une même IP...
    brute_force_window_min: int = 10    # ...dans cette fenêtre de temps
    spray_distinct_users: int = 5       # comptes différents visés par une même IP
    compromise_min_failures: int = 3    # échecs avant une connexion réussie
    web_404_threshold: int = 20         # erreurs 404 depuis une même IP...
    web_404_window_min: int = 5         # ...dans cette fenêtre de temps


RULES = {
    "SSH-BRUTE": dict(
        title="Force brute SSH", severity="high",
        mitre_id="T1110.001", mitre_name="Brute Force: Password Guessing",
        recommendation="Bloquer l'IP (pare-feu ou fail2ban), désactiver l'authentification SSH "
                       "par mot de passe (PasswordAuthentication no) et utiliser des clés."),
    "SSH-SPRAY": dict(
        title="Pulvérisation de mots de passe SSH", severity="high",
        mitre_id="T1110.003", mitre_name="Brute Force: Password Spraying",
        recommendation="Bloquer l'IP, restreindre les comptes autorisés (AllowUsers) et vérifier "
                       "qu'aucun compte par défaut (admin, test, pi…) n'existe sur le serveur."),
    "SSH-COMPROMISE": dict(
        title="Connexion réussie après une série d'échecs", severity="critical",
        mitre_id="T1078", mitre_name="Valid Accounts",
        recommendation="Traiter comme une compromission probable : isoler l'hôte, terminer les "
                       "sessions du compte, changer son mot de passe et examiner son activité "
                       "(historique de commandes, crontab, clés SSH ajoutées)."),
    "SSH-ROOT": dict(
        title="Connexion SSH directe en root", severity="medium",
        mitre_id="T1078.003", mitre_name="Valid Accounts: Local Accounts",
        recommendation="Interdire la connexion root (PermitRootLogin no) et passer par un compte "
                       "nominatif avec sudo pour garder la traçabilité."),
    "SUDO-FAIL": dict(
        title="Échecs d'élévation de privilèges (sudo)", severity="medium",
        mitre_id="T1548.003", mitre_name="Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        recommendation="Vérifier auprès de l'utilisateur si les tentatives sont légitimes et "
                       "examiner les commandes visées."),
    "WEB-RCE": dict(
        title="Tentative d'injection de commande", severity="high",
        mitre_id="T1190", mitre_name="Exploit Public-Facing Application",
        recommendation="Vérifier les versions des composants (ex. Log4j), appliquer les correctifs "
                       "et bloquer l'IP au pare-feu applicatif (WAF)."),
    "WEB-SQLI": dict(
        title="Tentative d'injection SQL", severity="high",
        mitre_id="T1190", mitre_name="Exploit Public-Facing Application",
        recommendation="Utiliser des requêtes paramétrées, vérifier les journaux de la base de "
                       "données et bloquer l'IP au pare-feu applicatif (WAF)."),
    "WEB-TRAVERSAL": dict(
        title="Tentative de traversée de répertoires", severity="high",
        mitre_id="T1190", mitre_name="Exploit Public-Facing Application",
        recommendation="Valider les chemins de fichiers côté serveur (liste blanche) et vérifier "
                       "qu'aucun fichier sensible n'a été servi."),
    "WEB-XSS": dict(
        title="Tentative de script intersite (XSS)", severity="medium",
        mitre_id="T1190", mitre_name="Exploit Public-Facing Application",
        recommendation="Encoder les sorties HTML, ajouter une politique CSP et vérifier si la "
                       "charge est réfléchie dans la réponse."),
    "WEB-PROBE": dict(
        title="Recherche de fichiers sensibles", severity="medium",
        mitre_id="T1595.003", mitre_name="Active Scanning: Wordlist Scanning",
        recommendation="S'assurer que .env, .git, sauvegardes et pages d'administration ne sont "
                       "pas exposés publiquement."),
    "WEB-SCANNER": dict(
        title="Outil d'analyse de vulnérabilités détecté", severity="medium",
        mitre_id="T1595.002", mitre_name="Active Scanning: Vulnerability Scanning",
        recommendation="Bloquer l'IP et vérifier si l'analyse est autorisée (test d'intrusion "
                       "planifié) ou malveillante."),
    "WEB-404-FLOOD": dict(
        title="Rafale d'erreurs 404 (énumération)", severity="medium",
        mitre_id="T1595.003", mitre_name="Active Scanning: Wordlist Scanning",
        recommendation="Limiter le débit par IP (rate limiting) et bloquer les sources abusives."),
}

# Motifs appliqués à l'URL décodée, dans l'ordre de priorité (une seule règle par requête)
WEB_PATTERNS = [
    ("WEB-RCE", re.compile(
        r"\$\{jndi:|;\s*(?:cat|wget|curl|nc|bash|sh|id|whoami)\b|\|\s*(?:wget|curl|nc|bash|sh)\b"
        r"|`[^`]+`|\$\([^)]+\)|/bin/(?:ba)?sh|cmd\.exe|powershell")),
    ("WEB-SQLI", re.compile(
        r"\bunion\b.{0,40}\bselect\b|'\s*or\s*'?\d+'?\s*=\s*'?\d+|\bor\s+1\s*=\s*1\b"
        r"|\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\(|information_schema|;\s*drop\s+table|'\s*--")),
    ("WEB-TRAVERSAL", re.compile(
        r"\.\./|\.\.\\|/etc/(?:passwd|shadow)|win\.ini|boot\.ini|php://|file://")),
    ("WEB-XSS", re.compile(
        r"<script|javascript:|on(?:error|load|mouseover)\s*=|<svg[^>]*on\w+\s*=|<iframe")),
    ("WEB-PROBE", re.compile(
        r"/\.env\b|/\.git/|/\.svn/|/\.ht(?:access|passwd)|wp-login\.php|xmlrpc\.php|/phpmyadmin"
        r"|/pma/|\.sql\b|\.bak\b|/server-status|/actuator|/cgi-bin/|/\.aws/|/\.ds_store")),
]
# Les charges Log4Shell et autres injections arrivent souvent dans l'en-tête User-Agent
UA_INJECTION = re.compile(r"\$\{jndi:|\$\{\$\{|/bin/(?:ba)?sh|\(\)\s*\{\s*:;\s*\};")
SCANNER_UA = re.compile(
    r"sqlmap|nikto|nmap|masscan|gobuster|dirbuster|dirb/|wpscan|zgrab|nuclei|acunetix"
    r"|hydra|ffuf|feroxbuster|openvas|nessus", re.IGNORECASE)
# Règles pour lesquelles une réponse 2xx peut signifier que l'attaque a réussi
ESCALATE_ON_SUCCESS = {"WEB-RCE", "WEB-SQLI", "WEB-TRAVERSAL"}


def _decode(value: str) -> str:
    for _ in range(2):  # gère le double encodage (%252e%252e)
        value = unquote_plus(value)
    return value.lower()


def _max_in_window(events: list[LogEvent], window: timedelta) -> int:
    """Plus grand nombre d'événements tombant dans une même fenêtre glissante."""
    times = sorted(e.timestamp for e in events if e.timestamp)
    if not times:
        return len(events)
    best = start = 0
    for end, t in enumerate(times):
        while t - times[start] > window:
            start += 1
        best = max(best, end - start + 1)
    return best


def _make(rule_id: str, events: list[LogEvent], description: str, ip: str | None = None,
          count: int | None = None, severity: str | None = None,
          evidence: list[LogEvent] | None = None) -> Finding:
    rule = RULES[rule_id]
    times = [e.timestamp for e in events if e.timestamp]
    return Finding(
        rule_id=rule_id, title=rule["title"], severity=severity or rule["severity"],
        mitre_id=rule["mitre_id"], mitre_name=rule["mitre_name"],
        description=description, recommendation=rule["recommendation"], ip=ip,
        count=count if count is not None else len(events),
        first_seen=min(times) if times else None, last_seen=max(times) if times else None,
        evidence=[e.raw[:MAX_EVIDENCE_CHARS] for e in (evidence or events)[:MAX_EVIDENCE]],
    )


def _users(values) -> str:
    names = sorted({v for v in values if v})
    shown = ", ".join(names[:8])
    return shown + (f" (+{len(names) - 8})" if len(names) > 8 else "")


def detect_ssh(events: list[LogEvent], cfg: Config) -> list[Finding]:
    findings: list[Finding] = []
    failed: dict[str, list[LogEvent]] = defaultdict(list)
    invalid: dict[str, list[LogEvent]] = defaultdict(list)
    accepted: list[LogEvent] = []
    sudo: dict[str, list[LogEvent]] = defaultdict(list)

    for e in events:
        if e.kind == "ssh_failed":
            failed[e.ip].append(e)
        elif e.kind == "ssh_invalid_user":
            invalid[e.ip].append(e)
        elif e.kind == "ssh_accepted":
            accepted.append(e)
        elif e.kind == "sudo_failure":
            sudo[e.user].append(e)

    window = timedelta(minutes=cfg.brute_force_window_min)
    for ip, evs in failed.items():
        peak = _max_in_window(evs, window)
        if peak >= cfg.brute_force_threshold:
            findings.append(_make("SSH-BRUTE", evs, ip=ip, description=(
                f"{len(evs)} échecs d'authentification SSH depuis {ip}, dont jusqu'à {peak} "
                f"en {cfg.brute_force_window_min} min. Comptes visés : {_users(e.user for e in evs)}.")))

    for ip in set(failed) | set(invalid):
        evs = failed.get(ip, []) + invalid.get(ip, [])
        users = {e.user for e in evs if e.user}
        if len(users) >= cfg.spray_distinct_users:
            evs.sort(key=lambda e: (e.timestamp is None, e.timestamp))
            findings.append(_make("SSH-SPRAY", evs, ip=ip, count=len(users), description=(
                f"{ip} a tenté de se connecter avec {len(users)} noms d'utilisateur différents : "
                f"{_users(users)}.")))

    root_logins: dict[str, list[LogEvent]] = defaultdict(list)
    for e in accepted:
        prior = [f for f in failed.get(e.ip, [])
                 if f.timestamp is None or e.timestamp is None or f.timestamp <= e.timestamp]
        if len(prior) >= cfg.compromise_min_failures:
            # La période couvre toute l'attaque ; les preuves montrent la fin, dont la connexion réussie
            findings.append(_make("SSH-COMPROMISE", prior + [e], ip=e.ip,
                                  evidence=prior[-(MAX_EVIDENCE - 1):] + [e], description=(
                f"Connexion réussie au compte « {e.user} » depuis {e.ip} après {len(prior)} échecs "
                f"depuis la même adresse. Un mot de passe a probablement été deviné.")))
        if e.user == "root":
            root_logins[e.ip].append(e)

    for ip, evs in root_logins.items():
        findings.append(_make("SSH-ROOT", evs, ip=ip, description=(
            f"{len(evs)} connexion(s) SSH directe(s) au compte root depuis {ip}.")))

    for user, evs in sudo.items():
        attempts = sum(e.extra.get("attempts", 1) for e in evs)
        findings.append(_make("SUDO-FAIL", evs, count=attempts, description=(
            f"L'utilisateur « {user} » a échoué {attempts} fois à s'authentifier avec sudo.")))
    return findings


def detect_web(events: list[LogEvent], cfg: Config) -> list[Finding]:
    findings: list[Finding] = []
    hits: dict[tuple[str, str], list[LogEvent]] = defaultdict(list)
    success: dict[tuple[str, str], bool] = defaultdict(bool)
    scanners: dict[str, list[LogEvent]] = defaultdict(list)
    tools: dict[str, set[str]] = defaultdict(set)
    not_found: dict[str, list[LogEvent]] = defaultdict(list)

    for e in events:
        if e.kind != "http_request":
            continue
        path, ua, status = _decode(e.extra["path"]), e.extra["user_agent"], e.extra["status"]

        rule = next((rid for rid, pattern in WEB_PATTERNS if pattern.search(path)), None)
        in_path = rule is not None
        if rule is None and UA_INJECTION.search(ua):
            rule = "WEB-RCE"
        if rule:
            hits[(rule, e.ip)].append(e)
            if in_path and 200 <= status < 300:
                success[(rule, e.ip)] = True

        if m := SCANNER_UA.search(ua):
            scanners[e.ip].append(e)
            tools[e.ip].add(m.group(0).lower())
        if status == 404:
            not_found[e.ip].append(e)

    for (rule, ip), evs in hits.items():
        desc = f"{len(evs)} requête(s) suspecte(s) depuis {ip}."
        severity = None
        if rule in ESCALATE_ON_SUCCESS and success[(rule, ip)]:
            severity = "critical"
            desc += (" Au moins une a reçu une réponse 2xx : le serveur a traité la requête, "
                     "vérifier si l'attaque a réussi.")
        findings.append(_make(rule, evs, ip=ip, description=desc, severity=severity))

    for ip, evs in scanners.items():
        findings.append(_make("WEB-SCANNER", evs, ip=ip, description=(
            f"{len(evs)} requête(s) depuis {ip} avec la signature d'un outil d'analyse : "
            f"{', '.join(sorted(tools[ip]))}.")))

    window = timedelta(minutes=cfg.web_404_window_min)
    for ip, evs in not_found.items():
        peak = _max_in_window(evs, window)
        if peak >= cfg.web_404_threshold:
            findings.append(_make("WEB-404-FLOOD", evs, ip=ip, description=(
                f"{len(evs)} erreurs 404 depuis {ip}, dont jusqu'à {peak} en "
                f"{cfg.web_404_window_min} min : énumération probable de fichiers.")))
    return findings


def run_all(events: list[LogEvent], cfg: Config | None = None) -> list[Finding]:
    cfg = cfg or Config()
    findings = detect_ssh(events, cfg) + detect_web(events, cfg)
    return sorted(findings, key=lambda f: (SEVERITIES.index(f.severity), -f.count, f.rule_id))


def summarize(events: list[LogEvent], parse_stats: dict) -> dict:
    kinds = Counter(e.kind for e in events)
    ips = Counter(e.ip for e in events if e.ip)
    times = [e.timestamp for e in events if e.timestamp]
    return {
        **parse_stats,
        "by_kind": dict(kinds),
        "unique_ips": len(ips),
        "top_ips": ips.most_common(10),
        "start": min(times).isoformat() if times else None,
        "end": max(times).isoformat() if times else None,
    }
