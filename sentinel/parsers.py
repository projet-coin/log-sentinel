"""Lecture des journaux : syslog/auth.log (sshd, sudo) et journaux d'accès Apache/Nginx."""
from __future__ import annotations

import re
from datetime import datetime, timedelta

from .models import LogEvent

MAX_LINES = 50_000
_IP = r"(?P<ip>[0-9a-fA-F:.]+)"
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

# En-têtes syslog : format classique (Oct 24 10:15:02) et format ISO (Ubuntu 24+, rsyslog)
SYSLOG_CLASSIC = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s\[:]+)(?:\[\d+\])?:\s*(?P<msg>.*)$")
SYSLOG_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s\[:]+)(?:\[\d+\])?:\s*(?P<msg>.*)$")

# Messages sshd et sudo
SSH_FAILED = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive/pam|none) for "
    r"(?P<inv>invalid user )?(?P<user>\S+) from " + _IP)
SSH_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from " + _IP)
SSH_INVALID = re.compile(r"^Invalid user (?P<user>\S*) from " + _IP)
SUDO_FAILED = re.compile(r"^\s*(?P<user>\S+) : (?P<n>\d+) incorrect password attempts?")

# Journal d'accès web (format « combined » d'Apache et Nginx)
ACCESS = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]{3,10}) (?P<path>\S+)(?: [^"]*)?" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')
ACCESS_TS = re.compile(r"(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2})")


def _classic_ts(mon: str, day: str, clock: str, year: int, now: datetime) -> datetime | None:
    """Le syslog classique n'indique pas l'année : on suppose l'année courante, ou la précédente
    si la date tombe dans le futur (journaux de décembre lus en janvier)."""
    try:
        h, m, s = map(int, clock.split(":"))
        ts = datetime(year, MONTHS[mon], int(day), h, m, s)
        if ts > now + timedelta(days=1):
            ts = ts.replace(year=year - 1)
        return ts
    except (KeyError, ValueError):
        return None


def _iso_ts(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def _access_ts(value: str) -> datetime | None:
    m = ACCESS_TS.match(value)
    if not m:
        return None
    day, mon, year, h, mi, s = m.groups()
    try:
        return datetime(int(year), MONTHS[mon], int(day), int(h), int(mi), int(s))
    except (KeyError, ValueError):
        return None


def _parse_auth(ts: datetime | None, proc: str, msg: str, raw: str) -> LogEvent | None:
    if proc.startswith("sshd"):
        if m := SSH_FAILED.search(msg):
            return LogEvent(ts, "auth", "ssh_failed", raw, m["ip"], m["user"],
                            {"invalid_user": bool(m["inv"])})
        if m := SSH_ACCEPTED.search(msg):
            return LogEvent(ts, "auth", "ssh_accepted", raw, m["ip"], m["user"])
        if m := SSH_INVALID.search(msg):
            return LogEvent(ts, "auth", "ssh_invalid_user", raw, m["ip"], m["user"])
    elif proc == "sudo":
        if m := SUDO_FAILED.search(msg):
            return LogEvent(ts, "auth", "sudo_failure", raw, None, m["user"],
                            {"attempts": int(m["n"])})
    return None


def parse_line(line: str, year: int, now: datetime) -> LogEvent | None:
    line = line.rstrip("\r\n")
    if not line.strip():
        return None
    if m := ACCESS.match(line):
        return LogEvent(
            _access_ts(m["ts"]), "web", "http_request", line, m["ip"], None,
            {"method": m["method"], "path": m["path"], "status": int(m["status"]),
             "user_agent": m["ua"] or ""})
    if m := SYSLOG_CLASSIC.match(line):
        ts = _classic_ts(m["mon"], m["day"], m["time"], year, now)
        return _parse_auth(ts, m["proc"], m["msg"], line)
    if m := SYSLOG_ISO.match(line):
        return _parse_auth(_iso_ts(m["ts"]), m["proc"], m["msg"], line)
    return None


def parse_text(text: str, year: int | None = None) -> tuple[list[LogEvent], dict]:
    """Analyse un bloc de texte. Retourne les événements reconnus et des statistiques de lecture."""
    now = datetime.now()
    year = year or now.year
    lines = text.splitlines()
    truncated = len(lines) > MAX_LINES
    lines = lines[:MAX_LINES]
    events = [e for e in (parse_line(line, year, now) for line in lines) if e is not None]
    return events, {"lines": len(lines), "recognized": len(events), "truncated": truncated}
