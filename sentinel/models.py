"""Structures de données partagées par les analyseurs et les détecteurs."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

SEVERITIES = ["critical", "high", "medium", "low"]
SEVERITY_LABELS = {"critical": "Critique", "high": "Élevée", "medium": "Moyenne", "low": "Faible"}
SEVERITY_ICONS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}


@dataclass
class LogEvent:
    """Une ligne de journal reconnue et normalisée."""

    timestamp: datetime | None
    source: str  # "auth" ou "web"
    kind: str  # ssh_failed, ssh_accepted, ssh_invalid_user, sudo_failure, http_request
    raw: str
    ip: str | None = None
    user: str | None = None
    extra: dict = field(default_factory=dict)


@dataclass
class Finding:
    """Une alerte produite par une règle de détection."""

    rule_id: str
    title: str
    severity: str
    mitre_id: str
    mitre_name: str
    description: str
    recommendation: str
    ip: str | None = None
    count: int = 1
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    evidence: list[str] = field(default_factory=list)

    @property
    def mitre_url(self) -> str:
        return f"https://attack.mitre.org/techniques/{self.mitre_id.replace('.', '/')}/"

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "mitre": {"id": self.mitre_id, "name": self.mitre_name, "url": self.mitre_url},
            "ip": self.ip,
            "count": self.count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "description": self.description,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
        }
