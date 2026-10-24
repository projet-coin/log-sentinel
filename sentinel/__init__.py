"""Log Sentinel : détection d'attaques dans les journaux SSH et web."""
from __future__ import annotations

from dataclasses import dataclass

from .detectors import Config, run_all, summarize
from .models import Finding
from .parsers import parse_text

__version__ = "0.1.0"
__all__ = ["AnalysisResult", "Config", "analyze_text"]


@dataclass
class AnalysisResult:
    findings: list[Finding]
    stats: dict


def analyze_text(text: str, cfg: Config | None = None) -> AnalysisResult:
    events, parse_stats = parse_text(text)
    return AnalysisResult(run_all(events, cfg), summarize(events, parse_stats))
