"""Data models for scan results."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ScanResult:
    """A single finding returned by a scanner module."""

    category: str
    severity: str  # Critical | High | Medium | Low | Info | Pass
    title: str
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class ScanSummary:
    """Aggregated results of a scan run."""

    target: str
    timestamp: str = ""
    duration: float = 0.0
    results: List[ScanResult] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def counts(self) -> Dict[str, int]:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0, "Pass": 0}
        for r in self.results:
            counts[r.severity] = counts.get(r.severity, 0) + 1
        return counts

    def severity_grouped(self) -> Dict[str, List[ScanResult]]:
        grouped = {}
        for r in self.results:
            grouped.setdefault(r.severity, []).append(r)
        return grouped

    def score(self) -> int:
        """0 (low risk) .. 100 (high risk) rough risk score."""
        weights = {"Critical": 40, "High": 25, "Medium": 12, "Low": 5, "Info": 1}
        total = sum(weights.get(r.severity, 0) for r in self.results)
        return min(100, total)


@dataclass
class CheckStatus:
    """Progress callback payload for a single check."""

    name: str
    status: str  # running | complete | error
    message: str = ""