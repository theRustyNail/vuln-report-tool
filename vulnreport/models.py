"""Data structures passed between the pipeline stages."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class Finding:
    """A single service detected by the scanner."""

    host: str
    port: str
    protocol: str
    service: str = "unknown"
    product: str = ""
    version: str = ""


@dataclass
class ScoredFinding:
    """A finding after it has been matched to a CVE and CVSS score."""

    finding: Finding
    cve_id: Optional[str] = None
    cvss_base_score: Optional[float] = None
    severity: Optional[str] = None
    matched: bool = False
    notes: str = ""
