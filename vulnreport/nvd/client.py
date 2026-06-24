"""Fetch a CVE from the NVD API and extract its CVSS base score.

Version policy (recorded in the design notes): use the CVSS v3.1 base score when
present, fall back to v3.0, and exclude anything that only carries a v2 score.
The version actually used is kept on the result so the report can state it.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

import requests
from dotenv import load_dotenv

from . import cache

load_dotenv()

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = 30  # seconds


@dataclass
class CvssResult:
    cve_id: str
    base_score: float
    severity: str
    version: str  # "3.1" or "3.0"
    vector: str


def extract_cvss(cve: dict) -> Optional[CvssResult]:
    """Pull the CVSS base score from one CVE object, preferring v3.1 over v3.0.

    ``cve`` is the object found at ``vulnerabilities[i]["cve"]`` in an NVD
    response. Returns None when the CVE carries no v3.x score (e.g. v2 only).
    """
    metrics = cve.get("metrics", {})
    cve_id = cve.get("id", "")

    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key)
        if entries:
            data = entries[0]["cvssData"]
            return CvssResult(
                cve_id=cve_id,
                base_score=data["baseScore"],
                severity=data.get("baseSeverity", ""),
                version=data["version"],
                vector=data["vectorString"],
            )
    return None


def get_cvss(cve_id: str) -> Optional[CvssResult]:
    """Look up a CVE by ID and return its CVSS base score.

    Reads the local cache first; on a miss, queries the NVD API and caches the
    raw response. An NVD API key is sent if ``NVD_API_KEY`` is set in the
    environment, which raises the rate limit but is not required for small runs.
    Returns None if the CVE is unknown or has no usable v3.x score.
    """
    data = cache.load(cve_id)
    if data is None:
        headers = {}
        api_key = os.getenv("NVD_API_KEY")
        if api_key:
            headers["apiKey"] = api_key
        response = requests.get(
            NVD_ENDPOINT,
            params={"cveId": cve_id},
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()
        cache.save(cve_id, data)

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return None
    return extract_cvss(vulnerabilities[0]["cve"])
