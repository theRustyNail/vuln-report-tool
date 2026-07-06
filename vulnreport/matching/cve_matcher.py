"""Match scanner findings to CVE identifiers.

Two parts make up this stage:

  * data/signatures.json   curated product/version -> CVE mappings (the data)
  * this module            the logic that applies them (the algorithm)

Each finding is assigned one of three statuses:

  STATUS_DIRECT        product and version matched a signature
  STATUS_TOOL_DECIDED  product is known, but the version is outside the rule
  STATUS_NONE          product is not in any signature

This stage sets cve_id, matched and status only. The CVSS score is filled in by
the scoring stage (the CVSS calculator), so it is left as None here.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from vulnreport.models import Finding, ScoredFinding

# Status values recorded on each ScoredFinding.status
STATUS_DIRECT = "direct_match"
STATUS_TOOL_DECIDED = "tool_decided"
STATUS_NONE = "no_match"

# data/signatures.json sits at the repo root, two levels up from this package.
_REPO_ROOT = Path(__file__).resolve().parents[2]
SIGNATURE_FILE = _REPO_ROOT / "data" / "signatures.json"


def load_signatures(path: Path = SIGNATURE_FILE) -> list[dict]:
    """Load the curated signature list from the JSON file.

    Each signature is a dict with a "product", a "cve", and a version spec that
    is either an exact "version" or a "version_min" / "version_max" range.
    """
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("signatures", [])


def _parse_version(text):
    """Turn a version string into a tuple of ints for comparison.

    Parses the leading numeric part of each dot-separated segment and stops at
    the first segment with no leading digits (so '4.7p1' becomes (4, 7)).
    Returns None for an empty or unparseable version.
    """
    if not text or not isinstance(text, str):
        return None

    if any(ch in text for ch in " -Xx"):
        return None

    parts = []
    for part in text.split('.'):
        match = re.match(r'^(\d+)', part)
        if match:
            parts.append(int(match.group(1)))
        else:
            break

    return tuple(parts) if parts else None


def version_matches(finding_version, signature):
    """Decide whether a finding's version satisfies a signature's version spec.

    Handles an exact "version", or a "version_max" / "version_min" bound.
    Versions are compared numerically (as tuples), padded so that 7.7 and 7.7.0
    compare equal, and a version that will not parse fails closed (False).
    """
    parsed_finding = _parse_version(finding_version)
    if not parsed_finding:
        return False

    if "version" in signature:
        parsed_sig = _parse_version(signature["version"])
        if not parsed_sig:
            return False

        length = max(len(parsed_finding), len(parsed_sig))
        pf = parsed_finding + (0,) * (length - len(parsed_finding))
        ps = parsed_sig + (0,) * (length - len(parsed_sig))
        return pf == ps

    matched_bound = False

    if "version_max" in signature:
        parsed_max = _parse_version(signature["version_max"])
        if not parsed_max:
            return False

        length = max(len(parsed_finding), len(parsed_max))
        pf = parsed_finding + (0,) * (length - len(parsed_finding))
        pmax = parsed_max + (0,) * (length - len(parsed_max))

        if pf > pmax:
            return False
        matched_bound = True

    if "version_min" in signature:
        parsed_min = _parse_version(signature["version_min"])
        if not parsed_min:
            return False

        length = max(len(parsed_finding), len(parsed_min))
        pf = parsed_finding + (0,) * (length - len(parsed_finding))
        pmin = parsed_min + (0,) * (length - len(parsed_min))

        if pf < pmin:
            return False
        matched_bound = True

    return matched_bound


def match_one(finding: Finding, signatures: list[dict]) -> ScoredFinding:
    """Match a single finding and assign one of the three statuses.

    Tier 1 (direct): product and version both match a signature.
    Tier 2 (tool-decided): the product matches a signature but the version does
        not, so the software is recognised but this version cannot be confirmed.
    Tier 3 (no match): the product is not in any signature.
    """
    product_seen = False

    for signature in signatures:
        if finding.product == signature.get("product"):
            product_seen = True
            if version_matches(finding.version, signature):
                return ScoredFinding(
                    finding=finding,
                    cve_id=signature["cve"],
                    matched=True,
                    status=STATUS_DIRECT,
                    notes="direct signature match",
                )

    if product_seen:
        return ScoredFinding(
            finding=finding,
            matched=False,
            status=STATUS_TOOL_DECIDED,
            notes="known product, version outside the signature's range",
        )

    return ScoredFinding(
        finding=finding,
        matched=False,
        status=STATUS_NONE,
        notes="no signature for this product",
    )


def match_findings(findings):
    """Match every finding. Entry point called by the pipeline (unchanged)."""
    signatures = load_signatures()
    return [match_one(f, signatures) for f in findings]
