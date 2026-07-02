"""Match scanner findings to CVE identifiers.

This stage decides which CVE, if any, corresponds to a detected service and
version. It is a stub for now so the pipeline runs end to end. The real logic
replaces the body: a curated signature file for the lab targets, with a
best-effort NVD lookup for anything not in the file.
"""

from vulnreport.models import ScoredFinding


def match_findings(findings):
    """Wrap each Finding as a ScoredFinding.

    Nothing is matched yet, so the report lists the parsed services with empty
    CVE and score columns.
    """
    return [
        ScoredFinding(finding=f, matched=False, notes="matching not yet implemented")
        for f in findings
    ]
