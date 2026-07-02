"""Scoring stage: compute CVSS base scores for matched findings.

For each direct match, the CVE's vector string is fetched from NVD and the
score is computed by the project's own CVSS v3.1 calculator. NVD's published
score is used only as a runtime cross-check: a disagreement is recorded in
the finding's notes, since the calculator should always agree with NVD for
a v3.x vector.
"""
from vulnreport.cvss.calculator import base_score, severity
from vulnreport.nvd.client import get_cvss



def _append_note(sf, text):
    sf.notes = f"{sf.notes} {text}".strip()


def score_findings(scored):
    """Fill in cvss_base_score and severity on each direct-match finding."""
    for sf in scored:
        if sf.status != "direct_match" or not sf.cve_id:
            continue

        result = get_cvss(sf.cve_id)
        if result is None:
            _append_note(sf, f"No usable CVSS v3.x data for {sf.cve_id}.")
            continue

        score = base_score(result.vector)
        sf.cvss_base_score = score
        sf.severity = severity(score)

        if abs(score - result.base_score) > 0.05:
            _append_note(
                sf,
                f"Calculator score {score} disagrees with NVD "
                f"published score {result.base_score} for {sf.cve_id}.",
            )
    return scored