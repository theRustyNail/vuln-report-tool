"""Tests for the Markdown report buildr."""

from vulnreport.models import Finding, ScoredFinding
from vulnreport.reporting.report import build_markdown


def _direct():
    return ScoredFinding(
        finding=Finding(host="127.0.0.1", port="8080", protocol="tcp",
                        service="http", product="Apache httpd", version="2.4.50"),
        cve_id="CVE-2021-42013", cvss_base_score=9.8, severity="Critical",
        matched=True, status="direct_match", notes="direct signature match",
    )


def _tool_decided():
    return ScoredFinding(
        finding=Finding(host="127.0.0.1", port="1445", protocol="tcp",
                        service="netbios-ssn", product="Samba smbd", version="3.X - 4.X"),
        matched=False, status="tool_decided",
        notes="known product, version outside the signature's range",
    )


def test_confirmed_and_unconfirmed_are_separated():
    text = build_markdown([_direct(), _tool_decided()], target_name="t")
    assert "## Confirmed vulnerabilities" in text
    assert "## Unconfirmed and unmatched services" in text
    assert "CVE-2021-42013" in text
    assert "No CVE is asserte" in text


def test_notes_appear_in_both_tables():
    text = build_markdown([_direct(), _tool_decided()], target_name="t")
    assert "direct signature match" in text
    assert "known product, version outside the signature's range" in text


def test_summary_counts():
    text = build_markdown([_direct(), _tool_decided()], target_name="t")
    assert "1 confirmed vulnerability (Critical: 1)." in text
    assert "1 service with no CVE asserted" in text


def test_no_confirmed_case():
    text = build_markdown([_tool_decided()], target_name="t")
    assert "No confirmed vulnerabilities." in text
    assert "## Confirmed vulnerabilities" not in text
