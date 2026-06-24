"""Offline tests for CVSS version selection in vulnreport.nvd.client.extract_cvss.

These feed hand-built, NVD-shaped CVE objects to ``extract_cvss`` and check that
the v3.1-first, v3.0-fallback, v2-excluded policy holds. No network access.
"""
from vulnreport.nvd.client import extract_cvss, CvssResult


def _v31_metric():
    return {
        "cvssData": {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "baseScore": 7.5,
            "baseSeverity": "HIGH",
        }
    }


def _v30_metric():
    return {
        "cvssData": {
            "version": "3.0",
            "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "baseScore": 9.8,
            "baseSeverity": "CRITICAL",
        }
    }


def _v2_metric():
    return {
        "cvssData": {
            "version": "2.0",
            "vectorString": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
            "baseScore": 5.0,
        },
        "baseSeverity": "MEDIUM",
    }


def _cve(metrics):
    return {"id": "CVE-0000-0001", "metrics": metrics}


def test_uses_v31_when_present():
    result = extract_cvss(_cve({"cvssMetricV31": [_v31_metric()]}))
    assert isinstance(result, CvssResult)
    assert result.version == "3.1"
    assert result.base_score == 7.5
    assert result.severity == "HIGH"


def test_prefers_v31_over_v30():
    metrics = {
        "cvssMetricV31": [_v31_metric()],
        "cvssMetricV30": [_v30_metric()],
    }
    result = extract_cvss(_cve(metrics))
    assert result.version == "3.1"
    assert result.base_score == 7.5


def test_falls_back_to_v30_when_no_v31():
    result = extract_cvss(_cve({"cvssMetricV30": [_v30_metric()]}))
    assert result.version == "3.0"
    assert result.base_score == 9.8


def test_v2_only_returns_none():
    result = extract_cvss(_cve({"cvssMetricV2": [_v2_metric()]}))
    assert result is None
