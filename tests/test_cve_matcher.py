"""Tests for the CVE matcher: version comparison and the matching tiers."""
import pytest

from vulnreport.models import Finding
from vulnreport.matching.cve_matcher import (
    version_matches,
    match_one,
    STATUS_DIRECT,
    STATUS_NONE,
)

# (finding_version, signature, expected) for version_matches.
VERSION_CASES = [
    ("2.4.49", {"version": "2.4.49"}, True),
    ("2.4.51", {"version": "2.4.49"}, False),
    ("4.7p1", {"version_max": "7.7"}, True),
    ("7.7", {"version_max": "7.7"}, True),
    ("7.8", {"version_max": "7.7"}, False),
    ("8.2p1", {"version_max": "7.7"}, False),
    ("", {"version_max": "7.7"}, False),
    ("2.4.49", {"version": "TBC"}, False),
    ("7.7", {"version": "7.7.0"}, True),
    ("7.0", {"version_min": "6.0", "version_max": "7.7"}, True),
]


@pytest.mark.parametrize("finding_version,signature,expected", VERSION_CASES)
def test_version_matches(finding_version, signature, expected):
    assert version_matches(finding_version, signature) == expected


# A small, controlled signature set so the tier tests do not depend on the
# real data/signatures.json.
SIGNATURES = [
    {"product": "Apache httpd", "version": "2.4.49", "cve": "CVE-2021-41773"},
    {"product": "OpenSSH", "version_max": "7.7", "cve": "CVE-2018-15473"},
]


def _finding(product, version):
    return Finding("10.0.0.1", "0", "tcp", "svc", product=product, version=version)


def test_direct_match_sets_cve_and_status():
    sf = match_one(_finding("Apache httpd", "2.4.49"), SIGNATURES)
    assert sf.matched is True
    assert sf.cve_id == "CVE-2021-41773"
    assert sf.status == STATUS_DIRECT


def test_range_match_via_version_max():
    sf = match_one(_finding("OpenSSH", "4.7p1"), SIGNATURES)
    assert sf.matched is True
    assert sf.cve_id == "CVE-2018-15473"
    assert sf.status == STATUS_DIRECT


def test_patched_version_does_not_match():
    sf = match_one(_finding("Apache httpd", "2.4.51"), SIGNATURES)
    assert sf.matched is False
    assert sf.cve_id is None
    assert sf.status == STATUS_NONE


def test_unknown_product_does_not_match():
    sf = match_one(_finding("MySQL", "5.0.51a"), SIGNATURES)
    assert sf.matched is False
    assert sf.status == STATUS_NONE
