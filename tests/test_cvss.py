"""Tests for the CVSS v3.1 base score calculator (vector -> score)."""
import pytest
from vulnreport.cvss.calculator import base_score, severity

# Vector -> published CVSS v3.1 base score. Covers both scope branches,
# the roundup, and the 0.0 / 10.0 extremes.
SCORE_CASES = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L", 7.7),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
]

@pytest.mark.parametrize("vector,expected", SCORE_CASES)
def test_base_score(vector, expected):
    assert base_score(vector) == expected

SEVERITY_CASES = [(0.0, "None"), (5.3, "Medium"), (6.1, "Medium"), (7.7, "High"), (9.8, "Critical")]

@pytest.mark.parametrize("score,label", SEVERITY_CASES)
def test_severity(score, label):
    assert severity(score) == label
