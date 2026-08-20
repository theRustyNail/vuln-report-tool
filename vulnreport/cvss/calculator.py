
from __future__ import annotations


# Metric weights from the CVSS v3.1 specification. Privileges Required is nested
# under the Scope value because its weight changes when Scope is Changed.
WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.00},
    "PR": {"U": {"N": 0.85, "L": 0.62, "H": 0.27},
           "C": {"N": 0.85, "L": 0.68, "H": 0.50}},
}

SEVERITY_BANDS = [(0.0, "None"), (3.9, "Low"), (6.9, "Medium"), (8.9, "High"), (10.0, "Critical")]


def parse_vector(vector):
    """Split a vector string into a metric -> value dict.

    "CVSS:3.1/AV:N/AC:L/..." becomes {"AV": "N", "AC": "L", ...}.
    """
    body = vector.split("/")[1:] if vector.startswith("CVSS:") else vector.split("/")
    return {k: v for k, v in (part.split(":") for part in body)}


def severity(score):
    """Map a base score to its qualitative rating."""
    if score == 0.0:
        return "None"
    for upper, label in SEVERITY_BANDS:
        if score <= upper:
            return label
    return "Critical"


def _roundup(value):
    """Round up to one decimal place per CVSS v3.1 spec (FIRST, 2019, s.7 and Appendix A).

    Uses integer arithmetic after scaling by 100,000 to avoid the
    floating-point artefacts described in Appendix A.
    """
    int_val = round(value * 100000)
    if int_val % 10000 == 0:
        return int_val / 100000.0
    return (int_val // 10000 + 1) / 10.0


def base_score(vector):
    metrics = parse_vector(vector)
    scope = metrics["S"]

    iss = 1.0 - ((1.0 - WEIGHTS["CIA"][metrics["C"]]) *
                 (1.0 - WEIGHTS["CIA"][metrics["I"]]) *
                 (1.0 - WEIGHTS["CIA"][metrics["A"]]))

    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    if impact <= 0:
        return 0.0

    pr_weight = WEIGHTS["PR"][scope][metrics["PR"]]
    exploitability = (
        8.22
        * WEIGHTS["AV"][metrics["AV"]]
        * WEIGHTS["AC"][metrics["AC"]]
        * pr_weight
        * WEIGHTS["UI"][metrics["UI"]]
    )

    if scope == "U":
        return _roundup(min(impact + exploitability, 10.0))
    return _roundup(min(1.08 * (impact + exploitability), 10.0))
