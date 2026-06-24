# Project log — TM470 vulnerability reporting tool

## 24 June 2026

Built the NVD lookup stage: a client that queries the NVD API for a given CVE and
extracts its CVSS base score, backed by a JSON file cache so repeated lookups
during development and evaluation do not re-query the service.

Applied the CVSS version policy decided earlier: use the v3.1 base score where one
exists, fall back to v3.0 (the base formula is effectively the same), and exclude
CVEs that carry only a v2 score. The version used is recorded on each result so it
can be stated in the report. Added four offline tests covering the selection logic.

Test run: 7 passing (3 Nmap parser, 4 NVD extract).

Live check: looking up CVE-2021-41773 returned a CVSS v3.1 base score of 9.8
(CRITICAL), and response was cached.

One point from that result: CVE-2021-41773 is a case where matching on
version alone is imperfect. The vulnerability is only exploitable in certain Apache
configurations, and its published score varies between databases, so a host running
that version is not necessarily exploitable. The evaluation's precision and recall
figures should quantify this, and the report should record it as a known limitation
of version-based matching.
