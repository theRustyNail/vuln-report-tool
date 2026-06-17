# Design decisions

A running record of the main design choices and the reasoning behind them.

## 2026-06-17 — Matching and scoring approach

**Decision.** Match scanner findings to CVEs using a curated signature file for
the lab targets, with a best-effort NVD lookup for anything not in the file.
Compute the CVSS v3.1 base score from the vector string rather than reading
NVD's published score directly.

**Reasoning.**

The lab is built and owned, so a curated map of service and version to known
CVEs gives reliable matches. This keeps the evaluation meaningful instead of
making it depend on fragile general-purpose matching of messy scanner output
(for example, Nmap's `ppp?` result for the Juice Shop service).

A general CPE-to-CVE lookup was considered and set aside for the prototype.
Nmap product names do not map cleanly onto CPE names, version formats vary, and
services Nmap cannot fingerprint give nothing to look up. The resulting accuracy
would be poor and would weaken the evaluation. It remains a possible extension
and is recorded here as the rejected alternative.

Computing the base score from the CVSS v3.1 vector, following the FIRST
specification, gives the tool a value of its own to compare against the NVD
published score. If the tool simply copied NVD's score, the mean absolute error
would be zero by definition and would measure nothing.

**Consequences.**

Findings are handled in three tiers: a direct match from the signature file, a
lower-confidence best-effort match, and no usable match. The tool records which
tier each finding used and does not guess silently.

Lab targets and their CVEs must be chosen so each CVE carries a CVSS v3.1 vector
in NVD. Some older entries, including parts of Metasploitable 2, hold only v2
scores and are unsuitable as v3.1 references.

Evaluation uses mean absolute error and RMSE for the computed scores (a
regression task), and precision, recall and a confusion matrix for the matching
(a classification task). ROC was considered and set aside as less suitable for
the scoring task.
