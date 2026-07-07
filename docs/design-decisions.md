# Design decisions

A running record of the main design choices and the reasoning behind them.

## 2026-06-17 — Matching and scoring approach

**Decision.** Match scanner findings to CVEs using a curated signature file
for the lab targets, with a best-effort NVD lookup for anything not in the
file. Compute the CVSS v3.1 base score from the vector string, instead of
reading NVD's published score directly.

**Reasoning.**

The lab is built and owned, so a curated map of service and version to known
CVEs gives reliable matches. General-purpose matching of messy scanner output
is fragile (Nmap returns `ppp?` for the Juice Shop service, for example), and
the evaluation shouldn't have to depend on it.

A general CPE-to-CVE lookup was considered and set aside for the prototype.
Nmap product names don't map cleanly onto CPE names. Version formats vary.
Services Nmap can't fingerprint give nothing to look up at all. The accuracy
would be poor, and that would weaken the evaluation. It stays on the list as
a possible extension, and this entry records it as the rejected alternative.

Computing the base score from the CVSS v3.1 vector, following the FIRST
specification, gives the tool a value of its own to compare against the NVD
published score. If the tool simply copied NVD's score, the mean absolute
error would be zero by definition and would measure nothing.

**Consequences.**

Findings are handled in three tiers: a direct match from the signature file,
a lower-confidence best-effort match, and no usable match. The tool records
which tier each finding used. It does not guess silently.

Lab targets and their CVEs must be chosen so each CVE carries a CVSS v3.1
vector in NVD. Some older entries, including parts of Metasploitable 2, hold
only v2 scores, so they can't be used as v3.1 references.

Evaluation uses mean absolute error and RMSE for the computed scores (a
regression task), and precision, recall and a confusion matrix for the
matching (a classification task). ROC was considered and set aside as less
suitable for the scoring task.

## 2026-07-02 — Refinement: what MAE actually measures, and dropping RMSE

**Decision.** Keep MAE in the evaluation, but redefine it as an end-to-end
measure over the whole answer key, not just the matched findings. Any target
the tool fails to report contributes its full expected score as error, as if
the tool had said 0. State openly in the report that agreement on correctly
matched findings is expected by construction. RMSE, listed alongside MAE on
17 June, is dropped.

**Reasoning.**

The 17 June entry argued that computing the score from the vector stops the
MAE being zero by definition. On review, that argument doesn't hold up. The
vector the calculator uses also comes from NVD, and a CVSS vector fully
determines its score. So for any correctly matched finding, the computed
score has to equal the published one. That agreement only shows the
arithmetic is deterministic. An MAE taken over matched findings alone would
be near zero by construction, and it would mostly repeat what the
calculator's unit tests and the runtime cross-check already establish.

Defined over the whole answer key, the metric does say something the matching
metrics can't. Precision and recall treat every miss as equal: failing to
report the OpenSSH finding (5.3) counts the same as failing to report the
vsftpd backdoor (9.8). Operationally those two failures are very different.
With unreported targets contributing their expected score as error, MAE
weights each failure by its severity. That is closer to what a user of the
report actually cares about. It also fits the justification already cited in
TMA02: Willmott and Matsuura (2005) favour MAE because it weights errors
linearly, without letting large ones dominate, and that is the behaviour
wanted here.

RMSE is dropped. With seven answer-key targets, the per-target error table in
the results will already show whether errors are concentrated or spread out,
and that is the one thing RMSE would add over MAE. Reporting both gains
nothing.

**Consequences.**

The evaluation module must compute MAE over all answer-key targets, using the
unmatched-scores-as-zero convention. The patched negative is excluded from
the score error, since it belongs to precision and recall. The results need a
per-target table of expected score, tool score and error. The TMA03 and EMA
write-ups should state the limitation and the redefinition directly, so the
marker isn't left to raise it. The Key Terms glossary carried over from TMA02
loses its RMSE entry.