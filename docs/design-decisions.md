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
Earlier plan: Willmott and Matsuura (2005) favour MAE because it weights errors
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
per-target table of expected score, tool score and error. The project report
should state the limitation and the redefinition directly rather than leave
the reader to raise it. The Key Terms glossary loses its RMSE entry.

## 2026-07-07 — MAE retired; the evaluation measures detection

**Decision.** Drop MAE entirely. This supersedes the 2 July entry, which kept
a redefined MAE. The primary evaluation metric is now CVE detection, measured
with precision, recall and a confusion matrix. The CVSS calculator stays in
the pipeline, with its unit tests and the runtime cross-check against NVD,
but score error is no longer an evaluation metric.

**Reasoning.**

The earlier plan proposed MAE between the tool's assigned CVSS scores and the NVD
baseline as the primary metric. The 2 July entry found the circular flaw in
that and tried to rescue the metric by redefining it over the whole answer
key. On further review, the flaw goes deeper than the redefinition can fix.

The base score is computed deterministically from the vector string, and the
vector is retrieved from the same NVD source (via the local cache) that
supplies the baseline. So for any correctly matched finding, the two numbers
have to agree. That agreement shows the calculator implements the
specification correctly. It says nothing about whether the tool found the
right vulnerabilities. That rationale would have held for a tool that
estimated severity independently. This prototype doesn't, so the comparison
is settled before it is run. MAE is retired, and precision and recall over
detection take its place.

**Consequences.**

Precision and recall are computed only over targets where the tool commits to
a direct-match decision. tool_decided targets, and targets not yet run, get
their own rows and stay out of the headline figures.

A direct match to the wrong CVE counts as one false positive. It is not also
counted as a false negative, because that would double-count a single error.

On the patched apache-2.4.51 target, the tool declined to assert a
vulnerability. That tool_decided outcome is counted as a true negative, with
a caveat recorded alongside it: the tool reached the right answer by failing
to match a signature. It did not actively recognise the patch.

The project report must present this as a change from the earlier
plan, with the circularity given as the reason, and the 2 July entry's
per-target score table is no longer needed.