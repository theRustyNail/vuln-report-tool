# Project log — TM470 vulnerability reporting tool
## 17 June 2026
Started the build with the repo foundation, the vulnreport package scaffolding,
and the Nmap parser with a sample scan and its first tests. Also recorded the
first design decision: hybrid matching (a curated signature file for the
lab-relevant services, not a general CPE-to-CVE lookup) and CVSS scoring
computed by the project's own calculator rather than read from a file.
The general CPE-to-CVE route was considered and rejected for the prototype.
Nmap's service names do not map cleanly to CPE identifiers, and version strings
vary in form, so building a reliable general lookup would have been a project
in itself and would not have shown the technical decision-making the module
rewards. The curated signature file gives a reliable core for the lab targets
and keeps the general lookup as a documented possible extension.

## 18 June 2026
Wired up the end-to-end pipeline: CLI entry point, report builder, matcher stub.
Nothing matches yet, but python -m vulnreport runs from parse to written
report, which meant every later stage had somewhere to plug in rather than
being built in isolation.

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
## 30 June 2026
Built the answer key for evaluation. Six CVE-pinned targets across CVSS bands
5.3, 7.7 and 9.8, plus one patched-version negative to test that the tool does
not flag what it should not.
One target was dropped during this: ProFTPD 1.3.5 (CVE-2015-3306). It looked
like a good fit — a real, well-known vulnerability on a service Nmap reads
cleanly — but NVD holds no v3.x score for it, only v2. The CVSS version policy
set earlier excludes v2, so keeping ProFTPD would have meant either changing
the policy for one target or scoring it inconsistently with the others. Dropped
it and moved on. This is the first realised consequence of the version policy:
some otherwise-good targets are unusable, and the answer key has to be built
around what NVD scores under v3.x rather than around what would make a
tidy demonstration.
Implemented version_matches with range support and built the matcher out to
its three-tier status.
The initial plan was a straightforward match / no-match: either the product
and version fit a signature, or they did not. Working through the sample scan
made it clear this hid something the tool actually knew. When Nmap reads
Apache 2.2.8 and the signature covers only 2.4.49, the tool has recognised
the product but cannot assert a CVE against it. Reporting that as no_match
throws away real information; reporting it as a match would be wrong.
Added a middle tier, tool_decided, for exactly this case: product recognised,
version outside the rule, no CVE asserted. Direct match, tool-decided, and
no-match now cover the three states the tool can genuinely be in. Version
comparison uses numeric tuples with zero-padding and inclusive version_max,
and fails closed on anything it cannot parse, so an unparseable version does
not silently direct-match.
Also relevant to the risk register: OpenVAS integration, listed as a planned
scanner in the TMA01 proposal, has been deferred. The fallback to Nmap-only
was written into the TMA01 risk register as the contingency for exactly this,
and it has now been invoked. The normalisation layer is kept in place so a
second scanner could be added later; attempting OpenVAS at this stage would
put the core deliverable at risk for a scoping addition. Recorded as a realised
risk rather than a change of plan.


## 2 July 2026

Implemented _roundup for the CVSS calculator. First draft used
math.floor(int_val / 10000) which works but does the division in
floating point before flooring. Switched to integer floor division
(int_val // 10000) to keep the rounding step in integer arithmetic,
matching appendix A of the CVSS v3.1 specification
(FIRST, 2019). Dropped the math import as a result. Tests still to
run once base_score is in.

Added the scoring stage into the pipeline. For each direct-match finding the
CVE's vector string is fetched from NVD and scored by the project's own CVSS
calculator, rather than reading NVD's published score directly. This keeps the
calculator on the critical path as evidence that the implementation works, with
NVD's score retained as a runtime cross-check: a difference beyond 0.05 is
recorded in the finding's notes. On the sample scan, vsftpd (CVE-2011-2523)
scores 9.8 Critical and OpenSSH (CVE-2018-15473) 5.3 Medium, both agreeing with
NVD. The tool_decided and no_match findings are left unscored by design, since
no CVE is asserted for them.
Not everything went smoothly. The new scoring module failed to import at first
(ModuleNotFoundError) because the file had been created at the top of the
vulnreport package rather than inside its sub-folder. Moving it into
vulnreport/scoring and adding the package __init__.py fixed it.
 While implementing base_score I initially indexed the impact weights as
WEIGHTS["C"], WEIGHTS["I"] and WEIGHTS["A"], which does not exist, the
specification gives Confidentiality, Integrity and Availability the same weight
table, so the scaffold stores them once under a single "CIA" key. fixing the
lookup fixed a KeyError that would otherwise have failed every test.
The Roundup function needed care. A naive implementation using floating-point
division rounds some valid CVSS intermediates the wrong way (the 0.1 + 0.2
problem noted in Appendix A of the specification). I followed the spec's
integer-arithmetic method instead, scaling by 100,000 before rounding, which is
why the calculator agrees with NVD's published scores rather than being just out of range for close cases.

## 3 July 2026
tried the first Vulhub target. Cloned the repo, ran docker compose up
on httpd/CVE-2021-41773, and Apache 2.4.49 came up on port 8080 without
any problems. Nmap -sV read the service as "Apache httpd 2.4.49" correctly.
Fed the XML into the tool and the report came back with CVE-2021-41773
scored 9.8 Critical - the expected result, but produced end to end from
a real container rather than the bundled sample. One target of seven in
the answer key done. The interesting ones (Samba, which Nmap often
version-ranges rather than pinning; and the patched 2.4.51 negative)
are still to run.

