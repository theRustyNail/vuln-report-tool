# Vulnerability reporting tool

A command-line tool that reads network scanner output (Nmap), matches the
findings to CVE (Common Vulnerabilities and Exposures) identifiers, retrieves
the corresponding CVSS (Common Vulnerability Scoring System) v3.1 vectors from
the NIST National Vulnerability Database (NVD), computes the base scores with
its own CVSS calculator, and produces a structured Markdown vulnerability
report.

It began as my BSc Cyber Security final-year project and is grounded in NIST
SP 800-115, the PTES, and the CVSS v3.1 specification. Built with AI
assistance; the design, evaluation and validation are my own.

## How it works

The pipeline runs in five stages, each an independent package under
`vulnreport/`:

1. **Parse.** Read an Nmap `-sV` XML scan into structured host and service records.
2. **Match.** Compare each service against a curated signature file. Every
   finding lands in one of three states: `direct_match` (product and version
   fall inside a known-vulnerable range, CVE asserted), `tool_decided`
   (product recognised but version outside the rule, no CVE asserted), or
   `no_match`. Version comparison fails closed: anything unparseable is never
   silently treated as a match.
3. **Look up.** Fetch each asserted CVE's CVSS vector from the NVD API, with a
   local JSON cache so evaluation runs offline and does not hammer the service.
4. **Score.** Compute the CVSS v3.1 base score from the vector with the
   project's own calculator, following the integer-arithmetic rounding method
   in Appendix A of the specification. NVD's published score is kept as a
   runtime cross-check; any divergence beyond 0.05 is flagged in the finding.
5. **Report.** Emit a severity-ordered Markdown report per host.

## Evaluation

The tool was evaluated against an answer key of CVE-pinned targets stood up in
a Vulhub and Metasploitable 2 lab (Apache path-traversal, OpenSSH user
enumeration, Samba, vsftpd backdoor, plus a patched-version negative control).
Detection was measured with precision and recall over the targets the tool
commits to, with declined and not-run targets reported separately rather than
forced into the counts. The evaluation harness, answer key and per-target
results are in `data/` and `reports/evaluation.md`.

A worked example of a real defect and its fix: an early version-range check
matched too loosely and produced a false positive, corrected by making version
comparison fail closed. The reasoning is recorded in `docs/design-decisions.md`
and `docs/project-log.md`.

## Requirements

- Python 3.10 or newer
- The packages listed in `requirements.txt`

## Setup

    git clone https://github.com/theRustyNail/vun-report-tool.git
    cd vun-report-tool
    python -m venv .venv
    .venv\Scripts\activate
    pip install -r requirements.txt

Optional: copy `.env.example` to `.env` and add an NVD API key for a higher
rate limit. The tool works without one.

## Use

    python -m vulnreport

Runs the pipeline against the bundled sample scan and writes a Markdown report
to `reports/`. Use `--scan <path>` to point it at another Nmap XML file and
`--name <name>` to set the report filename.

## Authorisation

Scans are only ever run against an isolated lab the author owns and controls.
This tool must not be used against any system without written authorisation.

## Licence

MIT. See `LICENSE`.
