# Vulnerability reporting tool

A command-line tool that reads network scanner output (Nmap first), matches
the findings to CVE (Common Vulnerabilities and Exposures) identifiers,
retrieves the corresponding CVSS (Common Vulnerability Scoring System) v3.1
vectors from the NIST National Vulnerability Database (NVD), computes the
base scores with its own CVSS calculator, and produces a structured
vulnerability report.

This is a TM470 project and is under active development.

## Status

Pipeline complete end to end; evaluation module and lab work in progress.

- [x] Nmap XML parser
- [x] CVE matching (curated signatures, three-tier status)
- [x] NVD lookup and local cache
- [x] CVSS v3.1 base score calculator
- [x] Report generation (Markdown)
- [ ] Evaluation (MAE over the lab answer key, and report production time)

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

Runs the pipeline against the bundled sample scan and writes a Markdown
report to `reports/`. Use `--scan <path>` to point it at another Nmap XML
file and `--name <name>` to set the report filename.

## Use and authorisation

Built for academic assessment. Scans are only run against an isolated lab the
author owns and controls. The tool is not for use against any system without
written authorisation.
