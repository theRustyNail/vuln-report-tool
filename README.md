# Vulnerability reporting tool

A command-line tool that reads network scanner output (Nmap first), matches the
findings to CVE identifiers, retrieves CVSS v3.1 base scores from the NIST
National Vulnerability Database (NVD), and produces a structured vulnerability
report.

This is a TM470 project and is under active development.

## Status

Early. The repository is being built up one stage at a time:

- [ ] Nmap XML parser
- [ ] CVE matching
- [ ] NVD lookup and local cache
- [ ] Report generation (Markdown, then HTML)
- [ ] Evaluation (mean absolute error against NVD baseline scores, and timing)

## Requirements

- Python 3.10 or newer
- The packages listed in `requirements.txt` (added in a later step)

## Setup

To be completed once the package and requirements are added.

## Use and authorisation

Built for academic assessment. Scans are only run against an isolated lab the
author owns and controls. The tool is not for use against any system without
written authorisation.
