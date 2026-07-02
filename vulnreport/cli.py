"""Command-line entry point for the vulnerability reporting tool."""

import argparse
from pathlib import Path

from vulnreport import config
from vulnreport.matching.cve_matcher import match_findings
from vulnreport.parsing.nmap import parse_nmap_xml
from vulnreport.reporting.report import build_markdown, write_report
from vulnreport.scoring.scorer import score_findings


def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="vulnreport",
        description="Parse scanner output, match CVEs and generate a report.",
    )
    parser.add_argument(
        "--scan",
        type=Path,
        default=config.SAMPLE_DIR / "nmap_scan.xml",
        help="path to an Nmap XML file (defaults to the bundled sample)",
    )
    parser.add_argument(
        "--name",
        default="scan",
        help="name used for the output report file",
    )
    return parser


def run(scan_path, name="scan"):
    """Run the full pipeline and return the findings, scored findings and path."""
    findings = parse_nmap_xml(scan_path)
    scored = match_findings(findings)
    scored = score_findings(scored)
    report = build_markdown(scored, target_name=name)
    out_path = write_report(report, target_name=name)
    return findings, scored, out_path


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    if not args.scan.exists():
        raise SystemExit(f"Scan file not found: {args.scan}")

    findings, _scored, out_path = run(args.scan, args.name)
    print(f"Parsed {len(findings)} services from {args.scan}")
    print(f"Report written to {out_path}")


if __name__ == "__main__":
    main()
