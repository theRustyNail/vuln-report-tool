"""Build the vulnerability report from scored findings."""

from datetime import datetime
from pathlib import Path

from vulnreport import config


def build_markdown(scored_findings, target_name="scan"):
    """Return a Markdown report as a string."""
    generated = datetime.now().strftime("%d-%m-%Y %H:%M")
    lines = [
        f"# Vulnerability report: {target_name}",
        "",
        f"Generated: {generated}",
        f"Services found: {len(scored_findings)}",
        "",
        "| Host | Port | Service | Product | Version | CVE | CVSS | Severity |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for s in scored_findings:
        f = s.finding
        score = s.cvss_base_score if s.cvss_base_score is not None else "-"
        lines.append(
            f"| {f.host} | {f.port}/{f.protocol} | {f.service} | {f.product} "
            f"| {f.version} | {s.cve_id or '-'} | {score} | {s.severity or '-'} |"
        )
    return "\n".join(lines) + "\n"


def write_report(text, target_name="scan", suffix="md"):
    """Write report text to the reports directory and return the path."""
    out_path = config.REPORTS_DIR / f"{target_name}.{suffix}"
    Path(out_path).write_text(text, encoding="utf-8")
    return out_path
