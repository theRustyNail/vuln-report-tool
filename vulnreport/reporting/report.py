"""Build the vulnerability report from scored findings.

The report has three parts: a summary, a table of confirmed
vulnerabilities (direct matches only), and a table of services where no
CVE was asserted (tool_decided and no_match), with the matcher's notes
shown so the reader can see why each service was left unconfirmed.
"""

from datetime import datetime

from pathlib import Path

from vulnreport import config

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "None"]


def _severity_counts(confirmed):
    """Count confirmed findings per severity band, highest first."""
    counts = {}
    for s in confirmed:
        label = s.severity or "Unscored"
        counts[label] = counts.get(label, 0) + 1
    ordered = [f"{label}: {counts[label]}" for label in SEVERITY_ORDER if label in counts]
    if "Unscored" in counts:
        ordered.append(f"Unscored: {counts['Unscored']}")
    return ", ".join(ordered)


def build_markdown(scored_findings, target_name="scan"):
    """Return a Markdown report as a string."""
    generated = datetime.now().strftime("%d-%m-%Y %H:%M")

    confirmed = [s for s in scored_findings if s.status == "direct_match"]
    unconfirmed = [s for s in scored_findings if s.status != "direct_match"]

    lines = [
        f"# Vulnerability report: {target_name}",
        "",
        f"Generated: {generated}",
        f"Services found: {len(scored_findings)}",
        "",
        "## Summary",
        "",
    ]

    if confirmed:
        noun = "vulnerability" if len(confirmed) == 1 else "vulnerabilities"
        lines.append(
            f"{len(confirmed)} confirmed {noun} "
            f"({_severity_counts(confirmed)})."
        )
    else:
        lines.append("No confirmed vulnerabilities.")
    if unconfirmed:
        noun = "service" if len(unconfirmed) == 1 else "services"
        lines.append(
            f"{len(unconfirmed)} {noun} with no CVE asserted; see the "
            "final section for the reason in each case."
        )

    if confirmed:
        lines += [
            "",
            "## Confirmed vulnerabilities",
            "",
            "| Host | Port | Service | Product | Version | CVE | CVSS | Severity | Notes |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
        for s in confirmed:
            f = s.finding
            score = s.cvss_base_score if s.cvss_base_score is not None else "-"
            lines.append(
                f"| {f.host} | {f.port}/{f.protocol} | {f.service} | {f.product} "
                f"| {f.version} | {s.cve_id} | {score} | {s.severity or '-'} "
                f"| {s.notes or '-'} |"
            )

    if unconfirmed:
        lines += [
            "",
            "## Unconfirmed and unmatched services",
            "",
            "No CVE is asserted for these services.",
            "",
            "| Host | Port | Service | Product | Version | Status | Notes |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
        for s in unconfirmed:
            f = s.finding
            lines.append(
                f"| {f.host} | {f.port}/{f.protocol} | {f.service} | {f.product} "
                f"| {f.version} | {s.status} | {s.notes or '-'} |"
            )

    return "\n".join(lines) + "\n"


def write_report(text, target_name="scan", suffix="md"):
    """Write report text to the reports directory and return the path."""
    out_path = config.REPORTS_DIR / f"{target_name}.{suffix}"
    Path(out_path).write_text(text, encoding="utf-8")
    return out_path
