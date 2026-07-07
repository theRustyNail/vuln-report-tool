"""Detection evaluation: score the tool's matching against the answer key.

This stage is deliberately separate from the tool's own reporting. It runs each
lab scan through the existing parse -> match pipeline and compares the matcher's
verdict against data/answer_key.json, which is independent ground truth.

It measures *detection*, not sscoring accuracy: did the tool identify the right
CVE when it committed to a match, correctly decline when it could not, and avoid
flagging the patched negative. The CVSS calculator is not exercised here, so the
evaluation needs no network access.

Outcome per target:
  TP            direct match to the expected CVE on a vulnerable target
  FP            a CVE asserted where none was expected (or the wrong CVE)
  FN            a vulnerable target the tool failed to flag (no_match)
  TN            correctly no CVE asserted on the non-vulnerable target
  tool_decided  product recognised, version not confirmable: reported on its
                own row, excluded from precision and recall by design
  not_run       no scan file present for this target yet

Headline precision and recall are computed over targets where the tool
committed to a direct-match decision. tool_decided and not_run cases are
excluded from those figures and reported separately, so the numbers are not
quietly inflated or deflated by cases the tool did not commit to.

Run:
  python -m vulnreport.evaluate                 # scans in the repo root
  python -m vulnreport.evaluate --scans-dir .   # explicit scan directory
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

from vulnreport import config
from vulnreport.matching.cve_matcher import (
    STATUS_DIRECT,
    STATUS_NONE,
    STATUS_TOOL_DECIDED,
    match_findings,
)
from vulnreport.parsing.nmap import parse_nmap_xml

ANSWER_KEY_FILE = config.DATA_DIR / "answer_key.json"
MANIFEST_FILE = config.DATA_DIR / "eval_manifest.json"


def load_answer_key(path: Path = ANSWER_KEY_FILE) -> list[dict]:
    """Return the list of target entries from the answer key."""
    with path.open(encoding="utf-8") as fh:
        return json.load(fh).get("targets", [])


def load_manifest(path: Path = MANIFEST_FILE) -> dict:
    """Return the answer-key-id -> scan-filename mapping.

    Kept as editable data rather than code so the scan filenames can be
    corrected without touching this module.
    """
    with path.open(encoding="utf-8") as fh:
        return json.load(fh).get("scans", {})


def _relevant_finding(scored, target):
    """Pick the scored finding in a scan that corresponds to this target.

    A scan usually holds one service, but Metasploitable-style hosts hold many.
    The finding is selected by matching the first word of the target's service
    against the finding's product or service string. This only associates a
    finding with a target; the classification below still relies on the
    matcher's own status, not on this filter.
    """
    if not scored:
        return None
    if len(scored) == 1:
        return scored[0]

    token = target["service"].split()[0].lower()
    for sf in scored:
        haystack = f"{sf.finding.product} {sf.finding.service}".lower()
        if token in haystack:
            return sf
    return None


def _decline_note(target, finding):
    """Suggest whether a tool_decided outcome was the right call.

    This is a suggestion for human confirmation, not an oracle. A non-vulnerable
    target should be declined; a vulnerable one is a legitimate decline only when
    Nmap could not return a pinned version.
    """
    version = (finding.version or "").strip()
    unpinned = (not version) or any(c in version for c in " xX-,")

    if not target["vulnerable"]:
        return "appropriate: correctly declined to flag a non-vulnerable version"
    if unpinned:
        return f"appropriate: no pinned version from Nmap ({version or 'empty'})"
    return "review: version looked pinned yet was not matched, possible signature gap"


def classify(target, scored):
    """Return an outcome record for one target given its scored findings."""
    record = {
        "id": target["id"],
        "service": target["service"],
        "expected_cve": target["expected_cve"],
        "vulnerable": target["vulnerable"],
        "tool_status": None,
        "tool_cve": None,
        "outcome": None,
        "note": "",
    }

    sf = _relevant_finding(scored, target)
    if sf is None:
        # Scan parsed but nothing in it corresponds to this target's service.
        record["tool_status"] = STATUS_NONE
        record["outcome"] = "TN" if not target["vulnerable"] else "FN"
        record["note"] = "no matching service found in the scan"
        return record

    record["tool_status"] = sf.status
    record["tool_cve"] = sf.cve_id

    if sf.status == STATUS_DIRECT:
        if not target["vulnerable"]:
            record["outcome"] = "FP"
            record["note"] = "flagged a CVE on the patched negative"
        elif sf.cve_id == target["expected_cve"]:
            record["outcome"] = "TP"
        else:
            record["outcome"] = "wrong_cve"
            record["note"] = f"matched {sf.cve_id}, expected {target['expected_cve']}"
    elif sf.status == STATUS_TOOL_DECIDED:
        if not target["vulnerable"]:
            record["outcome"] = "TN"
            record["note"] = "correctly asserted no CVE on the patched target (by non-match, not patch-recognition)"
        else:
            record["outcome"] = "tool_decided"
            record["note"] = _decline_note(target, sf.finding)
    else:  # STATUS_NONE
        if target["vulnerable"]:
            record["outcome"] = "FN"
            record["note"] = "product not recognised by any signature"
        else:
            record["outcome"] = "TN"
    return record


def evaluate(scans_dir: Path):
    """Run the pipeline for every target and classify each outcome."""
    answer_key = load_answer_key()
    manifest = load_manifest()
    records = []

    for target in answer_key:
        filename = manifest.get(target["id"])
        scan_path = (scans_dir / filename) if filename else None

        if not scan_path or not scan_path.exists():
            records.append(
                {
                    "id": target["id"],
                    "service": target["service"],
                    "expected_cve": target["expected_cve"],
                    "vulnerable": target["vulnerable"],
                    "tool_status": None,
                    "tool_cve": None,
                    "outcome": "not_run",
                    "note": f"no scan file ({filename or 'unmapped'})",
                }
            )
            continue

        scored = match_findings(parse_nmap_xml(scan_path))
        records.append(classify(target, scored))

    return records


def summarise(records):
    """Compute the confusion counts and headline detection metrics."""
    tp = sum(r["outcome"] == "TP" for r in records)
    fp = sum(r["outcome"] in ("FP", "wrong_cve") for r in records)
    fn = sum(r["outcome"] == "FN" for r in records)
    tn = sum(r["outcome"] == "TN" for r in records)

    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "tool_decided": [r for r in records if r["outcome"] == "tool_decided"],
        "not_run": [r for r in records if r["outcome"] == "not_run"],
    }


def _fmt(value):
    return f"{value:.2f}" if isinstance(value, float) else "n/a"


def render_markdown(records, metrics):
    """Render the evaluation as markdown for the report appendix."""
    stamp = datetime.now().strftime("%d-%m-%Y %H:%M")
    lines = [
        "# Detection evaluation",
        f"Generated: {stamp}",
        "",
        "Each target's scan was run through the parse and match pipeline and "
        "compared against the independent answer key.",
        "",
        "| Target | Service | Expected CVE | Vulnerable | Tool status | Tool CVE | Outcome |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in records:
        lines.append(
            f"| {r['id']} | {r['service']} | {r['expected_cve'] or '-'} "
            f"| {'yes' if r['vulnerable'] else 'no'} | {r['tool_status'] or '-'} "
            f"| {r['tool_cve'] or '-'} | {r['outcome']} |"
        )

    lines += [
        "",
        "## Headline detection metrics",
        "",
        "Computed over targets where the tool committed to a direct-match "
        "decision. tool_decided and not-run targets are excluded and listed "
        "separately.",
        "",
        f"- True positives: {metrics['tp']}",
        f"- False positives: {metrics['fp']}",
        f"- False negatives: {metrics['fn']}",
        f"- True negatives: {metrics['tn']}",
        f"- Precision: {_fmt(metrics['precision'])}",
        f"- Recall: {_fmt(metrics['recall'])}",
    ]

    if metrics["tool_decided"]:
        lines += ["", "## Tool-decided cases", "",
                  "| Target | Version reported | Decline judgement |",
                  "| --- | --- | --- |"]
        for r in metrics["tool_decided"]:
            lines.append(f"| {r['id']} | (see scan) | {r['note']} |")

    if metrics["not_run"]:
        lines += ["", "## Not yet run", ""]
        for r in metrics["not_run"]:
            lines.append(f"- {r['id']}: {r['note']}")

    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="vulnreport.evaluate",
        description="Score the matcher against the answer key (detection metric).",
    )
    parser.add_argument(
        "--scans-dir",
        type=Path,
        default=config.PROJECT_ROOT,
        help="directory holding the scan XML files (defaults to the repo root)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=config.REPORTS_DIR / "evaluation.md",
        help="path for the markdown evaluation report",
    )
    args = parser.parse_args(argv)

    records = evaluate(args.scans_dir)
    metrics = summarise(records)
    markdown = render_markdown(records, metrics)

    args.out.write_text(markdown, encoding="utf-8")

    print(f"Evaluated {len(records)} targets from {args.scans_dir}")
    print(
        f"TP={metrics['tp']} FP={metrics['fp']} FN={metrics['fn']} "
        f"TN={metrics['tn']}  precision={_fmt(metrics['precision'])} "
        f"recall={_fmt(metrics['recall'])}"
    )
    if metrics["tool_decided"]:
        print(f"tool_decided: {len(metrics['tool_decided'])} (see report)")
    if metrics["not_run"]:
        print(f"not run: {', '.join(r['id'] for r in metrics['not_run'])}")
    print(f"Report written to {args.out}")


if __name__ == "__main__":
    main()
