"""Nmap XML parser.

Adapted from the v0.1 prototype in the TMA01 exploratory work. Reads an Nmap
XML file and returns a list of Finding objects.
"""

import xml.etree.ElementTree as ET

from vulnreport.models import Finding


def parse_nmap_xml(filepath):
    """Parse an Nmap XML file and return a list of Finding objects."""
    findings = []
    tree = ET.parse(filepath)
    root = tree.getroot()

    for host in root.findall("host"):
        address_element = host.find("address")
        if address_element is None:
            continue
        address = address_element.get("addr")

        for port in host.findall(".//port"):
            service = port.find("service")
            findings.append(
                Finding(
                    host=address,
                    port=port.get("portid"),
                    protocol=port.get("protocol"),
                    service=service.get("name", "unknown") if service is not None else "unknown",
                    product=service.get("product", "") if service is not None else "",
                    version=service.get("version", "") if service is not None else "",
                )
            )
    return findings


if __name__ == "__main__":
    import sys
    from pathlib import Path

    from vulnreport import config

    target = Path(sys.argv[1]) if len(sys.argv) > 1 else config.SAMPLE_DIR / "nmap_scan.xml"
    if not target.exists():
        print(f"Error: file not found: {target}")
        sys.exit(1)

    print(f"Parsing: {target}\n")
    results = parse_nmap_xml(target)
    print(f"Found {len(results)} services:\n")
    for f in results:
        line = f"  {f.host}:{f.port}/{f.protocol} - {f.service} ({f.product} {f.version})"
        print(line.strip())
