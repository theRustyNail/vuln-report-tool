"""Tests for the Nmap XML parser."""

from vulnreport.config import SAMPLE_DIR
from vulnreport.parsing.nmap import parse_nmap_xml

SAMPLE = SAMPLE_DIR / "nmap_scan.xml"


def test_parses_all_sample_services():
    findings = parse_nmap_xml(SAMPLE)
    assert len(findings) == 5


def test_extracts_ftp_service_details():
    findings = parse_nmap_xml(SAMPLE)
    ftp = next(f for f in findings if f.port == "21")
    assert ftp.service == "ftp"
    assert ftp.product == "vsftpd"
    assert ftp.version == "2.3.4"


def test_every_finding_has_host_and_port():
    findings = parse_nmap_xml(SAMPLE)
    for f in findings:
        assert f.host
        assert f.port
