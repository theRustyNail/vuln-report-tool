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

Second Vulhub target done, OpenSSH 7.7 (CVE-2018-15473), though it took a few false starts.
With the container listening on 20022, Nmap -sV read the banner as "OpenSSH 7.7 (protocol 2.0)" and the tool matched CVE-2018-15473 at 5.3 Medium, agreeing with the answer key. Nmap reported the version as plain 7.7 rather than 7.7p1, so the portable-suffix handling in _parse_version wasn't used on this target, it's still needed for others but this didn't test it. Two of seven done (Apache 2.4.49 and OpenSSH).
### 6 july
Chased down a proper vsftpd 2.3.4 target and decided against getting it tonight. The Docker route was a dead end - it's not in Vulhub, the image I first tried (hmlio/vaas-cve-2011-2523) doesn't exist, and docker search only turned up general-purpose vsftpd images built on CentOS 7 or Debian, which ship 3.0.x, not 2.3.4. The metasploitable images on Docker Hub are all unofficial rebuilds from unknown publishers, so I'm not pulling one onto the lab machine just for a version banner. The clean source is the official Metasploitable 2 VM from Rapid7, which ships the real 2.3.4 and answers 220 (vsFTPd 2.3.4), and that's a download-and-VM job rather than a quick container.

Decided not to do that for TMA03. The detection set already stands at three direct matches (Apache 2.4.49, Apache 2.4.50, OpenSSH 7.7), one correct negative (Apache 2.4.51), and one tool_decided (Samba, version reported by Nmap as a range so the tool rightly declined to assert a CVE). vsftpd would add a fourth true positive but no detection case the existing three don't already cover, so it's an enhancement rather than a gap. Carrying it to the EMA as a planned addition: stand up the Rapid7 Metasploitable 2 VM, scan port 21, confirm Nmap reads 2.3.4, and add it as the exact-version-pinned CRITICAL. Open questions to resolve then are the VM networking (host-only or bridged, scan the VM's own IP not localhost) and whether to score only vsftpd or widen the answer key to the other services Metasploitable exposes.


Ran Apache 2.4.50 next and it was clean. Nmap read "Apache httpd 2.4.50" on 8080, the tool matched CVE-2021-42013 at 9.8, which is what the answer key expects. Third direct match, with 2.4.49 and OpenSSH.

Samba was a fight. The container wouldn't start because port 445 was already taken. Windows holds 445 itself for file sharing (the System process, PID 4), so it wasn't something I could just kill. Remapped the published port to 1445. First tried a compose override file, but that appended a second port mapping instead of replacing the original, so it still tried to bind 445 and collided. Editing the compose file directly worked, though I had a docker run container going by then as well, so there were two Sambas up and I had to be careful which one I scanned. Once it was listening on 1445, Nmap reported the version as "3.X - 4.X" rather than a pinned number, and the tool returned no CVE. Samba over SMB doesn't hand Nmap a clean version, which is worth knowing for the write-up.

Pulled httpd:2.4.51 for the patched negative and confirmed the container starts and binds 8081. Haven't scanned it yet, that's the next job.

Built the evaluation script (vulnreport/evaluate.py). It runs each scan through the existing parse and match pipeline and scores the result against the answer key, which stays separate so the tool isn't marking its own work. It's a detection metric, not a scoring one, so it needs no NVD calls and runs offline. Precision and recall are counted only over targets where the tool committed to a direct match; tool_decided and not-yet-run targets get their own rows instead of being forced into either bin, which is the handling I settled on. Snapshot as it stands: three true positives (2.4.49, 2.4.50, OpenSSH), one false negative (Samba), with the negative, vsftpd and nginx still outstanding. Precision 1.00, recall 0.75.

The Samba false negative is worth recording properly, because it points at a real bug rather than a gap. The tool missed it because Nmap writes the product as "Samba smbd" while my signature says "Samba", and the matcher compares the product string exactly, so it never reached the version check. Two fixes stack underneath: correct the product string, and even then the "3.X - 4.X" version can't be confirmed against the vulnerable range, so Samba would land as tool_decided rather than a match. Still to decide whether to fix the signature and rerun or report the false negative as it stands and explain it.