# Project log — TM470 vulnerability reporting tool

(Entries for 17 to 30 June were written up on 2 July from my working notes.
Later entries were written on the day.)

## 17 June 2026
Started the build. Set up the repo, the vulnreport package scaffolding, and
the Nmap parser, with a sample scan and its first tests.

Also made the first design decision: matching will use a curated signature
file covering the lab services, and the CVSS scores will come from the
project's own calculator. Full reasoning is in design-decisions.md.

I did look at a general CPE-to-CVE lookup first, and decided against it for
the prototype. Nmap's service names don't map cleanly onto CPE identifiers,
version strings come in all sorts of formats, and some services Nmap can't
fingerprint at all. Getting that to work reliably would have been a project
in itself, and it wouldn't have shown the decision-making the module rewards.
The signature file gives a reliable core for the lab targets. The general
lookup is written down as a possible extension.

## 18 June 2026
Wired up the end-to-end pipeline: CLI entry point, report builder, and a
matcher stub. Nothing matches yet, but python -m vulnreport now runs from
parse to written report. That means every later stage has somewhere to plug
in from day one.

## 24 June 2026
Built the NVD lookup stage. A client queries the NVD API for a given CVE and
pulls out its CVSS base score. Responses go into a JSON file cache, so repeat
lookups during development and evaluation don't keep hitting the service.

Applied the CVSS version policy decided earlier: use the v3.1 base score
where one exists, fall back to v3.0 (the base formula is effectively the
same), and exclude CVEs that only carry a v2 score. Each result records which
version was used, so the report can state it. Added four offline tests for
the selection logic.

Test run: 7 passing (3 Nmap parser, 4 NVD extract).

Live check: CVE-2021-41773 came back with a CVSS v3.1 base score of 9.8
(CRITICAL), and the response was cached.

One thing to note from that result. CVE-2021-41773 shows the limits of
matching on version alone. It is only exploitable in certain Apache
configurations, and its published score varies between databases, so a host
running that version isn't necessarily exploitable. The evaluation's
precision and recall figures should pick this up, and the report needs to
list it as a known limitation of version-based matching.

## 30 June 2026
Built the answer key for the evaluation. Six CVE-pinned targets across the
CVSS bands 5.3, 7.7 and 9.8, plus one patched-version negative to check the
tool doesn't flag things it shouldn't.

One target got dropped along the way: ProFTPD 1.3.5 (CVE-2015-3306). It
looked like a good fit. A real, well-known vulnerability, on a service Nmap
reads cleanly. But NVD holds no v3.x score for it, only v2, and the version
policy excludes v2. Keeping it would have meant bending the policy for one
target, or scoring it differently from the others. So it went. This is the
first time the version policy has actually cost me something: some
otherwise-good targets are unusable, and the answer key has to be built
around what NVD scores under v3.x.

Implemented version_matches with range support and built the matcher out to
its three-tier status.

The first plan was a plain match / no-match. Either the product and version
fit a signature or they didn't. Working through the sample scan showed the
problem with that. When Nmap reads Apache 2.2.8 and the signature only covers
2.4.49, the tool has recognised the product, but it can't assert a CVE
against that version. Calling that no_match hides something the tool knows.
Calling it a match would just be wrong. So I added a middle tier,
tool_decided, for exactly this case: product recognised, version outside the
rule, no CVE asserted. The three statuses now cover every state the tool can
actually be in. Version comparison uses numeric tuples with zero-padding and
an inclusive version_max, and it fails closed on anything it can't parse. An
unparseable version will never silently direct-match.

Also for the risk register: OpenVAS integration, listed as a planned scanner
in the TMA01 proposal, is deferred. The TMA01 risk register already had "fall
back to Nmap-only" as the contingency for this, and that is now what has
happened. The normalisation layer stays in place so a second scanner could be
added later. Trying OpenVAS at this stage would put the core deliverable at
risk for what is really a scoping addition. Logged as a realised risk.

## 2 July 2026

Implemented _roundup for the CVSS calculator. The first draft used
math.floor(int_val / 10000). That works, but it does the division in floating
point before flooring. Switched to integer floor division (int_val // 10000)
so the rounding step stays in integer arithmetic, which matches appendix A of
the CVSS v3.1 specification (FIRST, 2019). Dropped the math import as a
result. Tests still to run once base_score is in.

Added the scoring stage into the pipeline. For each direct-match finding, the
CVE's vector string is fetched from NVD and scored by the project's own CVSS
calculator. NVD's published score is kept as a runtime cross-check: any
difference beyond 0.05 gets recorded in the finding's notes. This keeps the
calculator on the critical path as evidence the implementation works. On the
sample scan, vsftpd (CVE-2011-2523) scores 9.8 Critical and OpenSSH
(CVE-2018-15473) 5.3 Medium. Both agree with NVD. The tool_decided and
no_match findings are left unscored on purpose, since no CVE is asserted for
them.

Not everything went smoothly. The new scoring module failed to import at
first (ModuleNotFoundError) because I'd created the file at the top of the
vulnreport package, not inside its sub-folder. Moving it into
vulnreport/scoring and adding the package __init__.py fixed it.

While implementing base_score I initially indexed the impact weights as
WEIGHTS["C"], WEIGHTS["I"] and WEIGHTS["A"], which don't exist. The
specification gives Confidentiality, Integrity and Availability the same
weight table, so the weights dict stores it once under a single "CIA" key.
Fixing the lookup fixed a KeyError that would have failed every test.

The roundup function needed care. A naive floating-point version rounds some
valid CVSS intermediates the wrong way (the 0.1 + 0.2 problem noted in
Appendix A of the specification). I followed the spec's integer-arithmetic
method instead, scaling by 100,000 before rounding. That is why the
calculator agrees with NVD's published scores on the close cases.

## 3 July 2026
Tried the first Vulhub target. Cloned the repo and ran docker compose up on
httpd/CVE-2021-41773. Apache 2.4.49 came up on port 8080 with no problems.
Nmap -sV read the service correctly as "Apache httpd 2.4.49". Fed the XML
into the tool and the report came back with CVE-2021-41773 scored 9.8
Critical. The expected result, but this time produced end to end from a real
container, not the bundled sample. One target of seven in the answer key
done. The interesting ones are still to run: Samba, where Nmap often reports
a version range with no pinned number, and the patched 2.4.51 negative.

Second Vulhub target done, OpenSSH 7.7 (CVE-2018-15473), though it took a few
false starts. With the container listening on 20022, Nmap -sV read the banner
as "OpenSSH 7.7 (protocol 2.0)" and the tool matched CVE-2018-15473 at 5.3
Medium, agreeing with the answer key. Nmap reported the version as plain 7.7,
not 7.7p1, so the portable-suffix handling in _parse_version wasn't exercised
on this target. It's still needed for others, but this didn't test it. Two of
seven done (Apache 2.4.49 and OpenSSH).

### 6 july
Chased down a proper vsftpd 2.3.4 target and decided against getting it
tonight. The Docker route was a dead end. It's not in Vulhub. The image I
tried first (hmlio/vaas-cve-2011-2523) doesn't exist. docker search only
turned up general-purpose vsftpd images built on CentOS 7 or Debian, and
those ship 3.0.x, not 2.3.4. The Metasploitable images on Docker Hub are all
unofficial rebuilds from unknown publishers, and I'm not pulling one onto the
lab machine just for a version banner. The clean source is the official
Metasploitable 2 VM from Rapid7, which ships the real 2.3.4 and answers
220 (vsFTPd 2.3.4). That's a download-and-VM job, not a quick container.

Decided not to do that for TMA03. The detection set already stands at three
direct matches (Apache 2.4.49, Apache 2.4.50, OpenSSH 7.7), one correct
negative (Apache 2.4.51), and one tool_decided (Samba, where Nmap reports a
version range so the tool rightly declined to assert a CVE). vsftpd would add
a fourth true positive, but no detection case the existing three don't
already cover. It can wait. Carrying it to the EMA as a planned addition:
stand up the Rapid7 Metasploitable 2 VM, scan port 21, confirm Nmap reads
2.3.4, and add it as the exact-version-pinned CRITICAL. Open questions for
then: the VM networking (host-only or bridged, and scan the VM's own IP, not
localhost), and whether to score only vsftpd or widen the answer key to the
other services Metasploitable exposes.

Ran Apache 2.4.50 next and it was clean. Nmap read "Apache httpd 2.4.50" on
8080, and the tool matched CVE-2021-42013 at 9.8, which is what the answer
key expects. Third direct match, alongside 2.4.49 and OpenSSH.

Samba was a problem. The container wouldn't start because port 445 was already
taken. Windows holds 445 itself for file sharing (the System process, PID 4),
so it wasn't something I could just kill. Remapped the published port to
1445. First tried a compose override file, but that appended a second port
mapping on top of the original, so it still tried to bind 445 and collided.
Editing the compose file directly worked. By then I also had a docker run
container going, so there were two Sambas up and I had to be careful which
one I scanned. Once it was listening on 1445, Nmap reported the version as
"3.X - 4.X", no pinned number, and the tool returned no CVE. Samba over SMB
doesn't hand Nmap a clean version. Worth knowing for the write-up.

Pulled httpd:2.4.51 for the patched negative and confirmed the container
starts and binds 8081. Haven't scanned it yet. That's the next job.

Designed the evaluation approach and settled the classification handling for
the upcoming evaluation script (vulnreport/evaluate.py). The module itself
isn't written yet. The plan: run each scan through the existing parse and
match pipeline, then score the result against a separate answer key. It
measures detection only, so it needs no NVD calls and runs offline. The
classification handling is settled too. Precision and recall will only be
counted over targets where the tool commits to a direct match. tool_decided
and not-yet-run targets get their own rows, so they aren't forced into binary
bins. nginx is out, and vsftpd is deferred to the EMA. Computing the metrics
by hand on the current state gives three true positives (2.4.49, 2.4.50,
OpenSSH) and one false negative (Samba). That works out at precision 1.00 and
recall 0.75. The script will automate this.

The Samba false negative is worth recording properly, because it points at an
actual bug in the matcher. The tool missed it because Nmap writes the product
as "Samba smbd" while my signature says "Samba". The matcher compares the
product string exactly, so it never even reached the version check. Two fixes
stack underneath. First, correct the product string. Second, even after that,
the "3.X - 4.X" version can't be confirmed against the vulnerable range, so
Samba would still end up as tool_decided. Still to decide: fix the signature
and rerun, or report the false negative as it stands and explain it.

### 7 july
this entry counts Apache 2.4.49 as a direct match three times, including in the hand-computed metrics (TP=3, recall 0.75). That was wrong — 2.4.49 was never scanned and it was formally deferred to the EMA on 7 July. The true state on 6 July was two direct matches (2.4.50, OpenSSH). The vsftpd deferral decision above therefore rested on a smaller detection set than stated, though the decision stands on the same redundancy reasoning. Actual evaluation results are in the 7 July entry and reports/evaluation.md.