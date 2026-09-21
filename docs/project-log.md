# Project log — vulnerability reporting tool

(Entries for 17 to 30 June were written up on 2 July from my working notes. Later entries were written on the day, except the 9 July to 3 August period, which was reconstructed on 4 August from notes, files and submission dates and is marked where memory rather than a record is the source.)

## 17 June 2026

Started the build. Set up the repo, the vulnreport package scaffolding, and the Nmap parser, with a sample scan and its first tests.

Also made the first design decision: matching will use a curated signature file covering the lab services, and the CVSS scores will come from the project's own calculator. Full reasoning is in design-decisions.md.

I did look at a general CPE-to-CVE lookup first, and decided against it for the prototype. Nmap's service names don't map cleanly onto CPE identifiers, version strings come in all sorts of formats, and some services Nmap can't fingerprint at all. Getting that to work reliably would have been a project in itself, and it wouldn't have shown the decision-making the module rewards. The signature file gives a reliable core for the lab targets. The general lookup is written down as a possible extension.

## 18 June 2026

Wired up the end-to-end pipeline: CLI entry point, report builder, and a matcher stub. Nothing matches yet, but python \-m vulnreport now runs from parse to written report. That means every later stage has somewhere to plug in from day one.

## 24 June 2026

Built the NVD lookup stage. A client queries the NVD API for a given CVE and pulls out its CVSS base score. Responses go into a JSON file cache, so repeat lookups during development and evaluation don't keep hitting the service.

Applied the CVSS version policy decided earlier: use the v3.1 base score where one exists, fall back to v3.0 (the base formula is effectively the same), and exclude CVEs that only carry a v2 score. Each result records which version was used, so the report can state it. Added four offline tests for the selection logic.

Test run: 7 passing (3 Nmap parser, 4 NVD extract).

Live check: CVE-2021-41773 came back with a CVSS v3.1 base score of 9.8 (CRITICAL), and the response was cached.

One thing to note from that result. CVE-2021-41773 shows the limits of matching on version alone. It is only exploitable in certain Apache configurations, and its published score varies between databases, so a host running that version isn't necessarily exploitable. The evaluation's precision and recall figures should pick this up, and the report needs to list it as a known limitation of version-based matching.

## 30 June 2026

Built the answer key for the evaluation. Six CVE-pinned targets across the CVSS bands 5.3, 7.7 and 9.8, plus one patched-version negative to check the tool doesn't flag things it shouldn't.

One target got dropped along the way: ProFTPD 1.3.5 (CVE-2015-3306). It looked like a good fit. A real, well-known vulnerability, on a service Nmap reads cleanly. But NVD holds no v3.x score for it, only v2, and the version policy excludes v2. Keeping it would have meant bending the policy for one target, or scoring it differently from the others. So it went. This is the first time the version policy has actually cost me something: some otherwise-good targets are unusable, and the answer key has to be built around what NVD scores under v3.x.

Implemented version\_matches with range support and built the matcher out to its three-tier status.

The first plan was a plain match / no-match. Either the product and version fit a signature or they didn't. Working through the sample scan showed the problem with that. When Nmap reads Apache 2.2.8 and the signature only covers 2.4.49, the tool has recognised the product, but it can't assert a CVE against that version. Calling that no\_match hides something the tool knows. Calling it a match would just be wrong. So I added a middle tier, tool\_decided, for exactly this case: product recognised, version outside the rule, no CVE asserted. The three statuses now cover every state the tool can actually be in. Version comparison uses numeric tuples with zero-padding and an inclusive version\_max, and it fails closed on anything it can't parse. An unparseable version will never silently direct-match.

Also for the risk register: OpenVAS integration, listed as a planned scanner in the original project proposal, is deferred. The project risk register already had "fall back to Nmap-only" as the contingency for this, and that is now what has happened. The normalisation layer stays in place so a second scanner could be added later. Trying OpenVAS at this stage would put the core deliverable at risk for what is really a scoping addition. Logged as a realised risk.

## 2 July 2026

Implemented \_roundup for the CVSS calculator. The first draft used math.floor(int\_val / 10000). That works, but it does the division in floating point before flooring. Switched to integer floor division (int\_val // 10000\) so the rounding step stays in integer arithmetic, which matches appendix A of the CVSS v3.1 specification (FIRST, 2019). Dropped the math import as a result. Tests still to run once base\_score is in.

Added the scoring stage into the pipeline. For each direct-match finding, the CVE's vector string is fetched from NVD and scored by the project's own CVSS calculator. NVD's published score is kept as a runtime cross-check: any difference beyond 0.05 gets recorded in the finding's notes. This keeps the calculator on the critical path as evidence the implementation works. On the sample scan, vsftpd (CVE-2011-2523) scores 9.8 Critical and OpenSSH (CVE-2018-15473) 5.3 Medium. Both agree with NVD. The tool\_decided and no\_match findings are left unscored on purpose, since no CVE is asserted for them.

Not everything went smoothly. The new scoring module failed to import at first (ModuleNotFoundError) because I'd created the file at the top of the vulnreport package, not inside its sub-folder. Moving it into vulnreport/scoring and adding the package **init**.py fixed it.

While implementing base\_score I initially indexed the impact weights as WEIGHTS\["C"\], WEIGHTS\["I"\] and WEIGHTS\["A"\], which don't exist. The specification gives Confidentiality, Integrity and Availability the same weight table, so the weights dict stores it once under a single "CIA" key. Fixing the lookup fixed a KeyError that would have failed every test.

The roundup function needed care. A naive floating-point version rounds some valid CVSS intermediates the wrong way (the 0.1 \+ 0.2 problem noted in Appendix A of the specification). I followed the spec's integer-arithmetic method instead, scaling by 100,000 before rounding. That is why the calculator agrees with NVD's published scores on the close cases.

## 3 July 2026

Tried the first Vulhub target. Cloned the repo and ran docker compose up on httpd/CVE-2021-41773. Apache 2.4.49 came up on port 8080 with no problems. Nmap \-sV read the service correctly as "Apache httpd 2.4.49". Fed the XML into the tool and the report came back with CVE-2021-41773 scored 9.8 Critical. The expected result, but this time produced end to end from a real container, not the bundled sample. One target of seven in the answer key done. The interesting ones are still to run: Samba, where Nmap often reports a version range with no pinned number, and the patched 2.4.51 negative.

Second Vulhub target done, OpenSSH 7.7 (CVE-2018-15473), though it took a few false starts. With the container listening on 20022, Nmap \-sV read the banner as "OpenSSH 7.7 (protocol 2.0)" and the tool matched CVE-2018-15473 at 5.3 Medium, agreeing with the answer key. Nmap reported the version as plain 7.7, not 7.7p1, so the portable-suffix handling in \_parse\_version wasn't exercised on this target. It's still needed for others, but this didn't test it. Two of seven done (Apache 2.4.49 and OpenSSH).

Ran Apache 2.4.50 next and it was clean. Nmap read "Apache httpd 2.4.50" on 8080, and the tool matched CVE-2021-42013 at 9.8, which is what the answer key expects. Third direct match, alongside 2.4.49 and OpenSSH.

Samba was a problem. The container would not start because port 445 was already taken. Windows holds 445 itself for file sharing (the System process, PID 4), so it was not something I could just kill. Remapped the published port to 1445\. First tried a compose override file, but that appended a second port mapping on top of the original, so it still tried to bind 445 and collided. Editing the compose file directly worked. By then I also had a docker run container going, so there were two Sambas up and I had to be careful which one I scanned. Once it was listening on 1445, Nmap reported the version as "3.X \- 4.X", with no pinned number, and the tool returned no CVE. Samba over SMB does not hand Nmap a clean version. Worth knowing for the write-up.

At the time I recorded this as a tool\_decided outcome. That was wrong, and I corrected it on 6 July once the evaluation script showed what actually happened — see that entry. The tool never reached the version check at all.

Pulled httpd:2.4.51 for the patched negative and confirmed the container starts and binds 8081\. Haven't scanned it yet. That is the next job, and it means 2.4.51 is not yet a confirmed negative in the results, only a prepared target.

(Note on dates: the 2.4.50, Samba and 2.4.51 work above was done during the 3 July session — the generated report headers and scan files carry 3 July timestamps. Some of it was written up from notes on 6 July, which is why it appeared under that date in an earlier version of this log. Moved here to match the file evidence.)

## 6 July 2026

Chased down a proper vsftpd 2.3.4 target and decided against getting it tonight. The Docker route was a dead end. It is not in Vulhub. The image I tried first (hmlio/vaas-cve-2011-2523) does not exist. A docker search only turned up general-purpose vsftpd images built on CentOS 7 or Debian, and those ship 3.0.x, not 2.3.4. The Metasploitable images on Docker Hub are all unofficial rebuilds from unknown publishers, and I am not pulling one onto the lab machine just for a version banner. The clean source is the official Metasploitable 2 VM from Rapid7, which ships the real 2.3.4 and answers 220 (vsFTPd 2.3.4). That is a download-and-VM job, not a quick container.

Decided not to do that yet. The detection set stands at three direct matches (Apache 2.4.49, Apache 2.4.50, OpenSSH 7.7), one prepared but unscanned negative (Apache 2.4.51), and Samba still to be resolved. vsftpd would add a fourth true positive, but no detection case the existing three do not already cover. It can wait. Carrying it forward as a planned addition: stand up the Rapid7 Metasploitable 2 VM, scan port 21, confirm Nmap reads 2.3.4, and add it as the exact-version-pinned CRITICAL. Open questions for then: the VM networking (host-only or bridged, and scan the VM's own IP, not localhost), and whether to score only vsftpd or widen the answer key to the other services Metasploitable exposes.

Went back to the Samba result and worked out why it really failed. On 3 July I had put it down as tool\_decided — product recognised, version unconfirmable. That was wrong. Nmap writes the product as "Samba smbd", and my signature says "Samba". The matcher compares the product string exactly, so the two never matched and it never reached the version check at all. The correct status is no\_match, which makes Samba a false negative, not a graceful decline. Two fixes stack underneath. First, correct the product string so Nmap's "Samba smbd" is recognised. Second, even after that, the "3.X \- 4.X" version cannot be confirmed against the vulnerable range, so Samba would then land as tool\_decided rather than a direct match. Still to decide: fix the signature and rerun, or report the false negative as it stands and explain it. Either is defensible; reporting it and then fixing it shows the self-review, which is probably the stronger account.

## 7 July 2026

Built and ran the evaluation script (vulnreport/evaluate.py). It runs each scan through the existing parse and match pipeline and scores the result against the separate answer key. It measures detection only, so it needs no NVD calls and runs offline. Precision and recall are counted only over targets where the tool commits to a direct match; tool\_decided and not-run targets get their own rows rather than being forced into a bin.

Running it turned up a problem with yesterday's hand-calculated figures. The Apache 2.4.49 scan XML from 3 July was not retained — the generated report survives in the reports folder, but the evaluation harness needs the raw XML to reproduce the result, and without it the script can only mark 2.4.49 as not\_run. So the hand figures were over-counted by one true positive.

I have left 2.4.49 as not\_run for now rather than trust a result I cannot reproduce, and deferred a clean rescan. That drops the reproducible true positives from three to two (Apache 2.4.50 and OpenSSH 7.7), with the one Samba false negative, giving precision 1.00 and recall 0.67 on what the tool can actually verify on disk. The vsftpd deferral still holds under the smaller set, since the reasoning for it did not depend on the count. Lesson for the rest: keep the raw scan input, not just the generated report, or the result cannot be checked later.

## 8 July 2026

Mainly rewriting the interim project report to catch up with the changes in the project. Reworked the design-decisions narrative and started folding the evaluation results in. No code changes. This was slower than expected — the document had drifted behind the code, so a fair amount of it needed rewriting rather than extending.

## 9 July 2026

Tutor replied to the ethics query: the checklist needs updating (informed consent item among others), no resubmission needed, updated form to go in the appendix with a note. He also reframed the planned user session as elicitation rather than validation: use the prototype and its report as the instrument to extract requirements for how the system should present itself. Replied confirming that approach.

Ran the session with one surrogate user (IT worker, Python-proficient, verbal consent, no personal data). NFR3: task succeeded on first attempt, about four minutes, via the README then \--help; finding: the entry point is not discoverable from the filesystem alone. Elicitation produced five candidate requirements — plain-English CVE descriptions, fixed-in versions, a severity-ordered multi-host summary, a clearer tool\_decided label, and non-colour-reliant severity emphasis — recorded in docs/evidence/session\_note\_2026-07-08.md. The Samba unconfirmed report was understood correctly without prompting, which is the fail-closed design communicating as intended.

## 10 to 14 July 2026

(Reconstructed on 4 August from memory; I did not keep daily notes through this stretch.)

Finishing and editing the interim project report for the 14 July cut-off. This was writing and revision rather than development — pulling the evaluation results, the design decisions and the user session into the report and tidying the structure as far as time allowed.

On the Samba question from 6 July, I submitted with the false negative reported as it stood rather than fixing the signature first, on the reasoning that the result and its cause were worth showing. The fix itself is carried forward.


## 14 July to 3 August 2026

(Reconstructed on 4 August.)

No project work on the vulnerability tool during this period. The interim report was submitted on 14 July, and I had another module deadline in this window, so I focused on that and paused this project while waiting for feedback. Recording the pause honestly rather than leaving a silent gap: there was no development, and none was planned until the feedback came back.

## 3 August 2026

Collected feedback on the interim report. The technical work was recognised; the strongest criticisms were structural — requirements embedded in prose rather than surfaced in a table, and the architecture discussion placed away from the diagram it explains. Read carefully rather than defensively, most of it is fair: the requirements were in the report, at 4.7, but buried where a reader would not spot them, so the comment is really about presentation rather than presence. The fixes are structural and mechanical — tables, diagrams, reordering, signposting — and they go on the list for the final report.

Started final-report preparation: arranged the requested discussion session, re-read the feedback and in-document comments, and drafted a task list and rough schedule for the run to the 14 September cut-off. Began this log repair as part of that, since the record had drifted during the July writing and the wait.  

## 4 August 2026

Rescanning the outstanding Apache targets

Started by closing the two gaps left at the interim report. Docker Desktop was not running to begin with, which took a few minutes to spot: the client answered but there was no server, and no whale in the tray. Worth remembering that docker version returning a Client section but no Server means the engine is down rather than anything being broken.

Apache 2.4.49 came up on 8080 from the Vulhub environment. Nmap read it as "Apache httpd 2.4.49 ((Unix))" and the tool matched CVE-2021-41773 at 9.8 Critical, agreeing with the answer key. This time I kept the XML as apache2449.xml in the repo root, which was the whole point. The 7 July loss came from keeping only the generated report, so the result could not be reproduced by the evaluation script.

Then the patched negative. Brought up stock httpd:2.4.51 on 8081. The docker run was refused at first because the container name was still held by the stopped container created on 3 July when testing whether the image pulled; docker rm apache2451-test cleared it. Nmap read the version as 2.4.51 rather than a bare "Apache httpd", which matters: had the image been running ServerTokens Prod, the tool would have declined for lack of a version rather than because it recognised a patched one, and the negative would have passed for the wrong reason. The report came back with no confirmed vulnerability and the service listed as tool_decided, "known product, version outside the signature's range". That is the correct decline, and it is the control showing the tool is not simply flagging everything.

A false negative I had been carrying in my head turned out to be already fixed. Samba now returns tool_decided rather than no_match, which means the signature product string was corrected at some point during the interim-report writing week. The matcher recognises Nmap's "Samba smbd", reaches the version check, finds "3.X - 4.X" unresolvable against the vulnerable range, and declines with a reason. That is what the three-tier design was for.

PEP 8 compliance (NFR6)

Set up flake8 to check style properly rather than assuming it. The first run reported 38 violations, 30 of them line-length complaints against the default 79-character limit. Added a setup.cfg setting the project limit to 99, which is a documented convention rather than a workaround: the default dates from terminal-era constraints and most current Python tooling uses 88 or more.

That left 8 substantive issues, now all fixed. One was an unused math import in calculator.py, which the 2 July log entry said had been removed. It had not, so that entry recorded an intention rather than what happened. The others were three over-indented continuation lines, two missing end-of-file newlines, a redundant blank line, and one genuinely over-long line in evaluate.py.

Rewrote the exploitability calculation to use bracketed continuation rather than backslashes. This briefly broke the file with an IndentationError before I noticed the opening line was indented six spaces instead of four. Since that edit touched the scoring arithmetic, I re-ran the test suite: 38 passing, so behaviour was unchanged. flake8 now reports zero violations, so NFR6 can be evidenced with tool output rather than asserted.

Also noted that pytest lives in the project's .venv, not globally, and that the day's earlier work had been run against the global Python. The evidence for the report should be produced inside the documented environment.

vsftpd 2.3.4 via Metasploitable 2

Stood up the Rapid7 Metasploitable 2 VM to get the deferred vsftpd target. VirtualBox was already installed. Metasploitable ships as VMware files, so rather than importing the .vmx I created a new VM and attached the existing .vmdk as its disk, which VirtualBox handles without conversion.

Set the network adapter to host-only rather than NAT or bridged. That gives the VM an address the Windows host can reach while leaving it no route out, which matters for a machine that is deliberately riddled with vulnerabilities. The adapter showed DHCP as disabled but the VM picked up 192.168.56.101 anyway, so no static configuration was needed.

Nmap read the FTP banner as "vsftpd 2.3.4" with no ambiguity, and the tool matched CVE-2011-2523 at 9.8 Critical, agreeing with the answer key. This is the only target in the set where an exact pinned version drives the match rather than a range, which is a different matching case from the others.

Position at the end of the day

The evaluation now covers six of seven targets: 4 true positives, 0 false positives, 0 false negatives, 1 true negative, 1 tool_decided (Samba), and 1 not run (nginx, excluded with reasons recorded on 6 July). Precision 1.00 and recall 1.00 over four committed targets.

Two things to carry into the write-up. First, recall reads 1.00 because it is computed only over targets where the tool commits to a direct match; Samba sits outside that denominator by design, on the reasoning that penalising the tool for honestly declining an unresolvable version would be perverse. I still think that is right, but the report needs to state the denominator explicitly rather than quoting a bare 1.00, and give the Samba case its own paragraph. A marker who has not followed the reasoning could otherwise read it as the metric being shaped to produce a clean number. Open question for supervision: whether the declined case should be counted in recall or reported separately.

Second, the vsftpd scan targets 192.168.56.101 rather than 127.0.0.1, and is the first in the set to do so. NFR5's fit criterion currently says every retained scan targets 127.0.0.1 on ports published by project lab containers, which no longer describes the evidence. The isolation claim still holds — a host-only adapter with no route to the internet is arguably stronger isolation than a published Docker port on the development machine — but the criterion needs rewording to cover both the container targets and the VM.