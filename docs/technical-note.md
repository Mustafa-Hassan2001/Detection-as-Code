# Detection Engineering as Software: Version-Controlled Sigma Rules with Continuous Validation and ATT&CK Coverage Reporting

*Technical note: Detection-as-Code project (companion to the SecureNet Lab).*

## 1. Problem

A Security Operations Centre (SOC) detects attacks with rules that run over telemetry
in a SIEM. In many organisations these rules live only inside the SIEM. Analysts edit
them through a web UI, and they have no review, no tests and no history. This causes
three well-known failures:

1. **Silent breakage.** A "tuning" edit that adds a broad exclusion can blind a rule. A
   log-source change, such as a field rename after an agent upgrade, can stop a rule from
   ever matching again. Neither raises an error: a rule that never fires looks exactly
   like a quiet network.
2. **Unknown coverage.** Without a structured link between rules and the adversary
   behaviours they address, the team cannot say which techniques it detects, which it
   does not, and whether a gap is closing.
3. **Vendor lock-in.** Rules written in one SIEM's query language must be rewritten for
   every other SIEM.

*Detection-as-Code* applies software-engineering practice to detection content. Rules
are source code in Git. Changes go through review. Automated checks gate every change.
Deployable artefacts are generated, never hand-written. This project implements that
workflow end to end for 20 rules, mapped to MITRE ATT&CK, on the Windows, Linux and
network layers of the SecureNet Lab.

## 2. Building blocks

**Sigma** is a vendor-neutral, YAML-based rule format. A rule declares:

- a `logsource` (for example `category: process_creation`, `product: windows`);
- named **selections**, which are field/value predicates with modifiers such as
  `|endswith`, `|contains|all` and `|re`;
- a boolean **condition** over those selections (for example
  `selection and not 1 of filter_*`);
- metadata: a UUID, a status, references, ATT&CK tags, false positives and a level.

The **pySigma** library parses rules into an abstract syntax tree. Two kinds of component
act on that tree:

- **Processing pipelines** rewrite it for a specific data model, for example
  `CommandLine` to `process.command_line` in the Elastic Common Schema.
- **Backends** serialise it into a target query language, such as Lucene, OpenSearch or
  SQL.

**sigma-cli** is the command-line front end to pySigma. One Sigma rule therefore yields
an Elastic query, a Wazuh/OpenSearch query and an SQLite query from the same abstract
syntax tree. Their meaning differs only where the field mappings or the target languages
differ, and those are exactly the places where this project adds tests.

**MITRE ATT&CK** is a knowledge base of adversary tactics (the goal: *why*) and
techniques and sub-techniques (the method: *how*). Rules are tagged with technique IDs
(`attack.t1003.001`) and tactic names (`attack.credential-access`). Those tags are what
make coverage measurable.

**Atomic Red Team** is a library of small, single-purpose emulations of ATT&CK
techniques. This project uses its YAML format for one emulation per rule, so that every
detection has a reproducible way to make it fire.

## 3. Repository design

The repository is organised so that every artefact has exactly one source of truth.

| Artefact | Source of truth | Generated? |
|---|---|---|
| Detection logic | `rules/**/*.yml` (Sigma) | No (authored) |
| Rule ↔ technique ↔ emulation ↔ telemetry ↔ test-data links | `mapping/detections.yml` | No (authored) |
| Emulations | `atomics/T*/T*.yaml` | No (authored) |
| Synthetic test data | `sample-logs/generate_samples.py` | Yes (`sample-logs/*.jsonl`) |
| SIEM queries (Elastic, Wazuh) | rules + `pipelines/` + `config/targets.yml` | Yes (`converted/`) |
| ATT&CK coverage | rules + mapping + pinned ATT&CK | Yes (`coverage/`) |
| ATT&CK reference data | MITRE STIX v20.0 | Yes (`mapping/attack/`, with SHA-256 of the source) |

Generated artefacts are committed. Reviewers can then see the *effect* of a rule change,
for example the exact Lucene query that will run in the SIEM, inside the pull-request
diff. A **drift check** (`git diff --exit-code` after regeneration) guarantees that the
committed copies always equal what the sources produce. Hand-editing a SIEM query becomes
impossible without CI noticing.

Two decisions deserve explanation.

- **Pinning ATT&CK.** pySigma's tag validator downloads the *latest* ATT&CK release at run
  time. That makes the build non-reproducible. ATT&CK v20 (October 2026) renamed Defense
  Evasion (TA0005) to *Stealth* and introduced *Defense Impairment* (TA0112), so any rule
  tagged `attack.defense-evasion` became invalid overnight. The project pins v20.0,
  stores a compact extract of it, and pre-fills pySigma's cache from that extract. Every
  tool then validates against the same version, even offline. A weekly scheduled workflow
  validates the rules against the newest release as an early warning. Upgrading remains a
  deliberate, reviewed change.
- **Explicit unsupported conversions.** Stock Wazuh has no decoder for Sysmon for Linux.
  Emitting queries with invented field names would create rules that can never fire,
  which is the "silent breakage" failure all over again. Instead, the Wazuh processing
  pipeline raises a `rule_failure` for that log source. The conversion target lists those
  rules as `expected_unsupported`. Any *other* conversion failure fails the build. The
  telemetry gap is therefore visible and documented, not hidden.

## 4. The detection-engineering workflow

Each rule follows the same life cycle, and the pipeline enforces it:

1. **Hypothesis.** Start from an attacker behaviour (an ATT&CK technique) and the
   telemetry that would record it. Example: credential dumping with `comsvcs.dll` shows
   up as a rundll32 process whose command line contains `MiniDump`.
2. **Rule.** Write the Sigma logic, then constrain it until legitimate activity is
   excluded. For example, Run-key writes are only interesting when they point to
   temp or public paths.
   Document the remaining false positives and the blind spots (`docs/rules.md`).
3. **Test data.** For each rule, write at least one *malicious* event and one *near-miss
   benign* event. A near-miss is an event that the rule would match if one of its filters
   were removed: Defender opening LSASS, a `/dev/tcp/127.0.0.1` health check, a dpkg
   maintainer script setting a setuid bit.
4. **Emulation.** Write an Atomic-format test that produces the behaviour safely and
   reversibly, plus a mapping entry that links all of the above.
5. **CI.** Push. The pipeline lints, validates, tests, converts and reports coverage.
6. **Lab validation.** Run the atomic in the SecureNet Lab. Then query the SIEM with the
   converted rule (`make hunt`) and record the outcome (`lab_validation`,
   `docs/results.md`).
7. **Maintain.** When a false positive is reported, change the rule *together with* a
   benign test event that reproduces it. The fix is then itself regression-tested.

## 5. How CI improves rule quality

Each stage catches a defect class that would otherwise reach production silently.

| Stage | Defect class caught | Example |
|---|---|---|
| YAML lint | Structural YAML errors | A duplicate key inside a selection silently overrides the first one. While the project was being built, an unquoted `#{input}` in an atomic test was parsed as a comment. |
| `sigma check` | Rules that do not compile, dead logic, invalid tags | A condition referencing an undefined selection; an unused selection; `*x*` wildcards that should be modifiers |
| Project validator | Incomplete or incorrect metadata, ATT&CK drift, broken traceability | A revoked technique (`T1086`); a tactic that no longer exists; `falsepositives: Unknown`; a mapping entry that points to the wrong rule or emulation |
| Self-test | A broken gate | A typo in the CI command that makes a check pass vacuously |
| Synthetic tests | Logic regressions: false negatives and over-broad rules | Removing the conhost.exe filter in the WinRM rule makes the benign event `win-106` alert, so the build fails. This was verified by deliberate mutation. |
| Conversion | Rules that cannot be deployed | A modifier or log source the backend or pipeline cannot express |
| Drift | Hand-edited or stale SIEM content | Someone edits a query in `converted/` instead of editing the rule |
| Coverage | Coverage claims that do not match reality | The heatmap is generated from the same tags the validator checks |

The synthetic tests deserve attention because they are what make this *testing* rather
than *linting*. Each rule is converted to SQL by pySigma's SQLite backend and executed
against in-memory tables built from the JSONL samples. This works the same way as the
Zircolite tool. The test is not a re-implementation of Sigma semantics: it is the
production compiler with a different backend. Windows rules pass through the same
`sysmon` processing pipeline that the Wazuh target uses, so the EventID constraint for
each log-source category is exercised as well.

Each test asserts set equality. The rule must match exactly its expected malicious
events, plus any events explicitly documented as known false positives. One such event is
`aud-104`: the logrotate package installing a cron job, which the cron rule *should*
match and an analyst must triage. Documenting accepted false positives keeps the
false-positive accounting honest instead of hiding it.

Making the semantics agree across backends was itself a finding. Sigma's `re` modifier
has *search* semantics, but Lucene regular expressions are implicitly anchored to the
whole value and do not support `^`. The first version of the DNS-tunneling regex,
`^[…]{40,}\.`, would therefore have matched in the SQLite test but **never** in the SIEM.
Rewriting it as `.*[…]{40,}\..*` gives identical meaning in both. Where semantics could
not be made identical, the documentation states it. One example is case-sensitive
keyword matching in the Wazuh indexer, versus Sigma's case-insensitive default.

## 6. Coverage reporting, and its limits

`tools/coverage.py` produces three outputs from the rule tags, the mapping and the pinned
ATT&CK release:

- an ATT&CK Navigator layer, where the score is the number of rules per (technique,
  tactic), with rule paths and lab-validation status in the metadata;
- a Markdown table of tactics to techniques to rules;
- a static heatmap.

A coverage map is easy to over-read. It shows that *a* rule exists for a technique. It
does not show that the technique is detected:

- One technique has many procedures. The LSASS rules catch comsvcs and handle-based
  dumping, but not driver-based dumping.
- A rule only works if its telemetry is collected. The auditd rules need specific watch
  rules, and Linux process rules cannot run in stock Wazuh.
- Synthetic tests prove the logic, not real-world precision.

For that reason the project tracks `lab_validation` separately for every rule, and keeps
real-world results (which rules fired, false-positive rates, final coverage numbers) in
`docs/results.md`. Those are filled in only from actual lab runs: [FILL FROM YOUR RUN].

## 7. Evaluation plan

- **Correctness (standalone).** All rules pass their synthetic tests. All malicious
  samples are detected. Benign alerts are limited to documented false positives. Result:
  [FILL FROM YOUR RUN].
- **Efficacy (lab).** For each rule: did the atomic make it fire in the SIEM, and how long
  did the event take to appear? Result: [FILL FROM YOUR RUN].
- **Precision (lab).** Run a benign-activity window with no atomics, and compute
  false-positive rates per rule against a stated denominator. Result:
  [FILL FROM YOUR RUN].
- **Maintainability.** Measure the time from "new rule" to "green pipeline", and whether
  the pipeline caught defects during development. Examples observed while building the
  project: the YAML-comment bug, the Lucene regex anchoring, and the filter mutation.

## 8. Limitations and future work

- **No aggregation.** All 20 rules are single-event rules. Slow brute force, beaconing and
  volumetric exfiltration need Sigma *correlation* rules (`event_count`,
  `value_count`, `temporal`). Those require backends with aggregation, such as ES|QL,
  EQL or Splunk, not plain Lucene.
- **Telemetry gaps.**
  - A Wazuh decoder for Sysmon for Linux would close the five unsupported conversions.
  - PowerShell Script Block Logging (EID 4104) and Windows Security events (4697, 4698,
    7045) would close documented blind spots.
- **Native Wazuh rules.** Generating Wazuh XML rules, rather than indexer queries, would
  allow real-time alerting in the Wazuh manager. There is no maintained pySigma backend
  for that today.
- **Automated lab loop.** A scheduled job in the SecureNet Lab could run every atomic,
  query the SIEM, and update `lab_validation` automatically. That would turn lab
  validation into continuous purple-team regression testing.
- **Real benign corpora.** The near-miss samples are hand-made. Replaying recorded,
  anonymised lab traffic would give a statistically meaningful false-positive estimate.

## References

- Sigma specification and SigmaHQ conventions: <https://github.com/SigmaHQ/sigma-specification>
- pySigma / sigma-cli: <https://github.com/SigmaHQ/pySigma>, <https://github.com/SigmaHQ/sigma-cli>
- MITRE ATT&CK Enterprise v20 (STIX): <https://github.com/mitre-attack/attack-stix-data>
- ATT&CK Navigator layer format 4.5: <https://github.com/mitre-attack/attack-navigator>
- Atomic Red Team: <https://github.com/redcanaryco/atomic-red-team>
- Zircolite (Sigma over SQLite): <https://github.com/wagga40/Zircolite>
