# `mapping/detections.yml` schema

The mapping file is the machine-readable link between **rule**, **ATT&CK technique**,
**attack emulation**, **log source** and **test data**. It is the single place to look up
"what do we detect, with which telemetry, and how do we prove it?".
`tools/validate_rules.py` checks it against every other artefact.

```yaml
schema_version: 1
attack_version: "20.0"            # must equal the pinned ATT&CK release
detections:
  - rule: rules/<...>.yml         # path, must exist, each rule mapped exactly once
    rule_id: <uuid>               # must equal the rule's `id`
    lab_validation: not-run       # not-run | fired | not-fired | partial (from your lab run)
    techniques: [T1059.001]       # must equal the rule's attack.tXXXX tags
    log_source:
      sigma: {category: process_creation, product: windows}   # must equal rule logsource
      telemetry: Sysmon Event ID 1                            # concrete event type needed
      collection: Sysmon -> Wazuh agent (eventchannel)        # how the lab collects it
    emulation:
      atomic: atomics/T1059.001/T1059.001.yaml  # ART-format file, must exist
      test: DAC - PowerShell -EncodedCommand execution  # test name inside it, must exist
      upstream: {technique: T1059.001, test: "..."}  # closest upstream Atomic Red Team test
    sample_data:
      file: sample-logs/windows/sysmon.jsonl
      expected_matches: [win-002]      # must fire; samples must be labelled malicious
      known_false_positives: []        # may fire; samples must be labelled benign
```

Why each cross-check exists:

| Check | Bug it prevents |
|---|---|
| `rule_id` equals the rule's `id` | Copying a mapping entry and forgetting to update it |
| `techniques` equals the rule tags | Coverage report and rule disagree about what is covered |
| `log_source.sigma` equals the rule logsource | Testing a rule against the wrong data |
| The atomic targets one of the rule's techniques | "Validating" a rule with an unrelated emulation |
| Expected samples are labelled `malicious` | A positive test that is really benign data |
| Known false positives are labelled `benign` | Hiding a true positive as an "accepted FP" |

The upstream Atomic Red Team test names are hints for finding the equivalent upstream
test. Verify them against the ART commit you use:
`Invoke-AtomicTest <T#> -ShowDetailsBrief`.
