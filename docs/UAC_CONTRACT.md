# Forensic JSON export contract

An alert is more useful when you can find the original log entry that caused it. This matters especially for a correlation: one alert may depend on several entries, in several files. Display strings are useful to read, but they are not reliable evidence references.

The forensic export keeps each alert's supporting records and their source locations as structured JSON. Another tool can use these references to link the alert to its own observations of the same evidence. Iwatobi supplies the references; it does not perform that linking.

This document describes `iwatobi-forensic-1.0.0`, using source-reference profile `uac-1.0.0`. The export is a native detection format, not an ECS event format. Iwatobi continues to read native logs and evaluate Sigma rules. Existing terminal, CSV, JSON and JSONL output remains available unchanged.

All examples below use synthetic data. JSON examples are excerpts unless described as a manifest. Values in angle brackets, such as `<file-sha256>`, are explanatory placeholders, not valid hashes. Replace them with the actual values before use.

For a complete example without hash placeholders, use the [sample manifest](examples/forensic/evidence-manifest.json), [synthetic input](examples/forensic/access.log) and [sample output bundle](examples/forensic/forensic-output.json). The [example guide](examples/forensic/README.md) explains how to run it and follow the three correlation members back to their original lines.

## Request an export

Add `--forensic-output FILE` to an offline `dfir-timeline` scan:

```sh
iwatobi dfir-timeline -d originals -r rules -z UTC \
  --forensic-output results/alerts.json \
  --evidence-manifest bindings.json
```

- `--forensic-output` writes one JSON bundle, independently of the ordinary output profile. It cannot be used with live analysis.
- `--evidence-manifest` is optional and requires `--forensic-output`. It supplies the identity of the evidence and maps local files to that identity. It is not discovered automatically.
- Create the output directory first. Use a fresh file outside the evidence directory, different from any ordinary output file. An existing forensic export is never overwritten, even with `--clobber`.
- Keep original logs and rule files unchanged throughout the scan.

You can export detections without a manifest:

```sh
iwatobi dfir-timeline -f originals/auth.log -r rules -z UTC \
  --forensic-output results/unbound-alerts.json
```

Those detections still contain native records and local locations. They do not have exact shared evidence references.

## Identify the evidence with a binding manifest

An **acquisition** is an identified set of collected evidence. A **collection** identifies a group of sources within that acquisition. A **binding** maps one local input file to its identity in that evidence inventory.

The manifest is a JSON object with these fields:

| Field | Meaning |
| --- | --- |
| `acquisition_id` | String identifying the acquisition. Optional or `null`; a blank string is rejected. Without it, evidence remains unbound. |
| `sources` | Array of file bindings. May be empty or omitted. |
| `sources[].input_path` | Local input file to scan. Absolute, or relative to the manifest's directory. |
| `sources[].collection_id` | Non-empty collection identifier from the evidence inventory. |
| `sources[].path` | Canonical relative path from that inventory, using `/` separators. |
| `sources[].sha256` | SHA-256 of the whole original file, as 64 hexadecimal characters. Uppercase input is accepted and converted to lowercase. |

For example, save this as `bindings.json` beside an `originals` directory. Replace the hash placeholder with the file's actual hash:

```json
{
  "acquisition_id": "example-acquisition",
  "sources": [
    {
      "input_path": "originals/auth.log",
      "collection_id": "host-a",
      "path": "var/log/auth.log",
      "sha256": "<file-sha256>"
    }
  ]
}
```

Here, `originals/auth.log` is where Iwatobi reads the file. `var/log/auth.log` is its identity in the evidence inventory. Do not derive that identity by guessing a prefix to remove from the local path.

The canonical path must not start with `/`, contain `\`, or have empty, `.` or `..` components. For example, `var/log/auth.log` is valid; `/var/log/auth.log`, `var//log/auth.log` and `../auth.log` are not.

The manifest is rejected if it contains unknown fields, invalid bindings, duplicate local input mappings, duplicate `(collection_id, path)` destinations, incorrect hashes, or bindings for files not selected by the scan. A selected file omitted from the manifest is retained as unbound; it does not make the whole manifest invalid.

An acquisition ID is an assertion supplied by the caller. A matching file hash does not prove that two acquisitions are the same. Use the same acquisition and collection identifiers in every tool that will exchange references.

## Read the bundle

The top-level object has these fields:

| Field | Contents |
| --- | --- |
| `schema` | `iwatobi-forensic-1.0.0`. Identifies the detection bundle format. |
| `source_reference_profile` | `uac-1.0.0`. Identifies the source-reference convention. |
| `run` | The scan's identity, tool information, settings and rule inventory. |
| `uac.acquisition` | Acquisition identity and whether the caller supplied it. |
| `sources` | Source identities, bindings, integrity and scan coverage. |
| `alerts` | Single detections and correlation alerts, including their members. An empty array means no exported alerts, not proof that the evidence contains no suspicious activity. |

For example, these are the format and acquisition fields of a bound bundle:

```json
{
  "schema": "iwatobi-forensic-1.0.0",
  "source_reference_profile": "uac-1.0.0",
  "uac": {
    "acquisition": {"id": "example-acquisition", "status": "supplied"}
  }
}
```

Without an acquisition ID, the same field is:

```json
{"uac": {"acquisition": {"id": null, "status": "unbound"}}}
```

Do not treat this format as a promise that an arbitrary tool or future schema version is compatible. A consumer must understand both identifiers before interpreting the bundle. JSON object key order is not an identity or matching mechanism.

## Alerts contain individual supporting members

A **member** is an individual rule hit supporting an alert. A single alert has one member. A correlation combines rule hits and retains their individual evidence.

| Alert field | Meaning |
| --- | --- |
| `id` | Detection-instance ID within this run, formed from the run UUID and an alert number. |
| `event.kind` | Always `alert`. |
| `kind` | `single` or `correlation`. |
| `uac.run_id`, `uac.acquisition` | Run and acquisition identity for this alert. |
| `rule` | The alert's rule metadata. |
| `timestamp` | Native event time for a single alert, or the latest member time for a correlation. Unknown single-event time is `null`. |
| `members` | Supporting rule hits, each with `rule` and `evidence`. Correlation members also have `base_rule_index`. |
| `members_total`, `members_truncated` | Total internal membership and whether fewer members were emitted. The exporter does not sample members. |
| `evidence_status`, `exact_members` | Summary of exact source references across the emitted members. See evidence states below. |

A single alert might include these fields. Follow `members[0].evidence` to get both the native record and its source reference:

```json
{
  "id": "<run-uuid>:1",
  "event": {"kind": "alert"},
  "kind": "single",
  "uac": {
    "run_id": "<run-uuid>",
    "acquisition": {"id": "example-acquisition", "status": "supplied"}
  },
  "rule": {"name": "Example accepted login", "level": "high"},
  "timestamp": "2026-11-25T07:01:02+00:00",
  "members_total": 1,
  "members_truncated": false,
  "evidence_status": "exact",
  "exact_members": 1,
  "members": [
    {
      "rule": {"name": "Example accepted login", "level": "high"},
      "evidence": {
        "native": {
          "raw": "Nov 25 07:01:02 host sshd[3]: Accepted password for alice from 192.0.2.9 port 42315 ssh2",
          "representation": "iwatobi_decoded_native_not_original_bytes"
        },
        "location": {
          "status": "exact",
          "coverage": "single_line",
          "native_location": {"file": "originals/auth.log", "line": 3},
          "source_refs": [
            {
              "collection_id": "host-a",
              "path": "var/log/auth.log",
              "sha256": "<file-sha256>",
              "locator": {
                "kind": "text_line",
                "coordinate": "decoded_decompressed_1_based",
                "line": 3
              },
              "exact": true
            }
          ]
        }
      }
    }
  ]
}
```

New runs have new run UUIDs and detection IDs, even if the results are identical. Do not use alert IDs as source-occurrence IDs, another tool's event IDs or stable cross-run identifiers.

Correlations also contain `first`, `last`, `count` and `group_values`. `first` and `last` describe the member time window, not a separate historical action. `count` is the rule's native metric; for a rule counting distinct values it need not equal the number of members.

For example, a correlation with two exact members and one unbound member has this summary. It still retains all three members:

```json
{
  "kind": "correlation",
  "members_total": 3,
  "members_truncated": false,
  "evidence_status": "partial",
  "exact_members": 2
}
```

The export does not rerun Sigma, reconstruct missing correlations or infer missing members from display strings.

## Each member keeps the native record

`members[].evidence.native` contains the record as Iwatobi decoded it, including:

- `raw`: decoded record text.
- `representation`: `iwatobi_decoded_native_not_original_bytes`.
- `match_text`: separate matching text when present, otherwise `null`.
- `fields`: ordered `{name, value}` entries. Values retain JSON string, number, boolean or null types.
- `hostname`, `logsource` and `logsource_tags`: native source classification.
- `timestamp`, `timestamp_inferred` and `timezone_explicit`: native time and how it was interpreted.

For example, typed field values look like this; fields not shown are omitted from the excerpt:

```json
{
  "evidence": {
    "native": {
      "representation": "iwatobi_decoded_native_not_original_bytes",
      "fields": [
        {"name": "example_text", "value": "alice"},
        {"name": "example_number", "value": 3},
        {"name": "example_boolean", "value": true},
        {"name": "example_missing", "value": null}
      ]
    }
  }
}
```

These example field names illustrate the value types; actual names depend on the parser. `native` itself can be `null` when a member has no retained native event.

Decoded text is not original-byte evidence. Decoding removes BOM/NUL and replaces invalid UTF-8. Preserve the hashed original file if you need its exact bytes.

## A source reference identifies one original occurrence

`members[].evidence.location` contains a local location and any shared source references. For an exact single-line record:

```json
{
  "status": "exact",
  "coverage": "single_line",
  "native_location": {"file": "originals/auth.log", "line": 3},
  "source_refs": [
    {
      "collection_id": "host-a",
      "path": "var/log/auth.log",
      "sha256": "<file-sha256>",
      "locator": {
        "kind": "text_line",
        "coordinate": "decoded_decompressed_1_based",
        "line": 3
      },
      "exact": true
    }
  ]
}
```

`native_location.file` is the local scan name. Use `source_refs[].path`, not that local name, for shared identity. Acquisition identity comes from `uac.acquisition`, not from inside the reference.

`decoded_decompressed_1_based` means count physical lines from 1, after decompression where applicable. LF and CRLF boundaries, blank lines and a final line without a newline are supported.

For example, this synthetic file has three physical lines. The empty line counts:

```text
Nov 25 07:01:02 host sshd[3]: Accepted password for alice from 192.0.2.9 port 42315 ssh2

Nov 25 07:01:02 host sshd[3]: Accepted password for alice from 192.0.2.9 port 42315 ssh2
```

If both records match a rule, their references use `locator.line: 1` and `locator.line: 3`. The text and timestamp are identical, but these are two different occurrences. Do not deduplicate them by text.

For a gzip input, the locator counts decompressed lines while `sha256` identifies the compressed original file:

```json
{
  "collection_id": "host-a",
  "path": "var/log/auth.log.1.gz",
  "sha256": "<compressed-file-sha256>",
  "locator": {
    "kind": "text_line",
    "coordinate": "decoded_decompressed_1_based",
    "line": 3
  },
  "exact": true
}
```

Do not substitute the decompressed content's hash. Native decompression supports `.gz`, not arbitrary archives or compression formats.

## Link records only when the whole reference matches

A consumer may attach an Iwatobi member to another tool's observation only if all of the following agree:

1. Both belong to the same supplied acquisition ID.
2. `collection_id`, canonical `path` and original-file `sha256` match.
3. `locator.kind`, `locator.coordinate` and `locator.line` match.
4. Both references have `exact: true`.

For example, start with the exact reference to `host-a`, `var/log/auth.log`, line 3 above:

| Other observation | May link? | Reason |
| --- | --- | --- |
| Same acquisition, collection, path, hash, locator and exactness | Yes | It refers to the same occurrence. |
| Same text and timestamp, but line 1 | No | It is a different occurrence. |
| Same path and line, but a different file hash | No | The original file differs. |
| Same file hash and locator, but a different acquisition | No | Equal content does not establish acquisition identity. |
| Same basename `auth.log`, but a different canonical path or collection | No | A basename is not a shared identity. |
| All values agree, but either reference has `exact: false` | No | The location is not qualified as exact. |

Never join on alert IDs, timestamps, raw text, usernames or IP addresses alone.

One occurrence may support no observations, one observation or several observations in the other tool. A grouped audit observation may itself reference several source lines. A hit on one of those lines does not mean Iwatobi evaluated the whole grouped transaction.

If no observation matches, retain the native detection without a link. If several match, retain the multiplicity or ambiguity; do not silently choose the first. An exact reference qualifies the original location, not an attachment already verified by the exporter.

## Interpret evidence states at member and alert level

Member state is in `evidence.location.status`:

| State | Meaning |
| --- | --- |
| `exact` | The file has a supplied binding and acquisition, hashes remain stable, the shared line boundaries are supported, and the native record equals that decoded physical line. |
| `partial` | The file is stable and bound, but the member cannot be qualified as one exact shared line. This includes unqualified multiline records, incompatible line boundaries and failed or partial reads. |
| `unbound` | The file has no supplied binding or the acquisition ID is missing. |
| `source_changed_or_unreadable` | Source hash stability could not be established when qualifying the member. Publication still has the final integrity requirements described below. |
| `unresolved` | No qualified location is available for this member. |

For example, without a manifest an otherwise retained record has this location:

```json
{
  "status": "unbound",
  "coverage": "unqualified_record_extent",
  "native_location": {"file": "originals/auth.log", "line": 3},
  "source_refs": []
}
```

If a file binding exists but the acquisition ID is missing, a source reference can still be present, but its `exact` flag is false. It must not be used for an exact attachment.

A multiline record can retain its start reference without claiming its whole extent:

```json
{
  "status": "partial",
  "coverage": "unqualified_record_extent",
  "native_location": {"file": "originals/sysmon.log", "line": 1},
  "source_refs": [
    {
      "collection_id": "host-a",
      "path": "var/log/sysmon.log",
      "sha256": "<file-sha256>",
      "locator": {
        "kind": "text_line",
        "coordinate": "decoded_decompressed_1_based",
        "line": 1
      },
      "exact": false
    }
  ]
}
```

Do not treat that start line as an exact span or invent an end line. Bare-CR line boundaries also prevent exact shared line references for the file. An `unresolved` location has an empty `source_refs` array and may omit `coverage`.

Alert summaries use a smaller set of states:

| Member qualification | Alert `evidence_status` | `exact_members` |
| --- | --- | --- |
| All emitted members exact | `exact` | Number of emitted members |
| Some emitted members exact | `partial` | Number that are exact |
| No emitted members exact | `unresolved` | `0` |

An alert-level `unresolved` does not discard its native evidence. It can contain members whose individual state is `unbound` or `partial`.

## Read source coverage separately from alert exactness

An exact alert reference does not say how much of its source was recognised. Each `sources[]` entry reports `input_path`, pre-scan `sha256`, optional `binding`, `mtime`, `integrity`, detected `format`, `events_after_time_filter`, `skipped`, `read_error` and `coverage`.

| Source field or value | Meaning |
| --- | --- |
| `binding: null` | No shared identity was supplied for this file. |
| `integrity: unchanged_before_after` | Source hashes agreed around reading and reference qualification. |
| `integrity: unresolved` | Source integrity could not be established. |
| `coverage: not_scanned` | The source was skipped; inspect `skipped` for the reason. |
| `coverage: partial` | A read error occurred; inspect `read_error`. |
| `coverage: parser_completed_not_full_recognition` | The parser completed. This does not mean every line was understood. |
| `events_after_time_filter` | Parsed event count after time filtering, not the number of physical lines or alerts. |

For example, this coverage excerpt does not claim complete recognition, even though no read error was reported:

```json
{
  "events_after_time_filter": 12,
  "skipped": null,
  "read_error": null,
  "coverage": "parser_completed_not_full_recognition"
}
```

Do not infer absence of suspicious activity from zero alerts, a completed parser or exact references to the subset that did match.

## Rule and run metadata explain how a detection was produced

Rule objects contain `id`, `name`, `level`, `description`, `tags`, `file`, `author`, `status`, `created`, `modified`, `references`, `false_positives` and `source`. Missing metadata stays absent in meaning, for example `id: null`; consumers must not invent a Sigma ID.

`source` records the loaded YAML file's path and hash. The hash covers the whole file, including any other YAML documents in it. For example:

```json
{
  "id": null,
  "name": "Example rule without a Sigma ID",
  "level": "low",
  "source": {"path": "rules/example.yml", "sha256": "<rule-file-sha256>"}
}
```

`rule_index` addresses `run.loaded_rules`. `correlation_index` addresses `run.loaded_correlations`; each correlation member's `base_rule_index` addresses that correlation's `base_rules`. These are zero-based indexes within this run, not stable global identifiers.

`run` records:

- `id`, `tool`, `version`, `started_at` and `completed_at`.
- `executable_sha256`, `sigma_dependency` and `cargo_lock_sha256`.
- `rules`: source YAML paths and hashes; `loaded_rules` and `loaded_correlations`: loaded rule metadata and correlation base rules.
- `settings`: command arguments, working directory, timezone, inclusive time bounds, filters, forced format, loaded/failed rule counts and supplied custom-format YAML.
- `correlation_hits_skipped_missing_group_by`: base hits excluded because required grouping fields were missing.

Preserve the executable, dependencies, rule files and original evidence if you need to replay a scan. Metadata and hashes do not preserve those files for you.

Times use RFC 3339 strings with offsets. Unknown native time is not replaced with analysis or collection time. Year inference can depend on source modification time, recorded as `mtime`. For portable interpretation use an explicit named or fixed timezone with `-z` and preserve source modification times. `local` also depends on the machine's timezone environment.

## Publication and failure behaviour

The destination receives a complete JSON bundle through atomic, no-overwrite publication. It is not a stream of alert rows. The output directory must already exist and be writable.

Invalid manifests and initial binding/hash failures reject the export. Before publication, Iwatobi compares source hashes that were available initially and re-reads the rule-file inventory. A changed or newly unreadable initially hashed source, or a changed rule inventory, prevents publication. Export failures return a non-zero exit status.

Read errors and unqualified locations can instead be represented by source coverage and member states in a published bundle. A published bundle is therefore not a declaration that every source was read completely. Inspect these fields even when the command succeeds.

Ordinary output may already have been written when final forensic publication fails. Do not treat its presence as proof that the forensic bundle was published.

Originals must remain immutable. Hashes taken before and after reading do not provide snapshot isolation against a hostile writer that changes and restores a file between reads.

## Limits of the contract

This contract identifies native detections and their supporting source occurrences. It does not provide an evidence parser for another tool, an automatic importer or linker, evidence custody, or proof that a rule's attack hypothesis is true. Rule severity and ATT&CK tags describe the rule; they do not prove successful execution.

The shared exact locator described here is a qualified text line. Do not assume support for arbitrary archives, database rows, file-only references or multiline spans. An external tool's additional input formats do not add those capabilities to Iwatobi.

The exporter retains detections and builds the JSON bundle in memory. It does not promise constant memory use, complete source recognition or full-acquisition coverage.
