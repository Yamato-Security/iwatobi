# Native forensic detection interchange, version 1

`--forensic-output alerts.json` adds a profile-independent JSON bundle to an
ordinary offline `dfir-timeline` scan. Existing terminal/CSV/JSON/JSONL output and
Sigma evaluation are unchanged. Iwatobi still reads native original logs, **not
TraceQuarry ECS records**. This is a detection contract, not an evidence parser,
ECS event normalizer, custody system, or KamoTrace importer.

```sh
iwatobi dfir-timeline -d originals -r rules -z UTC \
  --forensic-output alerts.json --evidence-manifest bindings.json
```

Use a fresh output path outside the evidence directory. Even `--clobber` cannot
replace a forensic bundle. Publication uses a private temporary file and atomic
no-clobber persistence. The option is incompatible with live analysis. Keep the
originals immutable throughout both tools' runs; pre/post hashes detect ordinary
changes, not a hostile concurrent writer changing and restoring a file.

## Explicit binding, never path guessing

The optional local binding manifest is an adapter over the acquisition/source
inventory shared with TraceQuarry. It is **not** TraceQuarry's run manifest and is
not auto-discovered. A caller supplies the acquisition ID and copies each
canonical collection ID, source path and byte hash from the verified inventory:

```json
{
  "acquisition_id": "synthetic-acquisition",
  "sources": [
    {
      "input_path": "originals/var/log/auth.log",
      "collection_id": "collection-a",
      "path": "var/log/auth.log",
      "sha256": "<64 hexadecimal characters: original file bytes>"
    }
  ]
}
```

`input_path` is absolute or relative to the binding manifest's directory. `path`
is the source inventory's slash-separated, relative canonical path, not a
basename or a path inferred by stripping an arbitrary prefix. Reject duplicate
input mappings, duplicate `(collection_id, path)` destinations, invalid paths,
unknown fields, mismatching hashes and bindings for inputs not selected by the
scan. A selected input omitted from the manifest remains **unbound**; its alerts
are retained. Missing acquisition identity also remains unbound even if content
hashes agree. Acquisition identity is a supplied assertion, not something this
tool proves from bytes. Do not merge different acquisitions with equal content.

## Bundle and detection identities

- `schema`: `iwatobi-forensic-1.0.0`.
- `source_reference_profile`: `uac-1.0.0`, qualified against TraceQuarry's initial
  ECS 8.17.0 / UAC profile 1.0.0 implementation, not all future producers.
- `run`: UUID, executable SHA-256, Iwatobi version, pinned Sigma dependency,
  embedded Cargo.lock SHA-256, actual loaded YAML source hashes, loaded rule and
  correlation registries, invocation, working directory, effective time bounds,
  timezone, filters and exact custom-format YAML used by the parser.
- `uac.acquisition`: `{id, status}`; `status` is `supplied` or `unbound`.
- `sources`: scanned input identities/hashes, canonical bindings when supplied,
  filesystem mtime (used by native year inference), format, parser/read status
  and event count **after time filtering**. Parser completion does not certify
  recognition of every line or absence of malicious activity.
- `alerts[]`: run-local `id`, `event.kind: alert`, `kind: single|correlation`,
  `uac.run_id`, acquisition, native rule metadata, timestamp and structured members.
  IDs are detection instances, **not** TraceQuarry `event.id` or source occurrence
  IDs. New runs get distinct detection IDs even with identical results.

Rule objects retain Sigma ID (nullable), name, level, description, tags including
ATT&CK, author, dates, status, references, false positives and loaded YAML
`source.path`/`source.sha256`. Never replace a missing Sigma ID with a guessed one.
`rule_index`, `correlation_index` and member `base_rule_index` address the loaded
registries in this run; they are not stable global rule IDs. A YAML file can hold
multiple documents; the source hash binds the entire original file, not just its
metadata. Preserve those rule files and the pinned binary/dependencies to replay.
For portable timestamp replay, use an explicit named/fixed `-z` and preserve input
mtime; `local` additionally requires the same timezone environment. No collection
time or analysis time is substituted for unknown native event time. Correlation
timestamp is the latest member; `first`/`last` describe its window, not a new
historical action.

## Structured members and shared source references

Every single alert has one member. Correlations export **every internal member**
with its base-rule identity, not parsed display strings. `members_total` and
`members_truncated` describe emitted membership (currently no export sampling).
`count` is the native correlation metric and need not equal member count for a
distinct-value correlation. Skipped missing-group-by base hits are counted in
run metadata. Export does not rerun Sigma or reconstruct missing correlations.

Each member contains `evidence.native` (raw decoded record, matching text when
different, ordered typed fields, hostname/logsource, native timestamp and
inference/explicit-zone flags) and `evidence.location`:

```json
{
  "status": "exact",
  "coverage": "single_line",
  "native_location": {"file": "originals/var/log/auth.log", "line": 3},
  "source_refs": [{
    "collection_id": "collection-a",
    "path": "var/log/auth.log",
    "sha256": "<original whole-file SHA-256>",
    "locator": {
      "kind": "text_line",
      "line": 3,
      "coordinate": "decoded_decompressed_1_based"
    },
    "exact": true
  }]
}
```

The `source_refs[]` objects have the same shape and semantics as TraceQuarry's
`uac.source_refs[]`. Join only with the **same supplied acquisition**, collection,
canonical source path, original byte hash, locator kind, coordinate and line;
require `exact: true` on both sides. Never join normalized event IDs, timestamps,
raw text, usernames, IPs or basenames alone. A shared reference can support several
facts, and a grouped audit fact can contain several distinct line references.
An alert on one audit line does not mean Iwatobi evaluated the grouped transaction.
No corresponding TraceQuarry fact is a valid outcome: retain the native detection
and occurrence, do not fabricate a normalized fact. This export does not perform
the consumer's fact attachment; its `exact` status qualifies the original-log
reference, **not** a verified attachment to some other tool's output.

Repeated identical records at different lines remain separate. Gzip locators
address decompressed lines but hash **compressed original bytes**, as TraceQuarry
does. The supported shared line boundary is LF or CRLF, including blank lines and
a final unterminated line. Bare CR is deliberately inexact: Python's universal
newline reader splits it, while Iwatobi's native reader does not. Iwatobi's decoded
text removes BOM/NUL and replaces invalid UTF-8; it is labelled a native decoded
representation, never original bytes. Preserve the hashed source for byte truth.

Per-member status is `exact`, `partial`, `unbound`,
`source_changed_or_unreadable`, or `unresolved`. `exact` requires supplied binding,
unchanged source hashes, compatible line boundaries and native record equality
with that decoded physical line. Multiline or transformed records that cannot
pass this check keep their start reference with `exact: false` and
`coverage: unqualified_record_extent`; no end/span is invented. Failed/partial
reads are not exact. At alert level, `evidence_status` is `exact` only when all
members are exact, `partial` when some are exact, otherwise `unresolved`;
`exact_members` gives the count. Unresolved members and native metadata remain.

This does not certify arbitrary parsers, archives, SQLite rows, file-only
TraceQuarry references, or multiline spans. Only `.gz` decompression is native in
Iwatobi; TraceQuarry's additional compression readers do not confer Iwatobi
support. Source/rule fingerprints do not substitute for preserved evidence,
coverage qualification or chain of custody. The bundle is a versioned native
detection schema using the shared reference contract, **not a claim of full ECS
schema compliance**.

## Verification

`cargo test` includes public CLI regressions for repeated identical auth lines,
metadata/provenance, unbound detections, bad binding rejection and no-clobber
publication, plus a three-member correlation over plain and gzip originals with
partial binding, multiline records and bare-CR coordinate rejection. Existing
native parser/detection/output regressions remain.

A separate synthetic public-CLI interoperability probe applied TraceQuarry's
actual local ECS patch to upstream `e6a79d13c9e7d9c0e33ce4a4789a6b3eb1c20bf2`.
It produced eight normalized facts and six Iwatobi alerts, including one
three-member native Sigma correlation. All eight member references resolved to
the expected facts: repeated CRLF auth lines, gzip auth lines, an individual
audit member in a grouped fact, and three web access occurrences. Wrong-line,
wrong-hash and different-acquisition controls did not join. Native outputs were
identical with the exporter enabled/disabled and original byte hashes were
unchanged. This is focused compatibility evidence, not a production linker or
universal corpus qualification.
