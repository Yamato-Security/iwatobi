# Forensic export example

This example shows how one correlation alert retains three separate log occurrences, even when their text is identical. All input is synthetic. The IP address `192.0.2.17` is reserved for documentation; no case evidence is included.

## Files

| File | Purpose |
| --- | --- |
| [access.log](access.log) | Three identical POST requests to `/index.php`, stored with LF line endings. |
| [evidence-manifest.json](evidence-manifest.json) | A complete binding manifest with the actual SHA-256 of `access.log`. |
| [forensic-output.json](forensic-output.json) | A complete JSON bundle emitted from this input and the shipped correlation rule. Only local invocation paths are sanitised: the executable name, working directory and destination path. |

The manifest's `input_path: access.log` is relative to the manifest's directory. Its shared identity is `synthetic-example-acquisition` / `synthetic-web-server` / `var/log/apache2/access.log`. That canonical path identifies the example evidence; it is not the local file to open.

The file hash is `bc1900865712d1fe1b0dd97c3f29bb2db2af356b796a78e56ea5f292590e2741`. Editing the input, including changing LF line endings to CRLF, changes its hash. If you adapt the example, calculate a new hash and update your manifest. Do not copy this manifest's hash onto different evidence.

## Run it

From the repository or unpacked release directory, with `iwatobi` on your command path:

```sh
iwatobi dfir-timeline \
  -f docs/examples/forensic/access.log \
  -r rules/iwatobi/web/webserver/web_rapid_posts_to_php_index.yml \
  -z UTC \
  --forensic-output forensic-example.json \
  --evidence-manifest docs/examples/forensic/evidence-manifest.json \
  -q -K -w -Q
```

Use a new destination each time. The export will not overwrite `forensic-example.json`, even with `--clobber`.

You should get one `correlation` alert with `count: 3`, `members_total: 3`, `members_truncated: false`, `exact_members: 3` and `evidence_status: exact`. Each member has the same native text but a different `locator.line`: 1, 2 or 3. The alert and its members retain the correlation rule and base-rule metadata respectively.

Your bundle will not be byte-identical to the sample. Run IDs, analysis times, executable hashes, source modification times and invocation paths describe your own run. Rule hashes also depend on the exact shipped rule bytes.

## Find the evidence

In [the sample output](forensic-output.json), read:

- `alerts[0].rule` for the correlation rule.
- `alerts[0].members[0].rule` for its first member's base rule.
- `alerts[0].members[0].evidence.native.raw` for the decoded log record.
- `alerts[0].members[0].evidence.location.source_refs[0]` for the original file identity and line 1.
- The second and third members for lines 2 and 3. Do not collapse them into one occurrence because their text matches.

Another tool can link to one of these members only if its supplied acquisition ID and exact source reference agree. Equal text or nearby timestamps do not establish a link. An exact reference does not prove a successful attack: these harmless requests trigger a rule about a pattern that can also occur legitimately.

## Try unbound output

Omit the manifest and use a different destination:

```sh
iwatobi dfir-timeline \
  -f docs/examples/forensic/access.log \
  -r rules/iwatobi/web/webserver/web_rapid_posts_to_php_index.yml \
  -z UTC --forensic-output forensic-unbound-example.json \
  -q -K -w -Q
```

The same correlation and all three native members remain. The acquisition is `unbound`, member locations are `unbound`, `source_refs` arrays are empty, `exact_members` is 0 and the alert's `evidence_status` is `unresolved`.

See the [contract](../../UAC_CONTRACT.md) for all evidence states, matching rules, compression semantics and limits.
