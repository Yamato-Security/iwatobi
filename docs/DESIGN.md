# Iwatobi design (v0.1.0)

Iwatobi (イワトビ, rockhopper penguin) is Yamato Security's native Sigma scanner for Linux text
logs: the Hayabusa/Suzaku sibling for syslog-family logs, web server access/error logs and PHP
logs. Rust binary, AGPL-3.0, repo https://github.com/Yamato-Security/iwatobi (private, currently
only LICENSE + README). Version `0.1.0`, release name "Vulnpocalypse Release".

Explicitly OUT of scope for 0.1.0: auditd, sysmon-for-linux, journald binary files (we only read
`journalctl` text export), `category: proxy` rules, Windows/macOS logs, DuckDB output, GeoIP.

## 1. Command line

```
iwatobi dfir-timeline <INPUT> [OPTIONS]      # the one analysis command
iwatobi list-profiles                        # print config/profiles.yaml
iwatobi help / -h / -V
```

`dfir-timeline` options (clap derive; headings and letters mirror Hayabusa/Suzaku):

Input (exactly one required, mutually exclusive):
- `-d, --directory <DIR>`   recursive scan of a directory (rotated `.1`, `.2.gz`, `-YYYYMMDD` files included)
- `-f, --file <FILE>`       one file
- `-l, --live-analysis`     find the local logs that the loaded rules need (see §7)

General:
- `-r, --rules <DIR/FILE>`  default `./rules` (resolved relative to the executable's directory if `./rules` does not exist in the cwd, like Hayabusa)
- `-z, --timezone <TZ>`     timezone of log timestamps that carry no zone information (ex: `UTC`, `Asia/Tokyo`, `+09:00`). Default: the local timezone of the machine running iwatobi.
- `-Q, --quiet-errors`      do not write `logs/errorlog-<ts>.log`
- `-w, --no-wizard`         never prompt (live analysis skips rules whose logs are not found; journal export is still done when possible)
- `--threads <N>`           rayon thread count (default: all cores)
- `-v, --verbose`           print per-file information (detected format, line counts, skipped files) to stdout
- `-h, --help`

Filtering:
- `-m, --min-level <LEVEL>` informational (default) | low | medium | high | critical
- `-D, --enable-deprecated-rules`, `-u, --enable-unsupported-rules` (status filter; both excluded by default like Hayabusa)
- `--exclude-status <S,...>` / `--include-status <S,...>`
- `--include-tag <T,...>` / `--exclude-tag <T,...>`
- `--timeline-start <RFC3339>`, `--timeline-end <RFC3339>`, `--time-offset <1y|3M|30d|24h|30m>`

Output:
- `-o, --output <FILE>`     save results. With several `-t` types the extension is normalized per type (`timeline` + `-t csv,jsonl` → `timeline.csv`, `timeline.jsonl`; exactly like Suzaku's `resolve_output_targets`)
- `-t, --output-type <csv|json|jsonl>[,...]` default csv (only with -o)
- `-C, --clobber`           required to overwrite existing output files
- `-p, --profile <NAME>`    output profile from `config/profiles.yaml`. Defaults: stdout uses `standard`, files use `verbose`. When given, applies to every output.
- `-N, --no-summary`

Time format: `-U, --utc` (default: local time with offset, Hayabusa style `2026-10-24 15:35:38.673 +09:00`).

Display: `-K, --no-color`, `-q, --quiet` (no banner).

Startup banner (unless -q): `art/logo.txt` printed in bright green RGB(0,255,0) exactly like Suzaku's `display_logo`, then `Start time:` and `Version: 0.1.0 (Vulnpocalypse Release)`. Assets (`art/*`, `config/*`) are embedded with `include_str!` so the binary works from any cwd; if `./config/<file>` exists next to the executable or in the cwd it overrides the embedded copy.

## 2. Pipeline

```
inputs (-f/-d/-l) ──► enumerate files ──► sniff format ──► LineParser ──► ParsedEvent
                                                                            │
   rules (-r) ──► load+normalize ──► filter ──► group by logsource ─────────┤ logsource match + rule.is_match()
                                                                            ▼
                                                        Detection records (+ correlation base hits)
                                                                            │
                           sort by time ──► stdout (standard) / CSV / JSON / JSONL (verbose) ──► summary
```

Files are processed in parallel with rayon (one file per task). Every detection is kept in memory
(owned `ParsedEvent` + rule reference + file + line) and written once, sorted by timestamp
(ascending, events without a timestamp last, ties by rule title then file/line), like Hayabusa.

## 3. Core types

```rust
// logsource.rs
pub struct LogSourceTag { product: Option<&'static str>, category: Option<&'static str>, service: Option<&'static str> }
```
An event carries a *set* of tags. A rule logsource `{product?, category?, service?}` matches an event
if some tag satisfies every field the rule specifies (case-insensitive). A rule with only
`product: linux` therefore matches every syslog-family event; `service: sshd` only sshd lines.
`sigma_rust::Rule.logsource` fields are read as `Option<String>` (the `Logsource` type is not
re-exported, so pass the three `Option<&str>` values around).

Tags the parsers can produce (the "supported" set; a rule whose logsource cannot be satisfied by any
of these is counted as *unsupported* and skipped at load):

| Tag | Produced by |
|---|---|
| `product: linux, service: syslog` | every syslog-format line |
| `product: linux, service: auth` | file auth.log / secure, or process in auth set (sshd, sudo, su, login, systemd-logind, useradd/usermod/userdel/groupadd/groupmod, passwd, chpasswd, gdm*, lightdm, sddm, polkitd, unix_chkpwd, pam_*) |
| `product: linux, service: sshd` | process sshd |
| `product: linux, service: cron` | process CRON/cron/crond/anacron or file cron* |
| `product: linux, service: sudo` | process sudo |
| `product: linux, service: vsftpd` | process vsftpd or file vsftpd.log |
| `product: linux, service: clamav` | process clamd/freshclam/clamav* or dir clamav |
| `product: linux, service: guacamole` | process guacd/guacamole or file guacd.log |
| `category: webserver` (+ `product: apache|nginx` when known from the path) | access logs (text or JSON) |
| `product: apache, service: apache` | Apache error log lines (incl. untimestamped stderr lines) |
| `product: nginx, service: nginx` | nginx error log lines |
| `product: php, service: error_log` | PHP error log lines, and Apache error-log lines whose module is `php*` |
| `product: php, service: fpm` | php-fpm master log lines |

Rules with `logsource: service: apache` (no product) match via the `service` field alone.

```rust
// event.rs
pub enum FieldValue { Str(String), Int(i64), UInt(u64), Bool(bool) }
pub struct ParsedEvent {
    pub timestamp: Option<DateTime<FixedOffset>>,
    pub timestamp_inferred: bool,     // borrowed from the previous entry (untimestamped line)
    pub hostname: Option<String>,
    pub primary_logsource: String,    // rendered in the LogSource column, e.g. "linux/sshd", "webserver", "apache", "php/error_log"
    pub tags: Vec<LogSourceTag>,
    pub fields: Vec<(String, FieldValue)>,  // ordered; the first `details_len` form the Details column
    pub details_len: usize,
    pub raw: String,
}
impl ParsedEvent {
    /// sigma_rust::Event with every field plus `raw` (the whole line) and `hostname`.
    pub fn to_sigma_event(&self) -> sigma_rust::Event;
}
```

## 4. Parsers (`src/parsers/`)

```rust
pub enum LogFormat { Syslog, AccessLog, AccessJson, ApacheError, NginxError, PhpError, PhpFpm }
pub struct ParseContext { file: PathBuf, tz: TzAssumption, year_hint: i32, mtime: Option<DateTime<Utc>>,
                          product_hint: Option<&'static str>, file_service_hints: Vec<LogSourceTag>,
                          hostname_hint: Option<String>, extra_tags: Vec<LogSourceTag> }
pub enum TzAssumption { Local, Fixed(FixedOffset), Named(chrono_tz::Tz) }
pub trait LineParser { fn parse_line(&mut self, line: &str) -> Option<ParsedEvent>; }  // None only for blank lines
pub fn parser_for(format, ctx) -> Box<dyn LineParser>;
pub fn sniff_format(sample: &[String], path: &Path) -> Option<LogFormat>;
```

Uniform policy: **every non-blank line becomes one event.** A line that does not match the format's
entry pattern is a *continuation* event: same tags, `message` = whole line, timestamp = the previous
entry's timestamp with `timestamp_inferred = true` (None if there was none yet). This is what makes
the untimestamped `sh: 1: wget: not found` lines in Apache error logs detectable and placeable.

Timestamps without zone information are interpreted in `TzAssumption` (default Local). Output is
converted to local time or UTC (-U) at render time.

### 4.1 Syslog (`syslog.rs`)
Accepts, per line (optional `<PRI>` prefix allowed on all):
1. RFC 3164: `Oct 26 17:39:01 host proc[pid]: msg` (no year: year = `year_hint`, minus one if the resulting date is more than one day after `mtime`), also with a 4-digit year after the time (some rsyslog templates).
2. rsyslog high precision / RFC 3339: `2026-10-26T17:39:01.123456+09:00 host proc[pid]: msg`.
3. RFC 5424: `<34>1 2026-10-26T17:39:01Z host app procid msgid [sd] msg` (`-` for nil); fields `facility`, `severity` from PRI, `msgid`, `structured_data`.
4. `journalctl -o short-iso` / `short-iso-precise`: `2026-10-26T17:32:36+0900 host proc[pid]: msg` (offset without colon).
Process regex: `^([^\s:\[]+(?:\([^)]*\))?)(?:\[(\d+)\])?:\s?(.*)$` → `process`, `pid`, `message`; no match → `message` = rest. Kernel lines (`kernel: [123.456] ...`) keep `process = kernel`.
Fields order: process, pid, message (Details) | facility, severity, msgid, structured_data (Extra).
Tags: always `linux/syslog`; plus file-derived (`auth.log*`/`secure*` → auth; `cron*` → cron; `vsftpd*` → vsftpd; `clamav/` → clamav; `guacd*` → guacamole) plus process-derived (table above).
`primary_logsource` = `linux/<most specific service>` (process-derived > file-derived > syslog).

### 4.2 Access log, text (`access.rs`)
Regex (CLF / combined / Apache `vhost_combined` / nginx `combined`, tolerant of trailing extras):
```
^(?:(?P<vhost>[^\s"]+?:\d+) )?(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<req>(?:[^"\\]|\\.)*)" (?P<status>\d{3}|-) (?P<bytes>\d+|-)(?: "(?P<ref>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?(?P<extra>.*)$
```
Request line `METHOD URI VERSION` (if it has fewer parts: `cs-uri` = whole string). Time `26/Oct/2026:17:39:01 +0900` (zone present → used as-is).
Fields (Sigma webserver taxonomy; SigmaHQ rules use `cs-uri-query` for the WHOLE path, so):
`c-ip`, `cs-method`, `cs-uri-query` (= full request target `path?query`), `sc-status` (int), `sc-bytes` (int; `-` → 0), `cs-referer`, `cs-user-agent` (Details) | `cs-uri-stem` (path only), `cs-uri` (= full target), `cs-version`, `cs-username`, `cs-host` (vhost), `c-useragent` (alias of cs-user-agent), `extra` (Extra).
Tags: `webserver`, and `webserver+product` if the path contains `apache2|httpd` → apache, `nginx` → nginx. `primary_logsource` = `webserver`.

### 4.3 Access log, JSON lines (`access.rs`, `LogFormat::AccessJson`)
One JSON object per line (Apache/nginx JSON `LogFormat`s, the honeypot `web.jsonl`). Every original
key is kept as a field (nested objects flattened with `.`), and taxonomy fields are added from the
first matching alias (case-insensitive):
- `c-ip`: remote_addr, remote_ip, client_ip, clientip, client, peerIp, peer_ip, src_ip, srcip, ip
- `cs-method`: method, request_method, http_method, verb
- `cs-uri`/`cs-uri-query`/`cs-uri-stem`: uri, request_uri, url, path, request_path, request (if `request` looks like `METHOD URI VERSION` it is split and also fills method/version)
- `cs-version`: proto, protocol, server_protocol, http_version, version
- `sc-status`: status, status_code, response_code, sc_status
- `sc-bytes`: bytes, bytes_sent, body_bytes_sent, respBytes, resp_bytes, response_bytes, size
- `cs-referer`: referer, referrer, http_referer, http_referrer
- `cs-user-agent` (+`c-useragent`): user_agent, useragent, http_user_agent, ua, agent
- `cs-host`: host, vhost, server_name, http_host
- `cs-username`: user, remote_user, username, auth_user
- timestamp: ts, time, timestamp, @timestamp, time_local (CLF `26/Oct/2026:17:39:01 +0900`), time_iso8601, datetime, date, msec, time_msec, timestamp_ms (RFC 3339 / CLF / epoch seconds or milliseconds)
Details = same seven keys as 4.2; everything else is Extra. Sniffing: a line that parses as a JSON
object containing a method-ish AND a status-ish key (or `request`) is AccessJson; other JSON lines are
unsupported (file skipped with a warning).

### 4.4 Apache error log (`apache_error.rs`)
2.4: `[Sat Oct 24 15:35:39.379473 2026] [core:notice] [pid 1:tid 1] [client 1.2.3.4:5678] AH00051: ...`
2.2: `[Sat Oct 24 15:35:39 2026] [error] [client 1.2.3.4] msg`
Time has no zone (→ TzAssumption). Fields: `module`, `level`, `pid`, `tid`, `client`, `c-ip` (client without port), `error_code` (`AH\d{5}` if present), `message` (Details: module, level, pid, client, message). Module `php*` adds tag `php/error_log`. Tags: `apache` (`product: apache, service: apache`). `primary_logsource` = `apache`.

### 4.5 nginx error log (`nginx_error.rs`)
`2026/10/24 15:35:39 [error] 1234#1234: *5 upstream prematurely closed connection ..., client: 1.2.3.4, server: _, request: "POST /index.php HTTP/1.1", upstream: "fastcgi://unix:/run/php/php8.3-fpm.sock:", host: "example.com", referrer: "..."`
Fields: `level`, `pid`, `tid`, `connection`, `message` (without the trailing `, key: value` pairs), `client`, `c-ip`, `server`, `request`, `upstream`, `host`, `referrer`. Details: level, pid, client, request, upstream, message. Tags: `nginx`. Lines like `worker process 1234 exited on signal 6 (core dumped)` are normal entries.

### 4.6 PHP error log (`php.rs`, `LogFormat::PhpError`)
`[24-Oct-2026 15:35:33 UTC] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0`
Zone token: IANA name via `chrono_tz::Tz::from_str` (`UTC`, `Europe/Berlin`), else TzAssumption with one warning per file. Fields: `php_type` (`Fatal error`, `Warning`, `Notice`, `Deprecated`, `Parse error`, `Stack trace`, ...), `message` (text after `PHP <type>:`), `file`, `line` (from trailing ` in <file> on line <n>`). Details: php_type, message, file, line. Tags: `php/error_log`.

### 4.7 php-fpm log (`php.rs`, `LogFormat::PhpFpm`)
`[24-Oct-2026 15:35:33] WARNING: [pool www] child 123 exited on signal 11 (SIGSEGV - core dumped) after 1.234 seconds from start`, `... child 123 said into stderr: "sh: 1: wget: not found"`, `[24-Oct-2026 15:35:33.123] NOTICE: fpm is running, pid 1`.
No zone → TzAssumption. Fields: `level`, `pool`, `child_pid`, `message`. Tags: `php/fpm`. Sniff rule: the FPM pattern (`] LEVEL: `) wins over PhpError when it matches.

### 4.8 Sniffing (`parsers/mod.rs`)
Read up to 64 non-blank lines (after gzip decompression). Skip the file if any sampled line contains NUL. Count entry-pattern matches per format; the best format must match ≥ 50 % of sampled lines, filename hints break ties (`access` → AccessLog/AccessJson, `error` under `apache2|httpd` → ApacheError, under `nginx` → NginxError, `fpm` → PhpFpm, `php` → PhpError, `syslog|messages|auth.log|secure|cron|kern.log|daemon.log|user.log|mail.log|vsftpd.log|guacd` → Syslog). No format → file skipped, warning in the error log (`-v` prints it).

## 5. Input enumeration (`input.rs`)
`-d` recurses; regular files only; `.gz` decoded with `flate2::read::MultiGzDecoder`; `.xz/.bz2/.zst/.journal`, `wtmp/btmp/lastlog` and zero-length files are skipped with a warning. Lines are read as bytes and converted with `from_utf8_lossy`; `\r` stripped; 1-based `LineNumber`. `ScanTarget { path, display_name, extra_tags }` is the unit of work (live analysis uses `extra_tags` and `display_name`, e.g. `journalctl`).

## 6. Rules (`rules.rs`)
- Walk `-r`; load `*.yml`/`*.yaml`.
- Each file is split into YAML documents with `yaml_serde::Deserializer::from_str(text)` iterated into `yaml_serde::Value`s. A file is a *correlation file* if any document has a `correlation` key.
- **Keyword normalization (critical).** sigma-rust matches a field-less list entry against WHOLE
  field values (`event.rs::contains_keyword` → `match_tokenized`), while the Sigma spec says keywords
  match anywhere in the log message and SigmaHQ Linux rules are almost all keyword lists (`stopping
  iptables`, `REPLACE`, `' denied AXFR from '`, `Trojan*FOUND`). Before deserializing a `Rule`, every
  `detection` entry (any key except `condition`) whose value is a sequence of scalars is rewritten:
  each string `s` becomes `*s*` unless it already starts/ends with an unescaped `*` (a trailing odd
  run of backslashes gets one more backslash before the appended `*`); numbers/bools become `*<text>*`
  strings. Map-shaped selections (field: value) are left untouched. Then `yaml_serde::from_value::<Rule>`.
- Correlation files: base documents are normalized and parsed as above; correlation documents are
  parsed with `from_value::<SigmaCorrelationRule>`. sigma-rust's `process_events` matches base events to
  a correlation by **`event.rule.title`**, so each entry of `correlation.rules` is resolved against the
  file's base rules by `name`, `id` or `title` and rewritten to that rule's `title` before
  `engine.add_correlation_rule`; base rules are added with `engine.add_base_rule(title, rule)`. Base
  rules of a correlation file are NOT loaded as standalone rules (their hits are only emitted when
  `generate: true`, exactly like Suzaku).
- Filters, in order: unsupported logsource (see §3) → status (`deprecated`/`unsupported` dropped unless -D/-u; `--include/exclude-status`) → `--min-level` → tags. Counters are printed like Suzaku: `Total detection rules`, `Total correlation rules`, `Rules skipped (unsupported log source / status / level)`, `Rules failed to load` (details in the error log).
- `RuleFile` = file name; `RuleID` = `id`; `Level` = lowercase of `format!("{:?}", level)`; `Status` same.
- Rules are grouped by their logsource triple; for each event only the groups whose triple matches the event's tags are evaluated.

## 7. Live analysis (`live.rs`, Linux only, `-l`)
1. Collect the distinct logsource triples of the loaded rules.
2. `config/log_locations.yaml` maps each triple to glob patterns:
```yaml
- logsource: {product: linux, service: syslog}
  paths: ["/var/log/syslog*", "/var/log/messages*"]
- logsource: {product: linux, service: auth}
  paths: ["/var/log/auth.log*", "/var/log/secure*"]
- logsource: {product: linux, service: sshd}
  paths: ["/var/log/auth.log*", "/var/log/secure*", "/var/log/syslog*", "/var/log/messages*"]
- logsource: {product: linux, service: cron}
  paths: ["/var/log/cron*", "/var/log/syslog*", "/var/log/messages*"]
- logsource: {product: linux, service: sudo}
  paths: ["/var/log/auth.log*", "/var/log/secure*", "/var/log/sudo.log*"]
- logsource: {product: linux, service: vsftpd}
  paths: ["/var/log/vsftpd.log*", "/var/log/xferlog*"]
- logsource: {product: linux, service: clamav}
  paths: ["/var/log/clamav/*.log*"]
- logsource: {product: linux, service: guacamole}
  paths: ["/var/log/guacd*.log*", "/var/log/tomcat*/catalina.out*", "/var/log/syslog*", "/var/log/messages*"]
- logsource: {product: linux}
  paths: ["/var/log/syslog*", "/var/log/messages*", "/var/log/auth.log*", "/var/log/secure*", "/var/log/cron*", "/var/log/kern.log*", "/var/log/daemon.log*", "/var/log/user.log*"]
- logsource: {service: apache}
  paths: ["/var/log/apache2/error*.log*", "/var/log/apache2/*error*.log*", "/var/log/httpd/error_log*", "/var/log/httpd/*error_log*"]
- logsource: {service: nginx}
  paths: ["/var/log/nginx/error*.log*", "/var/log/nginx/*error*.log*"]
- logsource: {category: webserver}
  paths: ["/var/log/apache2/access*.log*", "/var/log/apache2/*access*.log*", "/var/log/httpd/access_log*", "/var/log/httpd/*access_log*", "/var/log/nginx/access*.log*", "/var/log/nginx/*access*.log*"]
- logsource: {product: php, service: error_log}
  paths: ["/var/log/php_errors.log*", "/var/log/php-errors.log*", "/var/log/php/*.log*", "/var/log/php*.log*", "/var/log/apache2/error*.log*", "/var/log/httpd/error_log*"]
- logsource: {product: php, service: fpm}
  paths: ["/var/log/php*-fpm.log*", "/var/log/php-fpm/*.log*", "/var/log/php-fpm.log*"]
```
   (Matching a rule triple to table rows: a rule `{product: linux, service: sshd}` uses the row with the
   same triple; a rule with only `product: linux` uses the `{product: linux}` row; a rule `{service: apache}`
   the `{service: apache}` row. Unknown triple → treated as not found.)
3. Expand globs; keep readable regular files (unreadable → warning "permission denied — run as root or a member of adm"). Files found via a row get that row's logsource as `extra_tags`.
4. If no file exists for a triple that at least one rule needs: with `--no-wizard` skip those rules (count reported); otherwise prompt with `dialoguer::Select`:
   `No log files were found for rules with logsource {product: linux, service: cron} (1 rule). ▸ Enter a directory or file to scan ▸ Skip these rules`. An entered path is sniffed like `-d`/`-f` and its events additionally receive that triple as `extra_tags`.
5. If no syslog-family file exists at all and `journalctl` is on PATH: run `journalctl --no-pager -q -o short-iso-precise` (plus `--since` from `--time-offset`/`--timeline-start` when given) into a temp file and scan it as Syslog with `display_name = "journalctl"`; with the wizard, ask first (default Yes).
6. `Computer` for events without a hostname = the system hostname.

## 8. Detection (`detect.rs`)
Per `ScanTarget`: sniff → parser → for each line → `ParsedEvent` → time filter (`--timeline-*`; events without timestamp pass) → `to_sigma_event()` once → evaluate matching rule groups → `Detection { event: ParsedEvent, rule: &Rule, file: Arc<str>, line: usize }`. Correlation base rules are evaluated the same way; hits with a timestamp become `TimestampedEvent { event, timestamp (UTC), rule }`. After all files: `engine.process_events(&all)`; a matched result becomes a correlation detection (title/level from the correlation rule, timestamp = max member timestamp, Details = `Count: n ¦ Rules: t1, t2 ¦ Window: first..last`, LogSource = `correlation`), and member events are emitted only when `generate: true`.
Counters: total events, events with hits (counted once per event), per level / per rule / per date (UTC date of event) counts, first/last event time, scanned/skipped files, per-format file counts (for -v).

## 9. Output (`output/`)
`config/profiles.yaml` (Hayabusa format, `%Placeholder%` values):
```yaml
minimal:   Timestamp, RuleTitle, Level, Details
standard:  Timestamp, RuleTitle, Level, Computer, LogSource, Details
verbose:   Timestamp, RuleTitle, Level, Computer, LogSource, MitreTactics, MitreTags, OtherTags, LineNumber, Details, ExtraFieldInfo, RuleFile, RuleID, LogFile
super-verbose: verbose + RuleAuthor, RuleCreationDate, RuleModifiedDate, Status, Description, References, FalsePositives, RawLine
all-field-info: Timestamp, RuleTitle, Level, Computer, LogSource, LineNumber, AllFieldInfo, RuleFile, RuleID, LogFile
all-field-info-verbose: all-field-info + MitreTactics, MitreTags, OtherTags, RuleAuthor, Status
```
Placeholders: Timestamp, RuleTitle, Level, Computer, LogSource, MitreTactics (abbreviated through `config/mitre_tactics.txt`, Suzaku's file), MitreTags (`attack.t1190` → `T1190`, `attack.g0001` → `G0001`, `attack.s0001`), OtherTags (every other tag, e.g. `cve.2026-109618`), LineNumber, Details, ExtraFieldInfo, AllFieldInfo, RuleFile, RuleID, LogFile, RuleAuthor, RuleCreationDate, RuleModifiedDate, Status, Description, References, FalsePositives, RawLine.
- stdout: columns joined with ` · `, whole row colored by level (critical red 255,0,0; high orange 255,175,0; medium yellow 255,255,0; low green 0,255,0; informational default). Details/ExtraFieldInfo rendered `Key: value ¦ Key: value`; multi-valued placeholders joined with ` ¦ `.
- CSV: header row = profile keys; same string rendering; every field passes `sanitize_csv_field` (CWE-1236, as in Suzaku).
- JSON: one pretty-printed array of objects. JSONL: one compact object per line. In both, Details/ExtraFieldInfo/AllFieldInfo are nested objects, tag/reference placeholders are arrays, LineNumber is a number, empty values are `null`-free: missing → `-` like Hayabusa? → **No: in JSON use `null` for absent scalars and omit nothing**; in CSV/stdout absent values render as `-`.
- Timestamp: `%Y-%m-%d %H:%M:%S%.3f %:z` in local time, or UTC with `-U`; inferred timestamps are rendered the same (the `timestamp_inferred` flag is exposed as an `ExtraFieldInfo` entry `TimestampInferred: true`).
- `-o` without `-t` → csv. Existing files require `-C`.
Summary (unless -N), after the rows, like Suzaku/Hayabusa: `Results Summary` (events with hits / total events, data reduction), per-level `Total | Unique` counts, first/last event time, dates with most detections per level, `Top <level> alerts` tables (comfy-table), rule authors table, `Scanned files: N (skipped: M)`, `Results saved:` paths with sizes, `Elapsed time`.

Errors/warnings go to `logs/errorlog-<YYYYMMDD_HHMMSS>.log` (created lazily, first line = command line; Suzaku's `errorlog.rs` design), and the run ends with `Warnings and errors: N messages saved to <path>`.

## 10. Rules shipped in `rules/`
```
rules/sigma/linux/builtin/syslog/lnx_syslog_security_tools_disabling_syslog.yml   (SigmaHQ, verbatim)
rules/sigma/linux/builtin/syslog/lnx_syslog_susp_named.yml
rules/sigma/linux/builtin/sshd/lnx_sshd_susp_ssh.yml
rules/sigma/linux/builtin/cron/lnx_cron_crontab_file_modification.yml
rules/sigma/web/product/apache/web_apache_segfault.yml
rules/sigma/web/product/apache/web_apache_threading_error.yml
rules/sigma/web/product/nginx/web_nginx_core_dump.yml
rules/iwatobi/php/php2shell/...          (new, see §11)
rules/iwatobi/web/apache/...  rules/iwatobi/web/nginx/...  rules/iwatobi/web/webserver/...
rules/README.md                           (layout, how keyword normalization works, how to add rules)
```

## 11. PHP2Shell rules (CVE-2026-109618 / CVE-2026-109619), confirmed against the 0x4D31 honeypot evidence
Evidence (35 confirmed RCE cases, CC-BY-4.0): php-error.log, apache-error.log, apache stderr lines, web.jsonl (JSON access records). Message shapes observed:
- `PHP Fatal error:  Allowed memory size of N bytes exhausted (tried to allocate N bytes) in Unknown on line 0` (139×) — pre-script OOM (memory-pressure stages A1/A2)
- `PHP Warning:  PHP Request Startup: Session ID is too long or contains illegal characters. ...` (51×) — oversized PHPSESSID disclosure stage (B1)
- `PHP Warning:  PHP Request Startup: Failed to read session data: files (path: /tmp) in Unknown on line 0` / `Failed to write session data (files)...` (51× each) — side effect of B1
- `PHP Warning:  file_get_contents(http://162.35.99.94:8080/pwn-...): Failed to open stream: Connection timed out in Command line code on line 1` (9×) — `php -r` callback from the spawned shell
- Apache: `AH00051: child pid 31 exit signal Segmentation fault (11), possible coredump in /etc/apache2` (83×), `exit signal Abort (6)` (7×)
- Apache stderr (untimestamped): `sh: 1: wget: not found` (19×), `sh: 1: cannot create /var/www/html/p1: Read-only file system` (10×)
- Access: `POST /?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v` (52×, PoC memory-pressure request), `POST /` and `POST /index.php` with 200, no User-Agent; 4 POSTs within ~6 s per chain.

Rules (all `author: Zach Mathis (@yamatosecurity)`? → use `Yamato Security`; `date: 2026/10/26`; `references`: Wiz PHP2Shell blog, watchTowr, 9bie PoC, honeypot-data report; `tags: attack.initial-access, attack.t1190, cve.2026-109618`):
1. `php_pre_script_memory_exhaustion.yml` — "PHP Memory Exhausted Before Script Execution (PHP2Shell Memory Pressure)", logsource `product: php, service: error_log`, keywords `Allowed memory size of * exhausted * in Unknown on line 0`, level high.
2. `php_session_id_too_long.yml` — "PHP Session ID Too Long Or Illegal Characters (PHP2Shell Memory Disclosure)", keywords `Session ID is too long or contains illegal characters`, level high.
3. `php_outbound_request_from_command_line_code.yml` — "PHP Outbound HTTP Request From Command Line Code", keywords `file_get_contents(http*in Command line code on line`, `fopen(http*in Command line code on line`, `curl_exec(*in Command line code on line`, level medium, tags attack.command-and-control attack.t1105 attack.execution attack.t1059.
4. `php_post_content_length_exceeds_limit.yml` — "PHP POST Content-Length Exceeds Limit", keywords `POST Content-Length of * bytes exceeds the limit of * bytes`, level low, status experimental (attempt indicator from the 22–24 Oct report; not in the released case files).
5. `apache_worker_exit_abort_bus_error.yml` (rules/iwatobi/web/apache) — "Apache Worker Process Exited On Abort Or Bus Error Signal", `service: apache`, keywords `exit signal Abort (6)`, `exit signal Aborted (6)`, `exit signal Bus error (7)`, `exit signal Illegal instruction (4)`, `exit signal Floating point exception (8)`, level high (complements SigmaHQ's segfault rule).
6. `apache_shell_error_output_in_error_log.yml` — "Shell Error Output In Apache Error Log", `service: apache`, keywords `sh: *: not found`, `sh: *: cannot create *`, `sh: *: Permission denied`, `sh: *: command not found`, `/bin/sh: *`, `bash: *: command not found`, `/bin/bash: *`, level high, tags attack.execution attack.t1059.004.
7. `php_fpm_child_exited_on_signal.yml` — "PHP-FPM Child Process Exited On Signal", `product: php, service: fpm`, keywords `exited on signal 11 (SIGSEGV`, `exited on signal 6 (SIGABRT`, `exited on signal 7 (SIGBUS`, level high, experimental (FPM analogue; synthetic fixture).
8. `php_fpm_child_shell_stderr.yml` — "PHP-FPM Child Shell Error Output", keywords `said into stderr: "sh: `, `said into stderr: "/bin/sh: `, `said into stderr: "bash: `, level high, experimental.
9. `web_php2shell_memory_pressure_request.yml` (rules/iwatobi/web/webserver) — "PHP2Shell PoC Memory Pressure Request", `category: webserver`, selection `cs-method: POST`, `cs-uri-query|contains: 'q0000000=v&q0000001=v'`, level high.
10. `web_rapid_posts_to_php_index.yml` — correlation file: base rule "POST Request To Web Root Or PHP Index" (`cs-method: POST`, `cs-uri-stem: ['/', '/index.php']`, level informational, `name: post_to_php_index`) + `event_count` correlation "Rapid Repeated POST Requests To PHP Index Page" group-by `c-ip`, timespan 30s, `gte: 3`, level medium, generate false.
11. `php2shell_exploitation_chain.yml` — correlation file (temporal): base rules (named copies) `php2shell_oom` (rule 1 detection), `php2shell_session_id` (rule 2 detection), `php2shell_worker_crash` (`service: apache`, keywords `exit signal Segmentation fault`, `exit signal Abort`), correlation type `temporal`, no group-by, timespan 5m, level critical, title "PHP2Shell Exploitation Chain (Memory Pressure, Memory Disclosure, Worker Crash)".

## 12. Test fixtures (`test_files/`)
- `test_files/php2shell/` (derived from 0x4D31/honeypot-data `reports/php2shell/2026-10-24-rce-evidence`, CC-BY-4.0, attribution in `test_files/php2shell/README.md`): `php-error.log` (all PHP lines, deduplicated, time-sorted), `apache2/error.log` (AH00051 lines with the `sh:` stderr lines placed just before the crash of their case, plus a few benign `AH00163`/`AH00094` notices), `apache2/access.jsonl` (web.jsonl records), `apache2/access.log` (combined-format rendering of the same records, `"-" "-"` referer/UA since the requests had no User-Agent).
- `test_files/php2shell-fpm/` (synthetic): `php8.3-fpm.log` with worker crashes and `said into stderr` lines, `nginx/error.log` with upstream errors.
- `test_files/linux/`: synthetic `syslog` (RFC 3164, cron REPLACE, iptables stopping, named errors), `auth.log` (sshd error keywords), `secure` (RHEL), `cron.log`, `syslog.2.gz` (rotated), `rsyslog-iso.log`, `rfc5424.log`, `journalctl-short-iso.log`.
- `test_files/web/`: `apache2/error.log` with the threading error, `nginx/error.log` with `exited on signal 6 (core dumped)`, `apache2/access.log` combined sample, `nginx/access.json` sample.
Every shipped rule has at least one fixture line that fires it, and integration tests assert the exact count of detections per rule per fixture file.

## 13. Tests & CI
- Unit tests next to each module (parsers: one test per accepted line shape plus continuation/year-rollover/zone cases; rules: normalization incl. escaping edge cases and correlation name resolution; logsource matching; profiles; CSV sanitization; output path resolution).
- Integration tests `tests/cli.rs` run the built binary (`env!("CARGO_BIN_EXE_iwatobi")`) against `test_files/` with `-q -K`, check exit codes, detection counts, CSV header/rows, JSON validity, `-C` refusal, `--no-wizard` with a fake missing logsource.
- `.github/workflows/rust.yml`: on push to main and PRs: matrix ubuntu-latest / macos-latest / windows-latest; steps `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings` (`RUSTFLAGS=-D warnings`), `cargo build --locked`, `cargo test --locked`; Swatinem/rust-cache; actions SHA-pinned like Suzaku. Cargo.lock committed (binary).
- `Cargo.toml`: edition 2024, `rust-version = "1.88"`, deps with explicit floors (Suzaku's rule): clap 4 (derive), sigma-rust (git tag v0.7.2), yaml_serde 0.10, serde/serde_json 1, chrono 0.4, chrono-tz 0.10, regex 1, flate2 1 (zlib-rs), csv 1, termcolor 1, comfy-table 8, num-format 0.4, bytesize 2, terminal_size 0.4, rayon 1, glob 0.3, dialoguer 0.12, indicatif 0.18, hostname 0.4; dev: tempfile 3.
- Release profile: `lto = "fat"`, `codegen-units = 1`, `strip = true`? (Hayabusa uses lto/codegen-units; keep `strip = "debuginfo"`).

## 14. Docs
README.md in Suzaku's style (logo, about, features, download/build, `dfir-timeline` usage incl. live analysis, output profiles, rules layout + keyword normalization note, PHP2Shell rule set, contributing, license), CHANGELOG.md (`## 0.1.0 [Unreleased] "Vulnpocalypse Release"`), rules/README.md, test_files/php2shell/README.md (attribution), docs/ARCHITECTURE.md (this document, trimmed).

## 15. Amendments after the adversarial design review (binding; they override the sections above)

A1. **Process → service tags are case-insensitive patterns, not exact names.** cron: `^(cron|crond|crontab|anacron)$`; sshd: `^sshd(-session|-auth)?$` (OpenSSH ≥ 9.8 logs per-connection messages as `sshd-session`, 10.x adds `sshd-auth`); auth: the sshd set plus `^(su|sudo|login|systemd-logind|useradd|usermod|userdel|groupadd|groupmod|groupdel|passwd|chpasswd|gdm.*|lightdm|sddm|polkitd|unix_chkpwd|pam_.*)$`; php: `^php(-fpm.*|-cgi.*|[0-9.]*)$` → tag `php/error_log`. Process names may carry a path (`/usr/sbin/cron`): compare the final path component.

A2. **`FieldValue::Null` exists and numbers are always `i64`.** `FieldValue { Str, Int(i64), Bool, Null }` (no `UInt`: sigma-rust compares `Int` and `Unsigned` as unequal and YAML numbers deserialize as `Int`). `to_sigma_event` inserts `Null` as `None`. Every access-log event always carries the full taxonomy key set `c-ip, cs-method, cs-uri, cs-uri-stem, cs-uri-query, cs-version, sc-status, sc-bytes, cs-referer, cs-user-agent, c-useragent, cs-host, cs-username`; CLF `-` (and JSON `-`/missing/empty) for referer, user-agent, username, host, ident, status and request → `Null`; `sc-bytes` `-` → `Int(0)`. JSON numeric-looking strings for `sc-status`, `sc-bytes`, `cs-bytes`, `time-taken`, `s-port`, `pid`, `tid` → `Int` on the taxonomy key (the original key keeps its string). Rendering: `Null` → `-` in stdout/CSV, `null` in JSON.

A3. **PHP messages are recognized inside every other log.** After each parser extracts `message`, apply `^(?:.*?PHP message: )?PHP (?P<type>Fatal error|Warning|Notice|Deprecated|Parse error|Strict Standards|Recoverable fatal error|Core Warning|Core Error|Compile Error|Compile Warning|User Error|User Warning|User Notice|User Deprecated|Stack trace):\s{1,2}(?P<text>.*)$`; on match add tag `php/error_log` and fields `php_type`, `php_message`, `file`, `line` (` in <file> on line <n>` / ` in <file>:<n>` optional). Covers mod_php `[:error]` and `[php:error]`, `proxy_fcgi` `AH01071: Got error 'PHP message: ...'`, nginx `FastCGI sent in stderr: "PHP message: ..."`, php-fpm `said into stderr: "PHP ..."` and syslog `php[1234]: PHP ...`.

A4. **Apache error entry regex**: `^\[(?P<time>\w{3} \w{3} +\d{1,2} \d\d:\d\d:\d\d(?:\.\d{1,6})? \d{4})\] \[(?:(?P<module>[^:\]]*):)?(?P<level>\w+)\](?: \[pid (?P<pid>\d+)(?::tid (?P<tid>\d+))?\])?(?: \[client (?P<client>[^\]]+)\])? (?P<msg>.*)$` (prefork has no tid; CentOS mod_php logs `[:error]` with an empty module). `c-ip`: when the module group participated (2.4 header) and the text after the last `:` is all digits, strip it; otherwise `client` verbatim (2.2 logs `[client 2001:db8::1]` without a port). A trailing `, referer: <url>` is split into field `referer`. Extra tags: `product: apache, service: error` (taxonomy-canonical) in addition to `product: apache, service: apache`.

A5. **Syslog shapes**: RFC 3164 = `^(?:<(?P<pri>\d{1,3})>)?(?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<hms>\d\d:\d\d:\d\d)(?P<frac>\.\d{1,9})?(?: (?P<year>\d{4}))? (?P<host>\S+) (?P<rest>.*)$` (fractional seconds and space-padded day, optional year). RFC 5424 structured data = `-` or one or more `\[([^ =\]"]+)(?: ([^ =\]"]+)="((?:[^"\\]|\\.)*)")*\]` elements; after SD skip one space, an optional UTF-8 BOM and at most one more space before `message`. New **AppLog shape** (date-first daemon logs, no hostname): `^(?P<time>[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d \d{4}) (?P<rest>.*)$` with `rest` = `[pid N] [user] msg` (vsftpd), `-> msg` (clamd/freshclam) or anything else (xferlog); tags come from the file name (`vsftpd*`/`xferlog*` → `linux/vsftpd`, `clamav/`/`clamd*`/`freshclam*` → `linux/clamav`, else `linux/syslog`), `Computer` = hostname hint. `catalina.out` is dropped from the guacamole row.

A6. **Sniffing**: path hints are a prior, not a tie-breaker. If the file name/parents hint a format and ≥ 1 sampled line matches that format's entry pattern (or ≥ 10 %), use it; unhinted files need ≥ 50 %. Lines that look like continuations (leading whitespace, `#\d+ `, `Stack trace:`, `  thrown in`, `sh: `, `/bin/sh: `) are neutral in the denominator. New option `--log-format <syslog|applog|access|access-json|apache-error|nginx-error|php-error|php-fpm>` forces the parser for every input file (e.g. the honeypot `apache-stderr-segment.log`, 100 % untimestamped lines). Path hints are implemented with `Path::components()`/`file_name()` comparisons, never `/`-delimited substring tests (Windows CI).

A7. **Timestamps**: naive local times resolve with `from_local_datetime(&naive)` → `single()`, else `earliest()`, else (DST gap) `naive + 1h`; one warning per file on ambiguity. Year inference retries `year_hint - 1` when the date is invalid for `year_hint` (Feb 29). Epoch values: `< 1e11` seconds (fractional allowed), `< 1e14` milliseconds, else microseconds; separate `date` + `time` JSON keys are combined. PHP zone token: IANA name, then `[+-]HH:MM`, then TzAssumption with one warning per file; the zone may be absent (no warning). When one scan mixes zone-carrying and zone-less sources and `-z` was not given, print one warning (`-z UTC` is what the honeypot fixtures need, and the integration tests pass it). `-z` takes `allow_hyphen_values = true` (so `-z -05:00` works).

A8. **nginx error**: entry `^(?P<time>\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) \[(?P<level>\w+)\] (?P<pid>\d+)#(?P<tid>\d+):(?: \*(?P<conn>\d+))? (?P<rest>.*)$`; then repeatedly strip from the END of `rest` a suffix `, (client|server|request|upstream|host|referrer|subrequest): ("(?:[^"\\]|\\.)*"|[^,]*)$` until nothing matches; the remainder is `message` (quote-aware, right-to-left). Extra tag `product: nginx, service: error`.

A9. **PHP error log entry**: `^\[(?P<time>\d{2}-[A-Z][a-z]{2}-\d{4} \d{2}:\d{2}:\d{2})(?: (?P<zone>[A-Za-z][\w/+\-]*|[+-]\d{2}:?\d{2}))?\] (?P<msg>.*)$`; `PHP <type>:` prefix optional (user `error_log()` lines such as `WordPress database error ...` are entries too, `php_type` Null). Access logs: extra tag `product: apache|nginx, service: access` when the product is known.

A10. **Request line**: split on spaces; first token is `cs-method` if `^[A-Z]+$`, last is `cs-version` if `^HTTP/\d(\.\d)?$`, the rest rejoined is the target (`cs-uri` = `cs-uri-query` = target, `cs-uri-stem` = target up to `?`); `"-"` → all Null. Covers `"GET /"`, `"GET /a b HTTP/1.1"`, `"-"`, HTTP/2.0, HTTP/3.0.

A11. **Keyword normalization additions**: a scalar selection value is lifted to a one-element list before wrapping; a map-shaped selection key whose field name is empty (`'|all'`, `'|contains|all'`, `'|re'`, ...) is rewritten to `raw|<modifiers>`, adding `contains` when no match modifier is present (`'|all'` → `raw|contains|all`); sigma-rust's `contains` tokenizes values and wraps them in `*`, so wildcards keep their meaning.

A12. **Correlation evaluation is iwatobi's own sliding window, sigma-rust is used only to parse `SigmaCorrelationRule`.** sigma-rust buckets by fixed epoch-aligned windows, which misses confirmed honeypot chains that cross a boundary (case B15). `correlate.rs`: base-rule hits are collected as `BaseHit { correlation_file, base_name, timestamp (UTC), group_values, field_value (for value_count), event summary }`. Per correlation rule and per group-by value tuple, hits are sorted by time and a window of `timespan` slides over them: `event_count` fires when a window holds ≥ `gte`/`gt`/`eq` hits (`lt`/`lte` use fixed buckets, documented); `value_count` counts distinct values of `field` in the window; `temporal` fires when a window holds every referenced base rule; `temporal_ordered` additionally requires first occurrences in list order. Each fired cluster is reported once (the window then advances past its last member). Hits lacking a group-by field are dropped and counted (`correlation hits skipped (missing group-by field)`), never aborting the run. Base rules are keyed per correlation file (`file + name`), so identical titles across files cannot collide; `rules:` entries are resolved by `name`, then `id`, then `title`; an unresolvable or duplicate entry fails that file (error log + `Rules failed to load`). The correlation detection record carries Timestamp = latest member, Details = `Count: n ¦ Rules: ... ¦ First: .. ¦ Last: ..`, LogSource = `correlation`, Computer = the members' hostname if unique. `web_rapid_posts_to_php_index.yml` uses `timespan: 60s`.

A13. **`RuleMeta`**: one owned metadata view (title, id, level, status, author, date, modified, description, references, tags, falsepositives, rule file) built at load for both `Rule` and `SigmaCorrelationRule`; correlation level/status strings are lowercased and validated, so `--min-level`, `-D/-u` and the tag filters apply to correlation rules too. Every output placeholder renders from `RuleMeta`.

A14. **Live analysis**: expand every row first and build ONE `ScanTarget` per canonical file (rows never attach `extra_tags`; file/process tagging in the parsers does that). Only a path the user enters at the prompt gets the needed logsource as `extra_tags`. On start, if the effective uid is not 0, print a prominent warning that live analysis needs root or membership in `adm`/`systemd-journal` and that results may be incomplete (also recorded in the error log). Glob expansion distinguishes `PermissionDenied` (reported as such, no prompt) from not found. journalctl: `journalctl --system --no-pager -o short-iso-precise [--since ...]` without `-q`, stdout streamed straight into the Syslog parser, stderr captured to the error log, non-zero exit = failure; if stderr contains the "not seeing messages" hint the target is reported as partial. If stdin or stdout is not a terminal, `--no-wizard` behaviour applies with a warning; any `dialoguer` error is treated as "skip"/"no"; the path prompt validates existence and retries at most 3 times. `live.rs` compiles on every target and returns the error "live analysis is only supported on Linux" elsewhere. Hidden option `--log-locations <FILE>` overrides the table (used by tests).

A15. **Output**: rows stream as each file completes (like both siblings); `-s, --sort` ("Sort events before saving the file. (warning: this uses much more memory!)") buffers rendered rows and sorts by time (None last, then rule title, then file/line). JSON (`-t json`) is newline-separated pretty-printed objects like Hayabusa/Suzaku; JSONL is one compact object per line. `RawLine` is kept only when a selected profile uses it. The per-date summary counters use the date in the output timezone (local, or UTC with `-U`). Every rendered value passes a sanitizer that replaces C0/C1 control characters other than tab with `\xHH` (terminal/CSV injection), and CSV cells additionally pass `sanitize_csv_field`.

A16. **CI**: `.gitattributes` with `* text=auto eol=lf` and `*.gz binary`; integration tests compare parsed CSV/JSON values and normalize path separators; the `--no-wizard` live test uses `--log-locations` pointing at a temp file whose globs resolve inside a temp dir.

A17. **Post-implementation review (2026-10-27).** Three independent reviews of the integrated crate led to
these refinements, which override the corresponding text above: `generate: true` loads the base rules as
standalone rules too (Sigma correlation spec) and unreferenced detection documents of a correlation file are
standalone rules; `neq` is supported (read from the YAML, since sigma-rust's `CorrelationCondition` lacks it);
`eq`/`neq`/`lt`/`lte` use fixed buckets; null/empty group-by and value fields count as missing; aliases match
any base-rule identifier; same-second hits keep log order (file, line); unknown correlation keys, invalid
timespans, duplicate base names and `1 of`/`all of` patterns that match no selection fail at load; correlation
base matches count toward "events with hits". Parsing: a hinted format wins on one matching entry line; RFC 3164
year inference uses the file's mtime date in the `-z` zone; ISO syslog lines need a zone and a non-numeric host;
NUL runs are dropped (binary = control bytes in ≥ 25 % of sampled lines) and a leading BOM is stripped; the PHP
message detector only accepts a quote after `Got error '`, `said into stderr: "` or `sent in stderr: "`;
`php-fpm*` syslog processes also get `php/fpm`; Apache `*stderr*` files are Apache error logs; whole JSON floats
stay floats while `s-port`, `cs-bytes`, `time-taken`, `pid`, `tid` strings become integers. CLI: symlinked
directories are not followed and files are deduplicated by canonical path; read errors (truncated `.gz`) are
reported; the progress bar is hidden while rows stream to the terminal; a closed stdout pipe ends the run
quietly; `--time-offset` overflow is a CLI error; an unreadable or unrecognized `-f` file exits 1; the output
file can never be an input; error-log names are unique per run.

A18. **Log location on the terminal (0.1.0 re-release).** `standard` is Timestamp, RuleTitle, Level, Computer,
LogSource, LogFile, LineNumber, Details, so every terminal alert says where it was logged. A correlation row's
LogFile lists the files of its member events (deduplicated, in member order) and its LineNumber stays null.
PHP error log events keep only `php_type` and `message` as Details; PHP's own script location (`file`, `line`,
rendered `PhpFile` / `PhpLine`) and `zone` are ExtraFieldInfo, since the location is already in the message
and is usually `Unknown` / `0` for request-startup errors.

A19. **Progress bar (0.1.0 re-release).** As in Hayabusa, the bar is shown only when results are saved to a
file (`-o`), after an orange "Scanning in progress. Please wait." line: `[elapsed] done / total ⠁ [=====>   ] 37%`
with a green spinner and 40-column bar (plain with `-K`), and the file being scanned below it as
`"path" (size)`. It ends with "Scanning finished. Please wait while the results are being saved." (256-color 214).
`-q` and single-file scans no longer hide it; it still draws only on a terminal. Like Hayabusa, the
profile in use is printed before the scan in every mode (`Output profile: standard`). Messages printed during the
scan (`-v`, warnings) suspend the bar so they do not tear it. The journal counts as one more item.

A20. **One Details column, no Computer column (0.1.0 re-release).** Linux log lines have few fields, so
`%Details%` is every parsed field, the main fields of the format first (they are pushed first), plus
`TimestampInferred: true` when the timestamp was borrowed; a correlation's Details end with its `Members`.
`%ExtraFieldInfo%` and `%AllFieldInfo%` and the `all-field-info` / `all-field-info-verbose` profiles are
gone, and so is the details/extra split of `ParsedEvent` (`details_len`, `end_details`). No default profile
has `Computer`: an access log has no host name and a live scan's is the local one. `%Computer%` stays as a
placeholder for custom profiles (syslog host names from a central log server). This overrides §9, A15 and A18.

A21. **Custom and detected log formats (0.1.0 re-release).** `parsers/layout.rs` compiles a *layout* (one
anchored regex whose capture groups are named fields) from an nginx `log_format` (the string or the whole
directive; `$var`/`${var}`; a field between `"` is a quoted value with `\"`/`\x22` unescaped, between `[`/`]` a
bracketed one, `$time_local` keeps its space, otherwise one possibly empty token), an Apache `LogFormat` (`%h`,
`%t`, `%r`, `%>s`, `%{Header}i`, `%{strftime}t` → `time_format`, …, mapped to the nginx variable names), or a
user regex (named groups; `c_ip` → `c-ip`). Web server layouts feed the JSON access log mapping
(`RecordBuilder`, shared with `AccessJsonParser`), without repeating the columns it mapped or the time, and with
`-` → null for the rest; a regex can name any supported logsource (`Other` kind: fields keep their names, time
from `TIME_KEYS`, `hostname`/`host` → hostname). Formats live in `config/custom_log_formats.yaml`
(`--custom-formats FILE`; `formats:` list with `name`, one of `nginx`/`apache`/`regex`, optional `files` globs,
`time_format`, `logsource`; unknown keys, duplicate or built-in names and unsupported logsources are load
errors) and are `--log-format` values. Detection order per file: a custom format that applies to the file
(`files`) and matches the sample (one line with `files`, otherwise half), then the built-in sniffing, then
`infer_access_layout`: tokenize (bare / `"…"` / `[…]`), keep the dominant token shape (≥ 80 % of the sampled
entry lines), classify each column from ≥ 90 % of its non-dash values, and assign time, request (or method +
path + protocol), status, client IP and user agent (all required), then referer, bytes, virtual host and
ident/user; the rest are `field<N>`. The result is written as an nginx `log_format` and compiled with the same
code, so the printed layout pastes into the configuration unchanged. Detected layouts and the number of files
skipped as unrecognized are reported after the scan. Format names: `custom:<name>`, `access-auto`.
