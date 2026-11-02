# Iwatobi rules

Iwatobi loads every `*.yml` / `*.yaml` file under this directory (recursively) with `-r, --rules`
(default `./rules`).

| Directory | Content |
| --- | --- |
| `sigma/` | Rules taken verbatim from [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) release `r2026-07-01`, keeping the upstream directory layout (`linux/auditd/`, `linux/process_creation/`, `linux/builtin/<service>/`, `web/product/<server>/`, ...). They are licensed under the [Detection Rule License 1.1](sigma/LICENSE.Detection.Rules.md). |
| `iwatobi/` | Rules written for Iwatobi: `php/php2shell/` (PHP2Shell, CVE-2026-109618 / CVE-2026-109619), `php/fpm/` (php-fpm), `web/apache/` (Apache error log), `web/webserver/` (access logs). |

## Supported log sources

A rule is loaded when its `logsource` can be satisfied by one of the log formats Iwatobi parses:

| `logsource` | Log |
| --- | --- |
| `product: linux` (+ `service: syslog`, `auth`, `sshd`, `cron`, `sudo`, `vsftpd`, `clamav`, `guacamole`) | syslog-format files (`/var/log/syslog`, `messages`, `auth.log`, `secure`, `cron`, ...), `journalctl -o short-iso` output |
| `category: webserver` | Apache / nginx access logs (common, combined, vhost_combined, JSON lines) with the Sigma web server field names (`c-ip`, `cs-method`, `cs-uri-query`, `sc-status`, `cs-user-agent`, ...) |
| `service: apache` | Apache error log |
| `service: nginx` | nginx error log |
| `product: php`, `service: error_log` | PHP error log, and PHP messages inside the Apache error log |
| `product: php`, `service: fpm` | php-fpm log |
| `product: linux`, `service: auditd` | Linux audit records: `audit.log` (raw and ENRICHED), `ausearch -i` output, records forwarded by `audisp-syslog` |
| `product: linux`, `category: process_creation`, `network_connection`, `file_event`, `file_delete`, `process_termination`, `raw_access_thread` (and `service: sysmon`) | Sysmon for Linux events (event IDs 1, 3, 11, 23, 5, 9) in syslog, the journal, or one XML event per line |

Rules for other sources (Windows, cloud services, web proxies, ...) are skipped at load time and
counted in the start-up summary.

## Keywords match anywhere in the line

Sigma keyword lists (`keywords:` or any search identifier that is a list of strings) match
anywhere in the log message, as the specification requires. Iwatobi guarantees this by
surrounding each keyword with `*` wildcards before handing the rule to the sigma-rust engine
(whose own keyword matching is whole-value), so `- 'REPLACE'` matches
`crontab[12399]: (user) REPLACE (user)`. Keywords that already start or end with `*` are left as
they are; field-based selections (`field: value`) are not changed.

## Correlation rules

Sigma correlation rules (`event_count`, `value_count`, `temporal`, `temporal_ordered`) are
supported. Put the correlation and its base rules in one file separated by `---`; the
`rules:` list (and `aliases:`) may reference base rules by `name`, `id` or `title`.

- Base rules are only reported through the correlation, unless the correlation has
  `generate: true`, in which case they also report their own matches. A detection document
  of the file that no correlation references is an ordinary rule.
- Windows slide over the events (a chain that crosses a minute boundary is still found).
  Conditions that a sliding window cannot answer (`eq`, `neq`, `lt`, `lte`) are evaluated on
  fixed, epoch-aligned buckets of `timespan`.
- `group-by` and `value_count` fields that are missing or empty (`-` in an access log) do not
  form a group or a value; such events are counted as skipped in the summary.
- Unknown keys in `correlation:` or `condition:`, an invalid `timespan`, duplicate base rule
  names and `rules:` entries that resolve to nothing fail the whole file (see the error log).

## Writing rules

- Use the SigmaHQ field names for access logs (`cs-uri-query` holds the full request target,
  `cs-uri-stem` the path only).
- Syslog events expose `hostname`, `process`, `pid` and `message`; Apache error log events
  `module`, `level`, `pid`, `client`, `error_code` and `message`; PHP error log events
  `php_type`, `message`, `file` and `line`; php-fpm events `level`, `pool`, `child_pid` and
  `message`. Every event also has `raw` (the whole line).
- Audit record events have `type` and the record's fields under their own names (`a0`, `a1`, ...,
  `exe`, `comm`, `key`, `name`, `nametype`, `proctitle`, ...), decoded when auditd hex-encoded them,
  the interpreted upper-case fields of ENRICHED records, `SYSCALL` (the system call name) and
  `serial`. Unquoted decimal values are numbers.
- Sysmon for Linux events have `EventID`, every `EventData` field under its own name (`Image`,
  `CommandLine`, `ParentImage`, `User`, `TargetFilename`, `DestinationIp`, `DestinationPort`,
  `Initiated`, ...), `Channel`, `Computer`, `EventRecordID` and `Provider_Name`. Decimal values are
  numbers (`DestinationPort: 4444`, `LogonId: 0`).
- Test a rule with `iwatobi dfir-timeline -f <log> -r <rule.yml>`.

The auditd loader adapts EXECVE argument literal types and the known original shutdown-rule
selection shape in memory. The shutdown adapter checks the executable and exact `a1` runlevel,
or `systemctl` with a shutdown or reboot command at the start of the reconstructed `CommandLine`;
field names and unrelated argument text cannot supply its shutdown evidence. SigmaHQ files remain
unchanged for synchronization. See DESIGN amendment A23 for the exact scope.
