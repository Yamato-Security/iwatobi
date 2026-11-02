# Changes

## 1.0.0 [2026/11/02] - CODE BLUE Release

**New Features:**

- Linux audit logs: `audit.log` in the raw and ENRICHED formats, `ausearch -i` output and records forwarded to syslog by `audisp-syslog`, one event per record for the Sigma `service: auditd` rules. Hex-encoded values (`proctitle`, `EXECVE` arguments, `name`, `cwd`, ...) are decoded and split arguments joined, so field and keyword rules see the text `ausearch -i` shows; raw records get the `SYSCALL` name from the x86_64 / aarch64 system call number. A complete `EXECVE` argument list also gives a `CommandLine` for keyword rules, numbers in `EXECVE` argument selections match the arguments' text, and the SigmaHQ shutdown rule is checked against the command that ran and its runlevel (including `systemctl` shutdowns) instead of words anywhere in the record; the bundled rule files stay unchanged. (@YamatoSecurity)
- Sysmon for Linux: events in syslog, the systemd journal or one XML event per line (an event whose command line has a newline is joined back together), with every `EventData` field and the Sigma category of the event ID (`process_creation`, `network_connection`, `file_event`, `file_delete`, `process_termination`, `raw_access_thread`). (@YamatoSecurity)
- Rules: the SigmaHQ `r2026-07-01` Linux `auditd` (53), `process_creation` (122), `network_connection` (5) and `file_event` (8) rules, with the Detection Rule License. Live analysis reads `/var/log/audit/audit.log*` for audit rules and syslog / the journal for Sysmon rules. `--log-format` accepts `auditd` and `sysmon-linux`. (@YamatoSecurity)

**Other Changes:**

- License: Iwatobi is now copyright Shirofune Security Co., Ltd. and released under the Reciprocal Public License 1.5 (RPL-1.5) instead of the AGPLv3; every source file carries the copyright and the RPL License Notice. (@YamatoSecurity)

## 0.1.0 [2026/10/27] - Vulnpocalypse Release

**New Features:**

- First release of Iwatobi, a native Sigma scanner and DFIR timeline generator for Linux text logs, built on the same [sigma-rust](https://github.com/Yamato-Security/sigma-rust) engine as Suzaku. (@YamatoSecurity)
- `dfir-timeline` command: scan one file (`-f`), a directory (`-d`, recursively, rotated `.1`/`.2.gz` files included) or the live system (`-l, --live-analysis`). Live analysis works out which log files the loaded rules need from `config/log_locations.yaml`, asks for a directory (or skips the rules) when a log source is not found, and reads the systemd journal through `journalctl` when a host has no syslog files.
- Log formats: syslog (RFC 3164, RFC 5424, rsyslog ISO, `journalctl -o short-iso`), date-first daemon logs (vsftpd, clamd), Apache/nginx access logs (common, combined, vhost_combined and JSON lines, exposed with the Sigma web server field names), Apache and nginx error logs, PHP error logs and php-fpm logs. PHP engine messages are recognised inside Apache, nginx, php-fpm and syslog lines too.
- Custom log formats: access logs written with a customized nginx `log_format` or Apache `LogFormat` (virtual host first, split request line, extra columns, ...) are recognized automatically, and the detected layout is printed as an nginx `log_format` so it can be checked. Any other layout can be described in `config/custom_log_formats.yaml` (`--custom-formats`) as an nginx `log_format`, an Apache `LogFormat` or a regex with named groups and a Sigma logsource. Files whose format is not recognized are reported at the end of the scan. (@YamatoSecurity)
- Sigma rules: `rules/sigma/` holds SigmaHQ rules verbatim (syslog, sshd, cron, Apache, nginx); `rules/iwatobi/` holds new rules, including a PHP2Shell (CVE-2026-109618 / CVE-2026-109619) set validated against the published honeypot evidence, with Sigma correlation rules (`event_count`, `temporal`) evaluated with sliding windows.
- Output: terminal timeline by default (`standard` profile: timestamp, alert, level, log source, the log file and line of each alert, and the event details); `-o` with `-t csv,json,jsonl` saves the `verbose` profile with MITRE ATT&CK tags and rule file/ID as well. `Details` holds every parsed field, the main ones first; there is no `Computer` column (`%Computer%` can be added to a profile for syslog host names). Correlation alerts list the log files of their events. The script location that PHP reports in its messages is shown as `PhpFile` / `PhpLine`. The output profile in use is shown before scanning. While results are saved to a file, the same progress bar as Hayabusa shows the files scanned, the percentage and the file being scanned with its size. Profiles live in `config/profiles.yaml` (`list-profiles`).
- Release packages for Linux (x64/ARM64, glibc and static musl), macOS and Windows, built by the `Iwatobi Release Automation` workflow.
- `-z, --timezone` for logs whose timestamps carry no zone, `-U, --utc` output, `--timeline-start/--timeline-end/--time-offset`, `--min-level`, status and tag filters, `-s, --sort`, `-C, --clobber`, error log under `logs/`.
