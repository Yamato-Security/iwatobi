# Test files

Fixtures used by the unit tests and by `tests/cli.rs`. The expected detections below were derived by
hand from the lines and the rule keywords (not copied from a run).

| Directory | Content | Expected detections (shipped rules, `-z UTC`) |
| --- | --- | --- |
| `php2shell/` | PHP2Shell RCE evidence derived from [0x4D31/honeypot-data](https://github.com/0x4D31/honeypot-data) (CC BY 4.0, see its README) | `php-error.log`: memory exhausted 106, session ID 39, outbound `php -r` 5 · `apache2/error.log`: segfault 55, abort 7, shell stderr 29 · `apache2/access.log` and `access.jsonl`: PoC memory-pressure request 44 each, rapid-POST correlation 27 each · directory scan: exploitation-chain correlation 12 |
| `linux/` | Synthetic syslog-family logs: Debian `syslog`, `auth.log`, RHEL `secure` and `cron`, a rotated `syslog.2.gz`, rsyslog ISO, RFC 5424, `journalctl -o short-iso`, vsftpd and ClamAV logs | Modifying Crontab 4, Disabling Security Tools 2, Suspicious Named Error 4, Suspicious OpenSSH Daemon Error 11, PHP memory exhausted (via syslog) 1 |
| `web/` | Synthetic Apache 2.4/2.2 error log (event MPM, prefork, `[:error]`, proxy_fcgi, untimestamped glibc assertion), nginx error log, Apache combined access log, nginx JSON access log | segfault 1, abort 1, threading error 1, PHP memory exhausted 2, session ID 1, nginx core dump 1, PoC memory-pressure request 2, rapid-POST correlation 1, exploitation-chain correlation 1 (error.log lines 4, 6, 9) |
| `custom/logs/` | Synthetic logs in layouts the built-in formats do not know (documentation IP ranges, `example.com`): `auto/` an nginx access log with a split request line and extra columns (detected automatically), `nginx/`, `apache/` and `regex/` logs that need the formats in `custom/custom_log_formats.yaml` (`--custom-formats`) | `auto/www-access.log`: PoC memory-pressure request 3, rapid-POST correlation 1 · with the custom formats also `shop-access.log` and `intranet.log`: PoC request 1 each, `vpnd.log`: Suspicious OpenSSH Daemon Error 1; without them those three files are skipped as unrecognized |
| `auditd/` | Linux audit records from Splunk attack_data (see below): `raw/`, `enriched/` (`0x1D` separator), `interpreted/` (`ausearch -i`); synthetic `synthetic/audit.log` (hex-encoded and split `EXECVE` arguments, x86_64 / aarch64 system call numbers, `node=`) | Credentials In Files 3 (raw 2, synthetic 1), Hidden Files and Directories 1, ld.so.preload 4, insmod 2, firewall disabled 1, user account created 1, service reload/start 4, permissions change 1, split 2, magic SysRq 1, hidden paths 3, ASLR disabled 2 (synthetic), audio capture 1 (synthetic) |
| `sysmon-linux/` | Sysmon for Linux from Splunk attack_data: one event per line (`find.log`, `gawk.log`, `make.log` whose command lines contain newlines, `cron_append_excerpt.log`), syslog lines (`dirtyfrag-syslog.log`); synthetic `syslog` (Sysmon process and network events, an `audisp-syslog` audit record) and `journal` (`journalctl -o short-iso-precise`) | `find.log`: file and directory discovery 3, shell via find 3 · `gawk.log`: shell via AWK 2 · `cron_append_excerpt.log`: new cron file 7, script in a suspicious directory 1 (an 18-line event starting on line 7) · `syslog`: webshell 1, reverse shell 1, malware callback port 1, credentials in files 1 · `journal`: new cron file 1 |
| `php2shell-fpm/` | Synthetic php-fpm deployment: `php8.3-fpm.log`, PHP error log with IANA / offset / no zone tokens and a stack trace, nginx error log with FastCGI stderr | php-fpm exited on signal 2, php-fpm shell stderr 1, session ID 2, memory exhausted 2, POST content-length 1, outbound `php -r` 2 |

`php2shell/apache2/apache-stderr-segment.log` has no timestamps at all; its Apache-style name makes
it an Apache error log (shell stderr 3, so a scan of the whole `php2shell/` directory finds 32).

The `auditd/` and `sysmon-linux/` counts come from a run and were cross-checked with
[Zircolite](https://github.com/wagga40/Zircolite) 4.7.0 on the same files and rules: per rule they are
equal for the raw, ENRICHED and Sysmon files, once Zircolite's matches are limited to the Sysmon event
ID of each rule's category (Zircolite applies every rule to every event). The exception is System
Shutdown/Reboot: Zircolite matches 13 `grep -qE` records in `auditd/raw/find_ssh_files.log` whose
pattern contains `/shutdown$` and `/poweroff$`, while Iwatobi checks the command and its runlevel
argument and finds none ([DESIGN A23](../docs/DESIGN.md)). Zircolite does not read
`ausearch -i` output, hex-encoded or split arguments, raw `SYSCALL` numbers or events that span
several lines, which is what the synthetic files and `cron_append_excerpt.log` exercise.

## Splunk attack_data

The files of `auditd/raw/`, `auditd/enriched/`, `auditd/interpreted/` and `sysmon-linux/` (except
`syslog` and `journal`) are copies of files of [splunk/attack_data](https://github.com/splunk/attack_data),
licensed under the Apache License 2.0 ([`LICENSE-splunk-attack_data.txt`](LICENSE-splunk-attack_data.txt)).
They were renamed; `cron_append_excerpt.log` is lines 6114–6150 of its original. Sources (under
`datasets/attack_techniques/`):

| File | Original |
| --- | --- |
| `auditd/raw/find_ssh_files.log` | `T1552.004/linux_auditd_find_ssh_files/linux_auditd_find_ssh_files.log` |
| `auditd/raw/hidden_file.log` | `T1083/linux_auditd_hidden_file/linux_auditd_hidden_file.log` |
| `auditd/enriched/preload_file.log` | `T1574.006/linux_auditd_preload_file/linux_auditd_preload_file.log` |
| `auditd/enriched/insmod.log` | `T1547.006/linux_auditd_insmod/linux_auditd_insmod.log` |
| `auditd/enriched/disable_firewall.log` | `T1562.004/linux_auditd_disable_firewall/linux_auditd_disable_firewall.log` |
| `auditd/enriched/add_user_type.log` | `T1136.001/linux_auditd_add_user_type/linux_auditd_add_user_type.log` |
| `auditd/interpreted/daemon.log` | `T1562.012/auditd_daemon_type/linux_auditd_daemon.log` |
| `auditd/interpreted/split.log` | `T1030/linux_auditd_split_syscall_new/linux_auditd_new_split.log` |
| `auditd/interpreted/sysrq.log` | `T1529/auditd_path_sysrq/path_sysrq.log` |
| `auditd/interpreted/cron_path.log` | `T1053.003/linux_auditd_cron_file_audited/linux_path_cron.log` |
| `sysmon-linux/find.log` | `T1548/find/sysmon_linux.log` |
| `sysmon-linux/gawk.log` | `T1548/gawk/sysmon_linux.log` |
| `sysmon-linux/make.log` | `T1548/make/sysmon_linux.log` |
| `sysmon-linux/dirtyfrag-syslog.log` | `T1068/linux_dirtyfrag/linux_sysmon.log` |
| `sysmon-linux/cron_append_excerpt.log` | `T1053.003/cronjobs_entry/sysmon_linux_cron_append.log` (lines 6114–6150) |
