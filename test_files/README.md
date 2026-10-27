# Test files

Fixtures used by the unit tests and by `tests/cli.rs`. The expected detections below were derived by
hand from the lines and the rule keywords (not copied from a run).

| Directory | Content | Expected detections (shipped rules, `-z UTC`) |
| --- | --- | --- |
| `php2shell/` | PHP2Shell RCE evidence derived from [0x4D31/honeypot-data](https://github.com/0x4D31/honeypot-data) (CC BY 4.0, see its README) | `php-error.log`: memory exhausted 106, session ID 39, outbound `php -r` 5 · `apache2/error.log`: segfault 55, abort 7, shell stderr 29 · `apache2/access.log` and `access.jsonl`: PoC memory-pressure request 44 each, rapid-POST correlation 27 each · directory scan: exploitation-chain correlation 12 |
| `linux/` | Synthetic syslog-family logs: Debian `syslog`, `auth.log`, RHEL `secure` and `cron`, a rotated `syslog.2.gz`, rsyslog ISO, RFC 5424, `journalctl -o short-iso`, vsftpd and ClamAV logs | Modifying Crontab 4, Disabling Security Tools 2, Suspicious Named Error 4, Suspicious OpenSSH Daemon Error 11, PHP memory exhausted (via syslog) 1 |
| `web/` | Synthetic Apache 2.4/2.2 error log (event MPM, prefork, `[:error]`, proxy_fcgi, untimestamped glibc assertion), nginx error log, Apache combined access log, nginx JSON access log | segfault 1, abort 1, threading error 1, PHP memory exhausted 2, session ID 1, nginx core dump 1, PoC memory-pressure request 2, rapid-POST correlation 1, exploitation-chain correlation 1 (error.log lines 4, 6, 9) |
| `custom/logs/` | Synthetic logs in layouts the built-in formats do not know (documentation IP ranges, `example.com`): `auto/` an nginx access log with a split request line and extra columns (detected automatically), `nginx/`, `apache/` and `regex/` logs that need the formats in `custom/custom_log_formats.yaml` (`--custom-formats`) | `auto/www-access.log`: PoC memory-pressure request 3, rapid-POST correlation 1 · with the custom formats also `shop-access.log` and `intranet.log`: PoC request 1 each, `vpnd.log`: Suspicious OpenSSH Daemon Error 1; without them those three files are skipped as unrecognized |
| `php2shell-fpm/` | Synthetic php-fpm deployment: `php8.3-fpm.log`, PHP error log with IANA / offset / no zone tokens and a stack trace, nginx error log with FastCGI stderr | php-fpm exited on signal 2, php-fpm shell stderr 1, session ID 2, memory exhausted 2, POST content-length 1, outbound `php -r` 2 |

`php2shell/apache2/apache-stderr-segment.log` has no timestamps at all; its Apache-style name makes
it an Apache error log (shell stderr 3, so a scan of the whole `php2shell/` directory finds 32).
